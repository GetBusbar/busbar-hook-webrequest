use crate::config::open;
use crate::reply::{error_status, REQUEST_FAILED};
use crate::wire::request;
use std::io::{Read, Write};
use std::net::TcpListener;

#[test]
fn the_request_target_and_fields_follow_the_url() {
    let t = open(br#"{"url":"https://api.example.com"}"#).unwrap();
    let r = request(&t, b"{}".to_vec());
    assert_eq!(r.method, b"POST");
    assert_eq!(r.target, b"/");
    assert_eq!(
        r.fields,
        vec![
            (b"content-type".to_vec(), b"application/json".to_vec()),
            (b"accept".to_vec(), b"*/*".to_vec())
        ]
    );
    let t = open(br#"{"url":"https://u:p@api.example.com:8443/a?b=1"}"#).unwrap();
    let r = request(&t, b"{}".to_vec());
    assert_eq!(r.target, b"/a?b=1");
    assert_eq!(
        r.fields[0],
        (b"authorization".to_vec(), b"Basic dTpw".to_vec())
    );
}

/// What a raw listener received from the 1.5.5 client (reqwest as 1.5.5 built it) for one POST.
fn client_bytes(url: &str, timeout_ms: u64, body: &'static [u8]) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let url = url.replace("PORT", &port.to_string());
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = s.read(&mut buf).unwrap();
            got.extend_from_slice(&buf[..n]);
            if let Some(end) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&got[..end]).to_ascii_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .map_or(0, |v| v.trim().parse().unwrap());
                if got.len() >= end + 4 + len {
                    break;
                }
            }
            if n == 0 {
                break;
            }
        }
        s.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}")
            .unwrap();
        got
    });
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // The oracle dials its own loopback listener: an HTTP(S)_PROXY in the environment must not
        // turn the request into an absolute-form one sent to a proxy.
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_millis(timeout_ms))
            .build()
            .unwrap();
        client
            .post(reqwest::Url::parse(&url).unwrap())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .timeout(std::time::Duration::from_millis(timeout_ms))
            .send()
            .await
            .unwrap();
    });
    server.join().unwrap()
}

/// THE BYTE-IDENTITY ORACLE (C0 CAP webrequest): the request this crate writes equals, byte for byte,
/// what the 1.5.5 client wrote to a raw listener (with the framer's own two fields placed where hyper
/// places them).
#[test]
fn the_request_bytes_are_what_the_1_5_5_client_wrote() {
    let body: &'static [u8] = br#"{"request":{"pool":"p"},"op":"decide"}"#;
    for url in [
        "http://127.0.0.1:PORT/route",
        "http://127.0.0.1:PORT",
        "http://127.0.0.1:PORT/a/b?x=1&y=%20z",
        "http://127.0.0.1:PORT/route?token=abc",
        "http://svc:hunter2@127.0.0.1:PORT/route",
        "http://us%40er:p%3Ass@127.0.0.1:PORT/route",
        "http://only@127.0.0.1:PORT/route",
        "http://svc:p%+4ss@127.0.0.1:PORT/route",
        "http://svc%FF:pw@127.0.0.1:PORT/route",
        "http://svc:%FF@127.0.0.1:PORT/route",
        "http://:%FF@127.0.0.1:PORT/route",
        "http://svc:p%4@127.0.0.1:PORT/route",
        "http://localhost:PORT/route",
    ] {
        let want = client_bytes(url, 2_000, body);
        let cfg = format!(r#"{{"url":"{}"}}"#, url.replace("PORT", &want_port(&want)));
        // Retain the historical observation, but invalid decoded credentials are now refused.
        if url.contains("%FF") {
            assert!(open(cfg.as_bytes()).unwrap_err().contains("valid UTF-8"));
            continue;
        }
        let target = open(cfg.as_bytes()).unwrap();
        let ours = assemble(&request(&target, body.to_vec()), &target.url);
        assert_eq!(
            String::from_utf8_lossy(&ours),
            String::from_utf8_lossy(&want),
            "request bytes differ for {url}"
        );
        assert_eq!(ours, want);
    }
}

/// `host` or `host:port` as the http framer derives it from the origin: the port only when the URL
/// names a non-default one.
fn host_header(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// The bytes the http framer writes for `r`: the request line, the forwarder's fields in order, then
/// what the framer adds itself (`host` from the authority, then `content-length` from the body).
fn assemble(r: &crate::wire::Request, url: &url::Url) -> Vec<u8> {
    let mut head = format!(
        "{} {} HTTP/1.1\r\n",
        std::str::from_utf8(&r.method).unwrap(),
        std::str::from_utf8(&r.target).unwrap()
    );
    for (k, v) in &r.fields {
        head.push_str(&format!(
            "{}: {}\r\n",
            std::str::from_utf8(k).unwrap(),
            std::str::from_utf8(v).unwrap()
        ));
    }
    head.push_str(&format!("host: {}\r\n", host_header(url)));
    head.push_str(&format!("content-length: {}\r\n\r\n", r.body.len()));
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&r.body);
    bytes
}

/// The port the client dialled, read off the `host:` header it sent.
fn want_port(sent: &[u8]) -> String {
    let text = String::from_utf8_lossy(sent);
    let host = text
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .expect("a host header");
    host.rsplit(':').next().unwrap().to_string()
}

/// The 1.5.5 client's own error texts, surfaced through the same `without_url` wrapper, are this crate's
/// constants.
#[test]
fn the_failure_texts_are_what_the_1_5_5_client_said() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // The oracle dials its own loopback listener: an HTTP(S)_PROXY in the environment must not
        // turn the request into an absolute-form one sent to a proxy.
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead = l.local_addr().unwrap().port();
        drop(l);
        let e = client
            .post(format!("http://127.0.0.1:{dead}/x?token=abc"))
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
            .unwrap_err();
        assert_eq!(
            format!("webrequest: request failed: {}", e.without_url()),
            REQUEST_FAILED
        );

        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let e = client
            .post(format!("http://127.0.0.1:{port}/x"))
            .timeout(std::time::Duration::from_millis(100))
            .send()
            .await
            .unwrap_err();
        assert_eq!(
            format!("webrequest: request failed: {}", e.without_url()),
            REQUEST_FAILED
        );
        drop(l);

        for (status, reason) in [
            (404u16, "Not Found"),
            (418, "I'm A Teapot Custom"),
            (500, "Internal Server Error"),
        ] {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            let srv = std::thread::spawn(move || {
                let (mut s, _) = l.accept().unwrap();
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf);
                let head = format!("HTTP/1.1 {status} {reason}\r\ncontent-length: 2\r\n\r\n");
                s.write_all(head.as_bytes()).unwrap();
                s.write_all(b"{}").unwrap();
            });
            let r = client
                .post(format!("http://127.0.0.1:{port}/x"))
                .timeout(std::time::Duration::from_secs(2))
                .send()
                .await
                .unwrap();
            let e = r.error_for_status().unwrap_err();
            assert_eq!(
                format!(
                    "webrequest: target returned an error status: {}",
                    e.without_url()
                ),
                error_status(status, Some(reason))
            );
            srv.join().unwrap();
        }
    });
}
