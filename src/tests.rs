use super::*;

/// `open` fails closed on a missing/empty URL, a malformed config, and an SSRF-blocked URL; and
/// succeeds for a valid https target and a loopback http sidecar.
#[test]
fn open_fails_closed_on_bad_config() {
    assert!(open("").is_err(), "empty config (no url) must fail closed");
    assert!(open("{}").is_err(), "config without url must fail closed");
    assert!(
        open("{ not json").is_err(),
        "malformed config must fail closed"
    );
    assert!(
        open(r#"{"url":"http://169.254.169.254/x"}"#).is_err(),
        "an SSRF-blocked url must fail the load"
    );
    assert!(
        open(r#"{"url":"http://10.0.0.1/x"}"#).is_err(),
        "an RFC1918 url must fail the load"
    );
    assert!(
        open(r#"{"url":"http://api.example.com/x"}"#).is_err(),
        "plaintext http to a remote target must fail the load"
    );
    // An IP literal, not a name: `open` resolves a name through the real resolver, and a unit test
    // must not depend on (or wait for) live DNS (WREQ-18).
    assert!(
        open(r#"{"url":"https://192.0.2.10/route"}"#).is_ok(),
        "a valid https target must load"
    );
    assert!(
        open(r#"{"url":"http://127.0.0.1:9000/route"}"#).is_ok(),
        "a loopback http sidecar must load"
    );
}

/// The reply parser caps depth and reports a LENGTH-ONLY error (never echoing the reply bytes).
#[test]
fn parse_reply_depth_and_length_only_errors() {
    // A ~150-deep body is rejected before a Value is built (well under the size cap).
    let mut deep = String::from(r#"{"order":"#);
    deep.push_str(&"[".repeat(150));
    deep.push_str(&"]".repeat(150));
    deep.push('}');
    assert!(deep.len() < MAX_REPLY_BYTES);
    // The pre-check's own message, not serde_json's recursion limit (which would surface as
    // "invalid JSON"): the pre-check is what decides here (WREQ-10).
    let err = parse_reply(deep.as_bytes()).unwrap_err();
    assert!(err.contains("exceeded max nesting depth"), "{err}");

    // A malformed reply that echoes prompt content must not splash it into the error.
    let malformed = br#"{"order":[0,, "echo":"SENTINEL-PROMPT-TEXT"}"#;
    let err = parse_reply(malformed).unwrap_err();
    assert!(
        !err.contains("SENTINEL-PROMPT-TEXT"),
        "parse error echoed reply bytes: {err}"
    );
    assert!(
        err.contains("invalid JSON"),
        "expected length-only message: {err}"
    );

    // A well-formed reply parses.
    assert_eq!(
        parse_reply(br#"{"order":[1,0]}"#).unwrap(),
        serde_json::json!({"order": [1, 0]})
    );
}

/// The observable depth boundary of `parse_reply`: depth 127 parses, depth 128 does not.
///
/// NOTE the boundary this test pins is depth 127, not `MAX_REPLY_DEPTH` (128): `serde_json`'s OWN
/// internal recursion limit rejects a depth-128 document whatever the pre-check says (depth 127
/// parses; depth 128 fails serde_json's own parse even though the pre-check's `128 > 128` is
/// false). So this test cannot see an off-by-one in `exceeds_max_depth` (`>` changed to `>=` still
/// accepts 127 and refuses 128); `exceeds_max_depth_is_exact_at_its_own_boundary` pins that.
#[test]
fn parse_reply_depth_boundary_is_exact() {
    let nested = |n: usize| {
        let mut s = String::from(r#"{"order":"#);
        s.push_str(&"[".repeat(n));
        s.push_str(&"]".repeat(n));
        s.push('}');
        s
    };
    // n array levels + the outer `{` = a max depth of n+1.
    let at_boundary = nested(MAX_REPLY_DEPTH - 2); // depth 127: accepted
    assert!(
        parse_reply(at_boundary.as_bytes()).is_ok(),
        "depth 127 (one below serde_json's own internal recursion limit) must still be accepted"
    );
    let one_over = nested(MAX_REPLY_DEPTH - 1); // depth 128: rejected
    assert!(
        parse_reply(one_over.as_bytes()).is_err(),
        "depth 128 must be rejected"
    );
}

/// WREQ-10. `exceeds_max_depth`'s own boundary, away from serde_json's limit: `max` levels are
/// allowed, `max + 1` are not. A `>=` in place of `>` fails the second assertion.
#[test]
fn exceeds_max_depth_is_exact_at_its_own_boundary() {
    assert!(exceeds_max_depth(b"[[[", 2));
    assert!(!exceeds_max_depth(b"[[", 2));
    assert!(
        !exceeds_max_depth(b"[[]][[]]", 2),
        "depth, not bracket count"
    );
    assert!(exceeds_max_depth(br#"{"a":[{"b":1}]}"#, 2));
}

/// WREQ-11. Brackets inside a JSON string are text, not nesting, and an escaped quote does not end
/// the string. Without the string tracking the first reply below is 200 levels deep and refused;
/// without the escape tracking the second one is.
#[test]
fn brackets_inside_strings_do_not_count_as_depth() {
    let brackets = "[".repeat(200);
    let plain = format!(r#"{{"m":"{brackets}"}}"#);
    assert_eq!(
        parse_reply(plain.as_bytes()).unwrap(),
        serde_json::json!({ "m": brackets })
    );
    let escaped = format!(r#"{{"m":"a\"{brackets}"}}"#);
    assert_eq!(
        parse_reply(escaped.as_bytes()).unwrap(),
        serde_json::json!({ "m": format!("a\"{brackets}") })
    );
}

/// The non-object-payload fallback branch of `Envelope::serialize` (wraps a non-object projection
/// under a `payload` key rather than dropping it) is live, reachable code with no prior coverage —
/// prove it actually does what its comment claims instead of trusting the comment.
#[test]
fn envelope_wraps_a_non_object_payload_under_payload_key() {
    let payload = serde_json::json!(["not", "an", "object"]);
    let value = request_envelope("notify", &payload);
    assert_eq!(value["op"], "notify");
    assert_eq!(value["payload"], payload);
}

/// The RAW BYTE serialization (what actually goes on the wire via `post_op`'s `serde_json::to_vec`,
/// not the `to_value`-based `request_envelope` test helper, which would hide this: `to_value` builds
/// a `Map` that naturally collapses duplicate keys regardless of what the `Serialize` impl emits) must
/// never contain the `op` key twice, even when the projected payload itself carries a top-level `op`
/// field.
///
/// Without the skip, the payload's own `"op":"whatever"` and the discriminator's `"op":"decide"`
/// are both written to the byte stream — two `"op":` occurrences. As implemented, the payload's `op`
/// key is skipped and only the discriminator's `op` is emitted.
#[test]
fn envelope_byte_serialization_never_duplicates_the_op_key() {
    let payload = serde_json::json!({
        "op": "whatever-the-payload-happened-to-carry",
        "request": {"pool": "p"}
    });
    let bytes = serde_json::to_vec(&Envelope {
        op: "decide",
        payload: &payload,
    })
    .expect("envelope always serializes");
    let raw = String::from_utf8(bytes).unwrap();
    let op_key_count = raw.matches("\"op\":").count();
    assert_eq!(
        op_key_count, 1,
        "expected exactly one \"op\" key on the wire, got {op_key_count} in: {raw}"
    );
    // And it must be the discriminator's value, not the payload's stale one.
    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed["op"], "decide");
}

/// The request envelope merges the `op` discriminator into the projection object, preserving every
/// projected key (so any opt-in prompt/user the core granted rides straight through).
#[test]
fn request_envelope_merges_op_and_preserves_projection() {
    let payload = serde_json::json!({
        "request": {"pool": "p", "messages": [{"role": "user", "text": "hi"}]},
        "candidates": [{"idx": 0}]
    });
    let env = request_envelope("decide", &payload);
    assert_eq!(env["op"], "decide");
    assert_eq!(env["request"]["pool"], "p");
    assert_eq!(env["request"]["messages"][0]["text"], "hi");
    assert_eq!(env["candidates"][0]["idx"], 0);
}

/// `post_op`'s transport-error string is masked even when the target URL embeds a credential. The
/// unit-level twin of `tests/e2e.rs`'s `forward_transport_error_never_leaks_userinfo`, which skips
/// off CI when the cdylib is not built; this one always runs.
///
/// reqwest strips `user:pass@` off the URL into an auth header before the request is made, so the
/// userinfo is gone whatever this crate does. What `.without_url()` actually removes is the QUERY
/// STRING, which reqwest preserves verbatim, so the URL carries a `?token=` (WREQ-19): without it
/// this test could not fail with `.without_url()` deleted.
#[test]
fn post_op_error_string_never_contains_url_userinfo() {
    let fwd = Forwarder::new(Config {
        // RFC 5737 TEST-NET-1: unroutable, so the POST fails fast without a real network hop.
        url: "https://svc:hunter2@192.0.2.1/route?token=hunter3".to_string(),
        timeout_ms: Some(300),
    })
    .expect(
        "192.0.2.1 is a public IP over https, so it loads fine (the SSRF guard only blocks \
             plaintext http to a non-loopback host, and load-time RFC1918/link-local ranges)",
    );
    let err = fwd
        .post_op("decide", &serde_json::json!({}))
        .expect_err("192.0.2.1 is unroutable test-net space; the POST must fail");
    assert!(
        !err.contains("hunter2"),
        "post_op error leaked the URL's userinfo credential: {err}"
    );
    assert!(
        !err.contains("svc:"),
        "post_op error leaked the URL's userinfo username: {err}"
    );
    assert!(
        !err.contains("hunter3") && !err.contains("token="),
        "post_op error leaked the URL's query credential: {err}"
    );
}

/// `describe` returns the forwarder's own schema; `status` reports the target host and timeout with
/// no prompt/user content, and acks its own metrics shape.
#[test]
fn describe_and_status_report_own_state() {
    let fwd = Forwarder::with_lookup(
        Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: Some(1234),
        },
        no_dns(),
    )
    .expect("valid config");
    assert_eq!(fwd.describe()["schema"]["type"], "object");
    let status = fwd.status();
    assert_eq!(
        status["status"]["settings"]["target_host"],
        "api.example.com"
    );
    assert_eq!(status["status"]["settings"]["timeout_ms"], 1234);
}

/// `configure` RE-VALIDATES a pushed URL against the SSRF guard: a good URL ACKs (true), an
/// SSRF-blocked URL NACKs (false → the engine rejects the push), a missing url ACKs (nothing to check).
#[test]
fn configure_revalidates_pushed_url() {
    let fwd = Forwarder::with_lookup(
        Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: None,
        },
        no_dns(),
    )
    .expect("valid config");

    let mut ok = serde_json::Map::new();
    ok.insert(
        "url".into(),
        serde_json::json!("https://other.example.com/route"),
    );
    assert!(fwd.configure(&ok, 2), "a valid pushed url must ACK");

    let mut bad = serde_json::Map::new();
    bad.insert("url".into(), serde_json::json!("http://169.254.169.254/x"));
    assert!(
        !fwd.configure(&bad, 3),
        "an SSRF-blocked pushed url must NACK"
    );

    assert!(
        fwd.configure(&serde_json::Map::new(), 4),
        "a missing url ACKs"
    );
}

/// A pushed `url` that's PRESENT but not a string (a templating bug rendering it as a number or
/// null) must NACK, not be treated identically to an absent key.
///
/// A bare `settings.get("url").and_then(|v| v.as_str())` yields `None` for a non-string value
/// exactly as it does for a missing key, which would fall into the same "nothing to check, ACK" arm
/// as a genuinely absent url. As implemented, a present-but-wrong-typed url is distinguished and
/// NACKs.
#[test]
fn configure_nacks_a_present_but_wrong_typed_url() {
    let fwd = Forwarder::with_lookup(
        Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: None,
        },
        no_dns(),
    )
    .expect("valid config");

    let mut number_url = serde_json::Map::new();
    number_url.insert("url".into(), serde_json::json!(12345));
    assert!(
        !fwd.configure(&number_url, 5),
        "a non-string url must NACK, not be silently treated as absent"
    );

    let mut null_url = serde_json::Map::new();
    null_url.insert("url".into(), serde_json::Value::Null);
    assert!(
        !fwd.configure(&null_url, 6),
        "a null url must NACK, not be silently treated as absent"
    );
}

/// An operator-supplied `timeout_ms` is clamped to `[1, MAX_TIMEOUT_MS]` — MAX_TIMEOUT_MS must not
/// meaningfully exceed the engine's reference hook budget (see its doc comment), so a fat-fingered
/// huge value cannot pin the process-wide hook FFI permit for far longer than the engine itself
/// budgets for one hook call.
#[test]
fn timeout_ms_is_clamped_to_max_timeout_ms() {
    let fwd = Forwarder::with_lookup(
        Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: Some(60_000),
        },
        no_dns(),
    )
    .expect("valid config");
    assert_eq!(
        fwd.live.read().unwrap().timeout,
        Duration::from_millis(MAX_TIMEOUT_MS),
        "an oversized timeout_ms must clamp to MAX_TIMEOUT_MS, not pass through"
    );

    let fwd = Forwarder::with_lookup(
        Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: Some(0),
        },
        no_dns(),
    )
    .expect("valid config");
    assert_eq!(
        fwd.live.read().unwrap().timeout,
        Duration::from_millis(1),
        "a zero timeout_ms must clamp up to the 1ms floor"
    );
}

/// Validating a pushed `url` against the SSRF guard and ACKing without updating the live forwarder
/// would leave every subsequent `decide`/`transform`/`notify` posting to the URL from `open`,
/// silently, until an unrelated plugin reload. That would break busbar's documented contract for this
/// op (`docs/admin-api.md`'s `PATCH /hooks/{name}/settings`: "commit on ack", no restart-to-apply
/// carve-out for hooks) — an operator's PATCH would report success while nothing changed. As
/// implemented, a committed (ACKed) `url` push is visible immediately via `status()`.
#[test]
fn configure_commits_a_new_url_to_the_live_target() {
    let fwd = Forwarder::with_lookup(
        Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: None,
        },
        no_dns(),
    )
    .expect("valid config");
    assert_eq!(
        fwd.status()["status"]["settings"]["target_host"],
        "api.example.com"
    );

    let mut push = serde_json::Map::new();
    push.insert(
        "url".into(),
        serde_json::json!("https://other.example.com/route"),
    );
    assert!(fwd.configure(&push, 2), "a valid pushed url must ACK");

    assert_eq!(
        fwd.status()["status"]["settings"]["target_host"],
        "other.example.com",
        "an ACKed url push must take effect on the live forwarder, not just validate and discard"
    );
}

/// A committed `timeout_ms` push (with no `url` key in the same push) updates the live timeout and
/// leaves the live url untouched — the two settings commit independently.
#[test]
fn configure_commits_a_new_timeout_without_touching_the_url() {
    let fwd = Forwarder::with_lookup(
        Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: Some(1234),
        },
        no_dns(),
    )
    .expect("valid config");

    let mut push = serde_json::Map::new();
    push.insert("timeout_ms".into(), serde_json::json!(500));
    assert!(
        fwd.configure(&push, 2),
        "a valid pushed timeout_ms must ACK"
    );

    let status = fwd.status();
    assert_eq!(status["status"]["settings"]["timeout_ms"], 500);
    assert_eq!(
        status["status"]["settings"]["target_host"], "api.example.com",
        "a timeout_ms-only push must not disturb the live url"
    );
}

/// A pushed `timeout_ms` that's PRESENT but not a non-negative integer (a string, a float, a negative
/// number) must NACK the whole push — including any `url` key in the SAME push, which must not commit
/// partially.
#[test]
fn configure_nacks_a_present_but_wrong_typed_timeout_and_does_not_partially_apply() {
    let fwd = Forwarder::with_lookup(
        Config {
            url: "https://api.example.com/route".to_string(),
            timeout_ms: None,
        },
        no_dns(),
    )
    .expect("valid config");

    let mut push = serde_json::Map::new();
    push.insert(
        "url".into(),
        serde_json::json!("https://other.example.com/route"),
    );
    push.insert("timeout_ms".into(), serde_json::json!("soon"));
    assert!(
        !fwd.configure(&push, 2),
        "a non-integer timeout_ms must NACK"
    );
    assert_eq!(
        fwd.status()["status"]["settings"]["target_host"],
        "api.example.com",
        "a NACKed push must not partially commit the url from the same push"
    );
}

/// Dropping a `Forwarder` from INSIDE an async context (a tokio worker thread) must NOT panic.
/// This reproduces the hot-reload drop path: on config reload the last `Arc<App>` — and this
/// forwarder with it — can drop on a tokio async thread. A bare `Runtime` dropped there panics
/// ("Cannot drop a runtime in a context where blocking is not allowed"), which the SDK's
/// `ffi_guard` would catch and LEAK the handle. The `Drop` impl's `shutdown_background()` makes
/// the drop non-blocking, so no panic fires.
#[test]
fn drop_in_async_context_does_not_panic() {
    // A MULTI-thread runtime with worker threads: `block_on` here runs on a thread that IS a
    // tokio runtime context, so the inner forwarder's owned current-thread runtime would hit the
    // forbidden blocking-drop if `Drop` did not use `shutdown_background()`.
    let outer = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .expect("build outer runtime");
    outer.block_on(async {
        let fwd = Forwarder::with_lookup(
            Config {
                url: "https://api.example.com/route".to_string(),
                timeout_ms: None,
            },
            no_dns(),
        )
        .expect("valid config");
        // Dropping `fwd` here is the operation under test — it must not panic in this async context.
        drop(fwd);
    });
}

// ── Loopback targets and DNS answers for the connect-path tests ─────────────────────────────────

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

/// A loopback HTTP/1.1 target on a plain thread. Every connection gets one request read (its body
/// recorded) and the raw `response` pieces written back in order, flushed one at a time, then the
/// connection closes. `Connection: close` in every response keeps reqwest from pooling, so each
/// request is a fresh connect (and a fresh resolve).
struct Target {
    addr: SocketAddr,
    bodies: Arc<Mutex<Vec<String>>>,
}

impl Target {
    fn start(response: Vec<Vec<u8>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback target");
        let addr = listener.local_addr().expect("target address");
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&bodies);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(body) = read_request(&mut stream) else {
                    continue;
                };
                sink.lock().unwrap().push(body);
                for piece in &response {
                    if stream
                        .write_all(piece)
                        .and_then(|()| stream.flush())
                        .is_err()
                    {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        });
        Self { addr, bodies }
    }

    /// A target answering every request with `body` as a 200 JSON reply.
    fn json(body: &str) -> Self {
        Self::start(vec![json_response(body)])
    }

    fn port(&self) -> u16 {
        self.addr.port()
    }

    fn url(&self) -> String {
        format!("http://{}/", self.addr)
    }

    fn hits(&self) -> usize {
        self.bodies.lock().unwrap().len()
    }
}

/// Read one request off `stream` and return its body (`None` if the peer went away first).
fn read_request(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            while buf.len() < end + 4 + len {
                let n = stream.read(&mut chunk).ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&chunk[..n]);
            }
            return Some(String::from_utf8_lossy(&buf[end + 4..end + 4 + len]).into_owned());
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// A complete `200 OK` JSON response carrying `body`.
fn json_response(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// A lookup with no DNS behind it: every name fails to resolve, instantly, which the open/configure
/// check allows. For tests whose subject is not the connect path.
fn no_dns() -> net_guard::Lookup {
    Arc::new(|_: &str, _: u16| Err(std::io::Error::other("no DNS in unit tests")))
}

/// A lookup that answers the open/configure resolve check with `validate` (`None`: the name does
/// not resolve) and every CONNECT with `connect`, after `delay`. The two are told apart by port:
/// the check asks with the URL's port, the client's resolver asks with port 0.
fn split_lookup(validate: Option<IpAddr>, connect: IpAddr, delay: Duration) -> net_guard::Lookup {
    Arc::new(move |_: &str, port: u16| {
        if port != 0 {
            return validate
                .map(|ip| vec![SocketAddr::new(ip, port)])
                .ok_or_else(|| std::io::Error::other("no answer"));
        }
        std::thread::sleep(delay);
        Ok(vec![SocketAddr::new(connect, 0)])
    })
}

/// `0.0.0.0`: internal (unspecified) to the guard, yet a connect to it reaches the local host on
/// Linux, so a target on 127.0.0.1 counts a request that was dialed there. Nothing real is dialed.
const UNSPECIFIED: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn cfg(url: String, timeout_ms: u64) -> Config {
    Config {
        url,
        timeout_ms: Some(timeout_ms),
    }
}

/// WREQ-1. A name that did not resolve at open used to leave the client unpinned, and reqwest
/// then resolved it at connect with no check at all: SERVFAIL at open, `169.254.169.254` at the
/// request, and the envelope went to the metadata service. Every connect now checks its own
/// answer, and an internal one fails the connect before anything is dialed.
#[test]
fn an_internal_answer_at_connect_is_refused_before_any_dial() {
    let target = Target::json(r#"{"order":[0]}"#);
    let fwd = Forwarder::with_lookup(
        cfg(format!("http://svc.localhost:{}/", target.port()), 2000),
        split_lookup(None, UNSPECIFIED, Duration::ZERO),
    )
    .expect("a name that does not resolve at open is allowed (availability, not security)");
    let err = fwd
        .post_op("decide", &serde_json::json!({}))
        .expect_err("an internal answer at connect must fail the call");
    assert!(
        err.contains("SSRF guard") && err.contains("0.0.0.0"),
        "the failure must be the guard's refusal, not a connect error: {err}"
    );
    assert_eq!(
        target.hits(),
        0,
        "nothing may be dialed on a refused answer"
    );
}

/// WREQ-2. The address approved at open was pinned for the client's life, so when the target's
/// addresses rotated every call failed until a url push or a restart. The connect now resolves the
/// CURRENT answer and follows the target.
#[test]
fn the_connect_follows_the_targets_current_dns_answer() {
    let target = Target::json(r#"{"order":[0]}"#);
    // Approved at open: `::1`, where nothing listens on the target's port. The target has since
    // moved to 127.0.0.1, which is what DNS answers at connect.
    let fwd = Forwarder::with_lookup(
        cfg(format!("http://svc.localhost:{}/", target.port()), 2000),
        split_lookup(
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            LOOPBACK,
            Duration::ZERO,
        ),
    )
    .expect("loopback answers are allowed");
    let reply = fwd
        .post_op("decide", &serde_json::json!({}))
        .expect("the connect must reach the address DNS answers now, not the one from open");
    assert_eq!(reply, serde_json::json!({"order": [0]}));
    assert_eq!(target.hits(), 1);
}

/// WREQ-14. The resolver reaches the built client, and a url push rebuilds the client so the
/// resolver guards the NEW host: a pushed name is reached through the lookup, and when its answer
/// turns internal the connect is refused. A client left guarding the old host would resolve the
/// pushed name unchecked and dial it.
#[test]
fn the_client_resolves_the_pushed_host_through_the_guard() {
    let a = Target::json(r#"{"order":[0]}"#);
    let b = Target::json(r#"{"order":[1]}"#);
    let answers: Arc<Mutex<std::collections::HashMap<String, IpAddr>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let asked: Arc<Mutex<Vec<(String, u16)>>> = Arc::new(Mutex::new(Vec::new()));
    let lookup: net_guard::Lookup = {
        let answers = Arc::clone(&answers);
        let asked = Arc::clone(&asked);
        Arc::new(move |host: &str, port: u16| {
            asked.lock().unwrap().push((host.to_string(), port));
            let ip = answers.lock().unwrap().get(host).copied();
            ip.map(|ip| vec![SocketAddr::new(ip, 0)])
                .ok_or_else(|| std::io::Error::other("NXDOMAIN"))
        })
    };
    answers
        .lock()
        .unwrap()
        .insert("one.localhost".into(), LOOPBACK);
    answers
        .lock()
        .unwrap()
        .insert("two.localhost".into(), LOOPBACK);

    let fwd = Forwarder::with_lookup(
        cfg(format!("http://one.localhost:{}/", a.port()), 2000),
        lookup,
    )
    .expect("valid config");
    assert_eq!(
        fwd.post_op("decide", &serde_json::json!({})).unwrap(),
        serde_json::json!({"order": [0]})
    );
    assert_eq!(a.hits(), 1);
    assert!(
        asked
            .lock()
            .unwrap()
            .contains(&("one.localhost".to_string(), 0)),
        "the connect must resolve through the forwarder's lookup: {:?}",
        asked.lock().unwrap()
    );

    let mut push = serde_json::Map::new();
    push.insert(
        "url".into(),
        serde_json::json!(format!("http://two.localhost:{}/", b.port())),
    );
    assert!(fwd.configure(&push, 2), "a valid pushed url must ACK");
    assert_eq!(
        fwd.post_op("decide", &serde_json::json!({})).unwrap(),
        serde_json::json!({"order": [1]})
    );
    assert_eq!((a.hits(), b.hits()), (1, 1));

    answers
        .lock()
        .unwrap()
        .insert("two.localhost".into(), UNSPECIFIED);
    let err = fwd
        .post_op("decide", &serde_json::json!({}))
        .expect_err("the pushed host's internal answer must be refused");
    assert!(err.contains("SSRF guard"), "{err}");
    assert_eq!((a.hits(), b.hits()), (1, 1), "nothing may be dialed");
}

/// WREQ-3. `post_op` read the url and the client under two separate lock acquisitions, so a url
/// push landing between them paired the OLD url with the NEW client, whose resolver guards the new
/// host and resolved the old one unchecked. Both names here pass the open/configure check and
/// answer an internal address at connect, so every correctly paired request is refused before a
/// dial; a dial (a hit on either target) can only come from a torn pair. One lock makes that
/// impossible. The race is a narrow window, so this test catches the torn pair only
/// probabilistically; once the url and client share one lock it can never fire.
#[test]
fn a_url_push_never_pairs_the_old_url_with_the_new_client() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let a = Target::json(r#"{"order":[0]}"#);
    let b = Target::json(r#"{"order":[1]}"#);
    let url_a = format!("http://a.localhost:{}/", a.port());
    let url_b = format!("http://b.localhost:{}/", b.port());
    let fwd = Arc::new(
        Forwarder::with_lookup(
            cfg(url_a.clone(), 2000),
            split_lookup(Some(LOOPBACK), UNSPECIFIED, Duration::ZERO),
        )
        .expect("valid config"),
    );
    let stop = Arc::new(AtomicBool::new(false));
    let pusher = {
        let (fwd, stop) = (Arc::clone(&fwd), Arc::clone(&stop));
        std::thread::spawn(move || {
            let mut version = 1;
            while !stop.load(Ordering::Relaxed) {
                for url in [&url_b, &url_a] {
                    let mut push = serde_json::Map::new();
                    push.insert("url".into(), serde_json::json!(url));
                    version += 1;
                    assert!(fwd.configure(&push, version), "a valid push must ACK");
                }
            }
        })
    };
    let posters: Vec<_> = (0..4)
        .map(|_| {
            let (fwd, stop) = (Arc::clone(&fwd), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = fwd.post_op("decide", &serde_json::json!({}));
                }
            })
        })
        .collect();
    std::thread::sleep(Duration::from_millis(1500));
    stop.store(true, Ordering::Relaxed);
    pusher.join().unwrap();
    for p in posters {
        p.join().unwrap();
    }
    assert_eq!(
        (a.hits(), b.hits()),
        (0, 0),
        "a request was dialed through a client that does not guard its url's host"
    );
}

/// WREQ-6. The client's `connect_timeout` was frozen at the timeout in effect when it was built,
/// so a timeout-only push raising `timeout_ms` never raised the connect bound: opened at 50ms and
/// pushed to 2000ms, a connect that takes 200ms (here, a slow DNS answer) was still cut at 50ms.
/// The pushed timeout now bounds the whole call, connect included.
#[test]
fn a_pushed_timeout_bounds_the_connect_too() {
    let target = Target::json(r#"{"order":[0]}"#);
    let fwd = Forwarder::with_lookup(
        cfg(format!("http://svc.localhost:{}/", target.port()), 50),
        split_lookup(None, LOOPBACK, Duration::from_millis(200)),
    )
    .expect("valid config");
    let mut push = serde_json::Map::new();
    push.insert("timeout_ms".into(), serde_json::json!(2000));
    assert!(
        fwd.configure(&push, 2),
        "a valid pushed timeout_ms must ACK"
    );
    let reply = fwd
        .post_op("decide", &serde_json::json!({}))
        .expect("a 200ms connect is inside the pushed 2000ms timeout");
    assert_eq!(reply, serde_json::json!({"order": [0]}));
    assert_eq!(target.hits(), 1);
}

/// `203.0.113.7` (TEST-NET-3): neither loopback nor internal. The tests below only ever hand it to
/// the guard behind a loopback address, so nothing dials it.
const REMOTE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));

/// A lookup answering every name, at every port, with `ips`.
fn answer(ips: &'static [IpAddr]) -> net_guard::Lookup {
    Arc::new(move |_: &str, port: u16| {
        Ok(ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect())
    })
}

/// WREQ-4. A plaintext `http://` name passes the gate only because it is a `localhost` name, but
/// its answer was never required to be loopback: a resolver answering `svc.localhost` with a remote
/// address was accepted at open. It is now refused; a loopback-only answer, and the same remote
/// answer for an `https://` target, are still allowed.
#[test]
fn a_plaintext_target_must_resolve_to_loopback_at_open() {
    let plain = || cfg("http://svc.localhost:9/".into(), 2000);
    let tls = || cfg("https://svc.localhost:9/".into(), 2000);
    let mixed = answer(&[LOOPBACK, REMOTE]);
    assert!(
        Forwarder::with_lookup(plain(), Arc::clone(&mixed)).is_err(),
        "a plaintext target whose name answers a remote address must fail the load"
    );
    assert!(
        Forwarder::with_lookup(tls(), mixed).is_ok(),
        "TLS targets are not bound to loopback"
    );
    let loopback = answer(&[LOOPBACK, IpAddr::V6(Ipv6Addr::LOCALHOST)]);
    assert!(Forwarder::with_lookup(plain(), loopback).is_ok());
}

/// WREQ-4, at connect. The name did not resolve at open (allowed), and at connect it answers
/// loopback AND a remote address. The connector would dial the loopback address first and deliver
/// the envelope; the plaintext rule refuses the whole answer before any dial.
#[test]
fn a_plaintext_target_answering_remote_at_connect_is_refused_before_any_dial() {
    let target = Target::json(r#"{"order":[0]}"#);
    let lookup: net_guard::Lookup = Arc::new(|_: &str, port: u16| {
        if port != 0 {
            return Err(std::io::Error::other("no answer at open"));
        }
        Ok(vec![SocketAddr::new(LOOPBACK, 0), SocketAddr::new(REMOTE, 0)])
    });
    let fwd = Forwarder::with_lookup(
        cfg(format!("http://svc.localhost:{}/", target.port()), 2000),
        lookup,
    )
    .expect("a name that does not resolve at open is allowed");
    assert!(
        fwd.post_op("decide", &serde_json::json!({})).is_err(),
        "a remote address in a plaintext target's answer must fail the call"
    );
    assert_eq!(target.hits(), 0, "nothing may be dialed");
}

// ── Test-only coverage (WREQ-12, WREQ-13, WREQ-20, WREQ-21, WREQ-22) ─────────────────────────────

/// A forwarder at `url` (an IP-literal loopback target, so no lookup is ever made).
fn forwarder_at(url: String) -> Forwarder {
    Forwarder::with_lookup(cfg(url, 2000), no_dns()).expect("valid config")
}

/// WREQ-12. The reply cap is exact: a reply of exactly `MAX_REPLY_BYTES` is accepted.
#[test]
fn a_reply_of_exactly_the_cap_is_accepted() {
    let body = format!("\"{}\"", "x".repeat(MAX_REPLY_BYTES - 2));
    assert_eq!(body.len(), MAX_REPLY_BYTES);
    let target = Target::json(&body);
    let reply = forwarder_at(target.url())
        .post_op("decide", &serde_json::json!({}))
        .expect("a reply of exactly the cap is within it");
    assert_eq!(reply.as_str().map(str::len), Some(MAX_REPLY_BYTES - 2));
}

/// WREQ-12. The cap counts the WHOLE body across chunks: a 100 KiB reply streamed in 8 KiB chunks
/// (each far under the cap) is refused.
#[test]
fn the_reply_cap_is_cumulative_across_chunks() {
    let chunk = vec![b' '; 8 * 1024];
    let mut pieces = vec![b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        .to_vec()];
    for _ in 0..(100 / 8 + 1) {
        let mut piece = format!("{:x}\r\n", chunk.len()).into_bytes();
        piece.extend_from_slice(&chunk);
        piece.extend_from_slice(b"\r\n");
        pieces.push(piece);
    }
    pieces.push(b"0\r\n\r\n".to_vec());
    let target = Target::start(pieces);
    let err = forwarder_at(target.url())
        .post_op("decide", &serde_json::json!({}))
        .expect_err("a body past the cap must be refused");
    assert!(err.contains("byte cap"), "{err}");
}

/// WREQ-13. Redirects are not followed: a target answering `302` to a second target never causes
/// a request to it.
#[test]
fn a_redirect_is_not_followed() {
    let elsewhere = Target::json(r#"{"order":[0]}"#);
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Type: application/json\r\n\
         Content-Length: 2\r\nConnection: close\r\n\r\n{{}}",
        elsewhere.url()
    );
    let target = Target::start(vec![redirect.into_bytes()]);
    let _ = forwarder_at(target.url()).post_op("decide", &serde_json::json!({}));
    assert_eq!(target.hits(), 1);
    assert_eq!(
        elsewhere.hits(),
        0,
        "the redirect target must never be requested"
    );
}

/// WREQ-20. `status` reports the url under `url`, through the masker: the query is redacted and
/// the userinfo masked, never published raw.
#[test]
fn status_reports_the_masked_url() {
    let fwd = Forwarder::with_lookup(
        cfg(
            "https://svc:pw@h.example.invalid/r?token=S3CRET".to_string(),
            1234,
        ),
        no_dns(),
    )
    .expect("valid config");
    let status = fwd.status();
    let settings = &status["status"]["settings"];
    assert_eq!(
        settings["url"],
        "https://***@h.example.invalid/r?<redacted>"
    );
    assert_eq!(settings["target_host"], "h.example.invalid");
    assert!(!settings.to_string().contains("S3CRET"));
}

/// WREQ-21. A committed url push is what the next request uses: after the push the envelope goes
/// to the new target and never to the old one.
#[test]
fn a_committed_url_push_routes_the_next_request() {
    let a = Target::json(r#"{"order":[0]}"#);
    let b = Target::json(r#"{"order":[1]}"#);
    let fwd = forwarder_at(a.url());
    let mut push = serde_json::Map::new();
    push.insert("url".into(), serde_json::json!(b.url()));
    assert!(fwd.configure(&push, 2), "a valid pushed url must ACK");
    let reply = fwd
        .post_op("decide", &serde_json::json!({"request": {"pool": "p"}}))
        .expect("the pushed target answers");
    assert_eq!(reply, serde_json::json!({"order": [1]}));
    assert_eq!(a.hits(), 0, "the old target must not be requested");
    let bodies = b.bodies.lock().unwrap().clone();
    assert_eq!(bodies.len(), 1);
    let sent: serde_json::Value = serde_json::from_str(&bodies[0]).unwrap();
    assert_eq!(sent["op"], "decide");
    assert_eq!(sent["request"]["pool"], "p");
}

/// WREQ-22. A pushed `timeout_ms` is clamped to `[1, MAX_TIMEOUT_MS]` like the one given at open.
#[test]
fn a_pushed_timeout_is_clamped() {
    let fwd = forwarder_at("http://127.0.0.1:9/".to_string());
    for (pushed, applied) in [(600_000u64, MAX_TIMEOUT_MS), (0, 1)] {
        let mut push = serde_json::Map::new();
        push.insert("timeout_ms".into(), serde_json::json!(pushed));
        assert!(fwd.configure(&push, 2), "a pushed timeout_ms ACKs");
        assert_eq!(
            fwd.status()["status"]["settings"]["timeout_ms"],
            applied,
            "timeout_ms {pushed} must apply as {applied}"
        );
    }
}
