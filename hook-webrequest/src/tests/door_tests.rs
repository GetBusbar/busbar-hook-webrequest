//! The door's choices that need no host: configure's merge, its checkpoints and concurrent pushes,
//! the per-target request parts, and how a reply head is read.

use busbar_contract::abi::sdk::hook::Hook;

use crate::config;
use crate::door::{
    checkpoint_settings, head_answers, shown_reason, snapshot_capacity, Forwarder, Live,
};

fn forwarder(url: &str) -> Forwarder {
    let target = config::open(format!(r#"{{"url": "{url}"}}"#).as_bytes()).expect("opens");
    Forwarder::over(Live::new(target))
}

#[test]
fn concurrent_partial_configures_preserve_both_updates() {
    let f = forwarder("http://127.0.0.1:9001/a");
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let url = scope.spawn(|| {
            let settings = serde_json::json!({"url":"http://127.0.0.2:9002/b"});
            start.wait();
            assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
        });
        let timeout = scope.spawn(|| {
            let settings = serde_json::json!({"timeout_ms":777});
            start.wait();
            assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
        });
        url.join().unwrap();
        timeout.join().unwrap();
    });
    let live = f.live();
    assert_eq!(live.url.as_str(), "http://127.0.0.2:9002/b");
    assert_eq!(live.timeout, std::time::Duration::from_millis(777));
}

#[test]
fn configuration_checkpoints_preserve_normalized_url_timeout_and_partial_semantics() {
    let initial = "http://user:secret@127.0.0.1:9001/first";
    let f = forwarder(initial);
    let push = |settings: serde_json::Value, version| {
        f.configure_checkpoint(settings.as_object().unwrap(), version)
            .unwrap()
            .unwrap()
    };
    let first = push(serde_json::json!({"timeout_ms": 777}), 2);
    assert_eq!((first.revision, first.settings_version), (1, 2));
    let second = push(
        serde_json::json!({"url": "http://next:credential@127.0.0.2:9002/second"}),
        2,
    );
    assert_eq!((second.revision, second.settings_version), (2, 2));
    let empty = push(serde_json::json!({}), 3);
    let null = push(serde_json::json!({"timeout_ms": null}), 3);
    assert_eq!(empty.settings(), null.settings());
    assert_eq!((null.revision, null.settings_version), (4, 3));
    let stale = push(
        serde_json::json!({"url": false, "timeout_ms": "invalid"}),
        1,
    );
    assert_eq!((stale.revision, stale.settings_version), (4, 3));
    assert_eq!(stale.settings(), null.settings());
    assert!(f
        .configure_checkpoint(
            serde_json::json!({"timeout_ms": "invalid"})
                .as_object()
                .unwrap(),
            4
        )
        .is_err());
    let current = f.live();
    let restored = forwarder(initial);
    let settings: serde_json::Value = serde_json::from_slice(null.settings()).unwrap();
    restored
        .configure(settings.as_object().unwrap(), null.settings_version)
        .unwrap();
    assert_eq!(restored.live().url, current.url);
    assert_eq!(
        restored.live().timeout,
        std::time::Duration::from_millis(777)
    );
    assert!(!format!("{null:?}").contains("credential"));
}

#[test]
fn concurrent_equal_version_checkpoints_capture_the_complete_serialized_state() {
    let f = forwarder("http://127.0.0.1:9001/first");
    let start = std::sync::Barrier::new(2);
    let (url, timeout) = std::thread::scope(|scope| {
        let url = scope.spawn(|| {
            start.wait();
            f.configure_checkpoint(
                serde_json::json!({"url":"http://127.0.0.2:9002/second"})
                    .as_object()
                    .unwrap(),
                2,
            )
            .unwrap()
            .unwrap()
        });
        let timeout = scope.spawn(|| {
            start.wait();
            f.configure_checkpoint(
                serde_json::json!({"timeout_ms":777}).as_object().unwrap(),
                2,
            )
            .unwrap()
            .unwrap()
        });
        (url.join().unwrap(), timeout.join().unwrap())
    });
    assert_ne!(url.revision, timeout.revision);
    let latest = if url.revision > timeout.revision {
        url
    } else {
        timeout
    };
    let restored = forwarder("http://127.0.0.1:9001/first");
    let settings: serde_json::Value = serde_json::from_slice(latest.settings()).unwrap();
    restored
        .configure(settings.as_object().unwrap(), latest.settings_version)
        .unwrap();
    assert_eq!(restored.live().url.as_str(), "http://127.0.0.2:9002/second");
    assert_eq!(
        restored.live().timeout,
        std::time::Duration::from_millis(777)
    );
}

#[test]
fn concurrent_partial_configures_never_lose_an_update_under_repetition() {
    for round in 0..300 {
        let f = forwarder("http://127.0.0.1:9001/a");
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let settings = serde_json::json!({"url":"http://127.0.0.2:9002/b"});
                start.wait();
                assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
            });
            scope.spawn(|| {
                let settings = serde_json::json!({"timeout_ms":777});
                start.wait();
                assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
            });
        });
        let live = f.live();
        assert_eq!(
            live.url.as_str(),
            "http://127.0.0.2:9002/b",
            "round {round}"
        );
        assert_eq!(
            live.timeout,
            std::time::Duration::from_millis(777),
            "round {round}"
        );
    }
}

#[test]
fn complete_checkpoint_restores_status_spelling_and_effective_timeout() {
    let initial = "https://hooks.example";
    let f = forwarder(initial);
    let settings = serde_json::json!({"timeout_ms":99999});
    let checkpoint = f
        .configure_checkpoint(settings.as_object().unwrap(), 2)
        .unwrap()
        .unwrap();
    let restored = forwarder("https://different.example/start");
    let settings: serde_json::Value = serde_json::from_slice(checkpoint.settings()).unwrap();
    restored
        .configure(settings.as_object().unwrap(), checkpoint.settings_version)
        .unwrap();
    assert_eq!(
        crate::report::status(&f.live()),
        crate::report::status(&restored.live())
    );
    assert_eq!(
        restored.live().timeout,
        std::time::Duration::from_millis(crate::config::MAX_TIMEOUT_MS)
    );
    assert_eq!(
        crate::report::status(&restored.live())["status"]["settings"]["url"],
        initial
    );
    assert_eq!(
        crate::report::status(&restored.live())["status"]["settings"]["timeout_ms"],
        99999
    );
}

/// A head that arrived before its exchange failed answers a head-only `notify` whatever its status
/// (a 2xx head acknowledges delivery, as a 3xx one does); for `decide`/`transform` only a 3xx-5xx
/// head answers, since a 2xx head without its body is no reply.
#[test]
fn an_earlier_head_answers_a_notify_at_any_status_and_a_decision_only_at_3xx_to_5xx() {
    for status in [200, 204, 299, 301, 399, 404, 503] {
        assert!(head_answers(true, status), "notify {status}");
    }
    for status in [200, 204, 299] {
        assert!(!head_answers(false, status), "decide {status}");
    }
    for status in [300, 302, 399, 400, 404, 500, 599] {
        assert!(head_answers(false, status), "decide {status}");
    }
}

/// Only an error status shows the remote reason phrase, so only its phrase is decoded and scrubbed.
#[test]
fn only_an_error_status_shows_its_reason_phrase() {
    let reason: Option<&[u8]> = Some(b"phrase");
    for status in [100, 200, 204, 301, 399, 600] {
        assert_eq!(shown_reason(status, reason), None, "{status}");
    }
    for status in [400, 404, 500, 599] {
        assert_eq!(shown_reason(status, reason), reason, "{status}");
    }
    assert_eq!(shown_reason(503, None), None);
}

/// The checkpoint's settings are written into a buffer sized for the worst case, so serialising the
/// credential-bearing url text never reallocates (an outgrown buffer would be freed unwiped).
#[test]
fn checkpoint_settings_are_written_without_growing_their_buffer() {
    let long = "k".repeat(300);
    for settings in [
        r#"{"url":"https://svc:S3cr3t@hooks.example/v1"}"#.to_owned(),
        format!(r#"{{"url":"https://svc:S3cr3t@hooks.example/{long}?token={long}","timeout_ms":250}}"#),
        r#"{"url":"https://svc:pw@hooks.example/\u0001\u0002\u001f","timeout_ms":18446744073709551615}"#
            .to_owned(),
    ] {
        let target = config::open(settings.as_bytes()).expect("opens");
        let bytes = checkpoint_settings(&target).expect("encodes");
        assert_eq!(bytes.capacity(), snapshot_capacity(&target).unwrap(), "{settings}");
        let back: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back["url"], target.url_text.as_str());
        assert_eq!(back["timeout_ms"], target.timeout_text);
    }
}

/// A push the checkpoint cannot carry (its escaped url passes the checkpoint bound) is refused as
/// every other refusal is: NACKed in `configure()`'s words, and the live target unchanged.
#[test]
fn a_push_the_checkpoint_cannot_carry_is_refused_in_configures_words() {
    let f = forwarder("https://hooks.example/first");
    let path = "\u{1}".repeat(busbar_contract::abi::sdk::hook::configure_checkpoint::MAX_BYTES / 5);
    let settings = serde_json::json!({ "url": format!("https://hooks.example/{path}") });
    let refused = f
        .configure_checkpoint(settings.as_object().unwrap(), 2)
        .expect_err("refused");
    assert!(
        refused.starts_with("webrequest: configure() rejected: "),
        "{refused}"
    );
    assert_eq!(f.live().url.as_str(), "https://hooks.example/first");
}

/// The `authorization` the userinfo becomes is held sealed (a `Cred`, ahead of the plain fields), never
/// among the plain fields every request clones.
#[test]
fn the_userinfo_authorization_is_sealed_and_never_a_plain_field() {
    let target = config::open(br#"{"url":"https://user:pa%20ss@hooks.example/x"}"#).unwrap();
    let live = Live::new(target);
    assert!(!live
        .plain
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case(b"authorization")));
    assert_eq!(live.sealed.len(), 1);
    assert_eq!(live.sealed[0].0, 0);
    assert_eq!(live.sealed[0].1, b"authorization".to_vec());

    let target = config::open(br#"{"url":"https://hooks.example/x"}"#).unwrap();
    let live = Live::new(target);
    assert!(live.sealed.is_empty());
    assert_eq!(live.plain.len(), 2);
}

/// The checkpoint buffer is bounded by what a checkpoint may carry, not by the url's worst-case
/// escaping: a long url that escapes to nothing extra costs one bound-sized buffer, and still
/// encodes and is acknowledged.
#[test]
fn checkpoint_settings_never_allocate_past_the_checkpoint_bound() {
    use busbar_contract::abi::sdk::hook::configure_checkpoint::MAX_BYTES;
    let path = "a".repeat(MAX_BYTES / 5);
    let url = format!("https://hooks.example/{path}");
    let target = config::open(format!(r#"{{"url":"{url}"}}"#).as_bytes()).expect("opens");
    assert_eq!(snapshot_capacity(&target).unwrap(), MAX_BYTES);
    let bytes = checkpoint_settings(&target).expect("encodes");
    assert_eq!(bytes.capacity(), MAX_BYTES);
    assert_eq!(
        bytes.len(),
        r#"{"url":"","timeout_ms":null}"#.len() + url.len()
    );

    let f = forwarder("https://hooks.example/first");
    let settings = serde_json::json!({ "url": url });
    let checkpoint = f
        .configure_checkpoint(settings.as_object().unwrap(), 2)
        .expect("acknowledged")
        .expect("a checkpoint");
    assert_eq!(checkpoint.settings(), bytes.as_slice());
}
