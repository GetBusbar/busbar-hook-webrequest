use crate::config::{
    clamp_timeout, configure, open, unknown_keys, unknown_keys_in, warnings, warnings_in, Target,
    MAX_TIMEOUT_MS,
};
use std::time::Duration;

fn map(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    v.as_object().unwrap().clone()
}

fn live() -> Target {
    open(br#"{"url":"https://api.example.com/route","timeout_ms":2000}"#).unwrap()
}

#[test]
fn open_fails_closed_on_bad_config() {
    for bad in [
        &b""[..],
        b"{}",
        b"{ not json",
        b"   ",
        br#"{"url":"http://169.254.169.254/x"}"#,
        br#"{"url":"https://169.254.169.254/x"}"#,
        br#"{"url":"http://10.0.0.1/x"}"#,
        br#"{"url":"http://api.example.com/x"}"#,
        br#"{"url":"   "}"#,
        &[0xff, 0xfe],
    ] {
        assert!(open(bad).is_err(), "must fail closed: {bad:?}");
    }
    assert!(open(br#"{"url":"https://api.example.com/route"}"#).is_ok());
    assert!(open(br#"{"url":"http://127.0.0.1:9000/route"}"#).is_ok());
    // The IPv6 loopback sidecar is the same carve-out.
    assert!(open(br#"{"url":"http://[::1]:9000/route"}"#).is_ok());
}

#[test]
fn the_refusal_texts_are_1_5_5s() {
    assert_eq!(
        open(b"").unwrap_err(),
        "webrequest: settings.url is required"
    );
    assert_eq!(
        open(br#"{"url":"  "}"#).unwrap_err(),
        "webrequest: settings.url is required"
    );
    // `{}` says what a blank url says (R9), not serde's field text.
    assert_eq!(
        open(b"{}").unwrap_err(),
        "webrequest: settings.url is required"
    );
    assert!(open(b"{ nope")
        .unwrap_err()
        .starts_with("webrequest: invalid plugin config: "));
    assert!(open(br#"{"url":"ftp://x.example/"}"#)
        .unwrap_err()
        .starts_with("webrequest: settings.url must be an http:// or https:// URL"));
}

#[test]
fn timeout_defaults_and_is_clamped() {
    assert_eq!(
        open(br#"{"url":"https://a.example/"}"#).unwrap().timeout,
        Duration::from_millis(5_000)
    );
    assert_eq!(clamp_timeout(0), Duration::from_millis(1));
    assert_eq!(clamp_timeout(300), Duration::from_millis(300));
    assert_eq!(clamp_timeout(60_000), Duration::from_millis(MAX_TIMEOUT_MS));
    assert_eq!(
        open(br#"{"url":"https://a.example/","timeout_ms":99999}"#)
            .unwrap()
            .timeout,
        Duration::from_millis(5_000)
    );
}

#[test]
fn configure_with_nothing_to_change_acks_without_a_commit() {
    assert_eq!(configure(&live(), &map(serde_json::json!({}))), Ok(None));
    assert_eq!(
        configure(&live(), &map(serde_json::json!({"other": 1}))),
        Ok(None)
    );
}

#[test]
fn configure_commits_a_new_url_and_keeps_the_timeout() {
    let next = configure(
        &live(),
        &map(serde_json::json!({"url":"https://other.example/x"})),
    )
    .unwrap()
    .unwrap();
    assert_eq!(next.url.as_str(), "https://other.example/x");
    assert_eq!(next.timeout, Duration::from_millis(2000));
}

#[test]
fn configure_commits_a_new_timeout_and_keeps_the_url() {
    let next = configure(&live(), &map(serde_json::json!({"timeout_ms": 90000})))
        .unwrap()
        .unwrap();
    assert_eq!(next.url.as_str(), "https://api.example.com/route");
    assert_eq!(next.timeout, Duration::from_millis(MAX_TIMEOUT_MS));
}

#[test]
fn configure_nacks_wrong_types_and_blocked_urls_and_never_half_applies() {
    let nack = |v: serde_json::Value| configure(&live(), &map(v)).unwrap_err();
    assert!(nack(serde_json::json!({"url": 7})).contains("not a string"));
    assert!(nack(serde_json::json!({"url": null})).contains("not a string"));
    assert!(nack(serde_json::json!({"timeout_ms": "5"})).contains("not a non-negative integer"));
    assert!(nack(serde_json::json!({"timeout_ms": -1})).contains("not a non-negative integer"));
    assert!(nack(serde_json::json!({"url":"http://169.254.169.254/"}))
        .starts_with("webrequest: configure() rejected: settings.url must not target"));
    // A good url beside a bad timeout: the whole push is refused.
    assert!(configure(
        &live(),
        &map(serde_json::json!({"url":"https://other.example/","timeout_ms":"x"}))
    )
    .is_err());
}

#[test]
fn an_unknown_key_is_named_and_the_known_ones_are_not() {
    let map: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(r#"{"url":"https://h/","timeout":100,"timeout_ms":5,"headers":{}}"#)
            .unwrap();
    let w = unknown_keys(&map);
    assert_eq!(w.len(), 2, "{w:?}");
    for k in ["'timeout'", "'headers'"] {
        assert!(
            w.iter()
                .any(|m| m.contains(&format!("unknown setting {k}"))),
            "{w:?}"
        );
    }
    assert!(
        w.iter()
            .all(|m| m.contains("url") && m.contains("timeout_ms")),
        "{w:?}"
    );
    assert!(unknown_keys_in(br#"{"url":"https://h/"}"#).is_empty());
    assert!(unknown_keys_in(b"").is_empty());
    assert!(unknown_keys_in(b"[1]").is_empty());
}

#[test]
fn an_unknown_key_still_opens_as_1_5_5_did() {
    assert!(open(br#"{"url":"https://h/","timeout":100}"#).is_ok());
}

/// R6: the NACK carries the `webrequest: ` prefix once.
#[test]
fn a_configure_nack_has_one_prefix() {
    for v in [
        serde_json::json!({"url":"http://169.254.169.254/"}),
        serde_json::json!({"url":"ftp://x.example/"}),
        serde_json::json!({"url":"http://api.example.com/"}),
        serde_json::json!({"url": 5}),
        serde_json::json!({"timeout_ms": "x"}),
    ] {
        let nack = configure(&live(), &map(v)).unwrap_err();
        assert!(
            nack.starts_with("webrequest: configure() rejected: "),
            "{nack}"
        );
        assert_eq!(nack.matches("webrequest:").count(), 1, "{nack}");
    }
}

/// R5: a wrong-typed value is named by its key and never echoed (it may be a credential url).
#[test]
fn a_configure_nack_never_echoes_a_settings_value() {
    let nack = |v: serde_json::Value| configure(&live(), &map(v)).unwrap_err();
    let t = nack(serde_json::json!({"url": ["https://u:PWSECRET@h.example/KEYSECRET"]}));
    assert!(t.contains("settings.url") && !t.contains("SECRET"), "{t}");
    let t = nack(serde_json::json!({"timeout_ms": "PWSECRET"}));
    assert!(
        t.contains("settings.timeout_ms") && !t.contains("SECRET"),
        "{t}"
    );
    let t = nack(serde_json::json!({"timeout_ms": {"a": "PWSECRET"}}));
    assert!(!t.contains("SECRET"), "{t}");
}

/// R8: `timeout_ms: null` is absent in `configure`, as it is default in `open`.
#[test]
fn configure_reads_a_null_timeout_as_absent() {
    assert_eq!(
        configure(&live(), &map(serde_json::json!({"timeout_ms": null}))),
        Ok(None)
    );
    let next = configure(
        &live(),
        &map(serde_json::json!({"url":"https://other.example/","timeout_ms": null})),
    )
    .unwrap()
    .unwrap();
    assert_eq!(next.url.as_str(), "https://other.example/");
    assert_eq!(next.timeout, Duration::from_millis(2000));
    assert!(open(br#"{"url":"https://a.example/","timeout_ms":null}"#).is_ok());
}

/// R7: an out-of-range `timeout_ms` is still clamped, and says so once.
#[test]
fn a_clamped_timeout_is_warned_once() {
    for (settings, ms) in [
        (r#"{"url":"https://h/","timeout_ms":99999}"#, "99999"),
        (r#"{"url":"https://h/","timeout_ms":0}"#, "0"),
    ] {
        let w = warnings_in(settings.as_bytes());
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(
            w[0].contains("timeout_ms") && w[0].contains(ms) && w[0].contains("clamp"),
            "{w:?}"
        );
    }
    let in_range = warnings_in(br#"{"url":"https://h/","timeout_ms":5000}"#);
    assert!(in_range.is_empty(), "{in_range:?}");
    assert!(warnings_in(br#"{"url":"https://h/","timeout_ms":null}"#).is_empty());
    let w = warnings(&map(serde_json::json!({"timeout_ms": 60000, "x": 1})));
    assert_eq!(w.len(), 2, "{w:?}");
}
