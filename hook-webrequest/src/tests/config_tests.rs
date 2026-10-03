use crate::config::{clamp_timeout, configure, open, Target, MAX_TIMEOUT_MS};
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
        br#"{"url":"http://10.0.0.1/x"}"#,
        br#"{"url":"http://api.example.com/x"}"#,
        br#"{"url":"   "}"#,
        &[0xff, 0xfe],
    ] {
        assert!(open(bad).is_err(), "must fail closed: {bad:?}");
    }
    assert!(open(br#"{"url":"https://api.example.com/route"}"#).is_ok());
    assert!(open(br#"{"url":"http://127.0.0.1:9000/route"}"#).is_ok());
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
    assert!(open(b"{}")
        .unwrap_err()
        .starts_with("webrequest: invalid plugin config: missing field `url`"));
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
fn the_endpoint_is_host_port_and_tls() {
    let t = open(br#"{"url":"https://a.example/x"}"#).unwrap();
    assert_eq!(t.endpoint(), ("a.example".to_string(), 443));
    assert!(t.is_tls());
    let t = open(br#"{"url":"http://[::1]:9000/x"}"#).unwrap();
    assert_eq!(t.endpoint(), ("::1".to_string(), 9000));
    assert!(!t.is_tls());
    let t = open(br#"{"url":"http://localhost/x"}"#).unwrap();
    assert_eq!(t.endpoint(), ("localhost".to_string(), 80));
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
        .starts_with("webrequest: configure() rejected: webrequest: settings.url must not target"));
    // A good url beside a bad timeout: the whole push is refused.
    assert!(configure(
        &live(),
        &map(serde_json::json!({"url":"https://other.example/","timeout_ms":"x"}))
    )
    .is_err());
}
