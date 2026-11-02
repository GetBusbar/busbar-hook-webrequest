use crate::config::open;
use crate::report::{describe, status};

#[test]
fn describe_is_the_config_schema() {
    let d = describe();
    assert_eq!(d["schema"]["required"], serde_json::json!(["url"]));
    assert!(d["schema"]["properties"]["timeout_ms"].is_object());
}

#[test]
fn status_reports_the_url_under_its_own_key() {
    let t = open(br#"{"url":"https://api.example.com/route","timeout_ms":250}"#).unwrap();
    let s = status(&t);
    let settings = &s["status"]["settings"];
    assert_eq!(settings["url"], "https://api.example.com/route");
    assert_eq!(settings["target_host"], "api.example.com");
    assert_eq!(settings["timeout_ms"], 250);
    assert_eq!(s["status"]["metrics"], serde_json::json!([]));
}

/// The engine's drift check compares VALUES, so `status` echoes the url text the operator wrote
/// (not the masked, canonicalised form) under `url`, or a hook running its desired settings reports
/// drift on every poll.
#[test]
fn status_url_is_the_configured_text() {
    for text in [
        "https://hooks.example/v1/decide",
        "https://hooks.example",
        "https://hooks.example/a?b=1",
    ] {
        let t = open(format!(r#"{{"url":"{text}"}}"#).as_bytes()).unwrap();
        assert_eq!(status(&t)["status"]["settings"]["url"], text);
    }
    // ...and after a configure that moves the url.
    let live = open(br#"{"url":"https://hooks.example/v1/decide"}"#).unwrap();
    let pushed = serde_json::json!({"url": "https://other.example"});
    let next = crate::config::configure(&live, pushed.as_object().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(
        status(&next)["status"]["settings"]["url"],
        "https://other.example"
    );
}

/// The drift check compares VALUES, so `status` echoes `timeout_ms` as the operator wrote it: an
/// absent or `null` one reports `null` (not the 5000 ms default it runs with), and an out-of-range
/// one reports the written number (not the clamped bound).
#[test]
fn status_timeout_ms_is_the_configured_value() {
    let t = open(br#"{"url":"https://hooks.example/x","timeout_ms":null}"#).unwrap();
    assert_eq!(
        status(&t)["status"]["settings"]["timeout_ms"],
        serde_json::Value::Null
    );
    let t = open(br#"{"url":"https://hooks.example/x"}"#).unwrap();
    assert_eq!(
        status(&t)["status"]["settings"]["timeout_ms"],
        serde_json::Value::Null
    );
    let t = open(br#"{"url":"https://hooks.example/x","timeout_ms":99999999}"#).unwrap();
    assert_eq!(status(&t)["status"]["settings"]["timeout_ms"], 99_999_999);
    // configure: a non-null value moves it, null / absent leaves it alone.
    let live = open(br#"{"url":"https://hooks.example/x","timeout_ms":250}"#).unwrap();
    let pushed = serde_json::json!({"timeout_ms": 0});
    let next = crate::config::configure(&live, pushed.as_object().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(status(&next)["status"]["settings"]["timeout_ms"], 0);
    let pushed = serde_json::json!({"timeout_ms": null});
    assert!(crate::config::configure(&live, pushed.as_object().unwrap())
        .unwrap()
        .is_none());
    assert_eq!(status(&live)["status"]["settings"]["timeout_ms"], 250);
}
