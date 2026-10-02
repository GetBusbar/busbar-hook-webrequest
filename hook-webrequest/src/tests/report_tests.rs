use crate::config::open;
use crate::report::{describe, status};

#[test]
fn describe_is_the_config_schema() {
    let d = describe();
    assert_eq!(d["schema"]["required"], serde_json::json!(["url"]));
    assert!(d["schema"]["properties"]["timeout_ms"].is_object());
}

#[test]
fn status_reports_the_url_under_its_own_key_masked_and_redacted() {
    let t = open(
        br#"{"url":"https://svc:hunter2@api.example.com/route?token=abc#frag","timeout_ms":250}"#,
    )
    .unwrap();
    let s = status(&t);
    let text = s.to_string();
    for secret in ["hunter2", "token=abc", "frag"] {
        assert!(!text.contains(secret), "status leaked {secret}: {text}");
    }
    let settings = &s["status"]["settings"];
    assert_eq!(
        settings["url"],
        "https://***@api.example.com/route?<redacted>"
    );
    assert_eq!(settings["target_host"], "api.example.com");
    assert_eq!(settings["timeout_ms"], 250);
    assert_eq!(s["status"]["metrics"], serde_json::json!([]));
}
