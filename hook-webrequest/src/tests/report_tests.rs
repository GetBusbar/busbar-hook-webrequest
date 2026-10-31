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
    for secret in ["hunter2", "token=abc", "frag", "route"] {
        assert!(!text.contains(secret), "status leaked {secret}: {text}");
    }
    let settings = &s["status"]["settings"];
    assert_eq!(
        settings["url"],
        "https://***@api.example.com/***?<redacted>"
    );
    assert_eq!(settings["target_host"], "api.example.com");
    assert_eq!(settings["timeout_ms"], 250);
    assert_eq!(s["status"]["metrics"], serde_json::json!([]));
}

/// The path of a sidecar url can carry its key (`/v1/<key>`), so `status` cuts it as a log line does.
#[test]
fn status_never_shows_the_url_path() {
    let t = open(br#"{"url":"https://hooks.example.com/v1/KEY123"}"#).unwrap();
    let s = status(&t);
    let text = s.to_string();
    assert!(!text.contains("KEY123"), "status leaked the path: {text}");
    assert_eq!(
        s["status"]["settings"]["url"],
        "https://hooks.example.com/***"
    );
}

/// `https:user:pass@hk.example/x?k=SECRET` (no `//`) parses and is accepted; neither its status
/// nor its Debug carries the credential, path or query.
#[test]
fn a_slashless_url_with_userinfo_shows_no_credential_in_status_or_debug() {
    let t = open(br#"{"url":"https:user:pass@hk.example/x?k=SECRET"}"#).unwrap();
    let shown = format!("{} {t:?}", status(&t));
    for secret in ["user", "pass", "SECRET", "k="] {
        assert!(!shown.contains(secret), "leaked {secret}: {shown}");
    }
}
