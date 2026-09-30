use crate::reply::*;
use serde_json::json;

fn ok(body: &[u8]) -> Result<serde_json::Value, String> {
    interpret(200, None, body)
}

#[test]
fn a_reply_is_the_body_parsed_verbatim() {
    assert_eq!(ok(br#"{"abstain":1}"#).unwrap(), json!({"abstain": 1}));
    assert_eq!(ok(br#"{"order":[1,0]}"#).unwrap(), json!({"order": [1, 0]}));
}

#[test]
fn error_statuses_are_failures_and_redirects_are_not_followed() {
    assert_eq!(
        interpret(404, None, b"{}").unwrap_err(),
        "webrequest: target returned an error status: HTTP status client error (404 Not Found)"
    );
    assert_eq!(
        interpret(503, None, b"{}").unwrap_err(),
        "webrequest: target returned an error status: HTTP status server error (503 Service Unavailable)"
    );
    assert_eq!(interpret(399, None, b"{}").unwrap(), json!({}));
    assert_eq!(interpret(302, None, b"{}").unwrap(), json!({}));
    assert_eq!(
        interpret(204, None, b"").unwrap_err(),
        "webrequest: invalid JSON reply (0 bytes)"
    );
    // The phrase the server sent wins, exactly as the 1.5.5 client showed it; empty falls back.
    assert_eq!(
        interpret(418, Some("I'm A Teapot Custom"), b"{}").unwrap_err(),
        "webrequest: target returned an error status: HTTP status client error (418 I'm A Teapot Custom)"
    );
    assert_eq!(
        interpret(404, Some(""), b"{}").unwrap_err(),
        interpret(404, None, b"{}").unwrap_err()
    );
    // An unknown 5xx still reads as a server error.
    assert!(interpret(599, None, b"")
        .unwrap_err()
        .contains("server error"));
}

#[test]
fn the_cap_is_exact() {
    let mut body = vec![b' '; MAX_REPLY_BYTES - 2];
    body.extend_from_slice(b"{}");
    assert_eq!(ok(&body).unwrap(), json!({}));
    body.push(b' ');
    assert_eq!(ok(&body).unwrap_err(), cap_exceeded());
    assert_eq!(
        cap_exceeded(),
        "webrequest: response exceeded 65536 byte cap"
    );
}

#[test]
fn depth_and_parse_errors_are_length_only() {
    let deep = format!(
        "{}{}",
        "[".repeat(MAX_REPLY_DEPTH + 1),
        "]".repeat(MAX_REPLY_DEPTH + 1)
    );
    assert_eq!(
        parse_reply(deep.as_bytes()).unwrap_err(),
        format!(
            "webrequest: reply exceeded max nesting depth ({} bytes)",
            deep.len()
        )
    );
    // The boundary is exact: depth 127 (n arrays + the outer object) parses, 128 is refused.
    let nested = |n: usize| format!(r#"{{"order":{}{}}}"#, "[".repeat(n), "]".repeat(n));
    assert!(parse_reply(nested(MAX_REPLY_DEPTH - 2).as_bytes()).is_ok());
    assert!(parse_reply(nested(MAX_REPLY_DEPTH - 1).as_bytes()).is_err());
    assert!(!exceeds_max_depth(
        nested(MAX_REPLY_DEPTH - 1).as_bytes(),
        MAX_REPLY_DEPTH
    ));
    assert!(exceeds_max_depth(
        nested(MAX_REPLY_DEPTH).as_bytes(),
        MAX_REPLY_DEPTH
    ));
    let echo = br#"{"secret prompt": "#;
    let err = parse_reply(echo).unwrap_err();
    assert_eq!(
        err,
        format!("webrequest: invalid JSON reply ({} bytes)", echo.len())
    );
    assert!(!err.contains("secret"));
    // Brackets inside a string do not count.
    assert!(!exceeds_max_depth(
        format!("\"{}\"", "[".repeat(500)).as_bytes(),
        1
    ));
    assert!(!exceeds_max_depth(br#"["\"[[[[", "x"]"#, 2));
}

#[test]
fn a_failure_means_a_different_thing_per_op() {
    let fail: Result<serde_json::Value, String> = Err("webrequest: request failed".into());
    // decide: still a failure, so on_error runs.
    assert!(decide(fail.clone()).is_err());
    assert_eq!(
        decide(Ok(json!({"order":[0]}))).unwrap(),
        json!({"order":[0]})
    );
    // transform: abstain.
    assert_eq!(transform(fail.clone()), json!({}));
    assert_eq!(transform(Ok(json!({"reject":"x"}))), json!({"reject":"x"}));
    // notify: swallowed.
    notify(fail);
}
