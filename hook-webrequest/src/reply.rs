// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reply rules: the 1.5.5 status rule, the body cap, the nesting-depth guard and the length-only
//! parse error, and what a failure MEANS per op. The framed http exchange hands back `{status, body}`;
//! [`interpret`] is what the plugin makes of it.

use serde_json::Value;

/// Maximum reply body accepted from the target, in bytes: the reply is a small ranking/verdict object, so
/// a body past this is a hostile or buggy target.
pub const MAX_REPLY_BYTES: usize = 64 * 1024;

/// Maximum JSON nesting depth accepted in a reply (busbar's `MAX_JSON_DEPTH`, a security floor).
pub const MAX_REPLY_DEPTH: usize = 128;

/// The transport failure text: connect, send, timeout and a malformed head all read as this, with the
/// URL removed so a `?token=` never reaches the engine's log.
pub const REQUEST_FAILED: &str = "webrequest: request failed: error sending request";

/// The body-read failure text (a truncated or malformed body).
pub const READ_FAILED: &str = "webrequest: response read failed: error decoding response body";

/// The failure for a body past [`MAX_REPLY_BYTES`].
#[must_use]
pub fn cap_exceeded() -> String {
    format!("webrequest: response exceeded {MAX_REPLY_BYTES} byte cap")
}

/// The failure for an error status (4xx/5xx), the 1.5.5 client's own wording without the URL. `phrase`
/// is the reason phrase the server actually sent (the exchange's response head: the wire phrase on
/// HTTP/1.1); when it is absent or empty (h2 has none) the canonical phrase stands, as it did in 1.5.5.
#[must_use]
pub fn error_status(code: u16, phrase: Option<&str>) -> String {
    let (class, status) = match http::StatusCode::from_u16(code) {
        Ok(c) if c.is_client_error() => ("client", c),
        Ok(c) => ("server", c),
        Err(_) => ("server", http::StatusCode::INTERNAL_SERVER_ERROR),
    };
    let shown = match phrase.filter(|p| !p.is_empty()) {
        Some(p) => format!("{} {p}", status.as_u16()),
        None => status.to_string(),
    };
    format!("webrequest: target returned an error status: HTTP status {class} error ({shown})")
}

/// Parse a reply body into a `Value`, rejecting a pathologically nested body BEFORE building the value.
/// The parse-error path is LENGTH-ONLY: a target that echoed granted prompt content into a malformed
/// reply must not splash it into an error the engine might log.
///
/// # Errors
/// The 1.5.5 text.
pub fn parse_reply(bytes: &[u8]) -> Result<Value, String> {
    if exceeds_max_depth(bytes, MAX_REPLY_DEPTH) {
        return Err(format!(
            "webrequest: reply exceeded max nesting depth ({} bytes)",
            bytes.len()
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| format!("webrequest: invalid JSON reply ({} bytes)", bytes.len()))
}

/// Single-pass, string-aware scan for the maximum `{`/`[` nesting depth in `bytes`. Brackets inside JSON
/// string literals (and `\`-escaped quotes) do not count. Short-circuits once `max` is exceeded.
#[must_use]
pub fn exceeds_max_depth(bytes: &[u8], max: usize) -> bool {
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// The endpoint's answer as the framed http exchange hands it back: the status, its reason phrase and the body (already
/// held to [`MAX_REPLY_BYTES`] by the exchange's cap; the check here is the plugin's own, so a host that
/// hands more is refused too).
///
/// The status rule is the 1.5.5 client's `error_for_status`: 4xx/5xx is a failure, everything else
/// (redirects are never followed) carries its body as the reply.
///
/// # Errors
/// The 1.5.5 failure text.
pub fn interpret(status: u16, phrase: Option<&str>, body: &[u8]) -> Result<Value, String> {
    if status >= 400 {
        return Err(error_status(status, phrase));
    }
    if body.len() > MAX_REPLY_BYTES {
        return Err(cap_exceeded());
    }
    parse_reply(body)
}

/// `decide`: a failure means this hook COULD NOT ANSWER, which is not the same as having no opinion; the
/// engine resolves the operator's `on_error` chain on it. So the failure stays a failure.
///
/// # Errors
/// The failure text, unchanged.
pub fn decide(reply: Result<Value, String>) -> Result<Value, String> {
    reply
}

/// `transform`: any failure is `{}` (abstain, proceed with the ORIGINAL body); a parsed `reject` in the
/// reply is honoured by the engine.
#[must_use]
pub fn transform(reply: Result<Value, String>) -> Value {
    reply.unwrap_or_else(|_| serde_json::json!({}))
}

/// `notify`: fire-and-forget. The reply is not read for meaning and every error is swallowed: a tap can
/// NEVER delay or fail the served request.
pub fn notify(_reply: Result<Value, String>) {}
