// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reply rules: the status rule, the body cap, the nesting-depth guard and the length-only
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

/// The longest remote reason phrase a failure text shows, in characters.
pub const MAX_PHRASE_CHARS: usize = 128;

/// The remote's reason phrase as a log line may carry it: cut to [`MAX_PHRASE_CHARS`] characters
/// (marked with `\u{2026}`) and `Debug`-escaped, so a hostile target cannot flood the log, forge a line
/// or send terminal control bytes. An apostrophe stays as is (the 1.5.5 client showed it so).
fn loggable_phrase(phrase: &str) -> String {
    let mut out = String::new();
    for c in phrase.chars().take(MAX_PHRASE_CHARS) {
        if c == '\'' {
            out.push(c);
        } else {
            out.extend(c.escape_debug());
        }
    }
    if phrase.chars().nth(MAX_PHRASE_CHARS).is_some() {
        out.push('\u{2026}');
    }
    out
}

/// The failure for an error status (4xx/5xx), worded without the URL. `phrase` is the reason phrase
/// the server actually sent (the exchange's response head: the wire phrase on HTTP/1.1); when it is
/// absent or empty (h2 has none) the canonical phrase stands.
#[must_use]
pub fn error_status(code: u16, phrase: Option<&str>) -> String {
    let (class, status) = match http::StatusCode::from_u16(code) {
        Ok(c) if c.is_client_error() => ("client", c),
        Ok(c) => ("server", c),
        Err(_) => ("server", http::StatusCode::INTERNAL_SERVER_ERROR),
    };
    let shown = match phrase.filter(|p| !p.is_empty()) {
        Some(p) => format!("{} {}", status.as_u16(), loggable_phrase(p)),
        None => status.to_string(),
    };
    format!("webrequest: target returned an error status: HTTP status {class} error ({shown})")
}

/// Parse a reply body into a `Value`, rejecting a pathologically nested body BEFORE building the value.
/// The parse-error path is LENGTH-ONLY: a target that echoed granted prompt content into a malformed
/// reply must not splash it into an error the engine might log.
///
/// # Errors
/// The failure text.
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

/// The endpoint's answer as the framed http exchange hands it back: the status, its reason phrase and the body (the
/// exchange holds it only to its own bound, busbar-contract's `REPLY_MAX`, and `Op::exchange` offers no way to
/// lower it; the check here is what holds it to [`MAX_REPLY_BYTES`]).
///
/// The status rule: 4xx/5xx (400..=599) is a failure, everything else (redirects are never followed)
/// carries its body as the reply.
///
/// # Errors
/// The failure text.
pub fn interpret(status: u16, phrase: Option<&str>, body: &[u8]) -> Result<Value, String> {
    if (400..600).contains(&status) {
        return Err(error_status(status, phrase));
    }
    if body.len() > MAX_REPLY_BYTES {
        return Err(cap_exceeded());
    }
    parse_reply(body)
}

/// Whether a `notify` was delivered: any status short of an error status is, and the body is not read
/// (a tap's answer carries no meaning, so a `204` or an empty body is no warning).
///
/// # Errors
/// The failure text of a 4xx/5xx.
pub fn delivered(status: u16, phrase: Option<&str>) -> Result<(), String> {
    if (400..600).contains(&status) {
        return Err(error_status(status, phrase));
    }
    Ok(())
}

/// `decide`: any failure (transport, error status, timeout, malformed, oversize or over-deep reply, an
/// envelope that cannot be sent) is the hook FAILING, not a verdict: the failure text goes on to the
/// host, which applies the pool's `on_error` (a far-end 500 under `on_error: reject` refuses the
/// request; the default fail-open terminal routes as before). A reply the target sends deliberately
/// (`{}`, `{"abstain":true}`) is an abstain. The failure is also logged to the plugin's log (a warn).
///
/// # Errors
/// The failure text, passed through.
pub fn decide(reply: Result<Value, String>) -> Result<Value, String> {
    reply.inspect_err(|e| tracing::warn!("{e}; decide failed (on_error applies)"))
}

/// `transform`: any failure is the hook FAILING (the host's `on_error` for transform), as
/// [`decide`]; a deliberate `{}` proceeds with the ORIGINAL body, and a parsed `reject` in the reply
/// is honoured by the engine. The failure is logged to the plugin's log (a warn).
///
/// # Errors
/// The failure text, passed through.
pub fn transform(reply: Result<Value, String>) -> Result<Value, String> {
    reply.inspect_err(|e| tracing::warn!("{e}; transform failed (on_error applies)"))
}

/// `notify`: fire-and-forget. The reply is not read for meaning and every error is dropped from the
/// verdict: a tap can NEVER delay or fail the served request. A failure is logged to the plugin's log
/// (a warn).
pub fn notify(reply: Result<Value, String>) {
    if let Err(e) = reply {
        tracing::warn!("{e}; notify dropped");
    }
}
