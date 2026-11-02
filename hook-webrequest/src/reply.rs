// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reply rules: the status rule, the body cap, the nesting-depth guard and the length-only

use crate::{ALIAS, FORWARD_FAILED, NOTIFY_DROPPED};
use serde_json::Value;

/// Read an SDK response while retaining its raw body, reason and fields in wiping custody.
pub fn read_response<T>(
    response: busbar_contract::abi::sdk::exchange::ExchangeResponse,
    read: impl FnOnce(&busbar_contract::abi::sdk::exchange::ExchangeResponse) -> T,
) -> T {
    let response = crate::owners::Response(response);
    read(&response)
}

/// Maximum reply body accepted from the target, in bytes: the reply is a small ranking/verdict object, so
pub const MAX_REPLY_BYTES: usize = 64 * 1024;

/// Maximum JSON nesting depth accepted in a reply (busbar's `MAX_JSON_DEPTH`, a security floor).
pub const MAX_REPLY_DEPTH: usize = busbar_contract::spans::MAX_JSON_DEPTH;

/// The transport failure text: connect, send, timeout and a malformed head all read as this, with the
#[must_use]
pub fn request_failed() -> String {
    format!("{ALIAS}: request failed: error sending request")
}

/// The body-read failure text, the 1.5.5 reference wording that `wire_tests` pins. The host reports
/// a body-read failure (a truncated or malformed body) as a `ConnFailure`, which has no body-read
/// variant, so the plugin words it with [`request_failed`]; this text is not emitted in production.
#[must_use]
pub fn read_failed() -> String {
    format!("{ALIAS}: response read failed: error decoding response body")
}

/// The failure for a body past [`MAX_REPLY_BYTES`].
#[must_use]
pub fn cap_exceeded() -> String {
    format!("{ALIAS}: response exceeded {MAX_REPLY_BYTES} byte cap")
}

/// The longest remote reason phrase a failure text shows, in characters.
pub const MAX_PHRASE_CHARS: usize = 128;

/// The remote's reason phrase as a log line may carry it: cut to [`MAX_PHRASE_CHARS`] characters
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
    format!("{ALIAS}: target returned an error status: HTTP status {class} error ({shown})")
}

/// The failure for a redirect (3xx), which is never followed.
#[must_use]
pub fn redirect_not_followed(code: u16) -> String {
    format!("{ALIAS}: target answered a redirect that was not followed (HTTP status {code})")
}

/// Parse a reply body into a `Value`, rejecting a pathologically nested body BEFORE building the value.
pub fn parse_reply(bytes: &[u8]) -> Result<Value, String> {
    if exceeds_max_depth(bytes, MAX_REPLY_DEPTH) {
        return Err(format!(
            "{ALIAS}: reply exceeded max nesting depth ({} bytes)",
            bytes.len()
        ));
    }
    serde_json::from_slice(bytes)
        .map_err(|_| format!("{ALIAS}: invalid JSON reply ({} bytes)", bytes.len()))
}

/// The nesting-depth scanner is busbar's own (one copy, so a core fix or a changed floor reaches this
/// plugin at a `.busbar-ref` bump).
pub use busbar_contract::spans::exceeds_max_depth;

/// The endpoint's answer as the framed http exchange hands it back: its status, reason phrase and
pub fn interpret(status: u16, phrase: Option<&str>, body: &[u8]) -> Result<Value, String> {
    if (400..600).contains(&status) {
        return Err(error_status(status, phrase));
    }
    if (300..400).contains(&status) {
        return Err(redirect_not_followed(status));
    }
    if body.len() > MAX_REPLY_BYTES {
        return Err(cap_exceeded());
    }
    if body.is_empty() {
        return if status == 204 {
            Ok(serde_json::json!({}))
        } else {
            Err(format!("{ALIAS}: empty reply (HTTP status {status})"))
        };
    }
    parse_reply(body)
}

/// Whether a `notify` was delivered: any status short of an error status is, and the body is not read
pub fn delivered(status: u16, phrase: Option<&str>) -> Result<(), String> {
    if (400..600).contains(&status) {
        return Err(error_status(status, phrase));
    }
    Ok(())
}

/// `decide`: any failure (transport, error status, timeout, malformed, oversize or over-deep reply, an
pub fn decide(reply: Result<Value, String>) -> Result<Value, String> {
    reply.inspect_err(
        |e| tracing::warn!(diag = %FORWARD_FAILED, "{e}; decide failed (on_error applies)"),
    )
}

/// `transform`: any failure is the hook FAILING (the host's `on_error` for transform), as
pub fn transform(reply: Result<Value, String>) -> Result<Value, String> {
    reply.inspect_err(
        |e| tracing::warn!(diag = %FORWARD_FAILED, "{e}; transform failed (on_error applies)"),
    )
}

/// `notify`: fire-and-forget. The reply is not read for meaning and every error is dropped from the
pub fn notify(reply: Result<Value, String>) {
    if let Err(e) = reply {
        tracing::warn!(diag = %NOTIFY_DROPPED, "{e}; notify dropped");
    }
}
