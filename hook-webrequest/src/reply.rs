// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The reply rules: the status rule, the body cap, the nesting-depth guard and the length-only
//! parse error, and what a failure MEANS per op. The framed http exchange hands back its status,
//! reason phrase and body; [`interpret`] is what the plugin makes of them.

use crate::config::Json;
use crate::{ALIAS, FORWARD_FAILED, NOTIFY_DROPPED};

/// Read an SDK response while retaining its raw body, reason and fields in wiping custody.
pub fn read_response<T>(
    response: busbar_contract::abi::sdk::exchange::ExchangeResponse,
    read: impl FnOnce(&busbar_contract::abi::sdk::exchange::ExchangeResponse) -> T,
) -> T {
    let response = zeroize::Zeroizing::new(response);
    read(&response)
}

/// Maximum reply body accepted from the target, in bytes: the reply is a small ranking/verdict object, so
/// a body past this is a hostile or buggy target.
pub const MAX_REPLY_BYTES: usize = 64 * 1024;

/// Maximum JSON nesting depth accepted in a reply (busbar's `MAX_JSON_DEPTH`, a security floor).
pub const MAX_REPLY_DEPTH: usize = busbar_contract::spans::MAX_JSON_DEPTH;

/// The transport failure text: connect, send, timeout and a malformed head all read as this, with the
/// URL removed so a `?token=` never reaches the engine's log.
pub(crate) const REQUEST_FAILED: &str =
    concat!(alias_lit!(), ": request failed: error sending request");

/// [`REQUEST_FAILED`] with the host's `cause` after it, written once.
#[must_use]
pub(crate) fn request_failed_with(cause: &str) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: the failure text of a failed exchange, built once per failed op"
    )]
    let text = format!("{REQUEST_FAILED}: {cause}");
    text
}

/// The failure for a body past [`MAX_REPLY_BYTES`].
#[must_use]
pub fn cap_exceeded() -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: the failure text of an oversize reply, copied once from its fixed text"
    )]
    let text = CAP_EXCEEDED.to_owned();
    text
}

/// The oversize-reply failure text, fixed; [`MAX_REPLY_BYTES`] is written out and pinned below.
const CAP_EXCEEDED: &str = concat!(alias_lit!(), ": response exceeded 65536 byte cap");
const _: () = assert!(MAX_REPLY_BYTES == 65536);

/// The longest remote reason phrase a failure text shows, in characters.
pub const MAX_PHRASE_CHARS: usize = 128;

/// The remote's reason phrase as a log line may carry it: cut to [`MAX_PHRASE_CHARS`] characters
/// (marked with `\u{2026}`) and `Debug`-escaped, so a hostile target cannot flood the log, forge a line
/// or send terminal control bytes. An apostrophe stays as is (the 1.5.5 client showed it so).
/// Written straight into the failure text, with no intermediate string.
struct LoggablePhrase<'a>(&'a str);

impl std::fmt::Display for LoggablePhrase<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        for (i, c) in self.0.chars().enumerate() {
            if i >= MAX_PHRASE_CHARS {
                return f.write_char('\u{2026}');
            }
            if c == '\'' {
                f.write_char(c)?;
            } else {
                for e in c.escape_debug() {
                    f.write_char(e)?;
                }
            }
        }
        Ok(())
    }
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
    use std::fmt::Write as _;
    let phrase = phrase.filter(|p| !p.is_empty());
    // The words around the status, and the phrase as sent (escaping may grow it).
    // busbar:expect(bp::fresh_buffer, reason = "error: the failure text of an error status, written once per failed op into one allocation")
    let mut out = String::with_capacity(
        ALIAS.len() + 80 + phrase.map_or(32, |p| p.len().min(MAX_PHRASE_CHARS * 4) + 8),
    );
    let _ = write!(
        out,
        "{ALIAS}: target returned an error status: HTTP status {class} error ("
    );
    let _ = match phrase {
        Some(p) => write!(out, "{} {})", status.as_u16(), LoggablePhrase(p)),
        None => write!(out, "{status})"),
    };
    out
}

/// Whether `status` fits the three-digit HTTP status field. This is a syntax check, not a success
/// predicate. The exchange reports a code that fits no `u16` as `0`.
fn is_status_code(status: u16) -> bool {
    (100..1000).contains(&status)
}

/// The failure for a reply whose status is no three-digit HTTP status code.
#[must_use]
pub fn not_a_status(code: u16) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: the failure text of a status that is no status, built once per failed op"
    )]
    let text = format!("{ALIAS}: target answered no valid HTTP status (got {code})");
    text
}

/// The failure for a final response outside the operation's accepted status classes.
#[must_use]
pub fn non_success_status(code: u16) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: the failure text of a non-success status, built once per failed op"
    )]
    let text = format!("{ALIAS}: target answered a non-success HTTP status ({code})");
    text
}

/// The failure for a redirect (3xx), which is never followed.
#[must_use]
pub fn redirect_not_followed(code: u16) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "error: the failure text of a redirect, built once per failed op"
    )]
    let text =
        format!("{ALIAS}: target answered a redirect that was not followed (HTTP status {code})");
    text
}

/// Parse a reply body into a `Json`, rejecting a pathologically nested body BEFORE building the value.
pub fn parse_reply(bytes: &[u8]) -> Result<Json, String> {
    if exceeds_max_depth(bytes, MAX_REPLY_DEPTH) {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: the failure text of an over-deep reply, built once per failed op"
        )]
        return Err(format!(
            "{ALIAS}: reply exceeded max nesting depth ({} bytes)",
            bytes.len()
        ));
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "error: the failure text of an unparsable reply, built once per failed op"
    )]
    let parsed: Result<Json, String> = serde_json::from_slice(bytes)
        .map_err(|_| format!("{ALIAS}: invalid JSON reply ({} bytes)", bytes.len()));
    parsed
}

/// The nesting-depth scanner is busbar's own (one copy, so a core fix or a changed floor reaches this
/// plugin at a `.busbar-ref` bump).
pub use busbar_contract::spans::exceeds_max_depth;

/// The endpoint's answer as the framed http exchange hands it back: its status, reason phrase and
/// body. The door bounds collection to [`MAX_REPLY_BYTES`]; the check here also bounds direct calls.
///
/// Only a 2xx response carries a decision or transform reply. Redirects are never followed; every
/// other final status fails the call so the host applies `on_error`. An EMPTY body is a failure
/// whatever the status, a `204` included: an abstain is a deliberate `{}` or `{"abstain":true}`,
/// never a missing body.
///
/// A body that is not JSON (or is too deep) fails; any JSON value is returned as is, and busbar's
/// reply lowering reads its meaning.
///
/// # Errors
/// The failure text.
pub fn interpret(status: u16, phrase: Option<&str>, body: &[u8]) -> Result<Json, String> {
    if !is_status_code(status) {
        return Err(not_a_status(status));
    }
    if (400..600).contains(&status) {
        return Err(error_status(status, phrase));
    }
    if (300..400).contains(&status) {
        return Err(redirect_not_followed(status));
    }
    if !(200..300).contains(&status) {
        return Err(non_success_status(status));
    }
    if body.len() > MAX_REPLY_BYTES {
        return Err(cap_exceeded());
    }
    if body.is_empty() {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: the failure text of an empty reply, built once per failed op"
        )]
        return Err(format!("{ALIAS}: empty reply (HTTP status {status})"));
    }
    parse_reply(body)
}

/// Whether a `notify` was delivered: a 2xx or 3xx head acknowledges delivery without following a
/// redirect or reading the body. A tap's answer carries no meaning, so a `204` is no warning.
///
/// # Errors
/// The failure text for any other final status.
pub fn delivered(status: u16, phrase: Option<&str>) -> Result<(), String> {
    if !is_status_code(status) {
        return Err(not_a_status(status));
    }
    if (400..600).contains(&status) {
        return Err(error_status(status, phrase));
    }
    if !(200..400).contains(&status) {
        return Err(non_success_status(status));
    }
    Ok(())
}

/// `decide`: any failure (transport, error status, timeout, malformed, oversize or over-deep reply, an
/// envelope that cannot be sent) is the hook FAILING, not a verdict: the failure text goes on to the
/// host, which applies the pool's `on_error`. A reply the target sends deliberately (`{}`,
/// `{"abstain":true}`) is an abstain. The shared SDK lowering validates the hook reply and selects
/// the verdict; this forwarder does not implement a second semantic parser. A forwarding failure is
/// also logged to the plugin's log (a warn).
///
/// # Errors
/// The failure text, passed through.
pub fn decide(reply: Result<Json, String>) -> Result<Json, String> {
    reply.inspect_err(
        |e| tracing::warn!(diag = %FORWARD_FAILED, "{e}; decide failed (on_error applies)"),
    )
}

/// `transform`: any failure is the hook FAILING (the host's `on_error` for transform), as
/// [`decide`]; a deliberate `{}` proceeds with the ORIGINAL body, and a parsed `reject` in the reply
/// is honoured by the engine. The failure is logged to the plugin's log (a warn).
///
/// # Errors
/// The failure text, passed through.
pub fn transform(reply: Result<Json, String>) -> Result<Json, String> {
    reply.inspect_err(
        |e| tracing::warn!(diag = %FORWARD_FAILED, "{e}; transform failed (on_error applies)"),
    )
}

/// `notify`: fire-and-forget. The reply is not read for meaning and every error is dropped from the
/// verdict: a tap can NEVER delay or fail the served request. A failure is logged to the plugin's log
/// (a warn).
pub fn notify(reply: Result<Json, String>) {
    if let Err(e) = reply {
        tracing::warn!(diag = %NOTIFY_DROPPED, "{e}; notify dropped");
    }
}
