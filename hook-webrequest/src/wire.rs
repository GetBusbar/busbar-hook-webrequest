// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the forwarder hands the host's `http` framer for each op: the method, the request target and
//! the fields it sets, in a fixed order. The op envelope itself is written by the SDK
//! (`write_projection`), and the framer writes the bytes.

use busbar_contract::abi::sdk::url::{self as sdk_url, Userinfo};

use crate::config::Target;
use url::Position;

pub use busbar_contract::abi::sdk::exchange::Request;

/// The request for `body` to `target`.
#[must_use]
pub fn request(target: &Target, body: Vec<u8>) -> Request {
    let url = &target.url;
    let path = &url[Position::BeforePath..Position::AfterQuery];
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the request template is built once per target, at open or configure, and the SDK's Request owns its bytes"
    )]
    let request = Request {
        method: b"POST".to_vec(),
        target: if path.is_empty() {
            b"/"
        } else {
            path.as_bytes()
        }
        .to_vec(),
        fields: match basic_authorization(url) {
            Some(auth) => vec![
                (b"authorization".to_vec(), auth.into_bytes()),
                (b"content-type".to_vec(), b"application/json".to_vec()),
                (b"accept".to_vec(), b"*/*".to_vec()),
            ],
            None => vec![
                (b"content-type".to_vec(), b"application/json".to_vec()),
                (b"accept".to_vec(), b"*/*".to_vec()),
            ],
        },
        body,
        timeout_ms: u64::try_from(target.timeout.as_millis()).unwrap_or(u64::MAX),
    };
    request
}

/// `Basic base64(user:pass)` from the validated URL's percent-decoded UTF-8 userinfo. Target
/// validation refuses invalid decoded text before this function runs, so no credential is silently
/// omitted or shortened. A header is sent for a non-empty username or a present password.
pub(crate) fn basic_authorization(url: &url::Url) -> Option<String> {
    sdk_url::basic_authorization(url.username(), url.password(), Userinfo::Utf8)
}

/// The bytes the JSON escaping of `text` adds to it, as `serde_json` escapes (`"`, `\\` and the
/// short-form controls take two bytes, every other byte below `0x20` takes six, `\\u00XX`; all
/// else, non-ASCII included, passes as is). Scanned in fixed 32-byte blocks with branch-free folds
/// (which vectorise), and counted only in a block that holds a byte to escape.
#[must_use]
pub fn escape_extra(text: &str) -> usize {
    #[inline]
    fn extra(b: u8) -> u8 {
        let short = u8::from(b == b'"')
            | u8::from(b == b'\\')
            | u8::from(b == 0x08)
            | u8::from(b == 0x09)
            | u8::from(b == 0x0a)
            | u8::from(b == 0x0c)
            | u8::from(b == 0x0d);
        short | ((u8::from(b < 0x20) & (short ^ 1)) * 5)
    }
    #[inline]
    fn block(c: &[u8; 32]) -> usize {
        let dirty = c.iter().fold(0u8, |d, &b| {
            d | u8::from(b < 0x20) | u8::from(b == b'"') | u8::from(b == b'\\')
        });
        if dirty == 0 {
            return 0;
        }
        // At most 32 * 5 = 160: the sum fits a `u8`.
        usize::from(c.iter().fold(0u8, |n, &b| n + extra(b)))
    }
    let (blocks, tail) = text.as_bytes().as_chunks::<32>();
    let mut last = [b' '; 32];
    last[..tail.len()].copy_from_slice(tail);
    blocks.iter().map(block).sum::<usize>() + block(&last)
}

/// A JSON member's key, `"key":`, and the comma after it.
const fn key(name: &str) -> usize {
    name.len() + 4
}

/// A JSON string that needs no escaping (a name, a label): its text and quotes.
const fn label(text: &str) -> usize {
    text.len() + 2
}

/// A JSON string as written: its text, quotes and escapes.
fn quoted(text: &str) -> usize {
    text.len() + 2 + escape_extra(text)
}

/// The digits of `v`.
const fn digits(v: u64) -> usize {
    match v.checked_ilog10() {
        Some(log) => log as usize + 1,
        None => 1,
    }
}

/// An `i64` as JSON: its digits and sign.
const fn signed(v: i64) -> usize {
    digits(v.unsigned_abs()) + (v < 0) as usize
}

/// An `f64` as JSON at its longest (`-1.2345678901234567e-308`).
const FLOAT: usize = 24;

/// The members a signal bag adds, every value at its longest (a repeated signal's array included).
fn signals(bag: &busbar_contract::SignalBag) -> usize {
    use busbar_contract::signal::SignalValue;
    bag.iter()
        .map(|(signal, value)| {
            key(signal.name())
                + 2
                + match value {
                    SignalValue::Str(text) => quoted(text),
                    SignalValue::U64(v) => digits(*v),
                    SignalValue::I64(v) => signed(*v),
                    SignalValue::F64(_) => FLOAT,
                    SignalValue::Bool(_) => 5,
                }
        })
        .sum()
}

/// A capacity for the `op` envelope `write_projection` writes for `view`: its length counted the
/// way the SDK's projection writes it (texts with their escapes, integers by their digits, floats
/// at their longest, every member's comma), so the body is written into one allocation and never
/// regrown: the prompt is copied once, no outgrown copy of it is freed unwiped, and the capacity
/// the SDK wipes stays near the body's length. An estimate only: an envelope longer than it grows
/// the buffer as before.
#[must_use]
pub fn projection_hint(view: &busbar_contract::abi::sdk::hook::Decoded<'_>, op: &str) -> usize {
    let mut request = 2
        + key("has_tools")
        + 5
        + key("ingress_protocol")
        + quoted(&view.ingress_dialect)
        + key("message_count")
        + digits(view.message_count)
        + key("pool")
        + quoted(&view.pool)
        + key("request_id")
        + digits(view.request_id)
        + key("stream")
        + 5
        + key("total_chars")
        + digits(view.total_chars)
        + view
            .max_tokens
            .map_or(0, |t| key("max_tokens") + digits(u64::from(t)))
        + signals(&view.signals);
    if let Some(prompt) = &view.prompt {
        request += prompt
            .system
            .as_ref()
            .map_or(0, |s| key("system") + quoted(s));
        request += key("messages")
            + 2
            + prompt
                .messages
                .iter()
                .map(|(role, text)| 3 + key("role") + quoted(role) + key("text") + quoted(text))
                .sum::<usize>();
    }
    if let Some(user) = &view.user {
        request += key("user")
            + 2
            + [
                ("key_id", &user.key_id),
                ("key_name", &user.key_name),
                ("user", &user.user),
            ]
            .into_iter()
            .filter_map(|(name, v)| v.as_ref().map(|v| key(name) + quoted(v)))
            .sum::<usize>();
    }
    let candidates: usize = view
        .candidates
        .iter()
        .map(|c| {
            3 + key("available_concurrency")
                + digits(c.available_concurrency as u64)
                + key("idx")
                + digits(c.idx as u64)
                + key("model")
                + quoted(&c.model)
                + key("provider")
                + quoted(&c.provider)
                + key("weight")
                + digits(u64::from(c.weight))
                + c.context_max
                    .map_or(0, |m| key("context_max") + digits(m as u64))
                + c.tier.as_ref().map_or(0, |t| key("tier") + quoted(t))
                + [c.cost_per_mtok, c.latency_ms, c.rate_headroom]
                    .into_iter()
                    .flatten()
                    .count()
                    * (key("rate_headroom") + FLOAT)
                + c.budget_remaining
                    .map_or(0, |b| key("budget_remaining") + signed(b))
                + if c.tags.is_empty() {
                    0
                } else {
                    key("tags") + 2 + c.tags.iter().map(|t| quoted(t) + 1).sum::<usize>()
                }
                + signals(&c.signals)
        })
        .sum();
    let budget: usize = view
        .budget
        .iter()
        .map(|b| {
            3 + key("bucket_id")
                + quoted(&b.bucket_id)
                + key("budget_group")
                + b.budget_group.as_ref().map_or(4, |g| quoted(g))
                + key("budget_period")
                + quoted(&b.budget_period)
                + key("remaining_micros")
                + b.remaining_micros.map_or(4, signed)
                + key("spend_micros_at_current_rate")
                + signed(b.spend_micros_at_current_rate)
                + key("window_start")
                + digits(b.window_start)
                + b.pool.as_ref().map_or(0, |p| key("pool") + quoted(p))
        })
        .sum();
    let context =
        2 + if view.budget.is_empty() {
            0
        } else {
            key("budget") + 2 + budget
        } + view
            .budget_remaining
            .map_or(0, |r| key("budget_remaining") + signed(r));
    // `{"candidates":[..],"context":{..},"op":"..","request":{..}}`, and a little for escapes in
    // the short names counted as labels.
    2 + key("candidates")
        + 2
        + candidates
        + key("context")
        + context
        + key("op")
        + label(op)
        + key("request")
        + request
        + 16
}

/// [`projection_hint`] for a tap's envelope: its request (a tap carries no candidates and no
/// budget) and its stage.
#[must_use]
pub fn tap_hint(tap: &busbar_contract::abi::sdk::hook::DecodedTap<'_>, op: &str) -> usize {
    let stage = tap.stage.as_ref().map_or(0, |s| {
        key("stage")
            + 2
            + key("at")
            + label(s.at)
            + [
                ("model", &s.model),
                ("outcome", &s.outcome),
                ("previous_failure", &s.previous_failure),
            ]
            .into_iter()
            .filter_map(|(name, v)| v.as_ref().map(|v| key(name) + quoted(v)))
            .sum::<usize>()
            + s.attempt_number
                .map_or(0, |a| key("attempt_number") + digits(u64::from(a)))
            + s.remaining_candidates
                .map_or(0, |r| key("remaining_candidates") + digits(r as u64))
            + s.status.map_or(0, |v| key("status") + digits(u64::from(v)))
    });
    projection_hint(&tap.request, op) + stage
}
