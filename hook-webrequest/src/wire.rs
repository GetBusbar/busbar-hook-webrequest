// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What goes on the wire to the endpoint: the op envelope and the HTTP/1.1 request bytes. Both are
//! byte-identical to 1.5.5 (the C0 CAP webrequest cell holds it): the envelope is the projection with
//! the `op` key last, and the request's fields are the ones, in the order, the 1.5.5 client (reqwest over
//! hyper) wrote.

use crate::config::Target;
use busbar_contract::abi::sdk::cred::{Cred, Seal};
use url::Position;

/// The POST envelope for a per-request op: the engine's opaque `payload` projection (BORROWED, not
/// cloned) with an `op` discriminator merged in, mirroring the old webhook wire. The projection is
/// carried through UNCHANGED, so any opt-in `prompt`/`user` keys the CORE granted ride straight through.
struct Envelope<'a> {
    op: &'a str,
    payload: &'a serde_json::Value,
}

impl serde::Serialize for Envelope<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeMap;
        match self.payload {
            serde_json::Value::Object(m) => {
                let mut map = serializer.serialize_map(Some(m.len() + 1))?;
                // The `op` discriminator always wins: a projection's own top-level `op` is skipped
                // rather than emitted twice (a duplicate JSON key is ambiguous on the wire).
                for (k, v) in m.iter().filter(|(k, _)| k.as_str() != "op") {
                    map.serialize_entry(k, v)?;
                }
                map.serialize_entry("op", self.op)?;
                map.end()
            }
            // A non-object projection is unexpected, but relayed under a `payload` key, not dropped.
            other => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("payload", other)?;
                map.serialize_entry("op", self.op)?;
                map.end()
            }
        }
    }
}

/// The JSON body for `op` over `payload`.
///
/// # Errors
/// The 1.5.5 serialisation refusal text.
pub fn envelope(op: &str, payload: &serde_json::Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&Envelope { op, payload })
        .map_err(|e| format!("webrequest: failed to serialize op envelope: {e}"))
}

/// One framed http exchange's request: what the exchange is handed (THE DESIGN §5: the http framer
/// writes the bytes, so they are hyper's, the 1.5.5 client's own library). The framer adds
/// `content-length` from the body and `host` from the request's authority; the fields here are the ones
/// the forwarder itself sets, in the 1.5.5 client's order.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    /// Always `POST`.
    pub method: &'static str,
    /// The request target: the URL's path and query (`/` when it has neither).
    pub target: String,
    /// The `host` header value: the host, and the port only when the URL names a non-default one.
    pub authority: String,
    /// The public fields, in order: `content-type`, `accept`. The `authorization` the URL's userinfo
    /// becomes goes first, sealed ([`basic_authorization`]).
    pub fields: Vec<(&'static str, String)>,
    /// The op envelope.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let fields: Vec<(&str, &str)> = self
            .fields
            .iter()
            .map(|(n, v)| {
                if n.eq_ignore_ascii_case("authorization") {
                    (*n, "<redacted>")
                } else {
                    (*n, v.as_str())
                }
            })
            .collect();
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("target", &"<redacted>")
            .field("authority", &self.authority)
            .field("fields", &fields)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The request for `body` to `target`.
#[must_use]
pub fn request(target: &Target, body: Vec<u8>) -> Request {
    let url = &target.url;
    let path = &url[Position::BeforePath..Position::AfterQuery];
    let mut fields = Vec::with_capacity(2);
    fields.push(("content-type", "application/json".to_string()));
    fields.push(("accept", "*/*".to_string()));
    Request {
        method: "POST",
        target: if path.is_empty() { "/" } else { path }.to_string(),
        authority: host_header(url),
        fields,
        body,
    }
}

/// `host` or `host:port`: the port only when the URL names a non-default one.
fn host_header(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    }
}

/// `Basic base64(user:pass)` from the URL's percent-decoded user and the sealed password, as the
/// 1.5.5 client built it, made by the chip: a username that is not UTF-8 once decoded sends no
/// header at all, a password that is not UTF-8 counts as absent, and the header goes only for a
/// non-empty username or a present password.
#[must_use]
pub fn basic_authorization(target: &Target) -> Option<Seal> {
    let username = String::from_utf8(percent_decode(target.url.username())).ok()?;
    let password = target.password.as_ref().filter(|p| p.is_text());
    if username.is_empty() && password.is_none() {
        return None;
    }
    Some(
        password
            .cloned()
            .unwrap_or_else(Cred::empty)
            .basic(&username),
    )
}

/// Percent-decoding as `percent_encoding::percent_decode` does it: `%` decodes only when followed by
/// two ASCII hex digits, otherwise it stays literal.
pub(crate) fn percent_decode(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
        {
            let hex = |c: u8| (c as char).to_digit(16).unwrap_or(0) as u8;
            out.push(hex(b[i + 1]) << 4 | hex(b[i + 2]));
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}
