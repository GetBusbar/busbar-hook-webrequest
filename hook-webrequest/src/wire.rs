// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What goes on the wire to the endpoint: the op envelope and the HTTP/1.1 request bytes. The
//! envelope is the projection with the `op` key last, and the request's fields are written in a
//! fixed order.

use crate::config::Target;
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
/// The serialisation refusal text.
pub fn envelope(op: &str, payload: &serde_json::Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&Envelope { op, payload })
        .map_err(|e| format!("webrequest: failed to serialize op envelope: {e}"))
}

/// One framed http exchange's request: what the exchange is handed (the http framer writes the
/// bytes). The framer adds `content-length` from the body and `host` from the request's authority;
/// the fields here are the ones the forwarder itself sets.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    /// Always `POST`.
    pub method: &'static str,
    /// The request target: the URL's path and query (`/` when it has neither).
    pub target: String,
    /// The `host` header value: the host, and the port only when the URL names a non-default one.
    pub authority: String,
    /// The fields, in order (`Debug` redacts the target and the `authorization` value):
    /// `authorization` (only when the URL carries userinfo), `content-type`,
    /// `accept`.
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
    let mut fields = Vec::with_capacity(3);
    if let Some(auth) = basic_authorization(url) {
        fields.push(("authorization", auth));
    }
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

/// `Basic base64(user:pass)` from the URL's percent-decoded userinfo:
/// a username that is not UTF-8 once decoded sends no header at all, a password that is not UTF-8
/// counts as absent, and the header goes only for a non-empty username or a present password.
fn basic_authorization(url: &url::Url) -> Option<String> {
    let username = String::from_utf8(percent_decode(url.username())).ok()?;
    let password = url
        .password()
        .and_then(|p| String::from_utf8(percent_decode(p)).ok());
    if username.is_empty() && password.is_none() {
        return None;
    }
    let mut raw = username.into_bytes();
    raw.push(b':');
    if let Some(p) = password {
        raw.extend(p.into_bytes());
    }
    Some(format!("Basic {}", base64(&raw)))
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

fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}
