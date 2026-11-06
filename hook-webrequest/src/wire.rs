// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the forwarder hands the host's `http` framer for each op: the method, the request target and
//! the fields it sets, in a fixed order. The op envelope itself is written by the SDK
//! (`write_projection`), and the framer writes the bytes.

use busbar_contract::abi::sdk::url::{self as sdk_url, Userinfo};

use crate::config::Target;
use url::Position;

/// One framed http exchange's request: what the exchange is handed (the http framer writes the
/// bytes). The framer adds `content-length` from the body and `host` from the origin the exchange is
/// dialled to; the fields here are the ones the forwarder itself sets.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    /// Always `POST`.
    pub method: &'static str,
    /// The request target: the URL's path and query (`/` when it has neither).
    pub target: String,
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
        fields,
        body,
    }
}

/// `Basic base64(user:pass)` from the validated URL's percent-decoded UTF-8 userinfo. Target
/// validation refuses invalid decoded text before this function runs, so no credential is silently
/// omitted or shortened. A header is sent for a non-empty username or a present password.
pub(crate) fn basic_authorization(url: &url::Url) -> Option<String> {
    sdk_url::basic_authorization(url.username(), url.password(), Userinfo::Utf8)
}
