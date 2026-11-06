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
    let mut fields = Vec::with_capacity(3);
    if let Some(auth) = basic_authorization(url) {
        fields.push((b"authorization".to_vec(), auth.into_bytes()));
    }
    fields.push((b"content-type".to_vec(), b"application/json".to_vec()));
    fields.push((b"accept".to_vec(), b"*/*".to_vec()));
    Request {
        method: b"POST".to_vec(),
        target: if path.is_empty() {
            b"/"
        } else {
            path.as_bytes()
        }
        .to_vec(),
        fields,
        body,
        timeout_ms: u64::try_from(target.timeout.as_millis()).unwrap_or(u64::MAX),
    }
}

/// `Basic base64(user:pass)` from the validated URL's percent-decoded UTF-8 userinfo. Target
/// validation refuses invalid decoded text before this function runs, so no credential is silently
/// omitted or shortened. A header is sent for a non-empty username or a present password.
pub(crate) fn basic_authorization(url: &url::Url) -> Option<String> {
    sdk_url::basic_authorization(url.username(), url.password(), Userinfo::Utf8)
}
