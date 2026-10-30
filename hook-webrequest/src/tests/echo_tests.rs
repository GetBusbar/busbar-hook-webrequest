// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Credential-echo canaries (CREDENTIAL-LOCKDOWN H3 and A.3 for this hook): a credential planted in
//! the target URL's userinfo, path and query never reaches a `Debug` rendering or a logged
//! transport failure, even when the host's failure text quotes the URL back.

use crate::config::{self, Target};
use crate::door::{transport_failure, Live};
use crate::wire;
use busbar_contract::abi::sdk::conn::ConnFailure;

const CANARY: &str = "CANARYd41c07";

fn target() -> Target {
    config::open(
        format!(r#"{{"url": "http://svc:{CANARY}@127.0.0.1:9/hook/{CANARY}?token={CANARY}"}}"#)
            .as_bytes(),
    )
    .expect("a loopback sidecar opens")
}

/// The Basic value the userinfo becomes, which must not render either.
fn basic() -> String {
    wire::request(&target(), Vec::new())
        .fields
        .into_iter()
        .find(|(n, _)| *n == "authorization")
        .map(|(_, v)| v)
        .expect("the userinfo becomes an authorization")
}

#[test]
fn debug_of_the_target_and_the_wire_request_carries_no_credential() {
    let t = target();
    let r = wire::request(&t, b"{}".to_vec());
    let token = basic();
    let token = token.trim_start_matches("Basic ");
    for text in [
        format!("{t:?}"),
        format!("{t:#?}"),
        format!("{r:?}"),
        format!("{r:#?}"),
    ] {
        assert!(
            !text.contains(CANARY),
            "Debug carried the credential: {text}"
        );
        assert!(
            !text.contains(token),
            "Debug carried the Basic value: {text}"
        );
    }
    assert!(format!("{t:?}").contains("127.0.0.1"), "the host is kept");
}

#[test]
fn a_transport_failure_never_logs_the_hosts_echo_of_the_url() {
    let t = target();
    for failure in [
        ConnFailure::Failed(format!("error sending request for url ({}): reset", t.url)),
        ConnFailure::Refused(format!(
            "connect to {} refused; path {} query {}",
            t.url.as_str(),
            t.url.path(),
            t.url.query().unwrap_or("")
        )),
    ] {
        let text = transport_failure(&Live::new(t.clone()), &failure);
        assert!(
            !text.contains(CANARY),
            "the logged failure carried the credential: {text}"
        );
        assert!(
            text.starts_with("webrequest: request failed: error sending request: "),
            "1.5.5's prefix is kept: {text}"
        );
    }
}

/// A host that echoes the request's `Authorization` back: neither the header's value nor its
/// base64 token reaches the logged failure.
#[test]
fn a_transport_failure_never_logs_the_hosts_echo_of_the_authorization() {
    let t = target();
    let value = basic();
    let token = value.trim_start_matches("Basic ").to_string();
    for echo in [value.clone(), token.clone()] {
        let failure = ConnFailure::Failed(format!("bad request, headers: authorization: {echo}"));
        let text = transport_failure(&Live::new(t.clone()), &failure);
        assert!(!text.contains(&token), "the failure echoed the token: {text}");
    }
}
