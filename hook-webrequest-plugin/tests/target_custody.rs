// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Initialized owner-byte custody observed immediately before actual System deallocation.

#[cfg(target_os = "linux")]
use busbar_hook_webrequest::config;
#[cfg(target_os = "linux")]
use custody::CustodyAllocator;
#[cfg(target_os = "linux")]
use custody::{stop_watching, watch_allocations_of, watch_owner_prefix, OwnerProbe};

#[cfg(target_os = "linux")]
#[global_allocator]
static ALLOCATOR: CustodyAllocator = CustodyAllocator::new();

#[cfg(target_os = "linux")]
#[test]
fn retired_targets_wipe_each_owned_url_serialization() {
    // SAFETY: all registered URLs stay initialized, exclusively owned, and on this thread
    // until each is dropped below. Only each full serialization's initialized prefix is named.
    let probe = unsafe { OwnerProbe::start().expect("Linux memory observer") };
    let target = config::open(
        br#"{"url":"https://operator:password-canary@receiver.example/private-canary?key=query-canary"}"#,
    ).unwrap();
    let clone = target.clone();
    let settings = serde_json::json!({"timeout_ms":777});
    let updated = config::configure(&target, settings.as_object().unwrap())
        .unwrap()
        .unwrap();
    let mut registered = 0;
    for target in [&target, &clone, &updated] {
        let bytes = target.url.as_str().as_bytes();
        registered += 1;
        // SAFETY: Url::as_str names the entire owned serialization, not spare capacity or
        // object representation. Its owner stays on this thread until the explicit drops.
        unsafe { watch_owner_prefix(bytes) };
        registered += 1;
        // SAFETY: the actual Target also exclusively owns the initialized raw URL spelling.
        unsafe { watch_owner_prefix(target.url_text.as_bytes()) };
    }
    drop(updated);
    drop(clone);
    drop(target);
    let observed = probe.finish();
    assert_eq!(observed.payloads.len(), registered);
    for payload in observed.payloads {
        assert!(payload.freed, "{payload:?}");
        assert!(!payload.reallocated, "{payload:?}");
        assert_eq!(payload.bytes_read, payload.len, "{payload:?}");
        assert!(payload.wiped, "{payload:?}");
    }
}

/// A `configure` that moves the url supersedes the merge's copy of the old target: both of its
/// owned serializations of the old url (the parsed url and the raw text) are wiped when replaced.
#[cfg(target_os = "linux")]
#[test]
fn a_url_replacing_configure_wipes_the_superseded_url_serializations() {
    const LEN: usize = 111;
    let prefix = "https://operator:password-canary@receiver.example/";
    let old = format!("{prefix}{}", "p".repeat(LEN - prefix.len()));
    let target = config::open(format!(r#"{{"url":"{old}"}}"#).as_bytes()).unwrap();
    assert_eq!(
        (target.url.as_str(), target.url_text.as_str()),
        (&*old, &*old)
    );
    // Every allocation the merge makes for the short new url stays well under LEN bytes, so the
    // allocations of exactly LEN bytes are the merge's clone of the old url and of its text.
    let settings = serde_json::json!({"url": "https://next.example/"});
    let settings = settings.as_object().unwrap();
    // SAFETY: only allocations made on this thread during the merge below are registered: the two
    // String clones of the old url, each fully initialized by its copy and dropped in the merge.
    let probe = unsafe { OwnerProbe::start().expect("Linux memory observer") };
    // SAFETY: as above; every LEN-byte allocation the merge makes is a fully copied clone.
    unsafe { watch_allocations_of(LEN) };
    let updated = config::configure(&target, settings).unwrap().unwrap();
    stop_watching();
    let observed = probe.finish();
    assert_eq!(updated.url.as_str(), "https://next.example/");
    assert_eq!(updated.url_text, "https://next.example/");
    assert_wiped(observed, 2);
    drop(updated);
    drop(target);
}

#[cfg(target_os = "linux")]
#[test]
fn the_initialized_payload_observer_detects_an_unwiped_control() {
    // SAFETY: this String is exclusively owned, initialized and dropped on this thread.
    let probe = unsafe { OwnerProbe::start().expect("Linux memory observer") };
    let control = String::from("unwiped-control-canary");
    // SAFETY: registers only the String's initialized allocation prefix at its base.
    unsafe { watch_owner_prefix(control.as_bytes()) };
    drop(control);
    let observed = probe.finish();
    assert!(!observed.payloads.is_empty());
    for payload in observed.payloads {
        assert!(
            payload.freed && payload.bytes_read == payload.len,
            "{payload:?}"
        );
        assert!(
            !payload.wiped,
            "the negative control was not detected: {payload:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn the_forwarders_response_reader_wipes_its_initialized_echo_buffers_on_return_and_unwind() {
    use busbar_contract::abi::sdk::exchange::ExchangeResponse;
    for unwind in [false, true] {
        let response = ExchangeResponse {
            status: 503,
            reason: Some(b"denied PASSWORDCANARY".to_vec()),
            fields: vec![(b"x-token".to_vec(), b"FIELDCANARY".to_vec())],
            body: b"BODYCANARY".to_vec(),
        };
        // SAFETY: each response allocation stays exclusively owned on this thread through the
        // real reader's return or unwind. Only initialized allocation prefixes are registered.
        let probe = unsafe { OwnerProbe::start().expect("Linux memory observer") };
        for bytes in [
            response.reason.as_ref().unwrap().as_slice(),
            response.fields[0].0.as_slice(),
            response.fields[0].1.as_slice(),
            response.body.as_slice(),
        ] {
            // SAFETY: every slice is the complete initialized prefix at its owned allocation base.
            unsafe { watch_owner_prefix(bytes) };
        }
        let outcome = std::panic::catch_unwind(|| {
            busbar_hook_webrequest::reply::read_response(response, |response| {
                assert_eq!(response.status, 503);
                assert!(response
                    .reason
                    .as_deref()
                    .unwrap()
                    .ends_with(b"PASSWORDCANARY"));
                assert!(!unwind, "exercise the response owner's unwind path");
            })
        });
        assert_eq!(outcome.is_err(), unwind);
        assert_wiped(probe.finish(), 4);
    }
}

#[cfg(target_os = "linux")]
fn assert_wiped(observed: custody::Observations, expected: usize) {
    assert_eq!(observed.payloads.len(), expected);
    for payload in observed.payloads {
        assert!(
            payload.freed && payload.bytes_read == payload.len && payload.wiped,
            "{payload:?}"
        );
        assert!(!payload.reallocated, "{payload:?}");
    }
}

#[cfg(target_os = "linux")]
#[path = "../../hook-webrequest/src/tests/support/custody.rs"]
mod custody;
