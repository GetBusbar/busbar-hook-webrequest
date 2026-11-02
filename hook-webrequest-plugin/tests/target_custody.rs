// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Initialized owner-byte custody through the current SDK test-kit observer.

#[cfg(target_os = "linux")]
use busbar_hook_webrequest::config;
use busbar_test_kit::alloc_counter::Counting;
#[cfg(target_os = "linux")]
use busbar_test_kit::alloc_counter::{watch_initialized_payload, InitializedPayloadProbe};

#[global_allocator]
static ALLOCATOR: Counting = Counting::new();

#[cfg(target_os = "linux")]
#[test]
fn retired_targets_wipe_each_owned_url_serialization() {
    // SAFETY: all registered URLs stay initialized, exclusively owned, and on this thread
    // until each is dropped below. Only each full serialization's initialized prefix is named.
    let probe = unsafe { InitializedPayloadProbe::start().expect("Linux memory observer") };
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
        unsafe { watch_initialized_payload(bytes) };
    }
    drop(updated);
    drop(clone);
    drop(target);
    let observed = probe.finish();
    assert!(!observed.reentered, "{observed:?}");
    assert_eq!(observed.payloads.len(), registered);
    for payload in observed.payloads {
        assert!(payload.freed, "{payload:?}");
        assert!(!payload.reallocated, "{payload:?}");
        assert!(payload.complete_read, "{payload:?}");
        assert_eq!(payload.bytes_read, payload.len, "{payload:?}");
        assert!(payload.read_error.is_none(), "{payload:?}");
        assert!(payload.wiped, "{payload:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn the_initialized_payload_observer_detects_an_unwiped_control() {
    // SAFETY: this String is exclusively owned, initialized and dropped on this thread.
    let probe = unsafe { InitializedPayloadProbe::start().expect("Linux memory observer") };
    let control = String::from("unwiped-control-canary");
    // SAFETY: registers only the String's initialized allocation prefix at its base.
    unsafe { watch_initialized_payload(control.as_bytes()) };
    drop(control);
    let observed = probe.finish();
    assert!(!observed.reentered, "{observed:?}");
    assert!(!observed.payloads.is_empty());
    for payload in observed.payloads {
        assert!(payload.freed && payload.complete_read, "{payload:?}");
        assert!(payload.read_error.is_none(), "{payload:?}");
        assert!(
            !payload.wiped,
            "the negative control was not detected: {payload:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../../hook-webrequest/src/owners.rs"]
mod owners;

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
        let probe = unsafe { InitializedPayloadProbe::start().expect("Linux memory observer") };
        for bytes in [
            response.reason.as_ref().unwrap().as_slice(),
            response.fields[0].0.as_slice(),
            response.fields[0].1.as_slice(),
            response.body.as_slice(),
        ] {
            // SAFETY: every slice is the complete initialized prefix at its owned allocation base.
            unsafe { watch_initialized_payload(bytes) };
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
fn assert_wiped(observed: busbar_test_kit::alloc_counter::PayloadObservations, expected: usize) {
    assert!(!observed.reentered, "{observed:?}");
    assert_eq!(observed.payloads.len(), expected);
    for payload in observed.payloads {
        assert!(
            payload.freed && payload.complete_read && payload.wiped,
            "{payload:?}"
        );
        assert!(
            !payload.reallocated && payload.read_error.is_none(),
            "{payload:?}"
        );
        assert_eq!(payload.bytes_read, payload.len);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn lossy_phrases_and_owned_failure_echoes_wipe_before_deallocation() {
    use busbar_contract::abi::sdk::conn::ConnFailure;
    use busbar_contract::abi::sdk::exchange::OpFailure;
    // SAFETY: all registered guards stay exclusively owned and drop on this synchronous thread.
    let probe = unsafe { InitializedPayloadProbe::start().expect("Linux memory observer") };
    let phrase = owners::Phrase::new(b"denied PASSWORDCANARY \xff");
    // SAFETY: invalid UTF-8 forces an owned String; Deref names its complete initialized prefix.
    unsafe { watch_initialized_payload(phrase.as_bytes()) };
    drop(phrase);
    let text = owners::Text("raw URL https://u:RAWCANARY@receiver.example/key".to_string());
    // SAFETY: Text owns this complete initialized String allocation until dropped below.
    unsafe { watch_initialized_payload(text.as_bytes()) };
    drop(text);
    for cause in [
        OpFailure::Conn(ConnFailure::Failed("FAILED-CANARY".to_string())),
        OpFailure::Conn(ConnFailure::Refused("REFUSED-CANARY".to_string())),
        OpFailure::Unbuilt("UNBUILT-CANARY".to_string()),
    ] {
        let cause = owners::Failure(cause);
        let bytes = match &cause.0 {
            OpFailure::Unbuilt(text)
            | OpFailure::Conn(ConnFailure::Failed(text) | ConnFailure::Refused(text)) => {
                text.as_bytes()
            }
            _ => unreachable!(),
        };
        // SAFETY: the guarded cause owns each String allocation, not a formatted scratch copy.
        unsafe { watch_initialized_payload(bytes) };
        drop(cause);
    }
    assert_wiped(probe.finish(), 5);
}
