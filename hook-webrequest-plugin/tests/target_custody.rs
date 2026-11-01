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
