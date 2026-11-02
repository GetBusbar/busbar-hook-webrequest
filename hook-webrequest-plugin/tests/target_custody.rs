// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Initialized owner-byte custody observed immediately before actual System deallocation.

#[cfg(target_os = "linux")]
use busbar_hook_webrequest::config;
#[cfg(target_os = "linux")]
use custody::Counting;
#[cfg(target_os = "linux")]
use custody::{watch_initialized_payload, InitializedPayloadProbe};

#[cfg(target_os = "linux")]
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
    assert_eq!(observed.payloads.len(), registered);
    for payload in observed.payloads {
        assert!(payload.freed, "{payload:?}");
        assert!(!payload.reallocated, "{payload:?}");
        assert_eq!(payload.bytes_read, payload.len, "{payload:?}");
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
fn assert_wiped(observed: custody::PayloadObservations, expected: usize) {
    assert_eq!(observed.payloads.len(), expected);
    for payload in observed.payloads {
        assert!(
            payload.freed && payload.bytes_read == payload.len && payload.wiped,
            "{payload:?}"
        );
        assert!(!payload.reallocated, "{payload:?}");
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

// This test binary observes only explicitly registered initialized prefixes of its own
// exclusively owned allocations. It implements no plugin or host behavior.
#[cfg(target_os = "linux")]
mod custody {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    #[derive(Clone, Copy, Debug, Default)]
    pub struct Payload {
        address: usize,
        pub len: usize,
        pub freed: bool,
        pub reallocated: bool,
        pub bytes_read: usize,
        pub wiped: bool,
    }
    #[derive(Clone, Copy)]
    struct State {
        active: bool,
        entries: [Payload; 32],
        used: usize,
    }
    thread_local! {
        static STATE: Cell<State> = const { Cell::new(State {
            active: false,
            entries: [Payload { address: 0, len: 0, freed: false, reallocated: false,
                bytes_read: 0, wiped: false }; 32],
            used: 0,
        }) };
    }

    #[derive(Default)]
    pub struct Counting;
    impl Counting {
        pub const fn new() -> Self {
            Self
        }
    }

    // SAFETY: every allocation operation delegates to System with its original arguments.
    // Observation performs no allocation and reads only initialized bytes registered by an
    // exclusive owner on this thread before System releases its live allocation.
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: GlobalAlloc caller supplies a valid layout.
            unsafe { System.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            // SAFETY: ptr still names its live allocation until System.dealloc below.
            unsafe { observe(ptr, false) };
            // SAFETY: forwards the original live allocation and layout unchanged.
            unsafe { System.dealloc(ptr, layout) };
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            // SAFETY: ptr still names its live allocation until System.realloc below.
            unsafe { observe(ptr, true) };
            // SAFETY: forwards the allocator's original valid arguments.
            unsafe { System.realloc(ptr, layout, size) }
        }
    }

    unsafe fn observe(ptr: *mut u8, realloc: bool) {
        let _ = STATE.try_with(|cell| {
            let mut state = cell.get();
            if !state.active {
                return;
            }
            for entry in &mut state.entries[..state.used] {
                if entry.address != ptr as usize || entry.freed || entry.reallocated {
                    continue;
                }
                // SAFETY: watch_initialized_payload's contract guarantees this allocation's
                // initialized prefix remains exclusively owned until this deallocation hook.
                entry.wiped = true;
                for offset in 0..entry.len {
                    // SAFETY: offset stays inside the registered initialized allocation prefix.
                    entry.wiped &= unsafe { ptr.add(offset).read_volatile() } == 0;
                    entry.bytes_read += 1;
                }
                entry.freed = !realloc;
                entry.reallocated = realloc;
            }
            cell.set(state);
        });
    }

    pub struct InitializedPayloadProbe;
    #[derive(Debug)]
    pub struct PayloadObservations {
        pub payloads: Vec<Payload>,
    }
    impl InitializedPayloadProbe {
        /// # Safety
        /// Registrations must uphold watch_initialized_payload's exclusive owner contract.
        pub unsafe fn start() -> Result<Self, &'static str> {
            STATE.with(|cell| {
                let mut state = cell.get();
                if state.active {
                    return Err("nested custody probe");
                }
                state.active = true;
                state.used = 0;
                cell.set(state);
                Ok(Self)
            })
        }
        pub fn finish(self) -> PayloadObservations {
            let state = STATE.with(|cell| {
                let mut state = cell.get();
                state.active = false;
                cell.set(state);
                state
            });
            PayloadObservations {
                payloads: state.entries[..state.used].to_vec(),
            }
        }
    }
    impl Drop for InitializedPayloadProbe {
        fn drop(&mut self) {
            let _ = STATE.try_with(|cell| {
                let mut s = cell.get();
                s.active = false;
                cell.set(s);
            });
        }
    }

    /// # Safety
    /// Bytes names the complete initialized prefix at an owned allocation base.
    /// The owner must stay exclusively on this thread until it drops or reallocates.
    pub unsafe fn watch_initialized_payload(bytes: &[u8]) {
        STATE.with(|cell| {
            let mut state = cell.get();
            assert!(state.active && state.used < state.entries.len());
            state.entries[state.used] = Payload {
                address: bytes.as_ptr() as usize,
                len: bytes.len(),
                ..Payload::default()
            };
            state.used += 1;
            cell.set(state);
        });
    }
}
