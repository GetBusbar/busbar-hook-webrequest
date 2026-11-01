//! The door's per-op choices that need no host: which target a resumed op runs against.

use std::sync::Arc;

use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::hook::Hook;

use crate::config;
use crate::door::{transport_failure, Forwarder, Live};

const A_SECRET: &str = "AKEY-aaaa1111";
const B_SECRET: &str = "BKEY-bbbb2222";

fn forwarder(url: &str) -> Forwarder {
    let target = config::open(format!(r#"{{"url": "{url}"}}"#).as_bytes()).expect("opens");
    Forwarder::over(Live::new(target))
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

fn configure(f: &Forwarder, url: &str) {
    let settings = serde_json::json!({ "url": url });
    assert!(
        f.configure(settings.as_object().unwrap(), 2).is_ok(),
        "acked"
    );
}

#[test]
fn concurrent_partial_configures_preserve_both_updates() {
    let f = forwarder("http://127.0.0.1:9001/a");
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let url = scope.spawn(|| {
            let settings = serde_json::json!({"url":"http://127.0.0.2:9002/b"});
            start.wait();
            assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
        });
        let timeout = scope.spawn(|| {
            let settings = serde_json::json!({"timeout_ms":777});
            start.wait();
            assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
        });
        url.join().unwrap();
        timeout.join().unwrap();
    });
    let live = f.live();
    assert_eq!(live.url.as_str(), "http://127.0.0.2:9002/b");
    assert_eq!(live.timeout, std::time::Duration::from_millis(777));
}

#[test]
fn configuration_checkpoints_preserve_normalized_url_timeout_and_partial_semantics() {
    let initial = "http://user:secret@127.0.0.1:9001/first";
    let f = forwarder(initial);
    let push = |settings: serde_json::Value, version| {
        f.configure_checkpoint(settings.as_object().unwrap(), version)
            .unwrap()
            .unwrap()
    };
    let first = push(serde_json::json!({"timeout_ms": 777}), 2);
    assert_eq!((first.revision, first.settings_version), (1, 2));
    let second = push(
        serde_json::json!({"url": "http://next:credential@127.0.0.2:9002/second"}),
        2,
    );
    assert_eq!((second.revision, second.settings_version), (2, 2));
    let empty = push(serde_json::json!({}), 3);
    let null = push(serde_json::json!({"timeout_ms": null}), 3);
    assert_eq!(empty.settings(), null.settings());
    assert_eq!((null.revision, null.settings_version), (4, 3));
    let stale = push(
        serde_json::json!({"url": false, "timeout_ms": "invalid"}),
        1,
    );
    assert_eq!((stale.revision, stale.settings_version), (4, 3));
    assert_eq!(stale.settings(), null.settings());
    assert!(f
        .configure_checkpoint(
            serde_json::json!({"timeout_ms": "invalid"})
                .as_object()
                .unwrap(),
            4
        )
        .is_err());
    let current = f.live();
    let restored = forwarder(initial);
    let settings: serde_json::Value = serde_json::from_slice(null.settings()).unwrap();
    restored
        .configure(settings.as_object().unwrap(), null.settings_version)
        .unwrap();
    assert_eq!(restored.live().url, current.url);
    assert_eq!(
        restored.live().timeout,
        std::time::Duration::from_millis(777)
    );
    assert!(!format!("{null:?}").contains("credential"));
}

#[test]
fn concurrent_equal_version_checkpoints_capture_the_complete_serialized_state() {
    let f = forwarder("http://127.0.0.1:9001/first");
    let start = std::sync::Barrier::new(2);
    let (url, timeout) = std::thread::scope(|scope| {
        let url = scope.spawn(|| {
            start.wait();
            f.configure_checkpoint(
                serde_json::json!({"url":"http://127.0.0.2:9002/second"})
                    .as_object()
                    .unwrap(),
                2,
            )
            .unwrap()
            .unwrap()
        });
        let timeout = scope.spawn(|| {
            start.wait();
            f.configure_checkpoint(
                serde_json::json!({"timeout_ms":777}).as_object().unwrap(),
                2,
            )
            .unwrap()
            .unwrap()
        });
        (url.join().unwrap(), timeout.join().unwrap())
    });
    assert_ne!(url.revision, timeout.revision);
    let latest = if url.revision > timeout.revision {
        url
    } else {
        timeout
    };
    let restored = forwarder("http://127.0.0.1:9001/first");
    let settings: serde_json::Value = serde_json::from_slice(latest.settings()).unwrap();
    restored
        .configure(settings.as_object().unwrap(), latest.settings_version)
        .unwrap();
    assert_eq!(restored.live().url.as_str(), "http://127.0.0.2:9002/second");
    assert_eq!(
        restored.live().timeout,
        std::time::Duration::from_millis(777)
    );
}

fn current_live(f: &Forwarder) -> Arc<Live> {
    f.live()
}

// This wrapper only exposes a Weak witness for the real Forwarder's state. The actual
// decide path and generic SDK CANCEL are entered through the existing safe test door.
mod lifecycle {
    use super::*;
    use busbar_contract::abi::hook::{DecideIn, DecideOut, Ops};
    use busbar_contract::abi::mechanism::call::{OutHead, Outcome, FLAG_RESUME};
    use busbar_contract::abi::mechanism::lifecycle::{CancelIn, CancelOut, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::exchange::Op;
    use busbar_contract::abi::sdk::hook::{Decoded, HookOpen, Verdict};
    use busbar_test_kit::test_support::{
        fake::FakeHost, far::Far, reply, test_in::TestIn, DoorView,
    };
    use std::cell::RefCell;
    use std::task::Poll;

    thread_local! {
        static OPENING: RefCell<Option<Arc<Forwarder>>> = const { RefCell::new(None) };
    }
    struct Watched(Arc<Forwarder>);
    impl Hook for Watched {
        fn decide(&self, input: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
            self.0.decide(input, op)
        }
    }
    struct OpenWatched;
    impl HookOpen for OpenWatched {
        fn open(_: &str) -> Result<Box<dyn Hook>, String> {
            Ok(Box::new(Watched(
                OPENING.with(|opening| opening.borrow_mut().take().unwrap()),
            )))
        }
    }
    busbar_contract::hook_door! {
        open: OpenWatched,
        statement: busbar_contract::abi::sdk::door::statement("target-custody", "0", 64),
    }

    #[test]
    fn cancel_retires_the_old_target_without_reusing_its_high_slot() {
        let _far = Far::answering(200, b"{}");
        let host = FakeHost::new().far();
        let door = DoorView::of(MACRO_DOOR);
        for slot in 40..64 {
            let f = Arc::new(forwarder(&format!("http://127.0.0.1:9001/{A_SECRET}")));
            let old = Arc::downgrade(&current_live(&f));
            OPENING.with(|opening| *opening.borrow_mut() = Some(Arc::clone(&f)));
            let mut opened = reply::call_hosted_in(
                door.op::<Ops>(|ops| &ops.head.open).unwrap(),
                None,
                &host.lend_in(TestIn::<OpenIn>::new()),
                OpenOut::default(),
            );
            assert_eq!(opened.outcome, Outcome::Ready);
            let instance = opened.take_instance().unwrap();
            let input = TestIn::<DecideIn>::new().set(|i| &i.head.ticket, ticket(slot));
            let pending = reply::call_in(
                door.op::<Ops>(|ops| &ops.decide).unwrap(),
                Some(&instance),
                &input,
                DecideOut::default(),
            );
            assert_eq!(pending.outcome, Outcome::Pending);
            configure(&f, &format!("http://127.0.0.2:9002/{B_SECRET}"));
            assert!(
                old.upgrade().is_some(),
                "pending operation retains its original target"
            );
            let cancelled = reply::call_in(
                door.op::<Ops>(|ops| &ops.head.cancel).unwrap(),
                Some(&instance),
                &TestIn::<CancelIn>::new().set(|i| &i.ticket, ticket(slot)),
                CancelOut::default(),
            );
            assert_eq!(cancelled.outcome, Outcome::Ready);
            assert_eq!(
                cancelled.out.disposition,
                busbar_contract::abi::hook::cancel::ABORTED
            );
            let retired = old.upgrade().is_none();
            // Clean up even on the regression side before reporting the missed retirement.
            let closed = reply::close_in(
                door.op::<Ops>(|ops| &ops.head.close).unwrap(),
                instance,
                &TestIn::<busbar_contract::abi::mechanism::call::InHead>::new(),
                OutHead::default(),
            );
            assert_eq!(closed.outcome, Outcome::Ready);
            assert!(
                retired,
                "CANCEL retained the old target on unused slot {slot}"
            );
        }
    }

    #[test]
    fn pending_configuration_keeps_the_original_target_until_completion() {
        let far = Far::answering(200, b"{}");
        let host = FakeHost::new().far();
        let door = DoorView::of(MACRO_DOOR);
        let f = Arc::new(forwarder(&format!("http://127.0.0.1:9001/{A_SECRET}")));
        let old = Arc::downgrade(&current_live(&f));
        OPENING.with(|opening| *opening.borrow_mut() = Some(Arc::clone(&f)));
        let mut opened = reply::call_hosted_in(
            door.op::<Ops>(|ops| &ops.head.open).unwrap(),
            None,
            &host.lend_in(TestIn::<OpenIn>::new()),
            OpenOut::default(),
        );
        assert_eq!(opened.outcome, Outcome::Ready);
        let instance = opened.take_instance().unwrap();
        let run = |ticket, flags| {
            reply::call_in(
                door.op::<Ops>(|ops| &ops.decide).unwrap(),
                Some(&instance),
                &TestIn::<DecideIn>::new()
                    .set(|i| &i.head.ticket, ticket)
                    .set(|i| &i.head.flags, flags),
                DecideOut::default(),
            )
        };
        assert_eq!(run(ticket(7), 0).outcome, Outcome::Pending);
        configure(&f, &format!("http://127.0.0.2:9002/{B_SECRET}"));
        let original = old.upgrade().expect("pending retains old target");
        let failure = ConnFailure::Failed(format!("reset by http://127.0.0.1:9001/{A_SECRET}"));
        assert!(!transport_failure(&original, &failure).contains(A_SECRET));
        drop(original);
        loop {
            let answer = run(ticket(7), FLAG_RESUME);
            if answer.outcome != Outcome::Pending {
                assert_eq!(answer.outcome, Outcome::Ready);
                break;
            }
        }
        assert!(
            old.upgrade().is_none(),
            "completion releases its original target"
        );
        let next = Ticket {
            slot: 7,
            generation: 2,
        };
        let mut flags = 0;
        loop {
            let answer = run(next, flags);
            if answer.outcome != Outcome::Pending {
                assert_eq!(answer.outcome, Outcome::Ready);
                break;
            }
            flags = FLAG_RESUME;
        }
        let sent = far.sent();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].target, format!("/{A_SECRET}").as_bytes());
        assert_eq!(sent[1].target, format!("/{B_SECRET}").as_bytes());
        let closed = reply::close_in(
            door.op::<Ops>(|ops| &ops.head.close).unwrap(),
            instance,
            &TestIn::<busbar_contract::abi::mechanism::call::InHead>::new(),
            OutHead::default(),
        );
        assert_eq!(closed.outcome, Outcome::Ready);
    }
}
