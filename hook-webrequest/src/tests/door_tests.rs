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
    assert!(f.configure(settings.as_object().unwrap(), 2), "acked");
}

/// An op that parked against target A is resumed against A even when a `configure` moved the
/// forwarder to B in between: the origin handed to the exchange and the secrets a failure is
/// scrubbed of are A's; a fresh ticket reads B; a finished op leaves nothing behind.
#[test]
fn a_resumed_op_runs_against_the_target_it_parked_on() {
    let f = forwarder(&format!("http://127.0.0.1:9001/{A_SECRET}"));
    let parked = ticket(1);

    let first = f.entry_live(parked);
    assert_eq!(first.origin, "http://127.0.0.1:9001");
    f.park_live(parked, &first);

    configure(&f, &format!("http://127.0.0.2:9002/{B_SECRET}"));

    let resumed = f.entry_live(parked);
    assert_eq!(resumed.origin, "http://127.0.0.1:9001", "A's origin");
    assert!(Arc::ptr_eq(&first, &resumed));
    let failure = ConnFailure::Failed(format!("reset by http://127.0.0.1:9001/{A_SECRET}"));
    let text = transport_failure(&resumed, &failure);
    assert!(!text.contains(A_SECRET), "scrubbed of A's secret: {text}");

    let fresh = f.entry_live(ticket(2));
    assert_eq!(fresh.origin, "http://127.0.0.2:9002", "a fresh op reads B");

    f.release_live(parked);
    assert_eq!(f.entry_live(parked).origin, "http://127.0.0.2:9002");
}

/// A new generation on a recycled slot never inherits a cancelled op's entry, and parking on it
/// drops the cancelled op's entry (the slot's older generation), so entries do not pile up.
#[test]
fn a_recycled_slot_does_not_inherit_a_cancelled_ops_target() {
    let f = forwarder("http://127.0.0.1:9001/a");
    let old = ticket(7);
    let live = f.entry_live(old);
    f.park_live(old, &live);
    configure(&f, "http://127.0.0.2:9002/b");
    let new = Ticket {
        slot: 7,
        generation: 2,
    };
    assert_eq!(f.entry_live(new).origin, "http://127.0.0.2:9002");
    // The new generation's op parks; the cancelled generation's entry goes with it.
    f.park_live(new, &f.entry_live(new));
    assert_eq!(
        f.entry_live(old).origin,
        "http://127.0.0.2:9002",
        "the cancelled op's entry was dropped"
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
            assert!(f.configure(settings.as_object().unwrap(), 2));
        });
        let timeout = scope.spawn(|| {
            let settings = serde_json::json!({"timeout_ms":777});
            start.wait();
            assert!(f.configure(settings.as_object().unwrap(), 2));
        });
        url.join().unwrap();
        timeout.join().unwrap();
    });
    let live = f.entry_live(ticket(1));
    assert_eq!(live.url.as_str(), "http://127.0.0.2:9002/b");
    assert_eq!(live.timeout, std::time::Duration::from_millis(777));
}

fn current_live(f: &Forwarder) -> Arc<Live> {
    f.entry_live(ticket(1))
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
