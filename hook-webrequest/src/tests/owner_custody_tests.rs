//! Observe initialized allocations made by the real door's phrase and transport-error paths.

use std::cell::Cell;

use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::exchange::ExchangeResponse;

use crate::door::{read_head, transport_failure, Live};

type ReplyReader = fn(u16, Option<&str>, &[u8]) -> Result<serde_json::Value, String>;

#[path = "support/custody.rs"]
#[allow(dead_code)]
pub(super) mod custody;

#[global_allocator]
static ALLOCATOR: custody::CustodyAllocator = custody::CustodyAllocator::new();

thread_local! {
    static OBSERVING: Cell<bool> = const { Cell::new(false) };
}

/// Called only after an actual production owner has initialized its complete String.
pub(crate) fn observe(bytes: &[u8]) {
    if OBSERVING.with(Cell::get) {
        // SAFETY: callers supply a complete initialized owner prefix, retained on this synchronous
        // thread until that owner drops. No spare capacity or object representation is read.
        unsafe { custody::watch_owner_prefix(bytes) };
    }
}

struct Observing;
impl Drop for Observing {
    fn drop(&mut self) {
        OBSERVING.with(|active| active.set(false));
    }
}

fn observed(run: impl FnOnce()) -> custody::Observations {
    // SAFETY: registration is restricted to the synchronous production owners described above.
    let probe = unsafe { custody::OwnerProbe::start().expect("Linux owner observer") };
    OBSERVING.with(|active| active.set(true));
    let watching = Observing;
    run();
    drop(watching);
    probe.finish()
}

fn assert_one_wiped(observations: custody::Observations) {
    // Exactly one initialized owned phrase/formatted failure is constructed by each call. A
    // mutation bypassing its guard removes its registration and therefore fails this assertion.
    assert_eq!(observations.payloads.len(), 1, "{observations:?}");
    let payload = &observations.payloads[0];
    assert!(payload.len > 0);
    assert!(payload.freed && payload.wiped, "{payload:?}");
    assert!(!payload.reallocated, "{payload:?}");
    assert_eq!(payload.bytes_read, payload.len, "{payload:?}");
}

fn live() -> std::sync::Arc<Live> {
    Live::new(
        crate::config::open(br#"{"url":"https://svc:PASSWORDCANARY@hooks.example/key"}"#).unwrap(),
    )
}

#[test]
fn the_real_head_reader_wipes_its_lossy_phrase_on_return_and_unwind() {
    for unwind in [false, true] {
        let live = live();
        let response = ExchangeResponse {
            status: 503,
            reason: Some(b"denied PASSWORDCANARY \xff".to_vec()),
            ..ExchangeResponse::default()
        };
        let observations = observed(|| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let reader: ReplyReader = if unwind {
                    |_: u16, _: Option<&str>, _: &[u8]| -> Result<serde_json::Value, String> {
                        panic!("exercise the real head reader's unwind path")
                    }
                } else {
                    crate::reply::interpret
                };
                read_head(&live, reader, &response, &[])
            }));
            assert_eq!(result.is_err(), unwind);
            if let Ok(result) = result {
                let error = result.unwrap_err();
                assert!(!error.contains("PASSWORDCANARY"), "{error}");
            }
        });
        assert_one_wiped(observations);
    }
}

#[test]
fn the_real_transport_error_formatter_wipes_its_unscrubbed_text() {
    let live = live();
    for cause in [
        ConnFailure::Failed("denied PASSWORDCANARY".to_owned()),
        ConnFailure::Refused("refused PASSWORDCANARY".to_owned()),
    ] {
        let observations = observed(|| {
            let error = transport_failure(&live, &cause);
            assert!(!error.contains("PASSWORDCANARY"), "{error}");
        });
        assert_one_wiped(observations);
    }
}

#[test]
fn the_actual_failure_owner_wipes_each_owned_cause() {
    use busbar_contract::abi::sdk::exchange::OpFailure;
    for cause in [
        OpFailure::Conn(ConnFailure::Failed("FAILED-CANARY".to_owned())),
        OpFailure::Conn(ConnFailure::Refused("REFUSED-CANARY".to_owned())),
        OpFailure::Unbuilt("UNBUILT-CANARY".to_owned()),
    ] {
        let observations = observed(|| {
            let cause = crate::owners::Failure(cause);
            match &cause.0 {
                OpFailure::Unbuilt(text)
                | OpFailure::Conn(ConnFailure::Failed(text) | ConnFailure::Refused(text)) => {
                    observe(text.as_bytes());
                }
                _ => unreachable!(),
            }
            drop(cause);
        });
        assert_one_wiped(observations);
    }
}

pub(crate) fn observe_failure(cause: &busbar_contract::abi::sdk::exchange::OpFailure) {
    use busbar_contract::abi::sdk::exchange::OpFailure;
    match cause {
        OpFailure::Unbuilt(text)
        | OpFailure::Conn(ConnFailure::Failed(text) | ConnFailure::Refused(text)) => {
            observe(text.as_bytes());
        }
        _ => {}
    }
}

/// The real SDK constructs ExchangeFailure; its private fields are never forged by this fixture.
fn builder_failure() -> busbar_contract::abi::sdk::exchange::ExchangeFailure {
    use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::{slot, ValidateIn};
    use busbar_contract::abi::mechanism::ticket::HostTables;
    use busbar_contract::abi::sdk::conn::Host;
    use busbar_contract::abi::sdk::door::{blank_out, Entry};
    use busbar_contract::abi::sdk::exchange::{ExchangeFailure, Op};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
    use std::cell::RefCell;
    use std::task::Poll;

    thread_local! {
        static FAILURE: RefCell<Option<ExchangeFailure>> = const { RefCell::new(None) };
    }
    struct Builder;
    impl SafeSlot for Builder {
        type Kind = busbar_contract::plugin::markers::HookKind;
        type In = ValidateIn;
        type Out = OutHead;
        type State = ();

        fn call(
            instance: Instance<'_, (), busbar_contract::plugin::markers::HookKind>,
            _: Lent<'_, ValidateIn>,
            _: Out<'_, OutHead>,
        ) -> Outcome {
            // SAFETY: HostTables consists of integer handles, optional callbacks and raw pointers;
            // all-zero means no context, callbacks or nested tables. No connector is called: the
            // request builder returns its error before the exchange attempts any host operation.
            let mut tables: HostTables = unsafe { std::mem::zeroed() };
            tables.size = std::mem::size_of::<HostTables>() as u32;
            // SAFETY: every nested table is NULL and there are no callable function pointers.
            let host = unsafe { Host::test_from_raw(&tables) };
            let op = Op::new(&instance, Some(&host));
            let result = op.exchange_sealed_bounded_with_head(0, None, 1024, false, || {
                Err("UNBUILT-CUSTODY-CANARY".to_owned())
            });
            let Poll::Ready(Err(failure)) = result else {
                panic!("builder failure must be immediate");
            };
            FAILURE.with(|saved| *saved.borrow_mut() = Some(failure));
            Outcome::Ready
        }
    }
    // SAFETY: ValidateIn is a plain ABI record of integer fields and pointers; zeroed pointers
    // denote absent blobs and reason buffer. The exact size and slot are supplied below.
    let mut input: ValidateIn = unsafe { std::mem::zeroed() };
    input.head.size = std::mem::size_of::<ValidateIn>() as u32;
    input.head.op = slot::VALIDATE;
    let mut output = blank_out::<OutHead>();
    // SAFETY: this is a validate call with no instance, no lent memory and private complete ABI
    // records. Safe<Builder> constructs the SDK Instance under the normal entry contract.
    let outcome = unsafe {
        Safe::<Builder>::enter(std::ptr::null_mut(), slot::VALIDATE, &input, &mut output)
    };
    assert_eq!(outcome, Outcome::Ready);
    FAILURE.with(|saved| saved.borrow_mut().take().expect("SDK returned failure"))
}

#[test]
fn the_real_failed_response_reader_wipes_its_cause_on_return_and_unwind() {
    for unwind in [false, true] {
        let failure = builder_failure();
        let observations = observed(|| {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::door::read_failed_response(failure, |failure| {
                    assert!(failure.head().is_none());
                    assert!(!unwind, "exercise failed response reader unwind");
                    let cause = failure.into_failure();
                    assert!(matches!(
                        &cause.0,
                        busbar_contract::abi::sdk::exchange::OpFailure::Unbuilt(text)
                            if text == "UNBUILT-CUSTODY-CANARY"
                    ));
                });
            }));
            assert_eq!(result.is_err(), unwind);
        });
        assert_one_wiped(observations);
    }
}
