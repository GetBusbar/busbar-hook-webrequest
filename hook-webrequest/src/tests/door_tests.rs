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

/// Q-R2b: the reason phrase of an error status is scrubbed of the target's secret parts before it
/// is capped and escaped, as a transport failure is.
#[test]
fn an_error_status_phrase_is_scrubbed_of_the_targets_secrets() {
    let f = forwarder(&format!("http://127.0.0.1:9001/{A_SECRET}?tok={B_SECRET}"));
    let live = f.entry_live(ticket(1));
    let phrase = format!("denied for /{A_SECRET}?tok={B_SECRET}");
    let shown = crate::door::status_phrase(&live, Some(&phrase)).expect("a phrase");
    let text = crate::reply::error_status(500, Some(&shown));
    for secret in [A_SECRET, B_SECRET] {
        assert!(
            !text.contains(secret),
            "{secret} reached the status text: {text}"
        );
    }
    assert!(text.contains("denied for"), "{text}");
    assert_eq!(crate::door::status_phrase(&live, None), None);
}

/// R2-1: `configure` keeps the highest applied version; an older push is ACKed and NOT applied.
#[test]
fn a_stale_configure_version_is_acked_and_not_applied() {
    let f = forwarder("http://127.0.0.1:9001/a");
    let push = |url: &str, version| {
        let settings = serde_json::json!({ "url": url });
        f.configure(settings.as_object().unwrap(), version)
    };
    assert!(push("http://127.0.0.2:9008/v8", 8));
    assert!(push("http://127.0.0.3:9007/v7", 7), "a stale push is ACKed");
    assert_eq!(
        f.entry_live(ticket(1)).origin,
        "http://127.0.0.2:9008",
        "v8's settings stay live"
    );
    assert!(push("http://127.0.0.4:9009/v9", 9));
    assert_eq!(f.entry_live(ticket(2)).origin, "http://127.0.0.4:9009");
}

/// A stale push is ACKed and not applied even when it would not validate: the version check runs
/// before validation, so it is neither NACKed nor logged as a refusal.
#[test]
fn a_stale_push_that_would_not_validate_is_still_acked() {
    let f = forwarder("http://127.0.0.1:9001/a");
    let push = |url: &str, version| {
        let settings = serde_json::json!({ "url": url });
        f.configure(settings.as_object().unwrap(), version)
    };
    assert!(push("http://127.0.0.2:9008/v8", 8));
    assert!(push("ftp://not-allowed.example/x", 7), "stale: ACKed");
    assert_eq!(f.entry_live(ticket(1)).origin, "http://127.0.0.2:9008");
    assert!(!push("ftp://not-allowed.example/x", 9), "current: NACKed");
}
