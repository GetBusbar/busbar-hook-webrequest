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
