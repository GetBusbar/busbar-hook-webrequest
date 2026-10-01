// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the webrequest forwarder on the hook kind's memory ABI (`hook_door!`), on the SDK's safe
//! surface. No `unsafe` here.
//!
//! * `open` / `refresh` — [`crate::config::open`]: the settings to a live [`Target`], refused in
//!   1.5.5's words.
//! * `decide` / `transform` / `notify` — the op's 1.5.5 projection, enveloped ([`crate::wire`]) and
//!   POSTed to the target through the ONE declared need ([`NEEDS`]: outbound, the loopback-allowed
//!   egress class, over the host's `http` framer), one exchange per op. The op answers PENDING while
//!   the exchange pends and is re-entered on the wake (THE DESIGN, the plugin ABI: Ready|Pending(wake)).
//!   The reply means what it meant in 1.5.5 ([`crate::reply`]).
//! * `configure` — [`crate::config::configure`]'s commit-on-ack merge; a NACK is FAILED.
//! * `status` / `describe` — the forwarder's own documents ([`crate::report`]), never the target's.

use std::cell::Cell;
use std::sync::{PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::hook::{Tail, CLASS_GATE, PROMPT_RW, USER_RO};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, BLOB_ABSENT};
use busbar_contract::abi::mechanism::door::Statement;
use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{Op, Request};
use busbar_contract::abi::sdk::hook::{
    lower_decide_reply, lower_transform_reply, statement_with_tail, tail, Decoded, DecodedTap,
    Hook, HookOpen, RewriteVerdict, Verdict,
};
use busbar_contract::hook_wire::{OP_DECIDE, OP_NOTIFY, OP_TRANSFORM};

use crate::config::{self, Target};
use crate::{reply, report, wire};

/// The need index every op's exchange establishes on.
pub const NEED: u32 = 0;

const ABSENT: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// THE ONE NEED: outbound over the host's `http` framer, the target named by the plugin per op
/// (the configured URL's origin, so a `configure` that moves it is honoured), under the
/// loopback-allowed egress class: `https://`, or plaintext to loopback only; the node's own ports,
/// private, link-local and cloud-metadata hosts refused, the address resolved and pinned by the
/// host.
pub const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_LOOPBACK_ALLOWED,
    transport: abi_str("http"),
    auth: ABSENT,
    target_from: ABSENT,
    trust_from: ABSENT,
    details: Blob {
        ptr: std::ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    },
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
}];

/// A gate that may see and rewrite the prompt and read the caller (1.5.5's `needs_prompt: rw`,
/// `needs_user: ro`); the operator's grant decides what it is handed.
const TAIL: &Tail = &tail(CLASS_GATE, PROMPT_RW, USER_RO, &[]);

/// How many ops one instance holds in flight; the host clamps.
pub const MAX_INFLIGHT: u32 = 64;

/// THE STATEMENT: name, version, the hook tail and the one outbound need.
pub const STATEMENT: Statement = Statement {
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..statement_with_tail(
        statement(crate::NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT),
        TAIL,
    )
};

/// The forwarder: the live target, swapped whole by `configure`.
#[derive(Debug)]
pub struct Forwarder {
    live: RwLock<Target>,
}

/// The exchange's request for `body`: the 1.5.5 client's method, target and fields.
fn request(target: &Target, body: Vec<u8>) -> Request {
    let r = wire::request(target, body);
    Request {
        method: r.method.as_bytes().to_vec(),
        target: r.target.into_bytes(),
        fields: r
            .fields
            .into_iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.into_bytes()))
            .collect(),
        body: r.body,
        timeout_ms: u64::try_from(target.timeout.as_millis()).unwrap_or(u64::MAX),
    }
}

impl Forwarder {
    fn target(&self) -> Target {
        self.live
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// POST `op`'s envelope over the projection `payload` builds to the live target: PENDING while
    /// the exchange pends; READY with the reply, or the 1.5.5 failure text.
    fn post(
        &self,
        on: &Op<'_>,
        op: &str,
        payload: impl FnOnce() -> serde_json::Value,
    ) -> Poll<Result<serde_json::Value, String>> {
        let target = self.target();
        let unsendable = Cell::new(None);
        let origin = target.url.origin().ascii_serialization();
        let answer = on.exchange(NEED, Some(&origin), || {
            wire::envelope(op, &payload())
                .map(|body| request(&target, body))
                .map_err(|e| {
                    unsendable.set(Some(e));
                    ConnFailure::Refused(String::new())
                })
        });
        if let Some(e) = unsendable.take() {
            return Poll::Ready(Err(e));
        }
        answer.map(|r| match r {
            Ok(got) => {
                let phrase = got.reason.as_deref().map(String::from_utf8_lossy);
                reply::interpret(got.status, phrase.as_deref(), &got.body)
            }
            Err(_) => Err(reply::REQUEST_FAILED.to_string()),
        })
    }
}

impl Hook for Forwarder {
    fn decide(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
        self.post(op, OP_DECIDE, || view.projection_json(OP_DECIDE))
            .map(|r| lower_decide_reply(reply::decide(r)))
    }

    fn transform(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<RewriteVerdict> {
        self.post(op, OP_TRANSFORM, || view.projection_json(OP_TRANSFORM))
            .map(|r| lower_transform_reply(Ok(reply::transform(r))))
    }

    fn notify(&self, tap: &DecodedTap<'_>, op: &Op<'_>) -> Poll<()> {
        self.post(op, OP_NOTIFY, || tap.projection_json())
            .map(reply::notify)
    }

    fn configure(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        _version: u64,
    ) -> bool {
        let mut live = self.live.write().unwrap_or_else(PoisonError::into_inner);
        match config::configure(&live, settings) {
            Ok(None) => true,
            Ok(Some(next)) => {
                *live = next;
                true
            }
            Err(_) => false,
        }
    }

    fn status(&self) -> serde_json::Value {
        report::status(&self.target())
    }

    fn describe(&self) -> serde_json::Value {
        report::describe()
    }
}

/// Opens the forwarder: the settings document to its live target.
#[derive(Debug)]
pub struct Open;

impl HookOpen for Open {
    fn open(settings: &str) -> Result<Box<dyn Hook>, String> {
        let target = config::open(settings.as_bytes())?;
        Ok(Box::new(Forwarder {
            live: RwLock::new(target),
        }))
    }
}

busbar_contract::hook_door! {
    open: Open,
    statement: STATEMENT,
}
