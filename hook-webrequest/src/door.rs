// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the webrequest forwarder on the hook kind's memory ABI (`hook_door!`), on the SDK's safe
//! surface. No `unsafe` here.
//!
//! * `open` / `refresh` — [`crate::config::open`]: the settings to a live [`Target`], refused in
//!   its words.
//! * `decide` / `transform` / `notify` — the op's projection, enveloped ([`crate::wire`]) and
//!   POSTed to the target through the ONE declared need ([`NEEDS`]: outbound, the loopback-allowed
//!   egress class, over the host's `http` framer), one exchange per op. The op answers PENDING while
//!   the exchange pends and is re-entered on the wake (Ready|Pending(wake)). The reply's meaning is
//!   in [`crate::reply`].
//! * `configure` — [`crate::config::configure`]'s commit-on-ack merge; a NACK is FAILED.
//! * A settings key the forwarder does not read ([`crate::config::KEYS`]) is ignored
//!   and logged as a warning at `open`, `refresh` and an acknowledged `configure`.
//! * `status` / `describe` — the forwarder's own documents ([`crate::report`]), never the target's.

use std::cell::Cell;
use std::ops::Deref;
use std::sync::{Arc, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::hook::{Tail, CLASS_GATE, PROMPT_RW, USER_RO};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, KEEP_NAMED,
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
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

/// A gate that may see and rewrite the prompt and read the caller (`needs_prompt: rw`,
/// `needs_user: ro`); the operator's grant decides what it is handed.
const TAIL: &Tail = &tail(CLASS_GATE, PROMPT_RW, USER_RO);

/// How many ops one instance holds in flight; the host clamps.
pub const MAX_INFLIGHT: u32 = 64;

/// THE REFERENCE-CAPABLE, NOT-SECRET SETTINGS FIELDS (busbar lead ruling item 7a), stated in the
/// Statement's extensions under the contract's `EXT_REFERENCE_FIELDS` key: a `{env:}`/`{file:}`/
/// `{module:}` reference written at `url` is resolved by the kernel IN PLACE to its string (a 1.5.5
/// config's `url: {env: VAR}` keeps booting), and a literal url passes as written (never refused
/// as a secret literal). The value is not a secret: it is never lent. A reference anywhere
/// else is refused (OWNER RULING, CHIP-REVIEW-v4 change 2).
busbar_contract::statement_extensions!(pub EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

/// THE STATEMENT: name, version, the hook tail, the one outbound need and the reference-capable
/// `url`.
pub const STATEMENT: Statement = Statement {
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    extensions: EXTENSIONS,
    ..statement_with_tail(
        statement(crate::NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT),
        TAIL,
    )
};

/// The forwarder: the live target, swapped whole by `configure`.
#[derive(Debug)]
pub struct Forwarder {
    live: RwLock<Arc<Live>>,
}

/// A [`Target`] with what every op's exchange needs of it, built once when the target is set (at
/// `open` and an acknowledged `configure`): the origin the need dials, and the
/// method, request target and fields ([`wire::request`]) as the exchange takes them.
struct Live {
    target: Target,
    origin: String,
    method: Vec<u8>,
    request_target: Vec<u8>,
    fields: Vec<(Vec<u8>, Vec<u8>)>,
    timeout_ms: u64,
}

impl Deref for Live {
    type Target = Target;
    fn deref(&self) -> &Target {
        &self.target
    }
}

/// Names the target as a log line does; the request parts carry the credential and stay out.
impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.target, f)
    }
}

impl Live {
    fn new(target: Target) -> Arc<Self> {
        let r = wire::request(&target, Vec::new());
        Arc::new(Self {
            origin: target.url.origin().ascii_serialization(),
            method: r.method.as_bytes().to_vec(),
            request_target: r.target.into_bytes(),
            fields: r
                .fields
                .into_iter()
                .map(|(n, v)| (n.as_bytes().to_vec(), v.into_bytes()))
                .collect(),
            timeout_ms: u64::try_from(target.timeout.as_millis()).unwrap_or(u64::MAX),
            target,
        })
    }

    /// The exchange's request for `body`.
    fn request(&self, body: Vec<u8>) -> Request {
        Request {
            method: self.method.clone(),
            target: self.request_target.clone(),
            fields: self.fields.clone(),
            body,
            timeout_ms: self.timeout_ms,
        }
    }
}

impl Forwarder {
    fn live(&self) -> Arc<Live> {
        Arc::clone(&self.live.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// POST `op`'s envelope over the projection `payload` builds to the live target: PENDING while
    /// the exchange pends; READY with the reply, or the failure text.
    fn post(
        &self,
        on: &Op<'_>,
        op: &str,
        payload: impl FnOnce() -> serde_json::Value,
    ) -> Poll<Result<serde_json::Value, String>> {
        let live = self.live();
        let unsendable = Cell::new(None);
        let answer = on.exchange(NEED, Some(&live.origin), || {
            wire::envelope(op, &payload())
                .map(|body| live.request(body))
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
            Err(failure) => Err(transport_failure(&live, &failure)),
        })
    }
}

/// The text a transport failure is logged in: a fixed prefix, then the host's cause with every
/// credential-bearing part of the target (userinfo, path, query) cut from it, since the host's
/// words may quote the URL.
pub(crate) fn transport_failure(target: &Target, failure: &ConnFailure) -> String {
    let cause = crate::net_guard::scrub(&failure.to_string(), &target.url);
    format!("{}: {cause}", reply::REQUEST_FAILED)
}

impl Hook for Forwarder {
    fn decide(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
        self.post(op, OP_DECIDE, || view.projection_json(OP_DECIDE))
            .map(|r| lower_decide_reply(Ok(reply::decide(r))))
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
        let result = config::configure(&live.target, settings);
        if result.is_ok() {
            for warning in config::unknown_keys(settings) {
                tracing::warn!("{warning}");
            }
        }
        match result {
            Ok(None) => true,
            Ok(Some(next)) => {
                *live = Live::new(next);
                true
            }
            Err(reason) => {
                tracing::warn!("{reason}");
                false
            }
        }
    }

    fn status(&self) -> serde_json::Value {
        report::status(&self.live())
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
        for warning in config::unknown_keys_in(settings.as_bytes()) {
            tracing::warn!("{warning}");
        }
        Ok(Box::new(Forwarder {
            live: RwLock::new(Live::new(target)),
        }))
    }
}

busbar_contract::hook_door! {
    open: Open,
    statement: STATEMENT,
}
