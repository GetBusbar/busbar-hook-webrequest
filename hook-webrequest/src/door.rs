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

use std::ops::Deref;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::hook::{Tail, CLASS_GATE, PROMPT_RW, USER_RO};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::door::{Rewrite, Statement};
use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::cred::Cred;
use busbar_contract::abi::sdk::door::{abi_str, alias, statement};
use busbar_contract::abi::sdk::exchange::{Op, OpFailure, Request, SealedField, REPLY_OVER_BOUND};
use busbar_contract::abi::sdk::hook::{
    lower_decide_reply, lower_transform_reply, statement_with_tail, tail, ConfigureCheckpoint,
    Decoded, DecodedTap, Hook, HookOpen, RewriteVerdict, Verdict,
};
use busbar_contract::hook_wire::{OP_DECIDE, OP_NOTIFY, OP_TRANSFORM};

use crate::config::{self, Target};
use crate::owners::Parts;
use crate::{reply, report, wire};

/// The need index every op's exchange establishes on.
pub const NEED: u32 = 0;

/// THE ONE NEED: outbound over the host's `http` framer, the target named by the plugin per op
/// (the configured URL's origin, so a `configure` that moves it is honoured), under the
/// loopback-allowed egress class: `https://`, or plaintext to loopback only; the node's own ports,
/// private, link-local and cloud-metadata hosts refused, the address resolved and pinned by the
/// host.
pub const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_LOOPBACK_ALLOWED,
    transport: abi_str("http"),
    keep_mode: KEEP_NAMED,
    ..Need::EMPTY
}];

/// A gate that may see and rewrite the prompt and read the caller (`needs_prompt: rw`,
/// `needs_user: ro`); the operator's grant decides what it is handed.
const TAIL: &Tail = &tail(CLASS_GATE, PROMPT_RW, USER_RO);

/// How many ops one instance holds in flight; the host clamps.
pub const MAX_INFLIGHT: u32 = 64;

busbar_contract::statement_extensions!(
    /// THE REFERENCE-CAPABLE, NOT-SECRET SETTINGS FIELDS (busbar lead ruling item 7a), stated in
    /// the Statement's extensions under the contract's `EXT_REFERENCE_FIELDS` key: a `{env:}`/
    /// `{file:}`/`{module:}` reference written at `url` is resolved by the kernel IN PLACE to its
    /// string (a 1.5.5 config's `url: {env: VAR}` keeps booting), and a literal url passes as
    /// written (never refused as a secret literal). The value is not a secret: it is never lent.
    /// A reference anywhere else is refused (OWNER RULING, CHIP-REVIEW-v4 change 2).
    pub EXTENSIONS: [
    (busbar_contract::abi::mechanism::extensions::EXT_DECLARES, include_bytes!("../declares.json")),
    (busbar_contract::abi::mechanism::extensions::EXT_REFERENCE_FIELDS, br#"["url"]"#),
]);

/// The module name an operator writes, as the alias the registry holds beside [`crate::NAME`].
const REWRITES: &[Rewrite] = &[alias(crate::ALIAS)];

/// THE STATEMENT: name, version, the hook tail, the alias, the one outbound need and the
/// reference-capable `url`.
pub const STATEMENT: Statement = Statement {
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
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
    /// Serialises `configure` (validate, merge, version check and swap) and holds the highest
    /// version applied: a push older than it is acknowledged and not applied.
    applied: Mutex<(u64, u64)>,
}

/// A [`Target`] with what every op's exchange needs of it, built once when the target is set (at
/// `open` and an acknowledged `configure`): the origin the need dials, and the
/// method, request target and fields ([`wire::request`]) as the exchange takes them.
pub(crate) struct Live {
    target: Target,
    pub(crate) origin: String,
    method: Vec<u8>,
    request_target: Vec<u8>,
    /// The fields that carry no credential, in order (`content-type`, `accept`).
    plain: Vec<(Vec<u8>, Vec<u8>)>,
    /// The fields that do (the `authorization` the userinfo became): each goes in before the plain
    /// field `at` (their count: first), held as a [`Cred`] required to go out secured when the url
    /// names a secure scheme, so the SDK frames and wipes the value and a formatted exchange shows
    /// `<sealed>`.
    sealed: Vec<(usize, Vec<u8>, Cred)>,
    timeout_ms: u64,
    /// What a failure's text is scrubbed of ([`crate::net_guard::secret_parts`]), computed once with
    /// the target rather than for every failed op.
    secrets: Parts,
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
    pub(crate) fn new(target: Target) -> Arc<Self> {
        let r = wire::request(&target, Vec::new());
        let (mut plain, mut sealed) = (Vec::new(), Vec::new());
        for (name, value) in r.fields {
            if name.eq_ignore_ascii_case("authorization") {
                let mut v = serde_json::Value::String(value);
                let cred = Cred::take(&mut v)
                    .unwrap_or_else(Cred::empty)
                    .secure_for(target.url.as_str());
                sealed.push((plain.len(), name.as_bytes().to_vec(), cred));
            } else {
                plain.push((name.as_bytes().to_vec(), value.into_bytes()));
            }
        }
        Arc::new(Self {
            origin: target.url.origin().ascii_serialization(),
            method: r.method.as_bytes().to_vec(),
            request_target: r.target.into_bytes(),
            plain,
            sealed,
            timeout_ms: u64::try_from(target.timeout.as_millis()).unwrap_or(u64::MAX),
            secrets: Parts(crate::net_guard::secret_parts(&target.url)),
            target,
        })
    }

    /// The exchange's request for `body`, and the sealed fields it carries beside it.
    fn request(&self, body: Vec<u8>) -> (Request, Vec<SealedField>) {
        let request = Request {
            method: self.method.clone(),
            target: self.request_target.clone(),
            fields: self.plain.clone(),
            body,
            timeout_ms: self.timeout_ms,
        };
        let sealed = self
            .sealed
            .iter()
            .map(|(at, name, c)| (*at, name.clone(), c.field()))
            .collect();
        (request, sealed)
    }
}

impl Drop for Live {
    fn drop(&mut self) {
        drop(busbar_contract::abi::sdk::cred::Held::new(std::mem::take(
            &mut self.request_target,
        )));
    }
}

/// What an op makes of the target's answer: its status, reason phrase and body.
type Reading = fn(u16, Option<&str>, &[u8]) -> Result<serde_json::Value, String>;

/// A `notify` reads no reply: delivered, or the error status.
fn delivery(status: u16, phrase: Option<&str>, _body: &[u8]) -> Result<serde_json::Value, String> {
    reply::delivered(status, phrase).map(|()| serde_json::Value::Null)
}

impl Forwarder {
    /// A forwarder over `live`.
    pub(crate) fn over(live: Arc<Live>) -> Self {
        Self {
            live: RwLock::new(live),
            applied: Mutex::new((0, 0)),
        }
    }

    /// The SDK retains the original target with this operation through pending re-entries and
    /// configuration changes, and releases it on cancellation or completion.
    pub(crate) fn entry_live(&self, on: &Op<'_>) -> Result<Arc<Live>, &'static str> {
        on.context(|| self.live())
    }

    pub(crate) fn live(&self) -> Arc<Live> {
        Arc::clone(&self.live.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// POST `op`'s envelope over the projection `payload` builds to the live target: PENDING while
    /// the exchange pends; READY with the reply, or the failure text.
    fn post(
        &self,
        on: &Op<'_>,
        head_only: bool,
        payload: impl FnOnce(&mut Vec<u8>) -> Result<(), serde_json::Error>,
        read: Reading,
    ) -> Poll<Result<serde_json::Value, String>> {
        let live = match self.entry_live(on) {
            Ok(live) => live,
            Err(why) => return Poll::Ready(Err(why.to_owned())),
        };
        let answer = on.exchange_sealed_bounded_with_head(
            NEED,
            Some(&live.origin),
            reply::MAX_REPLY_BYTES,
            head_only,
            || {
                let mut body = Vec::new();
                payload(&mut body).map_err(|e| {
                    format!("{}: failed to serialize op envelope: {e}", crate::ALIAS)
                })?;
                Ok(live.request(body))
            },
        );
        answer.map(|r| match r {
            Ok(got) => {
                let phrase = got.reason.as_deref().map(String::from_utf8_lossy);
                let phrase = status_phrase(&live, phrase.as_deref());
                read(got.status, phrase.as_deref(), &got.body)
            }
            Err(failure) => {
                if let Some(head) = failure.head().filter(|h| (300..600).contains(&h.status)) {
                    let phrase = head.reason.as_deref().map(String::from_utf8_lossy);
                    let phrase = status_phrase(&live, phrase.as_deref());
                    return read(head.status, phrase.as_deref(), &[]);
                }
                match failure.into_cause() {
                    OpFailure::Unbuilt(reason) => Err(reason),
                    OpFailure::Conn(ConnFailure::Failed(reason)) if reason == REPLY_OVER_BOUND => {
                        Err(reply::cap_exceeded())
                    }
                    OpFailure::Conn(failure) => Err(transport_failure(&live, &failure)),
                }
            }
        })
    }
}

/// The remote's reason phrase as an error status may show it: the target's own words, which may
/// quote its URL back, cut of every secret part of the target ([`Live::secrets`]) before
/// [`reply::error_status`] caps and escapes it.
pub(crate) fn status_phrase(live: &Live, phrase: Option<&str>) -> Option<String> {
    phrase.map(|p| crate::net_guard::scrub(p, &live.secrets))
}

/// The text a transport failure is logged in: a fixed prefix, then the host's cause with every
/// credential-bearing part of the target (userinfo, path, query) cut from it, since the host's
/// words may quote the URL.
pub(crate) fn transport_failure(live: &Live, failure: &ConnFailure) -> String {
    let cause = crate::net_guard::scrub(&failure.to_string(), &live.secrets);
    format!("{}: {cause}", reply::request_failed())
}

impl Hook for Forwarder {
    fn decide(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
        self.post(
            op,
            false,
            |body| view.write_projection(OP_DECIDE, None, body),
            reply::interpret,
        )
        .map(|r| lower_decide_reply(reply::decide(r)))
    }

    fn transform(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<RewriteVerdict> {
        self.post(
            op,
            false,
            |body| view.write_projection(OP_TRANSFORM, None, body),
            reply::interpret,
        )
        .map(|r| lower_transform_reply(reply::transform(r)))
    }

    fn notify(&self, tap: &DecodedTap<'_>, op: &Op<'_>) -> Poll<()> {
        self.post(
            op,
            true,
            |body| tap.write_projection(OP_NOTIFY, None, body),
            delivery,
        )
        .map(reply::notify)
    }

    fn configure(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        version: u64,
    ) -> Result<(), String> {
        self.configure_checkpoint(settings, version).map(|_| ())
    }

    fn configure_checkpoint(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
        version: u64,
    ) -> Result<Option<ConfigureCheckpoint>, String> {
        // One configure at a time: the validation (the SSRF check and the merge) reads the live
        // target it is merged over, and the version check and the swap must not interleave with
        // another push's.
        let mut applied = self.applied.lock().unwrap_or_else(PoisonError::into_inner);
        // A push older than the applied one is acknowledged and not applied, whether or not it
        // would validate: the version check comes first.
        let current = self.live();
        let stale = version < applied.0;
        let next = match if stale {
            Ok(None)
        } else {
            config::configure(&current.target, settings)
        } {
            Ok(next) => next.map(Live::new),
            Err(reason) => {
                drop(applied);
                tracing::warn!(diag = %crate::CONFIGURE_REFUSED, "{reason}");
                return Err(reason);
            }
        };
        let revision = if stale {
            applied.1
        } else {
            applied
                .1
                .checked_add(1)
                .ok_or("configuration checkpoint revision exhausted")?
        };
        let settings_version = if stale { applied.0 } else { version };
        let target = next.as_deref().unwrap_or(&current);
        #[derive(serde::Serialize)]
        struct Snapshot<'a> {
            url: &'a str,
            timeout_ms: u64,
        }
        // Serialize borrowed fields directly: credential-bearing URL text is never cloned into
        // a temporary JSON DOM. Construct the wiping checkpoint before publishing this change.
        let bytes = serde_json::to_vec(&Snapshot {
            url: target.target.url.as_str(),
            timeout_ms: target.timeout_ms,
        })
        .map_err(|_| "cannot encode complete hook configuration")?;
        let checkpoint = ConfigureCheckpoint::new(revision, settings_version, bytes)?;
        if let Some(next) = next {
            *self.live.write().unwrap_or_else(PoisonError::into_inner) = next;
        }
        if !stale {
            *applied = (version, revision);
        }
        drop(applied);
        if !stale {
            config::log_warnings(settings);
        }
        Ok(Some(checkpoint))
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
        config::log_warnings_in(settings.as_bytes());
        Ok(Box::new(Forwarder::over(Live::new(target))))
    }
}

busbar_contract::hook_door! {
    open: Open,
    statement: STATEMENT,
}
