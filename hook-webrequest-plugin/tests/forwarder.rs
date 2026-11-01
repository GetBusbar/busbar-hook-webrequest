// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE FORWARDER, BOTH DOORS** — webrequest's linked + dropped-in conformance on the hook kind's
//! memory ABI, run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The forwarder is held two ways at once: LINKED (the logic crate's `door::door`, through the
//! loader's `load_linked`) and DROPPED IN (this crate's built cdylib, exporting the same door as
//! `busbar_plugin_door`, through `load_dropped`). Each arm is bound to a real dispatcher and to a
//! connection table that plays the far end ([`Upstream`]): it takes the framed request the host's
//! framer would put on the wire and answers a scripted reply, and it answers its FIRST read of every
//! reply PENDING and wakes the op's ticket from another thread. So every `decide`, `transform` and
//! `notify` crosses PENDING, is re-entered on the wake and completes from where its exchange parked
//! (THE DESIGN, the plugin ABI: Ready|Pending(wake); ARCHITECT ruling 2026-10-02: no hook-specific
//! seam). The two transcripts must agree, and every request must be the 1.5.5 client's: `POST` to
//! the URL's path, its fields, the 1.5.5 op envelope byte for byte.
//!
//! THE RED ARMS: a configuration the forwarder refuses never opens, in 1.5.5's words; a configure
//! that names a blocked URL is a NACK and leaves the live target; a far end's error status is an
//! FAILED `decide` and a FAILED `transform` (the operator's `on_error` applies; SIGN-hookexport-
//! webrequest-failure), while a deliberate `{}` reply stays an abstain; and the Statement declares exactly one need,
//! outbound, in the loopback-allowed egress class, over the host's `http` framer.
//!
//! THE BAN ([`net_ban`]): the plugin's shipped closure holds no socket crate and no TLS stack (THE
//! DESIGN §5: no plugin opens a socket, dials, binds or does TLS), with its RED arm.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::abi::hook::{
    slot, ConfigureIn, ConfigureOut, DecideOut, DescribeOut, NotifyIn, StatusOut, TransformOut,
    VERB_ABSTAIN, VERB_PREFER, VERB_REJECT, VERB_REWRITE,
};
use busbar_contract::abi::host::conn::connector::{DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED};
use busbar_contract::abi::host::hook::{Caps, DecideFrame, DecideView, NotifyFrame};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, OutHead, Outcome, BLOB_JSON,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, OpenIn, OpenOut, RefreshIn, ReleaseIn,
};
use busbar_contract::abi::mechanism::rendering::{self, ReadNeed};
use busbar_contract::abi::sdk::door::blank_out;
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece, PieceKind,
};
use busbar_contract::hooks::{Candidate, PromptProjection, RoutingContext, RoutingRequest};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::ConnFacts;
use busbar_contract::SignalBag;
use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, now_ns, out_head, rendering_of, Bind, Called, ConnTable,
    Diagnostic, DispatchConfig, Dispatcher, Done, Dropped, EnvelopeSink, Frame, InFrame, LinkedRow,
    Metric, OutFrame, Plugin,
};
use serde_json::{json, Value};

#[path = "support/net_ban.rs"]
mod net_ban;

/// The URL every opened forwarder is configured with: loopback plaintext, userinfo, a query.
const URL: &str = "http://user:pa%20ss@127.0.0.1:9/hook?x=1";

// The existing opaque CONFIGURE extension's v1 envelope: two little-endian u64 words,
// followed by the complete normalized settings document. No new SDK API is needed to read it.
const CONFIGURATION_CHECKPOINT_KEY: &str = "hook.configure_checkpoint.v1";
const CONFIGURATION_WORD_BYTES: usize = std::mem::size_of::<u64>();
const CONFIGURATION_CHECKPOINT_PREFIX_BYTES: usize = CONFIGURATION_WORD_BYTES * 2;
type ConfigurationSnapshot = (u64, u64, Value);

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_hook_webrequest_plugin");
    [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-hook-webrequest-plugin cdylib ({file}) is not built"))
}

/// The door's Statement rendering, as the pack tool signs it into the manifest.
fn stated() -> Vec<u8> {
    rendering_of(busbar_hook_webrequest::door::door).expect("the door renders its Statement")
}

// ── the far end ──────────────────────────────────────────────────────────────────────────────────

/// One request as the host's framer was handed it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sent {
    target: String,
    method: Vec<u8>,
    path: Vec<u8>,
    fields: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
    timeout_ms: u64,
}

/// The dispatcher's connection-table wake.
type Wake = busbar_contract::conn::ConnWake;

#[derive(Default)]
struct ReadState {
    phase: u8,
    body_at: usize,
}

/// THE FAR END, as a connection table: every need is framed; an open is the whole request (kept
/// in `sent`); each reply is the scripted `(status, reason, body)`, its first read PENDING with
/// the op's ticket woken from another thread.
struct Upstream {
    wake: Mutex<Option<Wake>>,
    answer: Mutex<(u32, &'static str, Vec<u8>)>,
    sent: Mutex<Vec<Sent>>,
    reads: Mutex<HashMap<u64, ReadState>>,
    body_bytes_read: AtomicUsize,
    next: AtomicU64,
    pended: AtomicU32,
    /// While set, every open is refused (the exchange fails to establish).
    fail_open: AtomicBool,
}

impl Upstream {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wake: Mutex::new(None),
            answer: Mutex::new((200, "OK", b"{}".to_vec())),
            sent: Mutex::new(Vec::new()),
            reads: Mutex::new(HashMap::new()),
            body_bytes_read: AtomicUsize::new(0),
            next: AtomicU64::new(1),
            pended: AtomicU32::new(0),
            fail_open: AtomicBool::new(false),
        })
    }

    fn answer(&self, status: u32, reason: &'static str, body: &[u8]) {
        *self.answer.lock().unwrap() = (status, reason, body.to_vec());
    }

    fn last(&self) -> Sent {
        self.sent
            .lock()
            .unwrap()
            .last()
            .cloned()
            .expect("a request")
    }
}

fn piece(kind: PieceKind, len: usize) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: true,
        status: None,
        status_code: None,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason: None,
        declared_len: None,
    }
}

impl Conns for Upstream {
    fn open(&self, _: InstanceId, _: NeedId, desc: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        if self.fail_open.load(Ordering::SeqCst) {
            return Err(ConnError::Refused);
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.sent.lock().unwrap().push(Sent {
            target: desc.target.to_owned(),
            method: desc.method.to_vec(),
            path: desc.head_target.to_vec(),
            fields: desc
                .fields
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
                .collect(),
            body: desc.body.to_vec(),
            timeout_ms: desc.timeout_ms,
        });
        self.reads.lock().unwrap().insert(id, ReadState::default());
        Ok(ConnId(id))
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let (status, reason, body) = self.answer.lock().unwrap().clone();
        let (step, body_start, body_end) = {
            let mut reads = self.reads.lock().unwrap();
            let state = reads.get_mut(&conn.0).ok_or(ConnError::Closed)?;
            let step = state.phase;
            if step < 2 {
                state.phase += 1;
                (step, 0, 0)
            } else if step == 2 {
                let start = state.body_at;
                let end = start + buf.len().min(body.len().saturating_sub(start));
                state.body_at = end;
                if end == body.len() {
                    state.phase = 3;
                }
                (step, start, end)
            } else {
                (step, 0, 0)
            }
        };
        match step {
            0 => {
                // The far end has not answered yet: the wake comes later, from elsewhere.
                self.pended.fetch_add(1, Ordering::SeqCst);
                let wake = self
                    .wake
                    .lock()
                    .unwrap()
                    .clone()
                    .expect("the table is armed");
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(5));
                    wake(caller, ticket);
                });
                Err(ConnError::Pending)
            }
            1 => {
                buf[..reason.len()].copy_from_slice(reason.as_bytes());
                Ok(Piece {
                    status_code: Some(status),
                    reason: Some(0..reason.len()),
                    ..piece(PieceKind::Fields, 0)
                })
            }
            2 => {
                let chunk = &body[body_start..body_end];
                buf[..chunk.len()].copy_from_slice(chunk);
                self.body_bytes_read
                    .fetch_add(chunk.len(), Ordering::SeqCst);
                Ok(Piece {
                    end: body_end == body.len(),
                    ..piece(PieceKind::Body, chunk.len())
                })
            }
            _ => Ok(piece(PieceKind::Completion, 0)),
        }
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, _: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.reads.lock().unwrap().remove(&conn.0);
        Ok(())
    }
}

impl DeclaredConns for Upstream {
    fn serves_scheme(&self, transport: &str) -> bool {
        transport == "http"
    }
    fn declare(
        &self,
        _: InstanceId,
        _: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        Ok(())
    }
    fn declared(&self, _: InstanceId, _: NeedId) -> Option<Result<(), ConnError>> {
        Some(Ok(()))
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        true
    }
}

// ── the host's side ──────────────────────────────────────────────────────────────────────────────

/// A JSON blob over `text` (the host's bytes, alive for the call).
fn json_blob(text: &str) -> Blob {
    Blob {
        ptr: text.as_ptr(),
        len: text.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// The text a FAILED/REFUSED answer carried, copied by the loader.
fn error_of(error: Option<&[u8]>) -> String {
    error
        .map(|e| String::from_utf8_lossy(e).into_owned())
        .unwrap_or_default()
}

/// The two doors.
#[derive(Clone)]
enum Arm {
    /// The logic crate's door, linked.
    Linked,
    /// The cdylib's door, dropped in.
    Dropped(PathBuf),
}

/// The host's envelope sink, recording every diagnostic as `(severity, text)`.
#[derive(Default)]
struct Recorder {
    diags: Mutex<Vec<(u8, String)>>,
}

impl Recorder {
    /// The texts of the warn (severity 1) diagnostics so far.
    fn warns(&self) -> Vec<String> {
        self.diags
            .lock()
            .unwrap()
            .iter()
            .filter(|(s, _)| *s == 1)
            .map(|(_, t)| t.clone())
            .collect()
    }
}

impl EnvelopeSink for Recorder {
    fn metric(&self, _: Metric<'_>) {}
    fn diag(&self, d: Diagnostic<'_>) {
        self.diags
            .lock()
            .unwrap()
            .push((d.severity, String::from_utf8_lossy(d.text).into_owned()));
    }
    fn dropped(&self, _: Dropped) {}
}

/// One arm, bound: the dispatcher, the far end and the plugin (not yet opened).
struct Bound {
    recorder: Arc<Recorder>,
    dispatcher: Arc<Dispatcher>,
    upstream: Arc<Upstream>,
    plugin: Plugin<Hook>,
}

impl Arm {
    fn bind(&self) -> Bound {
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig {
            workers: 2,
            ..Default::default()
        }));
        let upstream = Upstream::new();
        *upstream.wake.lock().unwrap() = Some(dispatcher.conn_waker());
        let conns: Arc<dyn DeclaredConns> = upstream.clone();
        let recorder = Arc::new(Recorder::default());
        let bind = Bind {
            instance: Arc::from("webrequest-conformance"),
            max_inflight_cap: 64,
            sink: recorder.clone(),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::Host(conns),
        };
        let plugin = match self {
            Arm::Linked => load_linked::<Hook>(
                &LinkedRow::of(busbar_hook_webrequest::door::door).expect("the row renders"),
                bind,
            ),
            Arm::Dropped(path) => load_dropped::<Hook>(path, &stated(), bind),
        }
        .expect("the door loads");
        Bound {
            recorder,
            dispatcher,
            upstream,
            plugin,
        }
    }
}

impl Bound {
    /// `open` over `settings`: `Ok` on READY, else the text the plugin stated.
    fn open(&self, settings: &str) -> Result<(), String> {
        let mut f = Frame::new(
            OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: json_blob(settings),
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
        );
        let called: Called = self.plugin.call(life::OPEN, &mut f);
        match called.outcome {
            Outcome::Ready => Ok(()),
            o => Err(format!("{o:?}: {}", error_of(called.error.as_deref()))),
        }
    }

    /// Op `s` on a fresh ticket, through the dispatcher: it may pend, and is resumed on its wake.
    fn submit<I: InFrame, O: OutFrame>(&self, s: u32, input: I, out: O) -> Done<I, O> {
        let ticket = self.dispatcher.mint(0).expect("a ticket");
        let reply = self.dispatcher.submit(
            &self.plugin,
            ticket,
            s,
            Frame::new(input, out),
            DeadlineClass::Call,
            now_ns() + 20_000_000_000,
        );
        let done = reply
            .wait(Duration::from_secs(30))
            .expect("the op completes");
        self.dispatcher.recycle(ticket);
        done
    }

    /// A leased JSON blob's document, then its lease released.
    fn leased(&self, blob: Blob, lease: u64) -> Value {
        assert!(!blob.ptr.is_null() && lease != 0, "a leased document");
        // SAFETY: the plugin's leased bytes, held until the release below.
        let bytes = unsafe { std::slice::from_raw_parts(blob.ptr, blob.len) }.to_vec();
        let mut f = Frame::new(
            ReleaseIn {
                head: in_head(),
                lease,
            },
            out_head(),
        );
        assert_eq!(
            self.plugin.call(life::RELEASE, &mut f).outcome,
            Outcome::Ready
        );
        serde_json::from_slice(&bytes).expect("the document is JSON")
    }

    fn status(&self) -> Value {
        let mut f = Frame::new(in_head(), blank_out::<StatusOut>());
        let called = self.plugin.call(slot::STATUS, &mut f);
        assert_eq!(called.outcome, Outcome::Ready);
        self.leased(f.out.status, called.lease)
    }

    fn describe(&self) -> Value {
        let mut f = Frame::new(in_head(), blank_out::<DescribeOut>());
        let called = self.plugin.call(slot::DESCRIBE, &mut f);
        assert_eq!(called.outcome, Outcome::Ready);
        self.leased(f.out.describe, called.lease)
    }

    /// `configure` with `settings` at `version`: `Ok` with the acked version, else the text.
    fn configure(&self, settings: &str, version: u64) -> Result<u64, String> {
        self.configure_snapshot(settings, version)
            .map(|(acked, _)| acked)
    }

    /// Read the existing opaque reply extension before releasing its lease. The regression uses
    /// the old raw CONFIGURE surface, so an absent checkpoint is a behavior failure.
    fn configure_snapshot(
        &self,
        settings: &str,
        version: u64,
    ) -> Result<(u64, Option<ConfigurationSnapshot>), String> {
        let mut f = Frame::new(
            ConfigureIn {
                head: in_head(),
                version,
                settings: json_blob(settings),
                name: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
            },
            blank_out::<ConfigureOut>(),
        );
        let called = self.plugin.call(slot::CONFIGURE, &mut f);
        let extension = f.out.head.extensions;
        let bytes = if extension.len == 0 {
            Vec::new()
        } else {
            assert!(!extension.ptr.is_null());
            // SAFETY: the loader validated this reply; its lease is held until RELEASE below.
            unsafe { std::slice::from_raw_parts(extension.ptr, extension.len) }.to_vec()
        };
        if called.lease != 0 {
            let mut release = Frame::new(
                ReleaseIn {
                    head: in_head(),
                    lease: called.lease,
                },
                out_head(),
            );
            assert_eq!(
                self.plugin.call(life::RELEASE, &mut release).outcome,
                Outcome::Ready
            );
        }
        match called.outcome {
            Outcome::Ready => {
                let snapshot = busbar_contract::abi::mechanism::extensions::get(
                    &bytes,
                    CONFIGURATION_CHECKPOINT_KEY,
                )
                .map(|value| {
                    assert!(value.len() > CONFIGURATION_CHECKPOINT_PREFIX_BYTES);
                    let revision =
                        u64::from_le_bytes(value[..CONFIGURATION_WORD_BYTES].try_into().unwrap());
                    let version = u64::from_le_bytes(
                        value[CONFIGURATION_WORD_BYTES..CONFIGURATION_CHECKPOINT_PREFIX_BYTES]
                            .try_into()
                            .unwrap(),
                    );
                    let settings =
                        serde_json::from_slice(&value[CONFIGURATION_CHECKPOINT_PREFIX_BYTES..])
                            .expect("complete JSON settings");
                    (revision, version, settings)
                });
                Ok((f.out.acked_version, snapshot))
            }
            _ => Err(error_of(called.error.as_deref())),
        }
    }
}

// ── the request a hook is handed ─────────────────────────────────────────────────────────────────

fn request() -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 42,
        pool: "pool-a",
        ingress_protocol: "openai",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: 5,
        system_chars: 0,
        max_tokens: Some(64),
        stream: false,
        prompt: Some(PromptProjection {
            system: None,
            messages: vec![("user".into(), "hello".into())],
        }),
        identity: None,
        signals: SignalBag::new(),
        session: None,
    }
}

fn candidates() -> Vec<Candidate<'static>> {
    [3usize, 9]
        .into_iter()
        .map(|idx| Candidate {
            idx,
            model: "m",
            provider: "p",
            weight: 1,
            context_max: None,
            tier: None,
            cost_per_mtok: None,
            tags: &[],
            latency_ms: None,
            available_concurrency: 1,
            budget_remaining: None,
            rate_headroom: None,
            signals: SignalBag::new(),
        })
        .collect()
}

fn context() -> RoutingContext<'static> {
    RoutingContext {
        pool: "pool-a",
        budget_remaining: None,
        budget: &[],
    }
}

/// The `decide`/`transform` frame, with room for any answer here.
fn decide_frame() -> Arc<DecideFrame> {
    DecideFrame::new(
        DecideView::build(&request(), &candidates(), &context()),
        Caps {
            order: 8,
            reject_message: 4096,
            restrict_tags: 4096,
            rewrite: 64 * 1024,
        },
    )
}

/// The 1.5.5 op envelope for `op`: the projection 1.5.5's host built, enveloped as 1.5.5's
/// forwarder did.
fn envelope_155(op: &'static str) -> Vec<u8> {
    let cands = if op == "notify" {
        Vec::new()
    } else {
        candidates()
    };
    let projection = serde_json::to_value(busbar_contract::hook_wire::build(
        op,
        &request(),
        &cands,
        &context(),
    ))
    .expect("the projection serializes");
    busbar_hook_webrequest::wire::envelope(op, &projection).expect("the envelope serializes")
}

/// The request every op must put on the wire for `op`: the 1.5.5 client's.
fn expected(op: &'static str) -> Sent {
    Sent {
        target: "http://127.0.0.1:9".into(),
        method: b"POST".to_vec(),
        path: b"/hook?x=1".to_vec(),
        fields: vec![
            ("authorization".into(), b"Basic dXNlcjpwYSBzcw==".to_vec()),
            ("content-type".into(), b"application/json".to_vec()),
            ("accept".into(), b"*/*".to_vec()),
        ],
        body: envelope_155(op),
        timeout_ms: 2000,
    }
}

// ── the script ───────────────────────────────────────────────────────────────────────────────────

/// Drive one arm through the whole script; its transcript.
fn script(arm: &Arm) -> Vec<String> {
    let mut t = Vec::new();
    let b = arm.bind();

    // RED: a configuration the forwarder refuses never opens, in 1.5.5's words.
    for (bad, words) in [
        (r#"{"url": ""}"#, "webrequest: settings.url is required"),
        ("{}", "webrequest: settings.url is required"),
        (r#"{"url": 5}"#, "webrequest: invalid plugin config"),
        (r#"{"url": "http://169.254.169.254/"}"#, "webrequest:"),
        (r#"{"url": "https://169.254.169.254/"}"#, "SSRF guard"),
    ] {
        let refused = arm.bind().open(bad).expect_err("refused");
        assert!(refused.contains(words), "{bad}: {refused}");
        t.push(format!("open {bad}: refused"));
    }

    let settings = format!(r#"{{"url": "{URL}", "timeout_ms": 2000}}"#);
    b.open(&settings).expect("the forwarder opens");

    // describe and status: the forwarder's own documents.
    let d = b.describe();
    assert_eq!(d["schema"]["required"], json!(["url"]));
    let s = b.status();
    assert_eq!(s["status"]["settings"]["target_host"], json!("127.0.0.1"));
    assert_eq!(s["status"]["settings"]["timeout_ms"], json!(2000));
    t.push(format!("status {s}"));

    // decide: the far end's order, after a PENDING crossing resumed on its wake.
    let frame = decide_frame();
    b.upstream.answer(200, "OK", br#"{"order":[9,3]}"#);
    let pended = b.upstream.pended.load(Ordering::SeqCst);
    let done = b.submit(slot::DECIDE, frame.input(), blank_out::<DecideOut>());
    assert_eq!(
        done.outcome,
        Outcome::Ready,
        "{}",
        error_of(done.error.as_deref())
    );
    let out = done.frame.expect("the frame comes back").out;
    assert_eq!(out.verbs & VERB_PREFER, VERB_PREFER);
    assert_eq!(frame.order(out.order_written), vec![9, 3]);
    assert!(
        b.upstream.pended.load(Ordering::SeqCst) > pended,
        "decide pended"
    );
    assert_eq!(b.upstream.last(), expected("decide"));
    t.push("decide 200: prefer [9, 3]".into());

    // RED: an error status is a FAILED decide, so the pool's `on_error` applies (a far-end 500
    // under `on_error: reject` refuses the request); a deliberate `{}` reply is still an abstain.
    b.upstream.answer(503, "Busy", b"");
    let failed = decide_failure(&b);
    assert!(failed.contains("HTTP status server error (503"), "{failed}");
    assert_eq!(b.upstream.last(), expected("decide"));
    t.push("decide 503: failed".into());
    b.upstream.answer(200, "OK", b"{}");
    assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
    t.push("decide {}: abstain".into());

    // transform: the far end's rewrite crosses as its JSON; a failure reaches on_error.
    let frame = decide_frame();
    let rewrite = json!({"messages": [{"role": "user", "content": "rewritten"}]});
    b.upstream.answer(
        200,
        "OK",
        &serde_json::to_vec(&json!({ "rewrite": rewrite })).unwrap(),
    );
    let done = b.submit(slot::TRANSFORM, frame.input(), blank_out::<TransformOut>());
    assert_eq!(done.outcome, Outcome::Ready);
    let out = done.frame.expect("the frame comes back").out;
    assert_eq!(out.verbs & VERB_REWRITE, VERB_REWRITE);
    assert_eq!(
        frame.rewrite(out.rewrite_written),
        serde_json::to_vec(&rewrite).unwrap()
    );
    assert_eq!(b.upstream.last(), expected("transform"));
    t.push("transform 200: rewrite".into());

    b.upstream.answer(500, "Internal Server Error", b"");
    let failed = transform_failure(&b);
    assert!(failed.contains("HTTP status server error (500"), "{failed}");
    t.push("transform 500: failed".into());

    // notify: fire-and-forget, the 1.5.5 notify envelope on the wire.
    let tap = NotifyFrame::build(&request(), None, true);
    b.upstream.answer(200, "OK", b"{}");
    let done = b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head());
    assert_eq!(done.outcome, Outcome::Ready);
    assert_eq!(b.upstream.last(), expected("notify"));
    t.push("notify: ready".into());

    // configure: commit-on-ack; a blocked URL is a NACK and leaves the live target.
    assert_eq!(b.configure(r#"{"timeout_ms": 100}"#, 7), Ok(7));
    let nack = b
        .configure(r#"{"url": "https://169.254.169.254/"}"#, 9)
        .expect_err("a blocked https URL is a NACK too");
    assert!(
        nack.contains("did not acknowledge settings_version 9"),
        "{nack}"
    );
    let nack = b
        .configure(r#"{"url": "http://169.254.169.254/"}"#, 8)
        .expect_err("a blocked URL is a NACK");
    assert!(
        nack.contains("did not acknowledge settings_version 8"),
        "{nack}"
    );
    let s = b.status();
    assert_eq!(s["status"]["settings"]["timeout_ms"], json!(100));
    assert_eq!(s["status"]["settings"]["target_host"], json!("127.0.0.1"));
    t.push(format!("configure: ack 7, nack 8, nack 9; status {s}"));

    // Every exchange pended once and completed on its wake.
    assert_eq!(
        b.upstream.pended.load(Ordering::SeqCst),
        b.upstream.sent.lock().unwrap().len() as u32
    );
    t
}

#[test]
fn the_linked_and_the_dropped_in_doors_answer_alike_and_as_1_5_5() {
    let linked = script(&Arm::Linked);
    let dropped = script(&Arm::Dropped(cdylib()));
    assert_eq!(linked, dropped);
}

/// RED: the Statement declares exactly one need: outbound, the loopback-allowed egress class, over
/// the host's `http` framer, its target named by the plugin per op (no `target_from`).
#[test]
fn red_the_statement_declares_one_outbound_loopback_allowed_http_need() {
    let read = rendering::read(&stated()).expect("the rendering reads");
    assert_eq!(read.needs.len(), 1);
    let need = &read.needs[0];
    assert_eq!(need.direction, DIRECTION_OUTBOUND);
    assert_eq!(need.egress_class, EGRESS_LOOPBACK_ALLOWED);
    assert_eq!(need.transport, "http");
    assert!(need.target_from.is_empty());
    // The dropped-in image states the same Statement as the linked door.
    let dropped = busbar_plugin_loader::dispatch::rendering_of_library(&cdylib())
        .expect("the cdylib opens")
        .expect("the cdylib exports the door");
    assert_eq!(dropped, stated());
}

/// D5: the Statement states its alias rewrite, the module name an operator writes, and the dropped-in
/// image states the same.
#[test]
fn red_the_statement_states_the_alias_rewrite() {
    let read = rendering::read(&stated()).expect("the rendering reads");
    assert_eq!(read.rewrites.len(), 1, "{:?}", read.rewrites);
    assert_eq!(read.rewrites[0].0, 1, "an alias rewrite");
    assert_eq!(read.rewrites[0].1, "webrequest");
}

/// D3: every operator-actionable line carries its declared catalogue code, and `declares.json`
/// declares exactly those codes.
#[test]
fn red_every_actionable_line_carries_its_declared_code() {
    let declares: Value =
        serde_json::from_str(include_str!("../../hook-webrequest/declares.json")).unwrap();
    let declared: Vec<u64> = declares["diagnostics"]
        .as_array()
        .expect("diagnostics")
        .iter()
        .map(|d| {
            assert_eq!(d["severity"], "actionable");
            assert_eq!(d["since"], "1.6.0");
            d["code"].as_u64().unwrap()
        })
        .collect();
    assert_eq!(declared, [7151, 7152, 7153, 7154]);
    use busbar_hook_webrequest::{
        CONFIGURE_REFUSED, FORWARD_FAILED, NOTIFY_DROPPED, TIMEOUT_CLAMPED,
    };
    assert_eq!(
        [
            FORWARD_FAILED,
            NOTIFY_DROPPED,
            CONFIGURE_REFUSED,
            TIMEOUT_CLAMPED
        ],
        ["BUSBAR-7151", "BUSBAR-7152", "BUSBAR-7153", "BUSBAR-7154"]
    );
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}", "timeout_ms": 99999}}"#))
            .expect("opens");
        // 7154: the clamp.
        assert!(
            warned(&b, &["timeout_ms", "clamp", "BUSBAR-7154"]),
            "{:?}",
            b.recorder.warns()
        );
        // 7153: a configure refusal.
        b.configure(r#"{"url": "http://169.254.169.254/"}"#, 2)
            .expect_err("a blocked URL is a NACK");
        assert!(
            warned(&b, &["configure() rejected:", "BUSBAR-7153"]),
            "{:?}",
            b.recorder.warns()
        );
        // 7151: a failed decide and a failed transform.
        b.upstream.answer(503, "Busy", b"");
        decide_failure(&b);
        assert!(
            warned(&b, &["decide failed", "BUSBAR-7151"]),
            "{:?}",
            b.recorder.warns()
        );
        transform_failure(&b);
        assert!(
            warned(&b, &["transform failed", "BUSBAR-7151"]),
            "{:?}",
            b.recorder.warns()
        );
        // 7152: a dropped notify.
        let tap = NotifyFrame::build(&request(), None, true);
        b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head());
        assert!(
            warned(&b, &["notify dropped", "BUSBAR-7152"]),
            "{:?}",
            b.recorder.warns()
        );
    }
}

/// RED: a `decide` that cannot pend (no ticket) answers at once, FAILED (a request it could not
/// send is a hook failure, so `on_error` applies); it never blocks a thread and puts nothing on the
/// wire.
#[test]
fn red_a_ticketless_decide_fails_at_once() {
    let b = Arm::Linked.bind();
    b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
    let frame = decide_frame();
    let mut f = Frame::new(frame.input(), blank_out::<DecideOut>());
    let called = b.plugin.call(slot::DECIDE, &mut f);
    assert_eq!(
        called.outcome,
        Outcome::Failed,
        "{}",
        error_of(called.error.as_deref())
    );
    assert!(error_of(called.error.as_deref()).contains("cannot pend"));
    assert!(b.upstream.sent.lock().unwrap().is_empty());
}

// ── nothing silent: every refusal is explained in the plugin's log ───────────────────────────────

fn arms() -> [Arm; 2] {
    [Arm::Linked, Arm::Dropped(cdylib())]
}

#[test]
fn extension_statuses_preserve_the_1_5_5_body_semantics_through_both_doors() {
    for arm in arms() {
        for status in [600, 999] {
            let b = arm.bind();
            b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
            b.upstream.answer(
                status,
                "Custom",
                br#"{"reject":{"status":403,"message":"no"}}"#,
            );
            assert_ne!(decide_verbs(&b) & VERB_REJECT, 0);
            assert!(b.recorder.warns().is_empty(), "{:?}", b.recorder.warns());
            assert!(b.upstream.reads.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn non_utf8_userinfo_keeps_the_1_5_5_basic_authorization_rules() {
    for arm in arms() {
        for (url, expected) in [
            ("http://svc%FF:pw@127.0.0.1:9/hook", None),
            (
                "http://user:%FF@127.0.0.1:9/hook",
                Some(&b"Basic dXNlcjo="[..]),
            ),
        ] {
            let b = arm.bind();
            b.open(&serde_json::json!({"url":url}).to_string()).unwrap();
            assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
            let sent = b.upstream.last();
            let authorization = sent
                .fields
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.as_slice());
            assert_eq!(authorization, expected, "{url}");
            assert!(b.recorder.warns().is_empty(), "{:?}", b.recorder.warns());
            assert!(b.upstream.reads.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn a_notify_redirect_is_acknowledged_without_interpreting_its_body() {
    for arm in arms() {
        for (status, reason) in [(301, "Moved Permanently"), (308, "Permanent Redirect")] {
            let b = arm.bind();
            b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
            b.upstream.answer(status, reason, b"not JSON");
            let tap = NotifyFrame::build(&request(), None, true);
            let done = b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head());
            assert_eq!(done.outcome, Outcome::Ready);
            assert!(b.recorder.warns().is_empty(), "{:?}", b.recorder.warns());
            assert_eq!(b.upstream.sent.lock().unwrap().len(), 1);
            assert!(b.upstream.reads.lock().unwrap().is_empty());
        }
    }
}

/// A `decide` through the dispatcher; its verbs.
fn decide_verbs(b: &Bound) -> u32 {
    let done = b.submit(
        slot::DECIDE,
        decide_frame().input(),
        blank_out::<DecideOut>(),
    );
    assert_eq!(
        done.outcome,
        Outcome::Ready,
        "{}",
        error_of(done.error.as_deref())
    );
    done.frame.expect("the frame").out.verbs
}

/// A `decide` through the dispatcher that FAILS (the pool's `on_error` applies); its text.
fn decide_failure(b: &Bound) -> String {
    let done = b.submit(
        slot::DECIDE,
        decide_frame().input(),
        blank_out::<DecideOut>(),
    );
    assert_eq!(done.outcome, Outcome::Failed, "a failed decide");
    error_of(done.error.as_deref())
}

/// A `transform` through the dispatcher that FAILS; its text.
fn transform_failure(b: &Bound) -> String {
    let done = b.submit(
        slot::TRANSFORM,
        decide_frame().input(),
        blank_out::<TransformOut>(),
    );
    assert_eq!(done.outcome, Outcome::Failed, "a failed transform");
    error_of(done.error.as_deref())
}

/// Some warn diagnostic contains every one of `parts`.
fn warned(b: &Bound, parts: &[&str]) -> bool {
    b.recorder
        .warns()
        .iter()
        .any(|w| parts.iter().all(|p| w.contains(p)))
}

/// RED: a configure refusal is a NACK and says why in the plugin's log (1.5.5 wrote it to stderr).
#[test]
fn red_a_configure_refusal_is_logged() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
        b.configure(r#"{"url": "http://169.254.169.254/"}"#, 2)
            .expect_err("a blocked URL is a NACK");
        let warns = b.recorder.warns();
        assert!(
            warned(&b, &["webrequest: configure() rejected:"]),
            "{warns:?}"
        );
    }
}

#[test]
fn stale_configures_preserve_the_whole_target_and_diagnostics() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url":"{URL}","timeout_ms":2000}}"#))
            .unwrap();
        assert_eq!(
            b.configure(
                r#"{"url":"http://127.0.0.2:8123/moved","timeout_ms":777}"#,
                8
            ),
            Ok(8)
        );
        let live = b.status();
        for settings in [
            r#"{"url":"http://127.0.0.3:8124/stale","timeout_ms":333}"#,
            r#"{"url":"ftp://bad.example/","timeout_ms":"bad"}"#,
        ] {
            assert_eq!(b.configure(settings, 7), Ok(7));
            assert_eq!(b.status(), live);
            assert!(b.recorder.warns().is_empty(), "{:?}", b.recorder.warns());
        }
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        assert_eq!(b.upstream.last().target, "http://127.0.0.2:8123");
        assert!(b.configure(r#"{"url":"ftp://bad.example/"}"#, 9).is_err());
        assert_eq!(b.status(), live);
        assert_eq!(b.configure(r#"{"timeout_ms":888}"#, 9), Ok(9));
        assert_eq!(b.status()["status"]["settings"]["timeout_ms"], 888);
    }
}

#[test]
fn a_pending_op_keeps_its_opening_target_across_configure() {
    for arm in arms() {
        let b = arm.bind();
        b.open(r#"{"url":"http://127.0.0.1:9/old"}"#).unwrap();
        let ticket = b.dispatcher.mint(0).expect("a ticket");
        let view = decide_frame();
        let mut first = Frame::new(view.input(), blank_out::<DecideOut>());
        assert_eq!(
            b.plugin
                .call_inline(ticket, false, slot::DECIDE, &mut first)
                .outcome,
            Outcome::Pending
        );
        let original = b.upstream.last();
        assert_eq!(
            b.configure(r#"{"url":"http://127.0.0.2:8123/new"}"#, 2),
            Ok(2)
        );
        let mut resumed = Frame::new(view.input(), blank_out::<DecideOut>());
        let outcome = b
            .plugin
            .call_inline(ticket, true, slot::DECIDE, &mut resumed)
            .outcome;
        b.dispatcher.recycle(ticket);

        assert_eq!(outcome, Outcome::Ready);
        assert_eq!(resumed.out.verbs, VERB_ABSTAIN);
        assert_eq!(b.upstream.sent.lock().unwrap().as_slice(), &[original]);
        assert!(b.upstream.reads.lock().unwrap().is_empty());
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        let fresh = b.upstream.last();
        assert_eq!(fresh.target, "http://127.0.0.2:8123");
        assert_eq!(fresh.path, b"/new");
    }
}

#[test]
fn a_cancelled_op_does_not_pin_the_next_fresh_op_to_its_old_target() {
    for arm in arms() {
        let b = arm.bind();
        b.open(r#"{"url":"http://127.0.0.1:9/old"}"#).unwrap();
        let ticket = b.dispatcher.mint(0).expect("a ticket");
        let view = decide_frame();
        let mut first = Frame::new(view.input(), blank_out::<DecideOut>());
        assert_eq!(
            b.plugin
                .call_inline(ticket, false, slot::DECIDE, &mut first)
                .outcome,
            Outcome::Pending
        );
        assert_eq!(b.upstream.last().target, "http://127.0.0.1:9");
        assert_eq!(
            b.configure(r#"{"url":"http://127.0.0.2:8123/new"}"#, 2),
            Ok(2)
        );

        let cancel = || {
            let mut frame = Frame::new(
                CancelIn {
                    head: in_head(),
                    ticket,
                },
                blank_out::<CancelOut>(),
            );
            assert_eq!(
                b.plugin.call(life::CANCEL, &mut frame).outcome,
                Outcome::Ready
            );
        };
        cancel();
        let mut fresh = Frame::new(view.input(), blank_out::<DecideOut>());
        let outcome = b
            .plugin
            .call_inline(ticket, false, slot::DECIDE, &mut fresh)
            .outcome;
        let sent = b.upstream.last();
        cancel();
        b.dispatcher.recycle(ticket);

        assert_eq!(outcome, Outcome::Pending);
        assert_eq!(sent.target, "http://127.0.0.2:8123");
        assert_eq!(sent.path, b"/new");
        assert!(b.upstream.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn an_oversized_reply_is_refused_before_its_remaining_body_is_read() {
    let cap = busbar_hook_webrequest::reply::MAX_REPLY_BYTES;
    let mut body = vec![b' '; cap * 4];
    body[..2].copy_from_slice(b"{}");
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
        b.upstream.answer(200, "OK", &body[..cap]);
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        assert_eq!(b.upstream.body_bytes_read.load(Ordering::SeqCst), cap);

        b.upstream.body_bytes_read.store(0, Ordering::SeqCst);
        b.upstream.answer(200, "OK", &body);
        let failure = decide_failure(&b);
        assert!(
            failure.contains(&format!("response exceeded {cap} byte cap")),
            "{failure}"
        );
        assert!(b.upstream.body_bytes_read.load(Ordering::SeqCst) < body.len());
        assert!(b.upstream.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn error_statuses_keep_their_meaning_when_the_body_exceeds_the_cap() {
    let body = vec![b'x'; busbar_hook_webrequest::reply::MAX_REPLY_BYTES * 4];
    for arm in arms() {
        for (status, reason, expected) in [
            (503, "Busy", "HTTP status server error (503 Busy)"),
            (
                302,
                "Found",
                "redirect that was not followed (HTTP status 302)",
            ),
        ] {
            let b = arm.bind();
            b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
            b.upstream.answer(status, reason, &body);
            let failure = decide_failure(&b);
            assert!(failure.contains(expected), "{failure}");
            assert!(b.upstream.body_bytes_read.load(Ordering::SeqCst) < body.len());
            assert!(b.upstream.reads.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn a_notify_reads_the_status_without_collecting_the_response_body() {
    let body = vec![b'x'; busbar_hook_webrequest::reply::MAX_REPLY_BYTES * 4];
    for arm in arms() {
        for (status, reason) in [(200, "OK"), (503, "Busy")] {
            let b = arm.bind();
            b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
            b.upstream.answer(status, reason, &body);
            let tap = NotifyFrame::build(&request(), None, true);
            let done = b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head());
            assert_eq!(done.outcome, Outcome::Ready);
            assert_eq!(b.upstream.body_bytes_read.load(Ordering::SeqCst), 0);
            if status == 200 {
                assert!(b.recorder.warns().is_empty(), "{:?}", b.recorder.warns());
            } else {
                assert!(warned(&b, &["503", "notify dropped"]));
            }
            assert!(b.upstream.reads.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn remote_error_phrases_cannot_echo_live_target_credentials() {
    for arm in arms() {
        let b = arm.bind();
        b.open(r#"{"url":"http://user:hunter2@127.0.0.1:9/PATHCANARY?token=QUERYCANARY"}"#)
            .unwrap();
        b.upstream.answer(
            503,
            "denied hunter2 /PATHCANARY token=QUERYCANARY dXNlcjpodW50ZXIy",
            b"",
        );
        let failure = decide_failure(&b);
        let warns = b.recorder.warns();
        assert!(!warns.is_empty());
        for text in std::iter::once(&failure).chain(warns.iter()) {
            for secret in ["hunter2", "PATHCANARY", "QUERYCANARY", "dXNlcjpodW50ZXIy"] {
                assert!(!text.contains(secret), "{text}");
            }
        }
        assert!(
            failure.contains("503") && failure.contains("denied"),
            "{failure}"
        );
    }
}

#[test]
fn unknown_settings_cannot_forge_log_lines() {
    for arm in arms() {
        let b = arm.bind();
        b.open(r#"{"url":"http://127.0.0.1:9/hook","x\r\nBUSBAR-9999 forged":1}"#)
            .unwrap();
        assert_eq!(b.configure(r#"{"y\r\nBUSBAR-9999 forged":1}"#, 2), Ok(2));
        let warns = b.recorder.warns();
        assert_eq!(warns.len(), 2);
        for warning in warns {
            assert!(!warning.contains(['\r', '\n']), "{warning:?}");
            assert!(warning.contains("\\r\\n"), "{warning:?}");
            assert!(warning.contains("BUSBAR-9999 forged"), "{warning:?}");
        }
    }
}

#[test]
fn wrong_typed_open_settings_never_echo_credentials() {
    for arm in arms() {
        for bad in [
            r#"{"url":"http://127.0.0.1:9/","timeout_ms":"https://user:PASSCANARY@h/KEYCANARY"}"#,
            r#"{"url":["https://user:PASSCANARY@h/KEYCANARY"]}"#,
        ] {
            let b = arm.bind();
            let validation = busbar_plugin_loader::hook_door::validate(&b.plugin, bad.as_bytes())
                .expect_err("wrong type refuses validation");
            let error = b.open(bad).expect_err("wrong type refuses open");
            for text in [validation, error].into_iter().chain(b.recorder.warns()) {
                assert!(!text.contains("CANARY"), "{text}");
                assert!(!text.contains("user:"), "{text}");
            }
        }
    }
}

#[test]
fn ambiguous_authority_refusals_never_echo_a_credential_fragment() {
    for arm in arms() {
        for url in [
            "https://user:pw/PREFIXCANARY@QUERYCANARY?token=TAILCANARY",
            "https://user:pw?token=PREFIXCANARY@QUERYCANARY",
            "SCHEMECANARY:password@host/path",
        ] {
            let b = arm.bind();
            let settings = serde_json::json!({"url":url}).to_string();
            let error = b.open(&settings).expect_err("ambiguous URL refused");
            assert!(error.contains("ambiguous"), "{error}");
            assert!(!error.contains("CANARY"), "{error}");
            let b = arm.bind();
            b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
            assert!(b.configure(&settings, 2).is_err());
            let warns = b.recorder.warns();
            assert!(!warns.is_empty());
            for text in warns {
                assert!(!text.contains("CANARY"), "{text}");
            }
        }
    }
}

/// RED: a settings key the forwarder does not read is not refused (1.5.5 ignored it, so a 1.5.5
/// document still opens), and not silent either: `open` and an acknowledged `configure` each log
/// it by name.
#[test]
fn red_an_unknown_setting_is_ignored_and_logged() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}", "timeout": 100}}"#))
            .expect("an unknown key opens, as in 1.5.5");
        assert!(
            warned(&b, &["webrequest: ignoring unknown setting 'timeout'"]),
            "{:?}",
            b.recorder.warns()
        );
        assert_eq!(
            b.configure(r#"{"timeout_ms": 900, "retries": 3}"#, 2),
            Ok(2)
        );
        assert!(
            warned(&b, &["webrequest: ignoring unknown setting 'retries'"]),
            "{:?}",
            b.recorder.warns()
        );
    }
}

/// RED: an error status FAILS the decide (not an abstain), and the reason is logged.
#[test]
fn red_a_failed_decide_fails_and_is_logged() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
        b.upstream.answer(503, "Busy", b"");
        let failed = decide_failure(&b);
        assert!(failed.contains("HTTP status server error (503"), "{failed}");
        let warns = b.recorder.warns();
        assert!(
            warned(&b, &["HTTP status server error (503", "decide failed"]),
            "{warns:?}"
        );
    }
}

/// RED: a transport failure (the exchange cannot establish) reaches the plugin as a failure it
/// answers itself: the decide FAILS with the request failure, which is logged; a transform against
/// a dead target fails too.
#[test]
fn red_a_transport_failure_fails_and_is_logged() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
        b.upstream.fail_open.store(true, Ordering::SeqCst);
        // The host's cause rides after the 1.5.5 prefix, not only the prefix.
        let failed = decide_failure(&b);
        assert!(
            failed.starts_with("webrequest: request failed: error sending request: "),
            "{failed}"
        );
        let warns = b.recorder.warns();
        assert!(
            warned(
                &b,
                &[
                    "webrequest: request failed: error sending request: ",
                    "decide failed"
                ]
            ),
            "{warns:?}"
        );
        let failed = transform_failure(&b);
        assert!(
            failed.starts_with("webrequest: request failed: error sending request: "),
            "{failed}"
        );
    }
}

/// RED: no diagnostic carries the URL's userinfo or query, through a configure refusal, an error
/// status and a failed open.
#[test]
fn red_the_log_never_leaks_the_url_secrets() {
    for arm in arms() {
        let b = arm.bind();
        b.open(r#"{"url": "http://user:hunter2@127.0.0.1:9/hook?token=SECRET123"}"#)
            .expect("opens");
        b.configure(r#"{"timeout_ms": "soon"}"#, 2)
            .expect_err("a bad timeout is a NACK");
        b.upstream.answer(503, "Busy", b"");
        decide_failure(&b);
        b.upstream.fail_open.store(true, Ordering::SeqCst);
        decide_failure(&b);
        // Guard against a vacuous pass: the three refusals were logged.
        let warns = b.recorder.warns();
        assert!(warns.len() >= 3, "{warns:?}");
        let all = format!("{:?}", b.recorder.diags.lock().unwrap());
        assert!(!all.contains("hunter2"), "{all}");
        assert!(!all.contains("SECRET123"), "{all}");
        // Nor the Authorization the userinfo becomes (base64 of `user:hunter2`).
        assert!(!all.contains("dXNlcjpodW50ZXIy"), "{all}");
    }
}

/// GREEN twin: a successful decide logs no warning.
#[test]
fn a_successful_decide_logs_no_warning() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
        b.upstream.answer(200, "OK", br#"{"order":[9,3]}"#);
        assert_eq!(decide_verbs(&b) & VERB_PREFER, VERB_PREFER);
        assert!(b.recorder.warns().is_empty(), "{:?}", b.recorder.warns());
    }
}

/// A committed configure moves the NEXT op's origin, path and timeout: the target is read per op,
/// never cached at open.
#[test]
fn a_committed_configure_moves_the_next_decide() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}", "timeout_ms": 2000}}"#))
            .expect("opens");
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        assert_eq!(b.upstream.last().target, "http://127.0.0.1:9");
        assert_eq!(
            b.configure(
                r#"{"url": "http://127.0.0.2:8123/moved?y=2", "timeout_ms": 777}"#,
                2
            ),
            Ok(2)
        );
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        let sent = b.upstream.last();
        assert_eq!(sent.target, "http://127.0.0.2:8123");
        assert_eq!(sent.path, b"/moved?y=2".to_vec());
        assert_eq!(sent.timeout_ms, 777);
    }
}

/// RED: a `timeout_ms` outside `[1, 5000]` is clamped and says so, at `open` and at `configure`.
#[test]
fn red_a_clamped_timeout_is_warned() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}", "timeout_ms": 99999}}"#))
            .expect("opens");
        assert!(
            warned(&b, &["timeout_ms", "99999", "clamp"]),
            "{:?}",
            b.recorder.warns()
        );
        assert_eq!(b.configure(r#"{"timeout_ms": 0}"#, 2), Ok(2));
        assert!(
            warned(&b, &["timeout_ms", "0", "clamp"]),
            "{:?}",
            b.recorder.warns()
        );
        assert_eq!(b.status()["status"]["settings"]["timeout_ms"], json!(1));
    }
}

/// RED: a notify the far end acknowledged with a `204` (or any 2xx/3xx, whatever the body) is
/// delivered and logs nothing; an error status still warns.
#[test]
fn red_a_notify_acknowledged_without_a_body_logs_no_warning() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
        let tap = NotifyFrame::build(&request(), None, true);
        for (status, reason) in [(204, "No Content"), (200, "OK"), (302, "Found")] {
            b.upstream.answer(status, reason, b"");
            let done = b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head());
            assert_eq!(done.outcome, Outcome::Ready);
        }
        assert!(b.recorder.warns().is_empty(), "{:?}", b.recorder.warns());
        b.upstream.answer(503, "Busy", b"");
        let done = b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head());
        assert_eq!(done.outcome, Outcome::Ready);
        assert!(
            warned(&b, &["503", "notify dropped"]),
            "{:?}",
            b.recorder.warns()
        );
    }
}

/// A loopback sidecar by its IPv6 literal opens through the door: `http://[::1]:9000/` is the
/// plaintext carve-out, and reaches the host as the bracketed origin.
#[test]
fn an_ipv6_loopback_sidecar_opens_and_is_dialled_by_its_bracketed_origin() {
    for arm in arms() {
        let b = arm.bind();
        b.open(r#"{"url": "http://[::1]:9000/hook"}"#)
            .expect("[::1] is the loopback carve-out");
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        assert_eq!(b.upstream.last().target, "http://[::1]:9000");
    }
}

/// RED: only a `204` is an abstaining "no opinion"; an empty body on a `200` is a FAILED decide.
#[test]
fn red_only_a_204_is_an_empty_abstain() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
        b.upstream.answer(204, "No Content", b"");
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        b.upstream.answer(200, "OK", b"");
        let failed = decide_failure(&b);
        assert!(failed.contains("empty reply (HTTP status 200)"), "{failed}");
    }
}

#[test]
fn concurrent_partial_configures_merge_through_both_loaded_doors() {
    const SHARED_VERSION: u64 = 2;
    const MERGED_TIMEOUT_MS: u64 = 777;
    const MOVED_URL: &str = "http://127.0.0.2:8123/moved";
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let url = scope.spawn(|| {
                start.wait();
                b.configure(&json!({"url": MOVED_URL}).to_string(), SHARED_VERSION)
            });
            let timeout = scope.spawn(|| {
                start.wait();
                b.configure(
                    &json!({"timeout_ms": MERGED_TIMEOUT_MS}).to_string(),
                    SHARED_VERSION,
                )
            });
            assert_eq!(url.join().unwrap(), Ok(SHARED_VERSION));
            assert_eq!(timeout.join().unwrap(), Ok(SHARED_VERSION));
        });
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        let sent = b.upstream.last();
        assert_eq!(sent.target, "http://127.0.0.2:8123");
        assert_eq!(sent.path, b"/moved");
        assert_eq!(sent.timeout_ms, MERGED_TIMEOUT_MS);
        assert_eq!(
            b.status()["status"]["settings"]["timeout_ms"],
            MERGED_TIMEOUT_MS
        );
        assert!(b.recorder.warns().is_empty(), "{:?}", b.recorder.warns());
    }
}

#[test]
fn complete_checkpoints_keep_empty_null_stale_and_refused_pushes_through_both_doors() {
    const CURRENT_VERSION: u64 = 8;
    const STALE_VERSION: u64 = CURRENT_VERSION - 1;
    const NEXT_VERSION: u64 = CURRENT_VERSION + 1;
    const MOVED_URL: &str = "http://127.0.0.2:8123/moved";
    const MERGED_TIMEOUT_MS: u64 = 777;
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
        let (_, first) = b
            .configure_snapshot(&json!({"url": MOVED_URL}).to_string(), CURRENT_VERSION)
            .unwrap();
        let first = first.expect("an acknowledged configure returns complete settings");
        let (_, second) = b
            .configure_snapshot(
                &json!({"timeout_ms": MERGED_TIMEOUT_MS}).to_string(),
                CURRENT_VERSION,
            )
            .unwrap();
        let second = second.expect("equal-version partial update returns complete settings");
        assert!(second.0 > first.0);
        let expected = json!({"url": MOVED_URL, "timeout_ms": MERGED_TIMEOUT_MS});
        assert_eq!(second.1, CURRENT_VERSION);
        assert_eq!(second.2, expected);
        let (_, empty) = b.configure_snapshot("{}", NEXT_VERSION).unwrap();
        let empty = empty.expect("empty push keeps complete effective settings");
        assert!(empty.0 > second.0);
        assert_eq!(empty.2, expected);
        let (_, null) = b
            .configure_snapshot(r#"{"timeout_ms":null}"#, NEXT_VERSION)
            .unwrap();
        let null = null.expect("null timeout keeps complete effective settings");
        assert!(null.0 > empty.0);
        assert_eq!(null.2, expected);
        let (_, stale) = b
            .configure_snapshot(r#"{"url":false}"#, STALE_VERSION)
            .unwrap();
        assert_eq!(
            stale,
            Some(null.clone()),
            "stale ACK retains the effective version and revision"
        );
        assert!(b
            .configure(r#"{"timeout_ms":false}"#, NEXT_VERSION)
            .is_err());
        let (_, after_refusal) = b
            .configure_snapshot(r#"{"url":false}"#, STALE_VERSION)
            .unwrap();
        assert_eq!(
            after_refusal,
            Some(null.clone()),
            "NACK leaves the checkpoint unchanged"
        );
        let restored = arm.bind();
        restored.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
        assert_eq!(restored.configure(&null.2.to_string(), null.1), Ok(null.1));
        assert_eq!(decide_verbs(&restored), VERB_ABSTAIN);
        let sent = restored.upstream.last();
        assert_eq!(sent.target, "http://127.0.0.2:8123");
        assert_eq!(sent.path, b"/moved");
        assert_eq!(sent.timeout_ms, MERGED_TIMEOUT_MS);
    }
}

#[test]
fn wrong_typed_configure_settings_never_echo_credentials_or_change_the_target() {
    const PUSH_VERSION: u64 = 2;
    const SECRET_MARKER: &str = "CONFIGURECANARY";
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
        let original = b.status();
        for bad in [
            r#"{"url":"http://127.0.0.2:8123/new","timeout_ms":"https://user:CONFIGURECANARY@h/key"}"#,
            r#"{"url":["https://user:CONFIGURECANARY@h/key"],"timeout_ms":777}"#,
        ] {
            let error = b
                .configure(bad, PUSH_VERSION)
                .expect_err("wrong type is a NACK");
            for text in std::iter::once(error).chain(b.recorder.warns()) {
                assert!(!text.contains(SECRET_MARKER), "{text}");
                assert!(!text.contains("user:"), "{text}");
            }
            assert_eq!(
                b.status(),
                original,
                "a refused partial push commits neither field"
            );
        }
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        let sent = b.upstream.last();
        assert_eq!(sent.target, "http://127.0.0.1:9");
        assert_eq!(sent.path, b"/hook?x=1");
    }
}

#[test]
fn a_pending_failure_scrubs_the_original_target_after_configure_through_both_doors() {
    const ORIGINAL_URL: &str = "http://user:OLDPASSWORD@127.0.0.1:9/OLDPATH?token=OLDQUERY";
    const MOVED_URL: &str = "http://next:NEWPASSWORD@127.0.0.2:8123/NEWPATH?token=NEWQUERY";
    const CONFIGURE_VERSION: u64 = 2;
    const SERVICE_UNAVAILABLE: u32 = 503;
    const FAILURE_PHRASE: &str =
        "denied OLDPASSWORD /OLDPATH token=OLDQUERY dXNlcjpPTERQQVNTV09SRA==";
    const OLD_SECRETS: [&str; 4] = [
        "OLDPASSWORD",
        "OLDPATH",
        "OLDQUERY",
        "dXNlcjpPTERQQVNTV09SRA==",
    ];
    for arm in arms() {
        let b = arm.bind();
        b.open(&json!({"url": ORIGINAL_URL}).to_string()).unwrap();
        b.upstream.answer(SERVICE_UNAVAILABLE, FAILURE_PHRASE, b"");
        let ticket = b.dispatcher.mint(0).expect("a ticket");
        let view = decide_frame();
        let mut first = Frame::new(view.input(), blank_out::<DecideOut>());
        assert_eq!(
            b.plugin
                .call_inline(ticket, false, slot::DECIDE, &mut first)
                .outcome,
            Outcome::Pending
        );
        assert_eq!(
            b.configure(&json!({"url": MOVED_URL}).to_string(), CONFIGURE_VERSION),
            Ok(CONFIGURE_VERSION)
        );
        let mut resumed = Frame::new(view.input(), blank_out::<DecideOut>());
        let called = b
            .plugin
            .call_inline(ticket, true, slot::DECIDE, &mut resumed);
        b.dispatcher.recycle(ticket);
        assert_eq!(called.outcome, Outcome::Failed);
        let error = error_of(called.error.as_deref());
        assert!(error.contains("503") && error.contains("denied"), "{error}");
        let warns = b.recorder.warns();
        assert!(!warns.is_empty());
        for text in std::iter::once(&error).chain(warns.iter()) {
            for secret in OLD_SECRETS {
                assert!(!text.contains(secret), "{text}");
            }
        }
        assert_eq!(
            b.upstream.sent.lock().unwrap().len(),
            1,
            "resume does not resend to the new target"
        );
        assert!(b.upstream.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn refresh_during_pending_retains_the_opening_target_until_completion_or_cancel() {
    const ORIGINAL_URL: &str = "http://127.0.0.1:9/old";
    const REFRESHED_URL: &str = "http://127.0.0.2:8123/refreshed";
    const REFRESHED_GENERATION: u64 = 2;
    enum Finish {
        Resume,
        Cancel,
    }
    for arm in arms() {
        for finish in [Finish::Resume, Finish::Cancel] {
            let b = arm.bind();
            b.open(&json!({"url": ORIGINAL_URL}).to_string()).unwrap();
            let ticket = b.dispatcher.mint(0).expect("a ticket");
            let view = decide_frame();
            let mut first = Frame::new(view.input(), blank_out::<DecideOut>());
            assert_eq!(
                b.plugin
                    .call_inline(ticket, false, slot::DECIDE, &mut first)
                    .outcome,
                Outcome::Pending
            );
            let original = b.upstream.last();
            let settings = json!({"url": REFRESHED_URL}).to_string();
            let mut refresh = Frame::new(
                RefreshIn {
                    head: in_head(),
                    generation: REFRESHED_GENERATION,
                    settings: json_blob(&settings),
                    secrets: std::ptr::null(),
                    secrets_len: 0,
                },
                out_head(),
            );
            assert_eq!(
                b.plugin.call(life::REFRESH, &mut refresh).outcome,
                Outcome::Ready
            );
            match finish {
                Finish::Resume => {
                    let mut resumed = Frame::new(view.input(), blank_out::<DecideOut>());
                    assert_eq!(
                        b.plugin
                            .call_inline(ticket, true, slot::DECIDE, &mut resumed)
                            .outcome,
                        Outcome::Ready
                    );
                    assert_eq!(resumed.out.verbs, VERB_ABSTAIN);
                }
                Finish::Cancel => {
                    let mut cancel = Frame::new(
                        CancelIn {
                            head: in_head(),
                            ticket,
                        },
                        blank_out::<CancelOut>(),
                    );
                    assert_eq!(
                        b.plugin.call(life::CANCEL, &mut cancel).outcome,
                        Outcome::Ready
                    );
                    assert_eq!(
                        cancel.out.disposition,
                        busbar_contract::abi::hook::cancel::ABORTED
                    );
                }
            }
            b.dispatcher.recycle(ticket);
            assert_eq!(b.upstream.sent.lock().unwrap().as_slice(), &[original]);
            assert!(b.upstream.reads.lock().unwrap().is_empty());
            assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
            let fresh = b.upstream.last();
            assert_eq!(fresh.target, "http://127.0.0.2:8123");
            assert_eq!(fresh.path, b"/refreshed");
        }
    }
}
