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
//! that names a blocked URL is a NACK and leaves the live target; a far end's error status is a
//! FAILED `decide` and a FAILED `transform` (the operator's `on_error` applies;
//! SIGN-hookexport-webrequest-failure), while a deliberate `{}` reply stays an abstain; and the
//! Statement declares exactly one need, outbound, in the loopback-allowed egress class, over the
//! host's `http` framer.
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
    VERB_ABSTAIN, VERB_PREFER, VERB_REWRITE,
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

const CONFIGURATION_CHECKPOINT_KEY: &str = "hook.configure_checkpoint.v1";
const CONFIGURATION_WORD_BYTES: usize = std::mem::size_of::<u64>();
const CONFIGURATION_CHECKPOINT_PREFIX_BYTES: usize = CONFIGURATION_WORD_BYTES * 2;
type ConfigurationSnapshot = (u64, u64, Value);

/// The freshly built actual forwarder image selected by CI.
fn cdylib() -> PathBuf {
    let path = std::env::var_os("BUSBAR_PLUGIN_CDYLIB")
        .map(PathBuf::from)
        .expect("set BUSBAR_PLUGIN_CDYLIB to the freshly built forwarder image");
    assert!(
        path.is_absolute() && path.is_file(),
        "actual forwarder cdylib required: {}",
        path.display()
    );
    path
}

/// The door's Statement rendering, as the pack tool signs it into the manifest.
fn stated() -> Vec<u8> {
    rendering_of(busbar_hook_webrequest::door).expect("the door renders its Statement")
}

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
        self.bind_mode(false)
    }

    fn bind_real(&self) -> Bound {
        self.bind_mode(true)
    }

    fn bind_mode(&self, real: bool) -> Bound {
        self.bind_over(real, None, false)
    }
    fn bind_over(&self, real: bool, anchors: Option<&str>, guarded: bool) -> Bound {
        let dispatcher = Arc::new(Dispatcher::with_services(
            DispatchConfig {
                workers: 2,
                ..Default::default()
            },
            Arc::new(
                busbar_kernel::host_services::KernelServices::new()
                    .with_mono_clock(Arc::new(now_ns)),
            ),
            busbar_contract::services::test_caller_binding(),
        ));
        let upstream = Upstream::new();
        *upstream.wake.lock().unwrap() = Some(dispatcher.conn_waker());
        let conns: Arc<dyn DeclaredConns> = if real {
            real_connector(dispatcher.conn_waker(), anchors, guarded)
        } else {
            upstream.clone()
        };
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
                &LinkedRow::of(busbar_hook_webrequest::door).expect("the row renders"),
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
        let entered = self.plugin.test_invocations().0;
        let resumed = self.plugin.test_invocations().1;
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
        let entries = self.plugin.test_invocations().0 - entered;
        let resumes = self.plugin.test_invocations().1 - resumed;
        assert_eq!(
            entries - resumes,
            1,
            "one initial hook entry, with every continuation counted separately"
        );
        assert_eq!(
            self.dispatcher.stats().deadline_without_wake,
            0,
            "a pending hook must arrange its wake"
        );
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
/// forwarder did (the projection's keys in order, then `op` last).
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
    let Value::Object(projection) = projection else {
        panic!("the projection is an object")
    };
    // 1.5.5 dropped any projected `op` and wrote its own last.
    let projection: serde_json::Map<String, Value> = projection
        .into_iter()
        .filter(|(key, _)| key != "op")
        .collect();
    assert!(!projection.is_empty(), "the projection carries the request");
    let mut body = serde_json::to_vec(&projection).expect("the envelope serializes");
    assert_eq!(body.pop(), Some(b'}'));
    body.extend_from_slice(format!(r#","op":"{op}"}}"#).as_bytes());
    body
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

/// Drive one arm through the whole script; its transcript.
fn script(arm: &Arm) -> Vec<String> {
    let mut t = Vec::new();
    let b = arm.bind();

    for (bad, words) in [
        (r#"{"url": ""}"#, "webrequest: settings.url is required"),
        ("{}", "webrequest: settings.url is required"),
        (r#"{"url": 5}"#, "webrequest: invalid plugin config"),
        (
            r#"{"url": "http://169.254.169.254/"}"#,
            "cloud-metadata host (SSRF guard",
        ),
        (r#"{"url": "https://169.254.169.254/"}"#, "SSRF guard"),
    ] {
        let refused = arm.bind().open(bad).expect_err("refused");
        assert!(refused.contains(words), "{bad}: {refused}");
        t.push(format!("open {bad}: refused"));
    }

    let settings = format!(r#"{{"url": "{URL}", "timeout_ms": 2000}}"#);
    b.open(&settings).expect("the forwarder opens");

    let d = b.describe();
    assert_eq!(d["schema"]["required"], json!(["url"]));
    let s = b.status();
    assert_eq!(s["status"]["settings"]["target_host"], json!("127.0.0.1"));
    assert_eq!(s["status"]["settings"]["timeout_ms"], json!(2000));
    t.push(format!("status {s}"));

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

    b.upstream.answer(503, "Busy", b"");
    let failed = decide_failure(&b);
    assert!(failed.contains("HTTP status server error (503"), "{failed}");
    assert_eq!(b.upstream.last(), expected("decide"));
    t.push("decide 503: failed".into());
    b.upstream.answer(200, "OK", b"{}");
    assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
    t.push("decide {}: abstain".into());

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

    let tap = NotifyFrame::build(&request(), None, true);
    b.upstream.answer(200, "OK", b"{}");
    let done = b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head());
    assert_eq!(done.outcome, Outcome::Ready);
    assert_eq!(b.upstream.last(), expected("notify"));
    t.push("notify: ready".into());

    assert_eq!(b.configure(r#"{"timeout_ms": 100}"#, 7), Ok(7));
    let nack = b
        .configure(r#"{"url": "https://169.254.169.254/"}"#, 9)
        .expect_err("a blocked https URL is a NACK too");
    assert!(
        nack.contains("configure() rejected: settings.url") && nack.contains("SSRF guard"),
        "{nack}"
    );
    let nack = b
        .configure(r#"{"url": "http://169.254.169.254/"}"#, 8)
        .expect_err("a blocked URL is a NACK");
    assert!(
        nack.contains("configure() rejected: settings.url") && nack.contains("SSRF guard"),
        "{nack}"
    );
    let s = b.status();
    assert_eq!(s["status"]["settings"]["timeout_ms"], json!(100));
    assert_eq!(s["status"]["settings"]["target_host"], json!("127.0.0.1"));
    t.push(format!("configure: ack 7, nack 8, nack 9; status {s}"));

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

#[test]
fn red_the_statement_declares_one_outbound_loopback_allowed_http_need() {
    let read = rendering::read(&stated()).expect("the rendering reads");
    assert_eq!(read.needs.len(), 1);
    let need = &read.needs[0];
    assert_eq!(need.direction, DIRECTION_OUTBOUND);
    assert_eq!(need.egress_class, EGRESS_LOOPBACK_ALLOWED);
    assert_eq!(need.transport, "http");
    assert!(need.target_from.is_empty());

    let dropped = busbar_plugin_loader::dispatch::rendering_of_library(&cdylib())
        .expect("the cdylib opens")
        .expect("the cdylib exports the door");
    assert_eq!(dropped, stated());
}

#[test]
fn red_the_statement_states_the_alias_rewrite() {
    let read = rendering::read(&stated()).expect("the rendering reads");
    assert_eq!(read.rewrites.len(), 1, "{:?}", read.rewrites);
    assert_eq!(read.rewrites[0].0, 1, "an alias rewrite");
    assert_eq!(read.rewrites[0].1, "webrequest");
}

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
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}", "timeout_ms": 99999}}"#))
            .expect("opens");

        assert!(
            warned(&b, &["timeout_ms", "clamp", "BUSBAR-7154"]),
            "{:?}",
            b.recorder.warns()
        );

        b.configure(r#"{"url": "http://169.254.169.254/"}"#, 2)
            .expect_err("a blocked URL is a NACK");
        assert!(
            warned(&b, &["configure() rejected:", "BUSBAR-7153"]),
            "{:?}",
            b.recorder.warns()
        );

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

        let tap = NotifyFrame::build(&request(), None, true);
        b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head());
        assert!(
            warned(&b, &["notify dropped", "BUSBAR-7152"]),
            "{:?}",
            b.recorder.warns()
        );
    }
}

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

fn arms() -> [Arm; 2] {
    [Arm::Linked, Arm::Dropped(cdylib())]
}

#[test]
fn non_success_statuses_fail_through_both_doors() {
    for arm in arms() {
        for status in [600, 999] {
            let b = arm.bind();
            b.open(&format!(r#"{{"url":"{URL}"}}"#)).unwrap();
            b.upstream.answer(
                status,
                "Custom",
                br#"{"reject":{"status":403,"message":"no"}}"#,
            );
            assert!(decide_failure(&b).contains("non-success HTTP status"));
            b.upstream.answer(
                status,
                "Custom",
                br#"{"rewrite":{"messages":[{"role":"user","content":"changed"}]}}"#,
            );
            assert!(transform_failure(&b).contains("non-success HTTP status"));
            b.upstream.answer(status, "Custom", b"{}");
            assert!(decide_failure(&b).contains("non-success HTTP status"));
            let tap = NotifyFrame::build(&request(), None, true);
            let done = b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head());
            assert_eq!(done.outcome, Outcome::Ready);
            assert!(warned(&b, &["non-success HTTP status", "notify dropped"]));
            assert!(b.upstream.reads.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn invalid_decoded_userinfo_refuses_open_and_configure_through_both_doors() {
    for arm in arms() {
        for url in [
            "http://user%FF:password-canary@127.0.0.1:9/hook",
            "http://user:password-canary%FF@127.0.0.1:9/hook",
            "http://:%FF@127.0.0.1:9/hook",
        ] {
            let b = arm.bind();
            let settings = serde_json::json!({"url":url,"timeout_ms":777}).to_string();
            let refused = b.open(&settings).unwrap_err();
            assert!(refused.contains("valid UTF-8"), "{refused}");
            assert!(!refused.contains("password-canary"), "{refused}");
            assert!(b.upstream.sent.lock().unwrap().is_empty());

            let b = arm.bind();
            b.open(&format!(r#"{{"url":"{URL}","timeout_ms":2000}}"#))
                .unwrap();
            let original = b.status();
            let refused = b.configure(&settings, 2).unwrap_err();
            assert!(refused.contains("valid UTF-8"), "{refused}");
            assert!(!refused.contains("password-canary"), "{refused}");
            assert_eq!(b.status(), original);
            assert!(b.upstream.sent.lock().unwrap().is_empty());
            assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
            assert_eq!(b.upstream.last().target, "http://127.0.0.1:9");
            assert_eq!(b.upstream.last().timeout_ms, 2000);
            assert!(b
                .recorder
                .warns()
                .iter()
                .all(|line| !line.contains("password-canary")));
        }
    }
}

#[test]
fn valid_userinfo_keeps_its_complete_authorization_through_both_doors() {
    for arm in arms() {
        for (userinfo, expected) in [
            ("user:password", "Basic dXNlcjpwYXNzd29yZA=="),
            ("user:", "Basic dXNlcjo="),
            (":password", "Basic OnBhc3N3b3Jk"),
            ("user:pa%3Ass", "Basic dXNlcjpwYTpzcw=="),
            ("us%C3%A9r:p%C3%A4ss", "Basic dXPDqXI6cMOkc3M="),
        ] {
            let b = arm.bind();
            b.open(
                &serde_json::json!({"url":format!("http://{userinfo}@127.0.0.1:9/hook")})
                    .to_string(),
            )
            .unwrap();
            assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
            let sent = b.upstream.last();
            let authorization = sent
                .fields
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.as_slice());
            assert_eq!(authorization, Some(expected.as_bytes()), "{userinfo}");
            assert!(b.recorder.warns().is_empty());
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
        let inline = b
            .dispatcher
            .inline_ticket()
            .expect("an authenticated inline ticket");
        let ticket = inline.ticket();
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
        drop(inline);

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
        let inline = b
            .dispatcher
            .inline_ticket()
            .expect("an authenticated inline ticket");
        let ticket = inline.ticket();
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
        drop(inline);

        assert_eq!(outcome, Outcome::Pending);
        assert_eq!(sent.target, "http://127.0.0.2:8123");
        assert_eq!(sent.path, b"/new");
        assert!(b.upstream.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn an_oversized_reply_is_refused_before_its_remaining_body_is_read() {
    let cap = 64 * 1024;
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
        let read = b.upstream.body_bytes_read.load(Ordering::SeqCst);
        assert!(
            read <= 2 * cap,
            "{read} body bytes read past a {cap} byte cap"
        );
        assert!(b.upstream.reads.lock().unwrap().is_empty());
    }
}

#[test]
fn error_statuses_keep_their_meaning_when_the_body_exceeds_the_cap() {
    let body = vec![b'x'; (64 * 1024) * 4];
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
            let read = b.upstream.body_bytes_read.load(Ordering::SeqCst);
            assert!(
                read <= 2 * (64 * 1024),
                "{read} body bytes read past the cap"
            );
            assert!(b.upstream.reads.lock().unwrap().is_empty());
        }
    }
}

#[test]
fn a_notify_reads_the_status_without_collecting_the_response_body() {
    let body = vec![b'x'; (64 * 1024) * 4];
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

#[test]
fn red_a_transport_failure_fails_and_is_logged() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
        b.upstream.fail_open.store(true, Ordering::SeqCst);

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

        let warns = b.recorder.warns();
        assert!(warns.len() >= 3, "{warns:?}");
        let all = format!("{:?}", b.recorder.diags.lock().unwrap());
        assert!(!all.contains("hunter2"), "{all}");
        assert!(!all.contains("SECRET123"), "{all}");

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
        b.upstream.answer(200, "OK", b"{}");
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
        assert_eq!(
            b.upstream.last().timeout_ms,
            5_000,
            "the exchange carries the clamped timeout, not the written one"
        );
        assert_eq!(b.configure(r#"{"timeout_ms": 0}"#, 2), Ok(2));
        assert!(
            warned(&b, &["timeout_ms 0 ", "clamped to 1"]),
            "{:?}",
            b.recorder.warns()
        );
        assert_eq!(b.status()["status"]["settings"]["timeout_ms"], json!(0));
    }
}

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

/// An empty reply is a failure whatever its status, a `204` included, as the 1.5.5 client failed to
/// parse it (busbar 1.5.5 `docs/hooks.md`: an "abstain via 204" fails under `on_error: reject`); only
/// a deliberate `{}` abstains.
#[test]
fn red_an_empty_reply_fails_whatever_its_status() {
    for arm in arms() {
        let b = arm.bind();
        b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
        for (status, reason) in [(204, "No Content"), (200, "OK")] {
            b.upstream.answer(status, reason, b"");
            let failed = decide_failure(&b);
            assert!(
                failed.contains(&format!("empty reply (HTTP status {status})")),
                "{failed}"
            );
            let failed = transform_failure(&b);
            assert!(
                failed.contains(&format!("empty reply (HTTP status {status})")),
                "{failed}"
            );
        }
        b.upstream.answer(200, "OK", b"{}");
        assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
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
        let inline = b
            .dispatcher
            .inline_ticket()
            .expect("an authenticated inline ticket");
        let ticket = inline.ticket();
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
        drop(inline);
        assert_eq!(called.outcome, Outcome::Failed);
        let error = error_of(called.error.as_deref());
        assert!(
            error.contains(&SERVICE_UNAVAILABLE.to_string()) && error.contains("denied"),
            "{error}"
        );
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
            let inline = b
                .dispatcher
                .inline_ticket()
                .expect("an authenticated inline ticket");
            let ticket = inline.ticket();
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
            drop(inline);
            assert_eq!(b.upstream.sent.lock().unwrap().as_slice(), &[original]);
            assert!(b.upstream.reads.lock().unwrap().is_empty());
            assert_eq!(decide_verbs(&b), VERB_ABSTAIN);
            let fresh = b.upstream.last();
            assert_eq!(fresh.target, "http://127.0.0.2:8123");
            assert_eq!(fresh.path, b"/refreshed");
        }
    }
}

#[test]
fn bare_query_values_and_path_keys_never_escape_any_operation_or_the_pending_target() {
    const OLD: &str = "http://127.0.0.1:9/v1/PATHONLYCANARY?token=QUERYONLYCANARY&other=RAW%2BCANARY&form=PLUS+CANARY";
    const MOVED: &str = "http://127.0.0.2:8123/v1/NEWPATH?token=NEWQUERY";
    const PHRASE: &str =
        "denied PATHONLYCANARY QUERYONLYCANARY RAW%2BCANARY RAW+CANARY PLUS+CANARY PLUS CANARY";
    const SECRETS: [&str; 6] = [
        "PATHONLYCANARY",
        "QUERYONLYCANARY",
        "RAW%2BCANARY",
        "RAW+CANARY",
        "PLUS+CANARY",
        "PLUS CANARY",
    ];
    for arm in arms() {
        let b = arm.bind();
        b.open(&json!({"url":OLD}).to_string()).unwrap();
        b.upstream.answer(503, PHRASE, b"");
        for text in [decide_failure(&b), transform_failure(&b)] {
            assert!(text.contains("503") && text.contains("denied"));
            for secret in SECRETS {
                assert!(!text.contains(secret), "{text}");
            }
        }
        let tap = NotifyFrame::build(&request(), None, true);
        assert_eq!(
            b.submit::<NotifyIn, OutHead>(slot::NOTIFY, tap.input(), out_head())
                .outcome,
            Outcome::Ready
        );
        let inline = b
            .dispatcher
            .inline_ticket()
            .expect("an authenticated inline ticket");
        let ticket = inline.ticket();
        let view = decide_frame();
        let mut first = Frame::new(view.input(), blank_out::<DecideOut>());
        assert_eq!(
            b.plugin
                .call_inline(ticket, false, slot::DECIDE, &mut first)
                .outcome,
            Outcome::Pending
        );
        b.configure(&json!({"url":MOVED}).to_string(), 2).unwrap();
        let mut again = Frame::new(view.input(), blank_out::<DecideOut>());
        let failed = b.plugin.call_inline(ticket, true, slot::DECIDE, &mut again);
        assert_eq!(failed.outcome, Outcome::Failed);
        drop(inline);
        for text in std::iter::once(error_of(failed.error.as_deref())).chain(b.recorder.warns()) {
            for secret in SECRETS {
                assert!(!text.contains(secret), "{text}");
            }
        }
        assert!(b.upstream.reads.lock().unwrap().is_empty());
    }
}

/// The real HTTP framer and connector must honor the settings timeout after a prompt head: a reply
/// head followed by a silent partial body fails `decide` and `transform` at the configured 1000 ms
/// whole-request expiry (well before the dispatcher's own deadline), and the expired exchange
/// closes its socket.
#[test]
fn the_real_connector_cuts_a_silent_partial_body_at_the_configured_whole_timeout() {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Instant;
    for arm in arms() {
        for transform in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let (closed, observed_close) = std::sync::mpsc::channel();
            let server = std::thread::spawn(move || {
                let (mut socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(4)))
                    .unwrap();
                let mut request = Vec::new();
                let mut bytes = [0u8; 4096];
                loop {
                    let n = socket.read(&mut bytes).unwrap();
                    assert_ne!(n, 0, "the request arrives before the response");
                    request.extend_from_slice(&bytes[..n]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .unwrap()
                            .trim()
                            .parse::<usize>()
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                socket
                    .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n{")
                    .unwrap();

                let eof = matches!(socket.read(&mut bytes), Ok(0));
                closed.send(eof).unwrap();
            });
            let b = arm.bind_real();
            b.open(
                &json!({"url":format!("http://127.0.0.1:{port}/hook"),"timeout_ms":1000})
                    .to_string(),
            )
            .unwrap();
            let started = Instant::now();
            let failure = if transform {
                transform_failure(&b)
            } else {
                decide_failure(&b)
            };
            assert!(failure.contains("deadline passed"), "{failure}");
            assert!(
                started.elapsed() < Duration::from_millis(3500),
                "settings timeout was lost after the head"
            );
            assert!(
                observed_close.recv_timeout(Duration::from_secs(5)).unwrap(),
                "the expired exchange did not close its socket"
            );
            server.join().unwrap();
        }
    }
}

// The real connector used by this file’s loopback wire tests.
fn real_connector(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
    guarded: bool,
) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    use busbar_contract::transport::{EgressTrust, TransportSettings};
    use busbar_core_connector::doors::Dispatched;
    use busbar_core_connector::registry::{Entry, Transports};
    use busbar_core_connector::{Connector, Judged, Verdict};
    use busbar_plugin_loader::dispatch::kinds::transport::Transport;
    use std::net::{SocketAddr, ToSocketAddrs};
    use std::sync::OnceLock;

    static IO: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    let io = IO
        .get_or_init(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("response test reactor");
            let handle = rt.handle().clone();
            std::thread::spawn(move || rt.block_on(std::future::pending::<()>()));
            handle
        })
        .clone();
    busbar_core_connector::io::install_process_reactor(io.clone());
    static TRANSPORT_DISPATCHER: OnceLock<Arc<Dispatcher>> = OnceLock::new();
    let transport_dispatcher = Arc::clone(TRANSPORT_DISPATCHER.get_or_init(|| {
        // The nested transport doors consume request-head deadlines through CLOCK_NOW.
        // Give them the same real kernel clock services as the outer hook dispatcher.
        let dispatcher = Arc::new(Dispatcher::with_services(
            Default::default(),
            Arc::new(
                busbar_kernel::host_services::KernelServices::new()
                    .with_mono_clock(Arc::new(now_ns)),
            ),
            busbar_contract::services::test_caller_binding(),
        ));
        dispatcher.install_runtime(io);
        dispatcher.install_io(busbar_core_connector::hostio::process());
        dispatcher
    }));
    let mut entries = Vec::new();
    for (name, door) in [
        ("tcp", busbar_transport_tcp::linked::MACRO_DOOR),
        ("http", busbar_transport_http::MACRO_DOOR),
    ] {
        let row = LinkedRow::of_macro(door).expect("actual transport row states");
        let transport = load_linked::<Transport>(
            &row,
            Bind {
                instance: Arc::from(name),
                max_inflight_cap: 1024,
                sink: Arc::new(busbar_plugin_loader::dispatch::NoSink),
                dispatcher: transport_dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("actual transport loads");
        entries.push(Entry {
            door: Arc::new(
                Dispatched::open_on(
                    transport,
                    &TransportSettings::default(),
                    Arc::clone(&transport_dispatcher),
                )
                .expect("actual transport opens"),
            ),
            alpn: Vec::new(),
        });
    }
    let view = Transports::new(entries).expect("TCP and HTTP compose");
    use rustls::pki_types::pem::PemObject;
    let trust = EgressTrust {
        extra_anchors: anchors
            .map(|pem| {
                rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
                    .map(|cert| cert.expect("local CA PEM").to_vec())
                    .collect()
            })
            .unwrap_or_default(),
        ..Default::default()
    };
    let tls =
        busbar_core_connector::tls::client::build_client_config(&trust).expect("client TLS builds");
    let judge = |dest: &str, _: u32, _: Judged| -> Option<Result<SocketAddr, Verdict>> {
        Some(
            dest.to_socket_addrs()
                .ok()
                .and_then(|mut addresses| addresses.find(|a| a.is_ipv4() && a.ip().is_loopback()))
                .ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE),
        )
    };
    let judge: Arc<dyn busbar_core_connector::DialJudge> = if guarded {
        let config = busbar_kernel::config::Destinations {
            block_private_addresses:
                busbar_kernel::config::sections::DEFAULT_BLOCK_PRIVATE_ADDRESSES,
            ..Default::default()
        };
        busbar_core_connector::process::judge(
            busbar_core_connector::process::dest_judge(&config).unwrap(),
            &[],
        )
    } else {
        Arc::new(judge)
    };
    Arc::new(Connector::serving(view, judge, Some(Arc::new(tls)), wake))
}

fn tls_hook_response() -> (String, String, std::thread::JoinHandle<bool>) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&params, ca_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&leaf_key, &issuer)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
    )
    .unwrap();
    // Bound to the IPv4 loopback the unguarded judge dials for `localhost`, so a host whose
    // `localhost` also resolves to an unbindable `::1` cannot split server and client.
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let served = std::thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(10);
        let mut tcp = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < until,
                        "actual TLS connection was attempted"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("local TLS accept: {error}"),
            }
        };
        // Accepted sockets inherit the listener's nonblocking mode on macOS.
        // This fixture drives rustls with blocking complete_io/read_exact calls.
        tcp.set_nonblocking(false).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        while connection.is_handshaking() {
            if connection.complete_io(&mut tcp).is_err() {
                return false;
            }
        }
        let mut stream = rustls::StreamOwned::new(connection, tcp);
        let mut header = Vec::new();
        let mut byte = [0u8; 1];
        while !header.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        let header = String::from_utf8(header).unwrap();
        assert!(header.starts_with("POST /route HTTP/1.1\r\n"));
        let len: usize = header
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .map(|(_, value)| value.trim().parse().unwrap())
            })
            .unwrap();
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).unwrap();
        let payload: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["op"], "decide");
        let body = br#"{"order":[9,3]}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        stream.flush().unwrap();
        stream.conn.send_close_notify();
        let _ = stream.conn.complete_io(&mut stream.sock);
        true
    });
    (addr, ca.pem(), served)
}

#[test]
fn actual_hook_http_need_uses_trusted_tls_and_refuses_withheld_anchors() {
    for arm in arms() {
        for trusted in [true, false] {
            let (address, ca, served) = tls_hook_response();
            let b = arm.bind_over(true, trusted.then_some(ca.as_str()), false);
            b.open(&json!({"url":format!("{address}/route"),"timeout_ms":2000}).to_string())
                .unwrap();
            let view = decide_frame();
            let done = b.submit(slot::DECIDE, view.input(), blank_out::<DecideOut>());
            if trusted {
                assert_eq!(done.outcome, Outcome::Ready, "{:?}", done.error);
                let out = done.frame.unwrap().out;
                assert_eq!(out.verbs, VERB_PREFER);
                assert_eq!(view.order(out.order_written), [9, 3]);
            } else {
                assert_eq!(done.outcome, Outcome::Failed);
                assert!(done.error.as_deref().is_some_and(|error| !error.is_empty()));
            }
            assert_eq!(
                served.join().unwrap(),
                trusted,
                "untrusted TLS never reaches HTTP request parsing"
            );
        }
    }
}

#[test]
fn the_production_guard_refuses_private_and_metadata_dials_and_admits_operator_loopback() {
    use busbar_contract::abi::host::conn::connector::{
        DIRECTION_OUTBOUND, EGRESS_DEFAULT, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
    };
    use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
    use busbar_contract::conn::{ConnError, InstanceId, NeedId, OpenDesc};
    use std::net::TcpListener;
    use std::time::Instant;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let table = real_connector(Arc::new(|_, _| {}), None, true);
    let owner = InstanceId(7);
    let mut sequence = 0;
    let mut dial = |class, target: &str| {
        sequence += 1;
        let need_id = NeedId(sequence);
        table
            .declare(
                owner,
                need_id,
                &ReadNeed {
                    direction: DIRECTION_OUTBOUND,
                    egress_class: class,
                    transport: "tcp".to_owned(),
                    auth: String::new(),
                    target_from: String::new(),
                    trust_from: String::new(),
                    details: ReadBlob {
                        fmt: 0,
                        flags: 0,
                        bytes: Vec::new(),
                    },
                    timeout_ms: 0,
                    keep_mode: KEEP_NAMED,
                    keep_response_headers: Vec::new(),
                    deny_response_headers: Vec::new(),
                },
                None,
                None,
            )
            .unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let answer = table.open(
                owner,
                need_id,
                &OpenDesc {
                    target,
                    timeout_ms: 2000,
                    ..Default::default()
                },
            );
            match answer {
                Err(ConnError::Pending) => {
                    assert!(Instant::now() < until);
                    std::thread::sleep(Duration::from_millis(2));
                }
                answer => break answer,
            }
        }
    };
    for (class, target) in [
        (EGRESS_DEFAULT, "10.0.0.1:443"),
        (EGRESS_DEFAULT, address.as_str()),
        (EGRESS_OPERATOR_INFRASTRUCTURE, "169.254.169.254:80"),
    ] {
        assert_eq!(dial(class, target).map(|_| ()), Err(ConnError::Refused));
    }
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "no refused destination is dialled"
    );
    let id =
        dial(EGRESS_OPERATOR_INFRASTRUCTURE, &address).expect("operator loopback control admitted");
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match listener.accept() {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < until,
                    "admitted dial reached its actual listener"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            other => panic!("loopback listener: {other:?}"),
        }
    }
    table
        .close(owner, id)
        .expect("close actual control connection");
}

#[test]
fn actual_hook_short_order_answer_is_recalled_once_on_its_same_ticket() {
    for arm in arms() {
        for short_again in [false, true] {
            let b = arm.bind();
            b.open(URL_SETTINGS).unwrap();
            b.upstream.answer(200, "OK", br#"{"order":[9,3,7]}"#);
            let mut rows = candidates();
            let mut third = candidates().remove(0);
            third.idx = 7;
            rows.push(third);
            let view = DecideView::build(&request(), &rows, &context());
            let caps = Caps {
                order: 2,
                ..Caps::initial(&view)
            };
            let first = DecideFrame::new(Arc::clone(&view), caps);
            let ticket = b.dispatcher.mint(0).unwrap();
            let entered = b.plugin.test_invocations().0;
            let resumed = b.plugin.test_invocations().1;
            let deadline = now_ns() + 10_000_000_000;
            let short = b
                .dispatcher
                .submit_watched(
                    &b.plugin,
                    ticket,
                    slot::DECIDE,
                    Frame::new(first.input(), blank_out::<DecideOut>()),
                    DeadlineClass::Call,
                    deadline,
                    Arc::clone(&first) as busbar_plugin_loader::dispatch::Lent,
                    Duration::from_secs(10),
                )
                .wait_done();
            assert!(short.short);
            assert_eq!(short.outcome, Outcome::Failed);
            assert_eq!(short.lease, 0);
            let out = short.frame.unwrap().out;
            assert_eq!(out.order_needed, 3);
            assert_eq!(out.order_written, 0);
            let grown = if short_again {
                DecideFrame::new(Arc::clone(&view), caps)
            } else {
                first.regrown_decide(&out)
            };
            let answer = b
                .dispatcher
                .submit_watched(
                    &b.plugin,
                    ticket,
                    slot::DECIDE,
                    Frame::new(grown.input(), blank_out::<DecideOut>()),
                    DeadlineClass::Call,
                    deadline,
                    Arc::clone(&grown) as busbar_plugin_loader::dispatch::Lent,
                    Duration::from_secs(10),
                )
                .wait_done();
            b.dispatcher.recycle(ticket);
            let resumes = b.plugin.test_invocations().1 - resumed;
            assert_eq!(b.plugin.test_invocations().0 - entered - resumes, 2);
            assert!(resumes > 0);
            assert_eq!(answer.lease, 0);
            if short_again {
                assert_eq!(answer.outcome, Outcome::Fault);
            } else {
                assert_eq!(answer.outcome, Outcome::Ready);
                let out = answer.frame.unwrap().out;
                assert_eq!(out.verbs, VERB_PREFER);
                assert_eq!(grown.order(out.order_written), [9, 3, 7]);
            }
            assert_eq!(
                b.upstream.sent.lock().unwrap().len(),
                1,
                "recall does not repeat the network request"
            );
            assert_eq!(b.dispatcher.stats().deadline_without_wake, 0);
        }
    }
}

const URL_SETTINGS: &str =
    r#"{"url":"http://user:pa%20ss@127.0.0.1:9/hook?x=1","timeout_ms":2000}"#;

fn counted_sync<I: InFrame, O: OutFrame>(
    b: &Bound,
    operation: u32,
    frame: &mut Frame<I, O>,
) -> Called {
    let entered = b.plugin.test_invocations().0;
    let resumed = b.plugin.test_invocations().1;
    let answer = b.plugin.call(operation, frame);
    assert_eq!(b.plugin.test_invocations().0 - entered, 1);
    assert_eq!(b.plugin.test_invocations().1 - resumed, 0);
    answer
}

#[test]
fn actual_hook_lifecycle_refusals_ready_refresh_tick_and_close_keep_the_original_contract() {
    use busbar_contract::abi::mechanism::call::InHead;
    use busbar_contract::abi::mechanism::lifecycle::{TickIn, TickOut, ValidateIn};
    for arm in arms() {
        let b = arm.bind();
        let before = b.plugin.test_invocations().0;
        assert_eq!(
            b.plugin.kind(),
            busbar_contract::abi::mechanism::KindCode::Hook
        );
        assert!(!b.plugin.name().is_empty());
        assert!(b.plugin.max_inflight() > 0);
        assert_eq!(b.plugin.test_invocations().0, before);
        for bad in [
            "not json",
            "{}",
            r#"{"url":""}"#,
            r#"{"url":5}"#,
            r#"{"url":"http://169.254.169.254/"}"#,
            r#"{"url":"https://169.254.169.254/"}"#,
        ] {
            let before = b.plugin.test_invocations().0;
            let mut reason = [0u8; 1024];
            let mut frame: Frame<ValidateIn, OutHead> = Frame::new(
                ValidateIn {
                    head: in_head(),
                    settings: json_blob(bad),
                    err_buf: reason.as_mut_ptr(),
                    err_cap: reason.len(),
                },
                out_head(),
            );
            let answer = counted_sync(&b, life::VALIDATE, &mut frame);
            assert_eq!(answer.outcome, Outcome::Failed);
            assert_eq!(answer.lease, 0);
            assert!(!answer.error.as_deref().unwrap_or_default().is_empty());
            assert_eq!(b.plugin.test_invocations().0 - before, 1);
            assert!(b.open(bad).is_err());
        }
        let inline = b
            .dispatcher
            .inline_ticket()
            .expect("an authenticated inline ticket");
        let ticket = inline.ticket();
        let view = decide_frame();
        let before = b.plugin.test_invocations().0;
        let mut unopened = Frame::new(view.input(), blank_out::<DecideOut>());
        assert_ne!(
            b.plugin
                .call_inline(ticket, false, slot::DECIDE, &mut unopened)
                .outcome,
            Outcome::Ready
        );
        assert_eq!(b.plugin.test_invocations().0, before);
        drop(inline);
        let mut valid: Frame<ValidateIn, OutHead> = Frame::new(
            ValidateIn {
                head: in_head(),
                settings: json_blob(URL_SETTINGS),
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            out_head(),
        );
        assert_eq!(
            counted_sync(&b, life::VALIDATE, &mut valid).outcome,
            Outcome::Ready
        );
        let before = b.plugin.test_invocations().0;
        b.plugin
            .ready(&b.dispatcher, Duration::from_secs(10))
            .unwrap();
        assert_eq!(
            b.plugin.test_invocations().0 - before,
            u64::from(b.plugin.has_ready())
        );
        let opened_before = b.plugin.test_invocations().0;
        b.open(URL_SETTINGS).unwrap();
        assert_eq!(b.plugin.test_invocations().0 - opened_before, 1);
        let managed_before = b.plugin.test_invocations().0;
        assert!(b.describe()["schema"].is_object());
        assert!(b.status()["status"]["settings"].is_object());
        assert_eq!(
            b.plugin.test_invocations().0 - managed_before,
            4,
            "status and describe each cross once and release their lease once"
        );
        let before = b.plugin.test_invocations().0;
        assert!(b.open(URL_SETTINGS).is_err());
        assert_eq!(
            b.plugin.test_invocations().0,
            before,
            "duplicate open is a host refusal"
        );
        let mut refresh = Frame::new(
            RefreshIn {
                head: in_head(),
                generation: 2,
                settings: json_blob("{}"),
                secrets: std::ptr::null(),
                secrets_len: 0,
            },
            out_head(),
        );
        assert_eq!(
            counted_sync(&b, life::REFRESH, &mut refresh).outcome,
            Outcome::Failed
        );
        b.upstream.answer(200, "OK", br#"{"order":[9,3]}"#);
        assert_eq!(
            decide_verbs(&b),
            VERB_PREFER,
            "refused refresh keeps the original target serving"
        );
        let settings = r#"{"url":"http://127.0.0.2:8123/refreshed","timeout_ms":2000}"#;
        let mut refresh = Frame::new(
            RefreshIn {
                head: in_head(),
                generation: 3,
                settings: json_blob(settings),
                secrets: std::ptr::null(),
                secrets_len: 0,
            },
            out_head(),
        );
        assert_eq!(
            counted_sync(&b, life::REFRESH, &mut refresh).outcome,
            Outcome::Ready
        );
        b.upstream.answer(200, "OK", br#"{"order":[9,3]}"#);
        assert_eq!(decide_verbs(&b), VERB_PREFER);
        assert_eq!(b.upstream.last().path, b"/refreshed");
        let mut unknown: Frame<ReleaseIn, OutHead> = Frame::new(
            ReleaseIn {
                head: in_head(),
                lease: 42,
            },
            out_head(),
        );
        let refused = counted_sync(&b, life::RELEASE, &mut unknown);
        assert_eq!(refused.outcome, Outcome::Refused);
        assert_eq!(
            refused.error.as_deref(),
            Some(busbar_contract::abi::sdk::life::NO_SUCH_LEASE.as_bytes())
        );
        let mut tick = Frame::new(
            TickIn {
                head: in_head(),
                now_ns: 1,
            },
            TickOut {
                head: out_head(),
                next_tick_ns: 7,
            },
        );
        assert_eq!(
            counted_sync(&b, life::TICK, &mut tick).outcome,
            Outcome::Ready
        );
        assert_eq!(tick.out.next_tick_ns, 0);
        let mut close: Frame<InHead, OutHead> = Frame::new(in_head(), out_head());
        assert_eq!(
            counted_sync(&b, life::CLOSE, &mut close).outcome,
            Outcome::Ready
        );
        let before = b.plugin.test_invocations().0;
        let inline = b
            .dispatcher
            .inline_ticket()
            .expect("an authenticated inline ticket");
        let ticket = inline.ticket();
        let view = decide_frame();
        let mut request = Frame::new(view.input(), blank_out::<DecideOut>());
        assert_ne!(
            b.plugin
                .call_inline(ticket, false, slot::DECIDE, &mut request)
                .outcome,
            Outcome::Ready
        );
        drop(inline);
        assert_eq!(b.plugin.test_invocations().0, before);
        assert_eq!(b.dispatcher.stats().deadline_without_wake, 0);
    }
}
