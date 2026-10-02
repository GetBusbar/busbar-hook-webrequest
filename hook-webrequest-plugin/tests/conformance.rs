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
//! FAILED `decide` and an abstaining `transform`; and the Statement declares exactly one need,
//! outbound, in the loopback-allowed egress class, over the host's `http` framer.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
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
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut, ReleaseIn};
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
    in_head, load_dropped, load_linked, now_ns, out_head, rendering_of, Bind, Called,
    DispatchConfig, Dispatcher, Done, Frame, InFrame, LinkedRow, NoSink, OutFrame, Plugin,
};
use serde_json::{json, Value};

/// The URL every opened forwarder is configured with: loopback plaintext, userinfo, a query.
const URL: &str = "http://user:pa%20ss@127.0.0.1:9/hook?x=1";

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
type Wake = Arc<dyn Fn(u64) + Send + Sync>;

/// THE FAR END, as a connection table: every need is framed; an open is the whole request (kept
/// in `sent`); each reply is the scripted `(status, reason, body)`, its first read PENDING with
/// the op's ticket woken from another thread.
struct Upstream {
    wake: Mutex<Option<Wake>>,
    answer: Mutex<(u32, &'static str, Vec<u8>)>,
    sent: Mutex<Vec<Sent>>,
    reads: Mutex<HashMap<u64, u8>>,
    next: AtomicU64,
    pended: AtomicU32,
}

impl Upstream {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            wake: Mutex::new(None),
            answer: Mutex::new((200, "OK", b"{}".to_vec())),
            sent: Mutex::new(Vec::new()),
            reads: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            pended: AtomicU32::new(0),
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
        reason: None,
    }
}

impl Conns for Upstream {
    fn open(&self, _: InstanceId, _: NeedId, desc: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
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
        self.reads.lock().unwrap().insert(id, 0);
        Ok(ConnId(id))
    }
    fn write(&self, _: InstanceId, _: ConnId, _: &[u8], _: bool) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(
        &self,
        _: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let step = {
            let mut reads = self.reads.lock().unwrap();
            let step = reads.get_mut(&conn.0).ok_or(ConnError::Closed)?;
            *step += 1;
            *step - 1
        };
        let (status, reason, body) = self.answer.lock().unwrap().clone();
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
                    wake(ticket);
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
                buf[..body.len()].copy_from_slice(&body);
                Ok(piece(PieceKind::Body, body.len()))
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
    fn declare(
        &self,
        _: InstanceId,
        _: NeedId,
        _: &ReadNeed,
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

/// One arm, bound: the dispatcher, the far end and the plugin (not yet opened).
struct Bound {
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
        let bind = Bind {
            instance: Arc::from("webrequest-conformance"),
            max_inflight_cap: 64,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: Some(conns),
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
        match called.outcome {
            Outcome::Ready => Ok(f.out.acked_version),
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
        (
            "{}",
            "webrequest: invalid plugin config: missing field `url`",
        ),
        (r#"{"url": 5}"#, "webrequest: invalid plugin config"),
        (r#"{"url": "http://169.254.169.254/"}"#, "webrequest:"),
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

    // RED: an error status is a FAILED decide, in 1.5.5's words with the far end's own phrase.
    b.upstream.answer(503, "Busy", b"");
    let done = b.submit(
        slot::DECIDE,
        decide_frame().input(),
        blank_out::<DecideOut>(),
    );
    assert_eq!(done.outcome, Outcome::Failed);
    let e = error_of(done.error.as_deref());
    assert_eq!(
        e,
        "webrequest: target returned an error status: HTTP status server error (503 Busy)"
    );
    t.push(format!("decide 503: {e}"));

    // transform: the far end's rewrite crosses as its JSON; a failure abstains.
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
    let done = b.submit(
        slot::TRANSFORM,
        decide_frame().input(),
        blank_out::<TransformOut>(),
    );
    assert_eq!(done.outcome, Outcome::Ready);
    assert_eq!(done.frame.expect("the frame").out.verbs, VERB_ABSTAIN);
    t.push("transform 500: abstain".into());

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
        .configure(r#"{"url": "http://169.254.169.254/"}"#, 8)
        .expect_err("a blocked URL is a NACK");
    assert!(
        nack.contains("did not acknowledge settings_version 8"),
        "{nack}"
    );
    let s = b.status();
    assert_eq!(s["status"]["settings"]["timeout_ms"], json!(100));
    assert_eq!(s["status"]["settings"]["target_host"], json!("127.0.0.1"));
    t.push(format!("configure: ack 7, nack 8; status {s}"));

    // Every exchange pended once and completed on its wake.
    assert_eq!(
        b.upstream.pended.load(Ordering::SeqCst),
        b.upstream.sent.lock().unwrap().len() as u32
    );
    t
}

#[test]
fn the_linked_and_dropped_in_doors_answer_alike_and_as_1_5_5() {
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

/// RED: a `decide` that cannot pend (no ticket) fails at once; it never blocks a thread.
#[test]
fn red_a_ticketless_decide_fails_at_once() {
    let b = Arm::Linked.bind();
    b.open(&format!(r#"{{"url": "{URL}"}}"#)).expect("opens");
    let frame = decide_frame();
    let mut f = Frame::new(frame.input(), blank_out::<DecideOut>());
    let called = b.plugin.call(slot::DECIDE, &mut f);
    assert_eq!(called.outcome, Outcome::Failed);
    assert_eq!(
        error_of(called.error.as_deref()),
        busbar_hook_webrequest::reply::REQUEST_FAILED
    );
    assert!(b.upstream.sent.lock().unwrap().is_empty());
}
