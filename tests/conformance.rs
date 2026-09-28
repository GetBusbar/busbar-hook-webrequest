// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE FORWARDER, BOTH DOORS, ONE ROW** — the webrequest hook's linked + dropped-in conformance,
//! run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! The hook is held two ways at once: LINKED (its `linked::HOOK` statement and boundary, the row a
//! busbar build that compiles it in registers) and DROPPED IN (this crate's built cdylib, signed
//! first-party under the SAME statement into a temp `plugins/` directory and found by the loader's
//! scan). Each arm is opened by the one `open_hook` and driven through one scenario against a LOCAL
//! MOCK UPSTREAM (a plain `std::net::TcpListener` HTTP server in this file): an ALLOW reply (an
//! `order`), a REJECT reply, a RESTRICT reply (`tags_any`), a SLOW upstream that answers only after
//! the configured timeout (the fail-closed failure the engine applies `on_error` to), plus the
//! load-time refusals (no URL, an SSRF-blocked URL). The two arms must agree byte for byte on the
//! row, every decision, every refusal, and every request body the upstream received.
//!
//! The RED arms are in the same test: the same cdylib signed as `kind: store` is refused at open
//! naming both kinds, and the dropped-in door driven against an upstream that answers the restrict
//! case differently yields a transcript that is NOT the linked one — the comparison can fail.

use busbar_contract::hooks::{
    Candidate, HookStatus, RoutingContext, RoutingDecision, RoutingRequest, TransformOutcome,
};
use busbar_plugin_loader::hook::HookProjectors;
use busbar_plugin_loader::sign::{sign, HookNeeds, Manifest, NeedLevel, SigningKey, TrustPolicy};
use busbar_plugin_loader::{LinkedPlugin, PluginRegistry};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The release key the dropped-in arm is signed with, and the policy's first-party key.
fn release() -> SigningKey {
    SigningKey::from_bytes(&[23u8; 32])
}

/// The version both arms state (a linked row states its binary's version; here, this crate's).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The forwarder's per-call timeout in the scenario, and how long the SLOW upstream waits — well past
/// it, so the slow case can only end as the forwarder's timeout failure.
const TIMEOUT_MS: u64 = 300;
const SLOW_MS: u64 = 1_500;

/// The wall-clock budget the engine hands each call (above the forwarder's own timeout).
const BUDGET: Duration = Duration::from_secs(5);

/// This crate's built cdylib (uplifted or under `deps`, newest wins). A missing artifact is a
/// failure, never a skip: this test IS the dropped-in door's proof.
fn cdylib() -> Vec<u8> {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let file = busbar_plugin_loader::plugin_library_filename("busbar_hook_webrequest");
    let found = [profile.join(&file), profile.join("deps").join(&file)]
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the busbar-hook-webrequest cdylib ({file}) is not built"));
    std::fs::read(found).expect("read the cdylib")
}

/// The statement both doors carry, as `kind`.
fn statement(kind: &str) -> Manifest {
    let (name, alias, _) = busbar_hook_webrequest::linked::HOOK;
    let abi = busbar_plugin_loader::supported_abi(kind)
        .iter()
        .copied()
        .max()
        .unwrap_or_default();
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: kind.into(),
        version: VERSION.into(),
        publisher: busbar_plugin_loader::sign::FIRST_PARTY_PUBLISHER.into(),
        abi_version: abi,
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: HookNeeds {
            prompt: NeedLevel::Ro,
            user: NeedLevel::No,
        },
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
    }
}

/// The LINKED row: exactly what a busbar composition root that links this crate states.
fn linked_registry() -> PluginRegistry {
    let row = LinkedPlugin::boundary(statement("hook"), busbar_hook_webrequest::linked::HOOK.2);
    PluginRegistry::empty()
        .link(vec![row])
        .expect("the linked row registers")
}

/// THE DROPPED-IN DOOR: `lib` signed first-party under `manifest` into a fresh `plugins/`
/// directory, scanned under a policy holding the release key.
fn dropped(tag: &str, manifest: Manifest, lib: &[u8]) -> PluginRegistry {
    let dir = std::env::temp_dir().join(format!("webrequest-conf-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let signed = sign(&release(), manifest, lib);
    let tarball = busbar_plugin_loader::tarball::package(&signed, "libhook.so", lib).unwrap();
    std::fs::write(dir.join("hook.tar.gz"), tarball).unwrap();
    let policy = TrustPolicy {
        first_party_key: Some(release().verifying_key()),
        binary_version: VERSION.into(),
        first_party_floors: Default::default(),
        first_party_high_water: Default::default(),
        publishers: Default::default(),
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: Default::default(),
    };
    busbar_plugin_loader::scan_and_validate(&dir, &policy).expect("the signed hook scans")
}

/// A LOCAL MOCK UPSTREAM. Each path answers a fixed JSON reply (after `SLOW_MS` for `/slow`); every
/// request body it receives is recorded under its path, in arrival order.
struct Upstream {
    base: String,
    seen: Arc<Mutex<BTreeMap<String, Vec<serde_json::Value>>>>,
}

fn upstream(restrict_tag: &'static str) -> Upstream {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen: Arc<Mutex<BTreeMap<String, Vec<serde_json::Value>>>> = Arc::default();
    let record = seen.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let record = record.clone();
            std::thread::spawn(move || serve_one(stream, restrict_tag, &record));
        }
    });
    Upstream { base, seen }
}

fn serve_one(
    stream: std::net::TcpStream,
    restrict_tag: &str,
    record: &Mutex<BTreeMap<String, Vec<serde_json::Value>>>,
) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut line = String::new();
    if reader.read_line(&mut line).unwrap_or(0) == 0 {
        return;
    }
    let path = line.split_whitespace().nth(1).unwrap_or("/").to_string();
    let mut len = 0usize;
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).unwrap();
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().unwrap();
            }
        }
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).unwrap();
    record
        .lock()
        .unwrap()
        .entry(path.clone())
        .or_default()
        .push(serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null));
    let reply = match path.as_str() {
        "/allow" => r#"{"order":[1,0]}"#.to_string(),
        "/reject" => r#"{"reject":{"status":451,"message":"blocked by policy"}}"#.to_string(),
        "/restrict" => format!(r#"{{"restrict":{{"tags_any":["{restrict_tag}"]}}}}"#),
        "/slow" => {
            std::thread::sleep(Duration::from_millis(SLOW_MS));
            r#"{"order":[0]}"#.to_string()
        }
        _ => "{}".to_string(),
    };
    let mut out = stream;
    let _ = write!(
        out,
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
        reply.len()
    );
}

/// Engine-side projectors on the loader's own terms: the decide projection carries the prompt and
/// the candidates, and the reply is normalized fail-closed — `reject`, then `restrict`, then `order`
/// (the precedence the engine's `hooks::wire` applies).
fn projectors() -> Arc<HookProjectors> {
    fn messages(req: &RoutingRequest<'_>) -> serde_json::Value {
        serde_json::json!(req.prompt.as_ref().map(|p| {
            p.messages
                .iter()
                .map(|(r, t)| serde_json::json!({"role": r.as_ref(), "text": t.as_ref()}))
                .collect::<Vec<_>>()
        }))
    }
    Arc::new(HookProjectors {
        decide: Box::new(|req, cands, _ctx| {
            serde_json::json!({
                "request": {"pool": req.pool, "messages": messages(req)},
                "candidates": cands.iter().map(|c| serde_json::json!({"idx": c.idx})).collect::<Vec<_>>(),
            })
        }),
        transform: Box::new(|req| serde_json::json!({"request": {"messages": messages(req)}})),
        normalize: Box::new(|v, cands| {
            if let Some(reject) = v.get("reject") {
                return Ok(RoutingDecision::Reject {
                    status: reject
                        .get("status")
                        .and_then(|s| s.as_u64())
                        .map(|s| s as u16)
                        .unwrap_or(403),
                    message: reject
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("")
                        .to_string(),
                });
            }
            if let Some(tags) = v
                .get("restrict")
                .and_then(|r| r.get("tags_any"))
                .and_then(|t| t.as_array())
            {
                return Ok(RoutingDecision::Restrict {
                    tags_any: tags
                        .iter()
                        .filter_map(|t| t.as_str().map(str::to_string))
                        .collect(),
                });
            }
            let Some(order) = v.get("order").and_then(|o| o.as_array()) else {
                return Ok(RoutingDecision::Abstain);
            };
            let valid: std::collections::HashSet<usize> = cands.iter().map(|c| c.idx).collect();
            Ok(RoutingDecision::from_ranked(
                order.iter().filter_map(|x| x.as_u64().map(|x| x as usize)),
                &valid,
            ))
        }),
        transform_outcome: Box::new(|_| TransformOutcome::Abstain),
        status: Box::new(|v| {
            v.get("status").map(|s| HookStatus {
                settings_version: None,
                settings: s.get("settings").and_then(|x| x.as_object()).cloned(),
                metrics: s.get("metrics").and_then(|m| m.as_array()).cloned(),
            })
        }),
        describe_schema: Box::new(|v| v.get("schema").cloned()),
    })
}

fn request() -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 7,
        pool: "p",
        ingress_protocol: "anthropic",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: 5,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(busbar_contract::hooks::PromptProjection {
            system: None,
            messages: vec![("user".into(), "hello".to_string().into())],
        }),
        identity: None,
        signals: Default::default(),
    }
}

fn cand(idx: usize) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
        signals: busbar_contract::signal::SignalBag::new(),
    }
}

/// What one door does, as one comparable transcript: the row's statement, the load-time refusals,
/// and — per scenario case, each a forwarder opened at `<upstream>/<case>` — the decision (or the
/// failure) and every body the upstream received. Nothing port-specific is recorded.
async fn transcript(registry: &PluginRegistry, restrict_tag: &'static str) -> serde_json::Value {
    let alias = busbar_hook_webrequest::ALIAS;
    let p = registry.resolve(alias).expect("the alias resolves");
    let stated = Manifest {
        sha256: String::new(),
        signature: String::new(),
        ..p.manifest.clone()
    };
    let refusal = |cfg: &str| match registry.open_hook(alias, cfg, "webrequest", projectors()) {
        Ok(_) => "opened".to_string(),
        Err(e) => e,
    };
    let refusals = [
        refusal(""),
        refusal(r#"{"url": "http://169.254.169.254/latest"}"#),
        refusal("not json"),
    ];

    let up = upstream(restrict_tag);
    let (cands, ctx) = (
        [cand(0), cand(1)],
        RoutingContext {
            pool: "p",
            budget_remaining: None,
            budget: &[],
        },
    );
    let mut decisions = BTreeMap::new();
    for case in ["allow", "reject", "restrict", "slow"] {
        let cfg =
            serde_json::json!({"url": format!("{}/{case}", up.base), "timeout_ms": TIMEOUT_MS});
        let policy = registry
            .open_hook(alias, &cfg.to_string(), "webrequest", projectors())
            .expect("the forwarder opens on a loopback upstream");
        let outcome = match policy.decide(&request(), &cands, &ctx, BUDGET).await {
            Ok(d) => format!("{d:?}"),
            Err(e) => format!("failed: {}", e.to_string().replace(&up.base, "<upstream>")),
        };
        decisions.insert(case, outcome);
    }
    let seen = up.seen.lock().unwrap().clone();
    serde_json::json!({
        "row": stated,
        "first_party": p.first_party(),
        "refusals": refusals,
        "decisions": decisions,
        "upstream_saw": seen,
    })
}

/// The webrequest hook registers ONE row and behaves as ONE forwarder through either door — and the
/// comparison is not vacuous (the RED arms).
#[tokio::test(flavor = "multi_thread")]
async fn the_linked_and_the_dropped_in_webrequest_hook_are_one_hook() {
    let lib = cdylib();
    let linked = transcript(&linked_registry(), "baa").await;
    let dropped_in = transcript(&dropped("dropped", statement("hook"), &lib), "baa").await;
    assert_eq!(linked, dropped_in, "the two doors are not one hook");

    // The scenario did what the forwarder is for.
    let d = &linked["decisions"];
    assert_eq!(d["allow"], "Prefer([1, 0])");
    assert_eq!(
        d["reject"],
        "Reject { status: 451, message: \"blocked by policy\" }"
    );
    assert_eq!(d["restrict"], "Restrict { tags_any: [\"baa\"] }");
    let slow = d["slow"].as_str().unwrap();
    assert!(
        slow.starts_with("failed: ") && slow.contains("could not answer"),
        "a slow upstream is the fail-closed failure, never a decision: {slow}"
    );
    let r = &linked["refusals"];
    assert!(
        r[0].as_str()
            .unwrap()
            .contains("webrequest: settings.url is required"),
        "{r}"
    );
    assert!(r[1].as_str().unwrap().contains("169.254.169.254"), "{r}");
    assert!(
        r[2].as_str()
            .unwrap()
            .contains("webrequest: invalid plugin config"),
        "{r}"
    );
    // The upstream received the op envelope the forwarder built from the engine's projection.
    let allow = &linked["upstream_saw"]["/allow"][0];
    assert_eq!(allow["op"], "decide");
    assert_eq!(allow["request"]["messages"][0]["text"], "hello");
    assert_eq!(linked["first_party"], true);

    // RED ARM (a): the same bytes signed as `store` are refused at open, naming both kinds.
    let wrong = dropped("as-store", statement("store"), &lib);
    let e = match wrong.open_store(busbar_hook_webrequest::ALIAS, "{}") {
        Ok(_) => panic!("a hook library signed as store must not open"),
        Err(e) => e,
    };
    assert!(
        e.contains("exports kind 'hook' but is being loaded as 'store'"),
        "{e}"
    );

    // RED ARM (b): the same dropped-in door against an upstream that restricts to another tag is
    // NOT the linked transcript.
    let red = transcript(&dropped("red", statement("hook"), &lib), "other").await;
    assert_ne!(
        red, linked,
        "a different upstream answer must not compare equal"
    );
    assert_eq!(
        red["decisions"]["restrict"],
        "Restrict { tags_any: [\"other\"] }"
    );
}
