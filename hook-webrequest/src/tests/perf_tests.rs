//! The request path's allocation work, pinned against what it replaced: the envelope body sized
//! once ([`crate::wire::projection_hint`]), the failure texts written once, and the scrub handed
//! only the parts it can cut. Each old function is kept here as the oracle.

use std::borrow::Cow;

use busbar_contract::abi::sdk::hook::{
    Bucket, Decoded, DecodedCandidate, DecodedTap, Prompt, Stage, User,
};
use busbar_contract::abi::sdk::url as sdk_url;
use busbar_contract::hook_wire::{OP_DECIDE, OP_NOTIFY, OP_TRANSFORM};
use busbar_contract::signal::{Signal, SignalValue};
use busbar_contract::SignalBag;

use crate::door::Live;
use crate::net_guard::{cut_order, scrub, secret_parts};
use crate::reply::{error_status, request_failed_with, MAX_PHRASE_CHARS};
use crate::wire::{escape_extra, projection_hint, tap_hint};

fn signals() -> SignalBag {
    let mut bag = SignalBag::default();
    bag.push(
        Signal::RequestedModel,
        SignalValue::Str(Cow::Borrowed("a\"b\n")),
    );
    bag.push(
        Signal::RequestedModel,
        SignalValue::Str(Cow::Borrowed("second")),
    );
    bag.push(
        Signal::CandidateErrorRate,
        SignalValue::F64(-1.234_567_890_123_456_7e-300),
    );
    bag.push(Signal::RequestTotalChars, SignalValue::U64(u64::MAX));
    bag.push(Signal::RequestToolCount, SignalValue::I64(i64::MIN));
    bag.push(Signal::RequestTextComplete, SignalValue::Bool(false));
    bag
}

fn candidate(idx: usize, full: bool) -> DecodedCandidate<'static> {
    DecodedCandidate {
        idx,
        model: Cow::Borrowed("gpt-4o-mini"),
        provider: Cow::Borrowed("open\"ai"),
        weight: u32::MAX,
        context_max: full.then_some(usize::MAX),
        tier: full.then_some(Cow::Borrowed("tier\\1")),
        cost_per_mtok: full.then_some(f64::MIN_POSITIVE),
        tags: if full {
            vec![
                Cow::Borrowed("fast"),
                Cow::Borrowed("\u{1}ctl"),
                Cow::Borrowed(""),
            ]
        } else {
            Vec::new()
        },
        latency_ms: full.then_some(-1.0e300),
        available_concurrency: usize::MAX,
        budget_remaining: full.then_some(i64::MIN),
        rate_headroom: full.then_some(0.1 + 0.2),
        signals: if full {
            signals()
        } else {
            SignalBag::default()
        },
    }
}

fn view<'a>(messages: &'a [(String, String)], full: bool) -> Decoded<'a> {
    Decoded {
        request_id: u64::MAX,
        pool: Cow::Borrowed("po\"ol"),
        ingress_dialect: Cow::Borrowed("openai"),
        message_count: messages.len() as u64,
        total_chars: u64::MAX,
        max_tokens: full.then_some(u32::MAX),
        has_tools: full,
        stream: full,
        signals: if full {
            signals()
        } else {
            SignalBag::default()
        },
        prompt: Some(Prompt {
            system: full.then_some(Cow::Borrowed("You are \"helpful\".\n\t")),
            messages: messages
                .iter()
                .map(|(r, t)| (Cow::Borrowed(r.as_str()), Cow::Borrowed(t.as_str())))
                .collect(),
            body: None,
        }),
        user: full.then_some(User {
            key_id: Some(Cow::Borrowed("k-1")),
            key_name: None,
            user: Some(Cow::Borrowed("al\u{7}ice")),
        }),
        candidates: (0..if full { 5 } else { 1 })
            .map(|i| candidate(i, full))
            .collect(),
        budget_remaining: full.then_some(-7),
        budget: if full {
            vec![
                Bucket {
                    bucket_id: Cow::Borrowed("b\"1"),
                    budget_group: None,
                    pool: Some(Cow::Borrowed("p")),
                    spend_micros_at_current_rate: i64::MIN,
                    remaining_micros: None,
                    window_start: u64::MAX,
                    budget_period: Cow::Borrowed("day"),
                },
                Bucket {
                    bucket_id: Cow::Borrowed("b2"),
                    budget_group: Some(Cow::Borrowed("g")),
                    pool: None,
                    spend_micros_at_current_rate: 0,
                    remaining_micros: Some(i64::MAX),
                    window_start: 0,
                    budget_period: Cow::Borrowed("month"),
                },
            ]
        } else {
            Vec::new()
        },
        session: None,
    }
}

fn prompts() -> Vec<Vec<(String, String)>> {
    let code = "fn main() {\n    println!(\"hi \\\"x\\\"\");\n}\n".repeat(50);
    let controls: String = (0u8..0x20).map(char::from).collect::<String>().repeat(9);
    vec![
        Vec::new(),
        vec![("user".into(), String::new())],
        vec![("user".into(), "plain prose ".repeat(300))],
        vec![("user".into(), code), ("assistant".into(), "ok".into())],
        vec![
            ("us\"er".into(), controls),
            ("tool".into(), "é漢字🙂\u{7f}".repeat(40)),
        ],
    ]
}

#[test]
fn escape_extra_is_what_serde_json_adds() {
    let mut specials: Vec<char> = (0u32..0x800).filter_map(char::from_u32).collect();
    specials.extend(['\u{2028}', '\u{feff}', '🙂']);
    for &c in &specials {
        for len in [1, 2, 31, 32, 33, 63, 64, 65, 100] {
            for pad in ["", "a", "\"", "\n"] {
                let s: String = std::iter::repeat_n(pad, len % 5)
                    .chain(std::iter::repeat_n(c.encode_utf8(&mut [0; 4]) as &str, len))
                    .collect();
                assert_eq!(
                    s.len() + 2 + escape_extra(&s),
                    serde_json::to_vec(&s).unwrap().len(),
                    "{c:?} x {len} after {pad:?}"
                );
            }
        }
    }
}

/// The SDK writes the envelope into the body the hint sized and never regrows it, so no outgrown
/// copy of the prompt is freed unwiped; the hint stays close, so the wiped capacity does too.
#[test]
fn the_envelope_is_written_into_one_allocation_close_to_its_length() {
    for messages in prompts() {
        for full in [false, true] {
            let v = view(&messages, full);
            for op in [OP_DECIDE, OP_TRANSFORM] {
                let mut body = Vec::new();
                v.write_projection(op, None, &mut body).unwrap();
                let hint = projection_hint(&v, op);
                assert!(
                    hint >= body.len(),
                    "{op} full={full}: {hint} < {}",
                    body.len()
                );
                assert!(
                    hint <= body.len() + body.len() / 4 + 1024,
                    "{hint} vs {}",
                    body.len()
                );
            }
            for stage in [
                None,
                Some(Stage {
                    at: "response",
                    model: Some(Cow::Borrowed("m\"")),
                    attempt_number: Some(u32::MAX),
                    remaining_candidates: Some(usize::MAX),
                    previous_failure: Some(Cow::Borrowed("timed out\n")),
                    outcome: Some(Cow::Borrowed("failed")),
                    status: Some(u16::MAX),
                }),
            ] {
                let tap = DecodedTap {
                    request: Decoded {
                        candidates: Vec::new(),
                        budget: Vec::new(),
                        budget_remaining: None,
                        ..v.clone()
                    },
                    stage,
                };
                let mut body = Vec::new();
                tap.write_projection(OP_NOTIFY, None, &mut body).unwrap();
                let hint = tap_hint(&tap, OP_NOTIFY);
                assert!(hint >= body.len(), "notify: {hint} < {}", body.len());
                assert!(hint <= body.len() + body.len() / 4 + 1024);
            }
        }
    }
}

/// The request the door builds is the one it built before (body written into a fresh `Vec`),
/// field for field, in a body allocated once.
#[test]
fn the_built_request_is_unchanged_and_never_regrown() {
    let target =
        crate::config::open(br#"{"url":"http://user:pa%20ss@127.0.0.1:9/hook?x=1"}"#).unwrap();
    let live = Live::new(target);
    for messages in prompts() {
        let v = view(&messages, true);
        let hint = projection_hint(&v, OP_DECIDE);
        let (request, sealed) = live
            .envelope(|body| v.write_projection(OP_DECIDE, None, body), hint)
            .unwrap();
        let mut old = Vec::new();
        v.write_projection(OP_DECIDE, None, &mut old).unwrap();
        assert_eq!(request.body, old);
        assert_eq!(request.body.capacity(), hint, "the body never regrew");
        let mut expected = live.request.clone();
        expected.body = old;
        assert_eq!(request, expected);
        assert_eq!(
            sealed
                .iter()
                .map(|(at, n, _)| (*at, n.clone()))
                .collect::<Vec<_>>(),
            vec![(0, b"authorization".to_vec())]
        );
    }
}

/// The old phrase rendering and error text, verbatim.
fn old_loggable_phrase(phrase: &str) -> String {
    let mut out = String::new();
    for (i, c) in phrase.chars().enumerate() {
        if i >= MAX_PHRASE_CHARS {
            out.push('\u{2026}');
            break;
        }
        if c == '\'' {
            out.push(c);
        } else {
            out.extend(c.escape_debug());
        }
    }
    out
}

fn old_error_status(code: u16, phrase: Option<&str>) -> String {
    let (class, status) = match http::StatusCode::from_u16(code) {
        Ok(c) if c.is_client_error() => ("client", c),
        Ok(c) => ("server", c),
        Err(_) => ("server", http::StatusCode::INTERNAL_SERVER_ERROR),
    };
    let shown = match phrase.filter(|p| !p.is_empty()) {
        Some(p) => format!("{} {}", status.as_u16(), old_loggable_phrase(p)),
        None => status.to_string(),
    };
    format!(
        "{}: target returned an error status: HTTP status {class} error ({shown})",
        crate::ALIAS
    )
}

#[test]
fn error_status_text_is_unchanged() {
    let long: String = "ab'\"\u{1b}[31m\n\u{202e}é🙂".repeat(40);
    let exact: String = long.chars().take(MAX_PHRASE_CHARS).collect();
    let phrases = [
        None,
        Some(""),
        Some("Service Unavailable"),
        Some("it's \"quoted\" \\ back"),
        Some("\u{0}\u{7f}\u{85}\u{200b}\r\n\t"),
        Some(long.as_str()),
        Some(exact.as_str()),
    ];
    for code in [
        0, 1, 99, 100, 200, 302, 399, 400, 404, 418, 499, 500, 503, 599, 600, 999, 1000,
    ] {
        for p in phrases {
            assert_eq!(
                error_status(code, p),
                old_error_status(code, p),
                "{code} {p:?}"
            );
        }
    }
    for cause in ["", "connection refused", "a: b ***"] {
        assert_eq!(
            request_failed_with(cause),
            format!(
                "{}: request failed: error sending request: {cause}",
                crate::ALIAS
            )
        );
    }
}

/// The scrub over the ordered, filtered parts is the SDK's scrub over every part, as written.
#[test]
fn scrub_cuts_exactly_what_cutting_every_part_cuts() {
    let urls = [
        "https://svc:hunter2@hooks.example/route",
        "http://user:pa%20ss@127.0.0.1:9/hook/segment?token=abc&x=1",
        "https://u*:p**w@hooks.example/a*b/***/c?k=*&v=a+b#frag",
        "https://hooks.example/",
        "https://hooks.example/%2A%2a/x?q=%2A",
        "https://a:@hooks.example/a/a/aa?x=a&y=aa",
        "https://%F0%9F%99%82:%C3%A9@hooks.example/%E6%BC%A2?t=%F0%9F",
    ];
    let texts = |url: &url::Url| {
        let mut texts = vec![
            String::new(),
            "connection refused (os error 61)".to_owned(),
            format!("error sending request for url ({url})"),
            format!("{url} {url} {}", url.path()),
            format!("x***{}***y", url.password().unwrap_or("p")),
            "***@***".to_owned(),
            "a*".repeat(200),
        ];
        let parts = secret_parts(url);
        for p in &parts {
            texts.push(format!("<{p}>"));
            texts.push(format!("{p}{p}*{p}"));
            texts.push(format!("pre {p} post").repeat(30));
        }
        texts.extend(parts.iter().map(|p| p.replace('*', "")));
        texts
    };
    for raw in urls {
        let url = url::Url::parse(raw).unwrap();
        let parts = secret_parts(&url);
        let ordered = cut_order(parts.clone());
        for text in texts(&url) {
            let all = sdk_url::scrub(&text, parts.clone(), false);
            assert_eq!(scrub(&text, &ordered), all, "{raw}: {text:?}");
            assert_eq!(scrub(&text, &parts), all, "{raw}: {text:?} (as written)");
        }
    }
    // A part an earlier cut completes: `x***` exists only once `SECRET` is cut.
    let parts = vec!["SECRET".to_owned(), "x***".to_owned()];
    let ordered = cut_order(parts.clone());
    for text in ["xSECRETy", "SECRET", "x**SECRET", "nothing"] {
        assert_eq!(
            scrub(text, &ordered),
            sdk_url::scrub(text, parts.clone(), false)
        );
    }
    assert_eq!(scrub("xSECRETy", &ordered), "***y");
}
