//! The door's per-op choices that need no host: which target a resumed op runs against.

use std::sync::Arc;

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

fn configure(f: &Forwarder, url: &str) {
    let settings = serde_json::json!({ "url": url });
    assert!(
        f.configure(settings.as_object().unwrap(), 2).is_ok(),
        "acked"
    );
}

#[test]
fn concurrent_partial_configures_preserve_both_updates() {
    let f = forwarder("http://127.0.0.1:9001/a");
    let start = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let url = scope.spawn(|| {
            let settings = serde_json::json!({"url":"http://127.0.0.2:9002/b"});
            start.wait();
            assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
        });
        let timeout = scope.spawn(|| {
            let settings = serde_json::json!({"timeout_ms":777});
            start.wait();
            assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
        });
        url.join().unwrap();
        timeout.join().unwrap();
    });
    let live = f.live();
    assert_eq!(live.url.as_str(), "http://127.0.0.2:9002/b");
    assert_eq!(live.timeout, std::time::Duration::from_millis(777));
}

#[test]
fn configuration_checkpoints_preserve_normalized_url_timeout_and_partial_semantics() {
    let initial = "http://user:secret@127.0.0.1:9001/first";
    let f = forwarder(initial);
    let push = |settings: serde_json::Value, version| {
        f.configure_checkpoint(settings.as_object().unwrap(), version)
            .unwrap()
            .unwrap()
    };
    let first = push(serde_json::json!({"timeout_ms": 777}), 2);
    assert_eq!((first.revision, first.settings_version), (1, 2));
    let second = push(
        serde_json::json!({"url": "http://next:credential@127.0.0.2:9002/second"}),
        2,
    );
    assert_eq!((second.revision, second.settings_version), (2, 2));
    let empty = push(serde_json::json!({}), 3);
    let null = push(serde_json::json!({"timeout_ms": null}), 3);
    assert_eq!(empty.settings(), null.settings());
    assert_eq!((null.revision, null.settings_version), (4, 3));
    let stale = push(
        serde_json::json!({"url": false, "timeout_ms": "invalid"}),
        1,
    );
    assert_eq!((stale.revision, stale.settings_version), (4, 3));
    assert_eq!(stale.settings(), null.settings());
    assert!(f
        .configure_checkpoint(
            serde_json::json!({"timeout_ms": "invalid"})
                .as_object()
                .unwrap(),
            4
        )
        .is_err());
    let current = f.live();
    let restored = forwarder(initial);
    let settings: serde_json::Value = serde_json::from_slice(null.settings()).unwrap();
    restored
        .configure(settings.as_object().unwrap(), null.settings_version)
        .unwrap();
    assert_eq!(restored.live().url, current.url);
    assert_eq!(
        restored.live().timeout,
        std::time::Duration::from_millis(777)
    );
    assert!(!format!("{null:?}").contains("credential"));
}

#[test]
fn concurrent_equal_version_checkpoints_capture_the_complete_serialized_state() {
    let f = forwarder("http://127.0.0.1:9001/first");
    let start = std::sync::Barrier::new(2);
    let (url, timeout) = std::thread::scope(|scope| {
        let url = scope.spawn(|| {
            start.wait();
            f.configure_checkpoint(
                serde_json::json!({"url":"http://127.0.0.2:9002/second"})
                    .as_object()
                    .unwrap(),
                2,
            )
            .unwrap()
            .unwrap()
        });
        let timeout = scope.spawn(|| {
            start.wait();
            f.configure_checkpoint(
                serde_json::json!({"timeout_ms":777}).as_object().unwrap(),
                2,
            )
            .unwrap()
            .unwrap()
        });
        (url.join().unwrap(), timeout.join().unwrap())
    });
    assert_ne!(url.revision, timeout.revision);
    let latest = if url.revision > timeout.revision {
        url
    } else {
        timeout
    };
    let restored = forwarder("http://127.0.0.1:9001/first");
    let settings: serde_json::Value = serde_json::from_slice(latest.settings()).unwrap();
    restored
        .configure(settings.as_object().unwrap(), latest.settings_version)
        .unwrap();
    assert_eq!(restored.live().url.as_str(), "http://127.0.0.2:9002/second");
    assert_eq!(
        restored.live().timeout,
        std::time::Duration::from_millis(777)
    );
}

#[test]
fn concurrent_partial_configures_never_lose_an_update_under_repetition() {
    for round in 0..300 {
        let f = forwarder("http://127.0.0.1:9001/a");
        let start = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let settings = serde_json::json!({"url":"http://127.0.0.2:9002/b"});
                start.wait();
                assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
            });
            scope.spawn(|| {
                let settings = serde_json::json!({"timeout_ms":777});
                start.wait();
                assert!(f.configure(settings.as_object().unwrap(), 2).is_ok());
            });
        });
        let live = f.live();
        assert_eq!(
            live.url.as_str(),
            "http://127.0.0.2:9002/b",
            "round {round}"
        );
        assert_eq!(
            live.timeout,
            std::time::Duration::from_millis(777),
            "round {round}"
        );
    }
}

#[test]
fn complete_checkpoint_restores_status_spelling_and_effective_timeout() {
    let initial = "https://hooks.example";
    let f = forwarder(initial);
    let settings = serde_json::json!({"timeout_ms":99999});
    let checkpoint = f
        .configure_checkpoint(settings.as_object().unwrap(), 2)
        .unwrap()
        .unwrap();
    let restored = forwarder("https://different.example/start");
    let settings: serde_json::Value = serde_json::from_slice(checkpoint.settings()).unwrap();
    restored
        .configure(settings.as_object().unwrap(), checkpoint.settings_version)
        .unwrap();
    assert_eq!(
        crate::report::status(&f.live()),
        crate::report::status(&restored.live())
    );
    assert_eq!(
        restored.live().timeout,
        std::time::Duration::from_millis(crate::config::MAX_TIMEOUT_MS)
    );
    assert_eq!(
        crate::report::status(&restored.live())["status"]["settings"]["url"],
        initial
    );
    assert_eq!(
        crate::report::status(&restored.live())["status"]["settings"]["timeout_ms"],
        99999
    );
}
