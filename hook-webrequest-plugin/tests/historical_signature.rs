// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The genuine released manifest remains an owner fixture. Core tests use neutral
//! signatures for admission mechanics; this test pins historical product compatibility.

use busbar_plugin_loader::sign::{
    canonical_manifest_bytes, evaluate, public_key_from_hex, Manifest, RejectKind, TrustInput,
    TrustPolicy, VerifyingKey, RETIRED_RELEASE_KEYS,
};
use ed25519_dalek::Signature;
use std::collections::BTreeMap;

const RELEASE_PUBKEY_1_5: &str = "b18395a332803151b9cd40a71489a86a96d8bea3ee6a37a45f59dec197bacba7";

fn policy(
    first_party_key: Option<VerifyingKey>,
    allow_unsigned: bool,
    allow_third_party: bool,
) -> TrustPolicy {
    TrustPolicy {
        first_party_key,
        binary_version: "1.5.0".into(),
        allow_unsigned,
        allow_third_party,
        ..TrustPolicy::default()
    }
}

fn retired_key_manifest() -> Manifest {
    serde_json::from_str(include_str!(
        "fixtures/manifest_1_5_5_busbar_webrequest.json"
    ))
    .expect("the 1.5.5 manifest parses")
}

#[test]
fn a_manifest_signed_by_the_retired_ci_key_is_refused() {
    assert!(
        RETIRED_RELEASE_KEYS
            .iter()
            .any(|(k, _)| *k == RELEASE_PUBKEY_1_5),
        "the retired 1.5 CI key is on the compiled-in retired list"
    );

    let m = retired_key_manifest();
    let lib = b"\x7fELF any library";
    let keyless = policy(None, false, false);
    let embeds_it = TrustPolicy {
        first_party_key: Some(public_key_from_hex(RELEASE_PUBKEY_1_5).unwrap()),
        ..policy(None, false, false)
    };
    for pol in [&keyless, &embeds_it] {
        let r = evaluate(lib, &m, pol).expect_err("a retired-key manifest never loads by default");
        assert_eq!(r.kind, RejectKind::RetiredKey, "got {r:?}");
        assert_eq!(r.kind.code(), "retired_key");
        assert!(
            r.reason.contains(RELEASE_PUBKEY_1_5),
            "names the key: {}",
            r.reason
        );
        assert!(
            r.reason.contains("RETIRED"),
            "says it is retired: {}",
            r.reason
        );
        assert!(
            r.reason.contains("plugins.trust.publishers"),
            "names the explicit opt-in: {}",
            r.reason
        );
    }

    let loose = policy(None, false, true);
    assert_eq!(
        evaluate(lib, &m, &loose).unwrap_err().kind,
        RejectKind::RetiredKey
    );

    let r = evaluate(
        b"\x7fELF any library",
        &retired_key_manifest(),
        &policy(None, true, false),
    )
    .expect_err("allow_unsigned never admits the retired 1.5 key");
    assert_eq!(r.kind, RejectKind::RetiredKey, "got {r:?}");
    assert!(r.reason.contains(RELEASE_PUBKEY_1_5), "{}", r.reason);
}

#[test]
fn explicit_retired_key_trust_still_requires_the_genuine_artifact() {
    let mins = BTreeMap::new();
    let floors = BTreeMap::new();
    let pol = TrustPolicy::from_config(TrustInput {
        publishers: &[("busbar-1-5-retired", RELEASE_PUBKEY_1_5)],
        allow_unsigned: false,
        allow_third_party: false,
        min_versions: &mins,
        first_party_floors: &floors,
        binary_version: "1.6.0",
    })
    .expect("the operator's entry for the retired key parses");
    let r = evaluate(b"\x7fELF any library", &retired_key_manifest(), &pol).unwrap_err();
    assert_eq!(
        r.kind,
        RejectKind::Tampered,
        "trusted explicitly, the retired key is no longer the refusal: {}",
        r.reason
    );
}

#[test]
fn an_old_manifest_with_no_former_names_parses_and_verifies_unchanged() {
    let text = include_str!("fixtures/manifest_1_5_5_busbar_webrequest.json");
    let m: Manifest = serde_json::from_str(text).expect("a 1.5.5 manifest parses");
    assert!(m.former_names.is_empty());
    assert_eq!(m.name, "busbar-webrequest");
    let key = public_key_from_hex(RELEASE_PUBKEY_1_5).unwrap();
    let sig: [u8; 64] = hex::decode(&m.signature).unwrap().try_into().unwrap();
    let canonical = canonical_manifest_bytes(&m);
    assert!(
        !String::from_utf8_lossy(&canonical).contains("former_names"),
        "an empty former-name list stays off the signed bytes"
    );
    key.verify_strict(&canonical, &Signature::from_bytes(&sig))
        .expect("the 1.5.5 release signature verifies over this binary's canonical bytes");

    let back: serde_json::Value = serde_json::to_value(&m).unwrap();
    let orig: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(back, orig);
}
