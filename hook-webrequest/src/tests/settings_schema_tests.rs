// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[path = "../../../testing/settings/integer_token.rs"]
mod settings_profile;

use super::STATEMENT;
use crate::config;

#[test]
fn settings_schema_matches_lifecycle() {
    let bytes = include_bytes!("../../settings.schema.json");
    let schema: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    assert_eq!(STATEMENT.settings_schema.len(), bytes.len());
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(crate::report::describe()["schema"], schema);
    assert_eq!(
        schema["properties"]["timeout_ms"]["default"],
        config::DEFAULT_TIMEOUT_MS
    );
    let validator = settings_profile::validator(&schema).unwrap();
    for (text, accepted) in [
        (r#"{"url":"https://hooks.example/route"}"#, true),
        (r#"{"url":"http://localhost/route"}"#, true),
        (r#"{"url":"https://hooks.example/route","unknown":1}"#, true),
        (
            r#"{"url":"https://hooks.example/route","timeout_ms":null}"#,
            true,
        ),
        (
            r#"{"url":"https://hooks.example/route","timeout_ms":0}"#,
            true,
        ),
        (
            r#"{"url":"https://hooks.example/route","timeout_ms":18446744073709551615}"#,
            true,
        ),
        ("{}", false),
        ("null", false),
        ("[]", false),
        (r#"{"url":null}"#, false),
        (r#"{"url":""}"#, false),
        (r#"{"url":"   "}"#, false),
        (r#"{"url":1}"#, false),
        (
            r#"{"url":"https://hooks.example/route","timeout_ms":-1}"#,
            false,
        ),
        (
            r#"{"url":"https://hooks.example/route","timeout_ms":1.5}"#,
            false,
        ),
        (
            r#"{"url":"https://hooks.example/route","timeout_ms":"1"}"#,
            false,
        ),
    ] {
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(validator.is_valid(&value), accepted, "schema: {text}");
        assert_eq!(
            config::open(text.as_bytes()).is_ok(),
            accepted,
            "lifecycle: {text}"
        );
    }
    for (ms, effective) in [(0, 1), (u64::MAX, config::MAX_TIMEOUT_MS)] {
        let text = serde_json::json!({"url":"https://hooks.example/route","timeout_ms":ms});
        assert_eq!(
            config::open(text.to_string().as_bytes())
                .unwrap()
                .timeout
                .as_millis(),
            u128::from(effective)
        );
    }
    assert!(config::open(b"").is_err());
}

#[test]
fn settings_schema_documents_runtime_url_policy() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../settings.schema.json")).unwrap();
    assert!(schema["properties"]["url"]["description"]
        .as_str()
        .unwrap()
        .contains("runtime validation"));
    // Structural schema validation does not perform the plugin's URL parsing or egress policy.
    // The real lifecycle must continue to refuse these structurally valid settings.
    let validator = settings_profile::validator(&schema).unwrap();
    for url in [
        "ftp://hooks.example/route",
        "https://169.254.169.254/",
        "http://hooks.example/",
    ] {
        let settings = serde_json::json!({"url":url});
        assert!(validator.is_valid(&settings));
        assert!(config::open(settings.to_string().as_bytes()).is_err());
    }
}

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value =
        serde_json::from_slice(include_bytes!("../../settings.schema.json")).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [(
        r#"/properties/timeout_ms"#,
        r#"{"url":"https://hooks.example/route","timeout_ms":TOKEN}"#,
        "1",
        "unsigned",
    )] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                config::open(text.as_bytes()).is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                config::open(text.as_bytes()).is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}
