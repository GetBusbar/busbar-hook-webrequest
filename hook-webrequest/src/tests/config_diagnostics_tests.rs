use super::*;

fn warnings_in(settings: &[u8]) -> Vec<String> {
    let (_, diagnostics) = open_with_diagnostics(settings).unwrap();
    let mut warnings: Vec<_> = diagnostics
        .unknown
        .iter()
        .map(|key| unknown_warning(key))
        .collect();
    warnings.extend(diagnostics.timeout_ms.and_then(clamp_warning));
    warnings
}

#[test]
fn a_clamped_timeout_is_warned_once() {
    for (settings, ms) in [
        (r#"{"url":"https://h/","timeout_ms":99999}"#, "99999"),
        (r#"{"url":"https://h/","timeout_ms":0}"#, "0"),
    ] {
        let w = warnings_in(settings.as_bytes());
        assert_eq!(w.len(), 1, "{w:?}");
        assert!(
            w[0].contains("timeout_ms")
                && w[0].contains(&format!("timeout_ms {ms} "))
                && w[0].contains("clamp"),
            "{w:?}"
        );
    }
    let in_range = warnings_in(br#"{"url":"https://h/","timeout_ms":5000}"#);
    assert!(in_range.is_empty(), "{in_range:?}");
    assert!(warnings_in(br#"{"url":"https://h/","timeout_ms":null}"#).is_empty());
    let w = warnings_in(br#"{"url":"https://h/","timeout_ms":60000,"x":1}"#);
    assert_eq!(w.len(), 2, "{w:?}");
}

#[test]
fn diagnostics_ignore_values_and_preserve_sorted_unique_unknown_names() {
    let warnings = warnings_in(
        br#"{"z":"PASSWORDCANARY","url":"https://h/","a":{"nested":"SECRETCANARY"},"z":null}"#,
    );
    assert_eq!(warnings.len(), 2);
    assert!(warnings[0].contains("'a'"));
    assert!(warnings[1].contains("'z'"));
    assert!(!warnings.join(" ").contains("CANARY"));
}

#[test]
fn duplicate_known_keys_are_refused_even_after_null_or_escaped_spelling() {
    for settings in [
        &br#"{"url":"https://h/","timeout_ms":null,"timeout_ms":1}"#[..],
        br#"{"url":"https://h/","u\u0072l":"https://other/"}"#,
    ] {
        assert!(open(settings).unwrap_err().contains("at most once"));
    }
}
