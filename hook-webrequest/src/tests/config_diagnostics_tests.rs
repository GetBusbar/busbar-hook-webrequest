use super::*;

#[test]
fn diagnostics_ignore_values_and_preserve_sorted_unique_unknown_names() {
    let (_, diagnostics) = open_with_diagnostics(
        br#"{"z":"PASSWORDCANARY","url":"https://h/","a":{"nested":"SECRETCANARY"},"z":null,"timeout_ms":60000}"#,
    ).unwrap();
    assert_eq!(&*diagnostics.unknown, &["a", "z"]);
    assert_eq!(diagnostics.timeout_ms, Some(60000));
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
