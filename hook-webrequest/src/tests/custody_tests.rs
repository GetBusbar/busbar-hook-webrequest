use crate::net_guard::{loggable_url, mask_userinfo, reportable_url};

#[test]
fn redaction_preserves_canonical_authority_empty_delimiters_and_opaque_paths() {
    for (raw, masked, reported, logged) in [
        (
            "https://svc:pw@[::1]:9443/a%2Fb?token=%2F#frag",
            "https://***@[::1]:9443/a%2Fb?token=%2F#frag",
            "https://***@[::1]:9443/a%2Fb?<redacted>",
            "https://***@[::1]:9443/***?<redacted>",
        ),
        (
            "https://:pw@host/?#",
            "https://***@host/?#",
            "https://***@host/?<redacted>",
            "https://***@host/?<redacted>",
        ),
        (
            "custom:opaque?key=secret#frag",
            "custom:opaque?key=secret#frag",
            "custom:opaque?<redacted>",
            "custom:%2F***?<redacted>",
        ),
        (
            "file:///tmp/path?key=secret#frag",
            "file:///tmp/path?key=secret#frag",
            "file:///tmp/path?<redacted>",
            "file:///***?<redacted>",
        ),
    ] {
        let url = url::Url::parse(raw).unwrap();
        assert_eq!(mask_userinfo(&url), masked, "{raw}");
        assert_eq!(reportable_url(&url), reported, "{raw}");
        assert_eq!(loggable_url(&url), logged, "{raw}");
    }
}
