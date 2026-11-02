use super::*;
use busbar_contract::net::{is_cgnat_shared_v4, is_link_local_v6, is_unique_local_v6, Ipv4Addr};

fn url(s: &str) -> url::Url {
    url::Url::parse(s).unwrap()
}

#[test]
fn cgnat_ula_linklocal_predicates_match_core() {
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 64, 0, 0)));
    assert!(is_cgnat_shared_v4(&Ipv4Addr::new(100, 100, 100, 200)));
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(100, 63, 255, 255)));
    assert!(!is_cgnat_shared_v4(&Ipv4Addr::new(8, 8, 8, 8)));
    assert!(is_unique_local_v6(&"fc00::1".parse().unwrap()));
    assert!(is_unique_local_v6(&"fd00:ec2::254".parse().unwrap()));
    assert!(!is_unique_local_v6(&"fe80::1".parse().unwrap()));
    assert!(is_link_local_v6(&"fe80::1".parse().unwrap()));
    assert!(!is_link_local_v6(&"fc00::1".parse().unwrap()));
}

#[test]
fn alternate_encoding_flags_obfuscated_forms() {
    assert!(is_alternate_ipv4_encoding("2130706433"));
    assert!(is_alternate_ipv4_encoding("0x7f000001"));
    assert!(is_alternate_ipv4_encoding("017700000001"));
    assert!(is_alternate_ipv4_encoding("127.1"));
    assert!(!is_alternate_ipv4_encoding("127.0.0.1"));
    assert!(!is_alternate_ipv4_encoding("example.com"));
    assert!(is_alternate_loopback_v4("2130706433"));
    assert!(is_alternate_loopback_v4("127.1"));
    assert!(!is_alternate_loopback_v4("2130706434"));
}

#[test]
fn host_is_blocked_blocks_internal_targets() {
    assert!(host_is_blocked(&url("http://169.254.169.254/latest")));
    assert!(host_is_blocked(&url("https://metadata.google.internal/x")));
    assert!(host_is_blocked(&url("https://100.100.100.200/meta")));
    assert!(host_is_blocked(&url("https://168.63.129.16/x")));
    assert!(host_is_blocked(&url("https://192.0.0.192/x")));

    assert!(host_is_blocked(&url("https://10.0.0.1/x")));
    assert!(host_is_blocked(&url("https://192.168.1.1/x")));
    assert!(host_is_blocked(&url("https://100.64.0.1/x")));
    assert!(host_is_blocked(&url("https://[fc00::1]/x")));
    assert!(host_is_blocked(&url("https://[fe80::1]/x")));

    assert!(!host_is_blocked(&url("http://127.0.0.1:8080/x")));
    assert!(!host_is_blocked(&url("http://localhost:8080/x")));
    assert!(!host_is_blocked(&url("https://[::1]:8080/x")));
    assert!(!host_is_blocked(&url("https://api.example.com/x")));
}

/// The classic SSRF bypass forms, driven through `host_is_blocked` itself rather than through the

#[test]
fn host_is_blocked_covers_the_classic_bypass_forms() {
    assert!(host_is_blocked(&url(
        "http://[::ffff:169.254.169.254]/latest"
    )));
    assert!(host_is_blocked(&url("https://[::ffff:10.0.0.1]/x")));
    assert!(host_is_blocked(&url("https://[::ffff:192.168.1.1]/x")));
    assert!(host_is_blocked(&url("https://[::ffff:100.100.100.200]/x")));

    assert!(!host_is_blocked(&url("http://[::ffff:127.0.0.1]:8080/x")));

    assert!(host_is_blocked(&url("http://2852039166/latest")));
    assert!(host_is_blocked(&url("http://0xa9fea9fe/latest")));
    assert!(host_is_blocked(&url("http://0251.0376.0251.0376/x")));
    assert!(host_is_blocked(&url("http://10.1/x")));

    assert!(!host_is_blocked(&url("http://2130706433:8080/x")));
    assert!(!host_is_blocked(&url("http://127.1:8080/x")));

    assert!(host_is_blocked(&url("https://metadata.internal/x")));
    assert!(host_is_blocked(&url("https://metadata.google.internal/x")));

    assert!(host_is_blocked(&url("https://METADATA.GOOGLE.INTERNAL/x")));
    assert!(host_is_blocked(&url("https://metadata.google.internal./x")));
    assert!(host_is_blocked(&url("https://metadata.internal./x")));

    assert!(host_is_blocked(&url("http://0.0.0.0:8080/x")));
    assert!(host_is_blocked(&url("http://[::]:8080/x")));
    assert!(host_is_blocked(&url("http://255.255.255.255/x")));

    assert!(host_is_blocked(&url("https://172.16.0.1/x")));
    assert!(host_is_blocked(&url("https://172.31.255.254/x")));

    assert!(!host_is_blocked(&url("https://172.15.0.1/x")));
    assert!(!host_is_blocked(&url("https://172.32.0.1/x")));

    assert!(host_is_blocked(&url("file:///etc/passwd")));
}

/// IPv6 forms that CARRY an internal IPv4 target but that `Ipv6Addr::to_ipv4` does not unwrap.

#[test]
fn ipv6_embeddings_of_internal_ipv4_targets_are_blocked() {
    assert_eq!(
        embedded_ipv4(&"64:ff9b::a9fe:a9fe".parse().unwrap()),
        Some(Ipv4Addr::new(169, 254, 169, 254))
    );
    assert!(host_is_blocked(&url("https://[64:ff9b::a9fe:a9fe]/latest")));
    assert!(host_is_blocked(&url("https://[64:ff9b::a00:1]/x")));

    assert_eq!(
        embedded_ipv4(&"64:ff9b:1::a9fe:a9fe".parse().unwrap()),
        Some(Ipv4Addr::new(169, 254, 169, 254))
    );
    assert!(host_is_blocked(&url("https://[64:ff9b:1::a9fe:a9fe]/x")));
    assert!(host_is_blocked(&url("https://[64:ff9b:1::a00:1]/x")));

    assert_eq!(
        embedded_ipv4(&"2002:a00:1::".parse().unwrap()),
        Some(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert!(host_is_blocked(&url("https://[2002:a00:1::]/x")));
    assert!(host_is_blocked(&url("https://[2002:a9fe:a9fe::]/x")));

    assert!(is_site_local_v6(&"fec0::1".parse().unwrap()));
    assert!(host_is_blocked(&url("https://[fec0::1]/x")));

    assert!(!host_is_blocked(&url("https://[2606:4700:4700::1111]/x")));
    assert_eq!(
        embedded_ipv4(&"2606:4700:4700::1111".parse().unwrap()),
        None
    );

    assert!(!host_is_blocked(&url("http://[64:ff9b::7f00:1]:8080/x")));
}

/// `fe80::/10` is a /10, not a /16. The only previous fixture was `fe80::1`, whose first segment is

#[test]
fn link_local_v6_is_a_slash_10_not_a_slash_16() {
    for addr in ["fe80::1", "fe9f::1", "febf::1", "feb0::dead"] {
        assert!(
            is_link_local_v6(&addr.parse().unwrap()),
            "{addr} is inside fe80::/10 and must be link-local"
        );
        assert!(host_is_blocked(&url(&format!("https://[{addr}]/x"))));
    }

    assert!(!is_link_local_v6(&"fe7f::1".parse().unwrap()));
    assert!(!is_link_local_v6(&"fec0::1".parse().unwrap()));
}

#[test]
fn validate_rejects_scheme_and_plaintext_remote() {
    assert!(validate_target_url("ftp://example.com/x").is_err());

    assert!(validate_target_url("http://api.example.com/x").is_err());

    assert!(validate_target_url("http://127.0.0.1:9000/route").is_ok());
    assert!(validate_target_url("http://localhost:9000/route").is_ok());

    assert!(validate_target_url("https://api.example.com/route").is_ok());

    assert!(validate_target_url("https://10.0.0.1/route").is_err());
}

#[test]
fn plaintext_loopback_carve_out_covers_dot_localhost_and_mapped_v6() {
    assert!(validate_target_url("http://sidecar.localhost:8080/h").is_ok());
    assert!(validate_target_url("http://SIDECAR.LOCALHOST/h").is_ok());

    assert!(validate_target_url("http://[::ffff:127.0.0.1]:9000/h").is_ok());

    assert!(validate_target_url("http://evil.localhost.example/h").is_err());
    assert!(validate_target_url("http://localhost.example.com/h").is_err());
    assert!(validate_target_url("http://notlocalhost/h").is_err());
}

#[test]
fn errors_mask_embedded_userinfo() {
    let err = validate_target_url("https://svc:hunter2@10.0.0.1/route").unwrap_err();
    assert!(
        !err.contains("hunter2"),
        "SSRF error leaked userinfo: {err}"
    );
    assert_eq!(
        mask_userinfo(&url("https://svc:hunter2@host/p?q=1")),
        "https://***@host/p?q=1"
    );
    assert_eq!(mask_userinfo(&url("https://host/p")), "https://host/p");
}

/// The status surface must not republish a query string. A sidecar authenticating by query

#[test]
fn the_reportable_url_redacts_a_query_string_and_the_fragment() {
    assert_eq!(
        reportable_url(&url("https://hooks.example.com/route?token=eyJhbGciOi")),
        "https://hooks.example.com/route?<redacted>"
    );
    assert_eq!(
        reportable_url(&url(
            "https://svc:hunter2@hooks.example.com/route?token=abc"
        )),
        "https://***@hooks.example.com/route?<redacted>"
    );

    assert_eq!(
        reportable_url(&url("https://hooks.example.com/route")),
        "https://hooks.example.com/route"
    );

    assert_eq!(
        reportable_url(&url("https://hooks.example.com/route#frag")),
        "https://hooks.example.com/route"
    );
}

/// Regression for the TAB-in-scheme-separator masking bypass: WHATWG URL parsing (which

#[test]
fn mask_userinfo_survives_tab_in_scheme_separator() {
    let raw = "https:\t//svc:hunter2@10.0.0.1/route";

    let parsed = url::Url::parse(raw).expect("WHATWG parsing accepts the embedded tab");
    assert_eq!(parsed.host_str(), Some("10.0.0.1"));

    let err = validate_target_url(raw).expect_err("10.0.0.1 must be SSRF-rejected");
    assert!(
        !err.contains("hunter2"),
        "mask_userinfo must mask a TAB-obfuscated scheme separator too, got: {err}"
    );
    assert_eq!(mask_userinfo(&parsed), "https://***@10.0.0.1/route");
}

/// The one internal-address predicate and the literal-text guard agree about every spelling of one

#[test]
fn the_shared_predicate_agrees_with_the_literal_text_guard() {
    let cases: [(&str, bool); 20] = [
        ("127.0.0.1", false),
        ("::1", false),
        ("10.0.0.1", true),
        ("172.16.0.1", true),
        ("192.168.1.1", true),
        ("169.254.169.254", true),
        ("100.64.0.1", true),
        ("fd00::1", true),
        ("fe80::1", true),
        ("93.184.216.34", false),
        ("::ffff:169.254.169.254", true),
        ("::ffff:127.0.0.1", false),
        ("64:ff9b::a9fe:a9fe", true),
        ("64:ff9b:1:abcd::a9fe:a9fe", true),
        ("2002:a9fe:a9fe::", true),
        ("fec0::1", true),
        ("::", true),
        ("0.0.0.0", true),
        ("255.255.255.255", true),
        ("2606:4700:4700::1111", false),
    ];
    for (raw, want_internal) in cases {
        let ip: std::net::IpAddr = raw.parse().unwrap();
        assert_eq!(
            ip_is_internal(&ip),
            want_internal,
            "address verdict for {raw}"
        );

        let url = url::Url::parse(&if ip.is_ipv6() {
            format!("https://[{raw}]/x")
        } else {
            format!("https://{raw}/x")
        })
        .unwrap();
        assert_eq!(
            host_is_blocked(&url),
            want_internal,
            "literal-text verdict for {raw} must match the address one"
        );
    }
}

/// Every refusal echoes the url as a log line names it: the path (which may carry the key) is cut.
#[test]
fn refusal_texts_never_show_the_url_path() {
    for raw in [
        "ftp://hooks.example.com/v1/KEY123",
        "https://10.0.0.1/v1/KEY123",
        "http://hooks.example.com/v1/KEY123",
    ] {
        let err = validate_target_url(raw).unwrap_err();
        assert!(!err.contains("KEY123"), "{raw}: {err}");
        assert!(err.contains("/***"), "{raw}: {err}");
    }
    let err = validate_target_url("https://svc:pw@10.0.0.1:8443/v1/KEY123?t=SECRET").unwrap_err();
    assert!(
        err.contains("got 'https://***@10.0.0.1:8443/***?<redacted>'"),
        "{err}"
    );
}

#[test]
fn the_literal_host_check_refuses_every_contract_internal_ipv4() {
    for host in [
        "198.18.0.1",
        "198.19.255.255",
        "0.1.2.3",
        "0.255.255.255",
        "192.0.0.5",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.255",
        "[::ffff:198.18.0.1]",
    ] {
        let raw = format!("https://{host}/x");
        let err = validate_target_url(&raw).expect_err(&raw);
        assert!(err.contains("SSRF guard"), "{raw}: {err}");
    }
    for host in ["127.0.0.1", "198.20.0.1", "1.2.3.4", "193.0.0.1"] {
        assert!(
            validate_target_url(&format!("https://{host}/x")).is_ok(),
            "{host}"
        );
    }
}

#[test]
fn the_literal_host_check_refuses_every_contract_internal_ipv6() {
    for host in ["ff02::1", "ff00::1", "fc00::1", "fe80::1", "::", "fec0::1"] {
        let raw = format!("https://[{host}]/x");
        let err = validate_target_url(&raw).expect_err(&raw);
        assert!(err.contains("SSRF guard"), "{raw}: {err}");
    }
    for host in ["::1", "::ffff:127.0.0.1", "2606:4700:4700::1111"] {
        assert!(
            validate_target_url(&format!("https://[{host}]/x")).is_ok(),
            "{host}"
        );
    }
    assert!(validate_target_url("http://[::1]:9000/x").is_ok());
}

/// The secrets a failure is scrubbed of include the `Authorization` value the userinfo becomes and

#[test]
fn secret_parts_include_the_authorization_value_and_its_token() {
    let parts = secret_parts(&url("https://svc:hunter2@hooks.example/route"));

    assert!(parts.iter().any(|p| p == "c3ZjOmh1bnRlcjI="), "{parts:?}");
    assert!(
        parts.iter().any(|p| p == "Basic c3ZjOmh1bnRlcjI="),
        "{parts:?}"
    );
    let scrubbed = scrub("echo: authorization: Basic c3ZjOmh1bnRlcjI=", &parts);
    assert!(!scrubbed.contains("c3ZjOmh1bnRlcjI="), "{scrubbed}");
}

#[test]
fn a_url_with_an_at_after_the_host_is_refused_without_its_credential() {
    for raw in [
        "https://tok/en@hooks.example/x",
        "https://u:123/x@hooks.example/x",
        "https://svc:pa/ss@hooks.example/x",
        "https://hooks.example/a@b",
        "https://hooks.example/x?to@ken",
    ] {
        let err = validate_target_url(raw).unwrap_err();
        assert!(
            err.starts_with("webrequest: settings.url ") && err.contains("ambiguous"),
            "{raw}: {err}"
        );
        for secret in ["tok", "en@", "pa/ss", "to@ken", "123"] {
            assert!(!err.contains(secret), "{raw} echoed {secret}: {err}");
        }
        let nack = refuse_target_url(raw).unwrap_err();
        assert!(
            nack.starts_with("settings.url ") && nack.contains("ambiguous"),
            "{nack}"
        );
    }

    let err =
        validate_target_url("https://u:p/w@hooks.example/k/KEYCANARY?token=QCANARY").unwrap_err();
    for canary in ["KEYCANARY", "QCANARY", "p/w", "hooks.example"] {
        assert!(!err.contains(canary), "{canary} echoed: {err}");
    }

    assert!(validate_target_url("https://hooks.example/a%40b").is_ok());
    assert!(validate_target_url("https://svc:hunter2@hooks.example/x").is_ok());
}

#[test]
fn separately_echoed_query_values_and_path_segments_are_scrubbed() {
    let target = url(
        "https://hooks.example/v1/PATHCANARY?token=QUERYCANARY&raw=ENC%2BCANARY&form=FORM+CANARY",
    );
    let parts = secret_parts(&target);
    let echo = "denied PATHCANARY QUERYCANARY ENC%2BCANARY ENC+CANARY FORM+CANARY FORM CANARY";
    assert_eq!(scrub(echo, &parts), "denied *** *** *** *** *** ***");
    assert_eq!(
        scrub("unrelated remote phrase", &parts),
        "unrelated remote phrase"
    );
}
