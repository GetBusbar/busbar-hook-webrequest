// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SSRF guard the `webrequest` forwarder applies to its operator-configured target URL.
//!
//! This plugin makes an OUTBOUND HTTP call to a URL the operator put in `settings.url`, so — exactly
//! like the retired `webhook` hook transport it replaces — it must refuse a URL that points at an
//! internal target (cloud-metadata, RFC1918 private, RFC6598 CGNAT, link-local, IPv6 ULA, or the
//! alternate IPv4 encodings a resolver still expands to those). A signed, trusted forwarder that
//! could be pointed at `169.254.169.254` would be an SSRF pivot; the guard closes that.
//!
//! ## Policy parity with the old `webhook` hook (deliberate)
//!
//! Link-local / IMDS / RFC1918 / CGNAT / cloud-metadata are BLOCKED, but loopback / `localhost` are
//! ALLOWED (a hook sidecar is typically co-located on loopback), and plaintext `http://` is permitted
//! ONLY for a loopback host, so a hook on `route: webhook` can migrate by pointing this plugin at the
//! same URL.
//!
//! ## Shared predicates
//!
//! The context-free address predicates (`ipv4_is_internal`, `ipv6_is_internal`, `embedded_ipv4`,
//! `is_alternate_ipv4_encoding`) and the cloud-metadata host list are the contract's
//! (`busbar_contract::net`), the same ones the host's own guard reads. Only the policy lives here:
//! loopback sidecars are carved out.
//!
//! These predicates validate the URL's literal host text at open/configure time. Name resolution,
//! the resolved-address check and the address pin (DNS rebinding) belong to the host's
//! loopback-allowed egress class, which every connection this plugin opens goes through.

use crate::owners::{ParsedUrl, Parts};
use crate::ALIAS;
use busbar_contract::abi::sdk::url as sdk_url;
use busbar_contract::net::{
    embedded_ipv4, ipv4_is_internal, ipv6_is_internal, is_alternate_ipv4_encoding, IpAddr,
    Ipv6Addr, METADATA_HOSTS,
};

/// IPv6 site-local `fec0::/10`. Deprecated by RFC 3879 but still routed on plenty of real networks,
/// and NOT covered by the ULA or link-local masks (`0xfec0 & 0xfe00` is `0xfe00`, not `0xfc00`;
/// `0xfec0 & 0xffc0` is `0xfec0`, not `0xfe80`), so without this it was simply allowed.
pub fn is_site_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfec0
}

/// True iff `host` is an alternate (non-dotted-quad) IPv4 encoding that unambiguously denotes a
/// loopback address in `127.0.0.0/8` (decimal `2130706433`, hex `0x7f000001`, octal `017700000001`,
/// or a short-dotted `127.1` / `127.0.1`). Used to permit the loopback-sidecar exception while
/// still blocking every OTHER alternate-encoded internal target. Conservative: anything it cannot
/// positively confirm as loopback is treated as non-loopback (and therefore blocked).
pub fn is_alternate_loopback_v4(host: &str) -> bool {
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return u32::from_str_radix(hex, 16)
                .ok()
                .is_some_and(|v| (v >> 24) == 127);
        }
        if let Some(oct) = host.strip_prefix('0').filter(|_| host.len() > 1) {
            if let Ok(v) = u32::from_str_radix(oct, 8) {
                return (v >> 24) == 127;
            }
        }
        if let Ok(v) = host.parse::<u32>() {
            return (v >> 24) == 127;
        }
        return false;
    }
    if host.split('.').count() >= 4 {
        return false;
    }
    let Some(first) = host.split('.').next().and_then(|p| p.parse::<u32>().ok()) else {
        return false;
    };
    first == 127 && host.split('.').all(|p| p.parse::<u32>().is_ok())
}

/// True iff the target URL's host is the loopback/localhost target the forwarder MAY reach — the exact
/// carve-out `host_is_blocked` leaves un-blocked (parity with the old webhook policy, which allowed a
/// loopback sidecar). Used to gate the plaintext-`http://` allowance to loopback only.
pub fn host_is_loopback(url: &url::Url) -> bool {
    let Some(host) = host_of(url) else {
        return false;
    };
    if is_alternate_ipv4_encoding(host) {
        return is_alternate_loopback_v4(host);
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => ip_is_loopback(&ip),
        Err(_) => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .rsplit_once('.')
                    .is_some_and(|(_, tld)| tld.eq_ignore_ascii_case("localhost"))
        }
    }
}

/// The loopback predicate over an IP literal ([`host_is_loopback`]): v4 loopback, `::1`, and the
/// IPv4-mapped/compatible spellings of a v4 loopback.
fn ip_is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
    }
}

/// SSRF block predicate for the target URL: identical to a full internal check EXCEPT loopback and the
/// `localhost` DNS name are NOT blocked (the loopback-sidecar carve-out the old webhook policy kept).
/// Every other internal/metadata target is blocked: cloud-metadata names + IMDS literal, RFC1918
/// private, RFC6598 CGNAT, link-local, IPv6 ULA/link-local/site-local/unspecified, the IPv4
/// addresses embedded in IPv4-mapped, IPv4-compatible, NAT64 and 6to4 IPv6 forms, and the
/// alternate-IPv4 encodings that resolve to those.
///
/// This inspects the URL's literal host TEXT only and never resolves a name: a NAME that resolves to
/// an internal address is refused by the host's loopback-allowed egress class when the connection is
/// opened, which also pins the approved addresses.
pub fn host_is_blocked(url: &url::Url) -> bool {
    let Some(host) = host_of(url) else {
        return true;
    };
    if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
        return true;
    }
    if is_alternate_ipv4_encoding(host) {
        return !is_alternate_loopback_v4(host);
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => ip_is_internal(&ip),

        Err(_) => false,
    }
}

/// The internal-address predicate over the literal host [`host_is_blocked`] parsed, the loopback
/// carve-out for sidecars included.
fn ip_is_internal(ip: &IpAddr) -> bool {
    if ip_is_loopback(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => ipv4_is_internal(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = embedded_ipv4(v6) {
                return ipv4_is_internal(&v4);
            }
            ipv6_is_internal(v6) || is_site_local_v6(v6)
        }
    }
}

/// The URL's host with the IPv6 `[...]` brackets and a single trailing FQDN-root `.` stripped, so the
/// predicates see the same canonical form the OTLP/webhook guard did. `None` for a hostless URL.
fn host_of(url: &url::Url) -> Option<&str> {
    let host = url.host_str()?;
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    Some(host)
}

/// Case-insensitive equality of a URL's scheme to `want` (an ASCII-lowercase literal).
fn scheme_is(url: &url::Url, want: &str) -> bool {
    url.scheme().eq_ignore_ascii_case(want)
}

/// Validate the operator-configured target URL against the SSRF guard, returning the parsed `url::Url`
/// on success or a stable, credential-free error on rejection. Accepts `https://` for any
/// allowed host and `http://` ONLY for a loopback host (parity with the old webhook policy: a plaintext
/// hop must stay on loopback so a payload — which may carry granted prompt/user content — is never sent
/// in cleartext to a remote host). Any embedded `user:pass@` userinfo is masked out of every error.
pub fn validate_target_url(raw: &str) -> Result<url::Url, String> {
    refuse_target_url(raw).map_err(|reason| {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: the refusal text of a refused url, built once at open or configure"
        )]
        let text = format!("{ALIAS}: {reason}");
        text
    })
}

/// [`validate_target_url`] with the refusal's reason WITHOUT the `webrequest: ` prefix, for a caller
/// that frames it in its own words (`configure`'s NACK).
///
/// # Errors
/// The reason.
pub fn refuse_target_url(raw: &str) -> Result<url::Url, String> {
    if let Some(refusal) = ambiguous_url(raw) {
        return Err(refusal);
    }
    #[expect(
        clippy::disallowed_methods,
        reason = "error: the refusal text of an unparsable url, built once at open or configure"
    )]
    let url = ParsedUrl::parse(raw).map_err(|e| format!("settings.url is not a valid URL: {e}"))?;
    if !(scheme_is(&url, "https") || scheme_is(&url, "http")) {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: the refusal text of a url with another scheme, built once at open or configure"
        )]
        return Err(format!(
            "settings.url must be an http:// or https:// URL (got '{}')",
            echo_of(echoable_scheme(url.scheme()), true)
        ));
    }
    if url
        .username()
        .as_bytes()
        .windows(3)
        .any(|w| w.eq_ignore_ascii_case(b"%3a"))
    {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: the refusal text of an unusable user name, built once at open or configure"
        )]
        return Err(
            "settings.url userinfo names a user containing an encoded ':', which Basic \
             authorization cannot carry (RFC 7617); the password goes after the first ':'"
                .to_string(),
        );
    }
    for userinfo in std::iter::once(url.username()).chain(url.password()) {
        let decoded = sdk_url::percent_decode(userinfo.as_bytes());
        let valid_utf8 = std::str::from_utf8(&decoded).is_ok();
        drop(busbar_contract::abi::sdk::cred::Held::new(decoded));
        if !valid_utf8 {
            #[expect(
                clippy::disallowed_methods,
                reason = "error: the refusal text of undecodable userinfo, built once at open or configure"
            )]
            return Err(
                "settings.url userinfo must decode to valid UTF-8; credentials cannot be omitted or shortened"
                    .to_string(),
            );
        }
    }
    if host_is_blocked(&url) {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: the refusal text of a blocked host, built once at open or configure"
        )]
        return Err(format!(
            "settings.url must not target a link-local/private/CGNAT/cloud-metadata host \
             (SSRF guard; loopback sidecars are allowed); got '{}'",
            loggable_url(&url)
        ));
    }
    if scheme_is(&url, "http") && !host_is_loopback(&url) {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: the refusal text of a plaintext remote url, built once at open or configure"
        )]
        return Err(format!(
            "settings.url must use https:// for a non-loopback target (plaintext http:// is \
             only permitted for a loopback sidecar; the payload could otherwise be sent in cleartext); \
             got '{}'",
            loggable_url(&url)
        ));
    }
    Ok(url.into_url())
}

/// The ambiguous-URL refusal (without the `webrequest: ` prefix): `Some(the refusal)` when `raw`
/// carries an `@` after its host, `https://tok/en@hooks.example/x` or `https://u:123/x@host/…`, a
/// credential holding an unescaped `/`, `?` or `#`, which a parser reads as host `tok` (or `u`,
/// port `123`) and a path, so the credential would be dialled as a host. An `@` meant for the path
/// is written `%40`. A url that does not parse and holds an `@` anywhere is refused the same way.
///
/// The refusal echoes NOTHING of the text but its scheme: `scheme://***` for a url that parses,
/// `scheme:***` for one that does not. The words are the SDK's ([`sdk_url::ambiguous_url`]) in this
/// plugin's shape, `settings.url ...`.
#[must_use]
pub fn ambiguous_url(raw: &str) -> Option<String> {
    let parsed = ParsedUrl::parse(raw);
    let (shown, from_path) = match &parsed {
        Ok(url) => (
            echo_of(echoable_scheme(url.scheme()), true),
            &url[url::Position::BeforePath..],
        ),
        Err(_) => (echo_of(scheme_of(raw), false), raw),
    };
    if !from_path.contains('@') {
        return None;
    }

    let refusal = sdk_url::ambiguous_url(shown, from_path)?;
    Some(match refusal.strip_prefix("settings: url ") {
        Some(rest) => {
            #[expect(
                clippy::disallowed_methods,
                reason = "error: the refusal text of an ambiguous url, built once at open or configure"
            )]
            let text = format!("settings.url {rest}");
            text
        }
        None => refusal,
    })
}

/// The echo of an echoable `scheme` (`scheme://***` for a url that parses, `scheme:***` for one that
/// does not), or `***` alone when the scheme is not one that may be shown.
fn echo_of(scheme: &str, parsed: bool) -> &'static str {
    match (scheme, parsed) {
        ("http", true) => "http://***",
        ("https", true) => "https://***",
        ("http", false) => "http:***",
        ("https", false) => "https:***",
        _ => "***",
    }
}

/// `scheme` when it is `http` or `https`, else `***`: a schemeless `admin:secret@host/x` parses
/// with scheme `admin`, which is credential, so no other scheme is echoed.
fn echoable_scheme(scheme: &str) -> &'static str {
    if scheme.eq_ignore_ascii_case("http") {
        "http"
    } else if scheme.eq_ignore_ascii_case("https") {
        "https"
    } else {
        "***"
    }
}

/// The scheme `raw` starts with (up to its first `:`), echoable per [`echoable_scheme`]; a url
/// that does not parse echoes no more than this.
fn scheme_of(raw: &str) -> &'static str {
    echoable_scheme(raw.split_once(':').map_or("", |(scheme, _)| scheme))
}

/// Replace any `user[:pass]@` userinfo on `url` with `***@`. One step of [`reportable_url`], which is
/// what every URL echo uses; this alone leaves a `?token=` query in place. It masks the PARSED url's
/// userinfo, so a raw spelling WHATWG parsing normalises (`https:\t//svc:pw@host`) is masked too.
pub fn mask_userinfo(url: &url::Url) -> String {
    display_url(url, false, false, false)
}

/// The target URL in a form that is safe to echo ANYWHERE: the ONE masker every URL echo in this
/// crate goes through ([`loggable_url`], which every refusal echo uses, is this with the path cut).
/// Userinfo is masked, the query is redacted to a marker (a sidecar may authenticate by `?token=`),
/// and the fragment is dropped (it never reaches the wire).
pub fn reportable_url(url: &url::Url) -> String {
    display_url(url, false, true, true)
}

/// The target URL as a `Debug` rendering or a log line names it: [`reportable_url`] with the path
/// cut too (`/***`), for a sidecar may take its key in the path as well as the query.
#[must_use]
pub fn loggable_url(url: &url::Url) -> String {
    display_url(url, true, true, true)
}

fn display_url(url: &url::Url, cut_path: bool, cut_query: bool, cut_fragment: bool) -> String {
    use url::Position;

    let prefix = &url[..Position::BeforeUsername];
    let userinfo = if url.username().is_empty() && url.password().is_none() {
        ""
    } else {
        "***@"
    };
    let authority = &url[Position::BeforeHost..Position::BeforePath];
    let path = if cut_path && !matches!(url.path(), "" | "/") {
        if url.cannot_be_a_base() {
            "%2F***"
        } else {
            "/***"
        }
    } else {
        url.path()
    };
    let query = url
        .query()
        .map(|q| if cut_query { "<redacted>" } else { q });
    let fragment = if cut_fragment { None } else { url.fragment() };
    let capacity = prefix.len()
        + userinfo.len()
        + authority.len()
        + path.len()
        + query.map_or(0, |q| q.len() + 1)
        + fragment.map_or(0, |f| f.len() + 1);
    // busbar:expect(bp::fresh_buffer, reason = "error: the echoed url text is built once, at its exact size, for a refusal, a log line or the per-target scrub list, never for a served op")
    let mut out = String::with_capacity(capacity);
    out.push_str(prefix);
    out.push_str(userinfo);
    out.push_str(authority);
    out.push_str(path);
    if let Some(query) = query {
        out.push('?');
        out.push_str(query);
    }
    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }
    out
}

/// Every part of `url` that can carry a credential, each also percent-decoded
/// ([`sdk_url::and_decoded`]): the URL as written and as echoed, its path, query, username and
/// password, individual path segments and query values, and the `authorization` value it becomes.
/// What [`scrub`] cuts (longest first, empty parts dropped).
#[must_use]
pub fn secret_parts(url: &url::Url) -> Vec<String> {
    let mut parts = Parts::new(vec![
        owned(url.as_str()),
        mask_userinfo(url),
        reportable_url(url),
    ]);
    if !matches!(url.path(), "" | "/") {
        parts.push(owned(url.path()));

        parts.extend(
            url.path()
                .split('/')
                .filter(|part| !part.is_empty())
                .map(owned),
        );
    }
    if let Some(q) = url.query().filter(|q| !q.is_empty()) {
        parts.push(owned(q));
        for field in q.split('&') {
            if let Some((_, value)) = field.split_once('=') {
                if !value.is_empty() {
                    parts.push(owned(value));

                    if value.contains('+') {
                        #[expect(
                            clippy::disallowed_methods,
                            reason = "config: each scrub part is built once per target, at open or configure"
                        )]
                        parts.push(value.replace('+', " "));
                    }
                }
            }
        }
    }
    if let Some(p) = url.password() {
        parts.push(owned(p));
    }
    parts.push(owned(url.username()));

    if let Some(value) = crate::wire::basic_authorization(url) {
        parts.extend(value.strip_prefix("Basic ").map(owned));
        parts.push(value);
    }
    sdk_url::and_decoded(std::mem::take(&mut *parts))
}

/// An owned copy of one part of the target, for the scrub list.
fn owned(text: &str) -> String {
    #[expect(
        clippy::disallowed_methods,
        reason = "config: each scrub part is copied once per target, at open or configure"
    )]
    let copy = text.to_owned();
    copy
}

/// `parts` in the order [`sdk_url::scrub`] cuts them, as it orders them: empty parts dropped,
/// longest first (a stable sort), and a part equal to the one before it dropped. Done once per
/// target so a failure's scrub has fewer parts to try; the SDK orders what it is handed again, which
/// leaves this order as it is. Every dropped part is wiped.
#[must_use]
pub fn cut_order(parts: Vec<String>) -> Parts {
    let mut parts = Parts::new(parts);
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the scrub parts are filtered once per target, at open or configure"
    )]
    parts.retain(|p| !p.is_empty());
    #[expect(
        clippy::disallowed_methods,
        reason = "config: the scrub parts are ordered once per target, at open or configure, stably as the SDK scrub orders them"
    )]
    parts.sort_by_key(|p| std::cmp::Reverse(p.len()));
    parts.dedup_by(|removed, kept| {
        if removed == kept {
            zeroize::Zeroize::zeroize(removed);
            true
        } else {
            false
        }
    });
    parts
}

/// Whether `text` holds `part`. A failure's words are short, where finding `part`'s first byte
/// (`str::find` of an ASCII char is a `memchr`) and comparing there costs less than setting up
/// `str::contains`'s searcher for every part. A longer text, whose scan could take `text` times
/// `part` steps, or a part that starts outside ASCII goes to `str::contains`.
fn holds(text: &str, part: &str) -> bool {
    const SHORT: usize = 256;
    let Some(&first) = part.as_bytes().first() else {
        return true;
    };
    if part.len() > text.len() {
        return false;
    }
    if text.len() > SHORT || !first.is_ascii() {
        return text.contains(part);
    }
    let last = text.len() - part.len();
    let mut from = 0;
    // `from` is always just past an ASCII byte (or 0), so a char boundary.
    while let Some(found) = text[from..].find(char::from(first)) {
        let at = from + found;
        if at > last {
            return false;
        }
        if &text.as_bytes()[at..at + part.len()] == part.as_bytes() {
            return true;
        }
        from = at + 1;
    }
    false
}

/// `text` (the host's words, which may quote the target) with every one of `parts`
/// ([`secret_parts`] in [`cut_order`], computed once per target) replaced by `***`
/// ([`sdk_url::scrub`], unquoted).
///
/// Only the parts that can be cut are handed over (copied, so the SDK wipes them): one `text`
/// holds, or one holding a `*`, which an earlier cut's `***` may complete. Any other part matches
/// at no step of the SDK's cuts (a cut joins what was around it with `***`, so a match a cut makes
/// spans a `*`), so leaving it out leaves every cut as it was, with one exception the loop keeps:
/// the SDK drops a part equal to the one before it, so two equal parts that only a left-out part
/// kept apart (in `parts` they are not adjacent) are kept apart by that part, which is as long as
/// they are (the order is by length) and cuts nothing. A failure then copies a few parts rather
/// than all of them. That reasoning needs `parts` in [`cut_order`] (what a [`crate::door::Live`]
/// holds); `parts` in any other order are all handed over, as written.
#[must_use]
pub fn scrub(text: &str, parts: &[String]) -> String {
    let in_cut_order = parts
        .windows(2)
        .all(|w| !w[1].is_empty() && w[0].len() >= w[1].len() && w[0] != w[1]);
    if !in_cut_order || parts.first().is_some_and(String::is_empty) {
        #[expect(
            clippy::disallowed_methods,
            reason = "error: the SDK scrub consumes its list, copied once per failed exchange text"
        )]
        let list = parts.to_vec();
        return sdk_url::scrub(text, list, false);
    }
    // busbar:expect(bp::fresh_buffer, reason = "error: the parts a failure text can be cut by, gathered once per failed exchange text for the SDK scrub to consume")
    let mut cuttable: Vec<String> = Vec::new();
    let mut left_out: Option<&String> = None;
    for part in parts {
        if !part.is_empty() && (part.contains('*') || holds(text, part)) {
            if let Some(between) = left_out.filter(|_| cuttable.last() == Some(part)) {
                cuttable.push(between.clone());
            }
            cuttable.push(part.clone());
            left_out = None;
        } else {
            left_out = Some(part);
        }
    }
    sdk_url::scrub(text, cuttable, false)
}

#[cfg(test)]
#[path = "../tests/net_guard_tests.rs"]
mod tests;
