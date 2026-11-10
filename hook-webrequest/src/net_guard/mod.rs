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

use crate::owners::{ParsedUrl, Parts, Text};
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
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() >= 4 || parts.is_empty() {
        return false;
    }
    let Some(first) = parts.first().and_then(|p| p.parse::<u32>().ok()) else {
        return false;
    };
    first == 127 && parts.iter().all(|p| p.parse::<u32>().is_ok())
}

/// True iff the target URL's host is the loopback/localhost target the forwarder MAY reach — the exact
/// carve-out `host_is_blocked` leaves un-blocked (parity with the old webhook policy, which allowed a
/// loopback sidecar). Used to gate the plaintext-`http://` allowance to loopback only.
pub fn host_is_loopback(url: &url::Url) -> bool {
    let Some(host) = host_of(url) else {
        return false;
    };
    if is_alternate_ipv4_encoding(&host) {
        return is_alternate_loopback_v4(&host);
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
    if is_alternate_ipv4_encoding(&host) {
        return !is_alternate_loopback_v4(&host);
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
fn host_of(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    let host = host.strip_prefix('[').unwrap_or(host);
    let host = host.strip_suffix(']').unwrap_or(host);
    let host = host.strip_suffix('.').unwrap_or(host);
    Some(host.to_string())
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
    refuse_target_url(raw).map_err(|reason| format!("{ALIAS}: {reason}"))
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
    let url = ParsedUrl::parse(raw).map_err(|e| format!("settings.url is not a valid URL: {e}"))?;
    if !(scheme_is(&url, "https") || scheme_is(&url, "http")) {
        return Err(format!(
            "settings.url must be an http:// or https:// URL (got '{}')",
            loggable_url(&url)
        ));
    }
    if url
        .username()
        .as_bytes()
        .windows(3)
        .any(|w| w.eq_ignore_ascii_case(b"%3a"))
    {
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
            return Err(
                "settings.url userinfo must decode to valid UTF-8; credentials cannot be omitted or shortened"
                    .to_string(),
            );
        }
    }
    if host_is_blocked(&url) {
        return Err(format!(
            "settings.url must not target a link-local/private/CGNAT/cloud-metadata host \
             (SSRF guard; loopback sidecars are allowed); got '{}'",
            loggable_url(&url)
        ));
    }
    if scheme_is(&url, "http") && !host_is_loopback(&url) {
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
    let (shown, from_path) = match ParsedUrl::parse(raw) {
        Ok(parsed) => (
            echo_of(&echoable_scheme(parsed.scheme()), "://***"),
            Text::new(parsed[url::Position::BeforePath..].to_string()),
        ),
        Err(_) => (echo_of(&scheme_of(raw), ":***"), Text::new(raw.to_string())),
    };

    let refusal = sdk_url::ambiguous_url(&shown, &from_path)?;
    Some(match refusal.strip_prefix("settings: url ") {
        Some(rest) => format!("settings.url {rest}"),
        None => refusal,
    })
}

/// The echo `scheme` + `rest`, or `***` alone when the scheme is not one that may be shown.
fn echo_of(scheme: &str, rest: &str) -> String {
    if scheme == "***" {
        scheme.to_string()
    } else {
        format!("{scheme}{rest}")
    }
}

/// `scheme` when it is `http` or `https`, else `***`: a schemeless `admin:secret@host/x` parses
/// with scheme `admin`, which is credential, so no other scheme is echoed.
fn echoable_scheme(scheme: &str) -> String {
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        scheme.to_ascii_lowercase()
    } else {
        "***".to_string()
    }
}

/// The scheme `raw` starts with (up to its first `:`), echoable per [`echoable_scheme`]; a url
/// that does not parse echoes no more than this.
fn scheme_of(raw: &str) -> String {
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
        url.as_str().to_string(),
        mask_userinfo(url),
        reportable_url(url),
    ]);
    if !matches!(url.path(), "" | "/") {
        parts.push(url.path().to_string());

        parts.extend(
            url.path()
                .split('/')
                .filter(|part| !part.is_empty())
                .map(str::to_owned),
        );
    }
    if let Some(q) = url.query().filter(|q| !q.is_empty()) {
        parts.push(q.to_string());
        for field in q.split('&') {
            if let Some((_, value)) = field.split_once('=') {
                if !value.is_empty() {
                    parts.push(value.to_string());

                    if value.contains('+') {
                        parts.push(value.replace('+', " "));
                    }
                }
            }
        }
    }
    if let Some(p) = url.password() {
        parts.push(p.to_string());
    }
    parts.push(url.username().to_string());

    if let Some(value) = crate::wire::basic_authorization(url) {
        parts.extend(value.strip_prefix("Basic ").map(str::to_owned));
        parts.push(value);
    }
    sdk_url::and_decoded(std::mem::take(&mut *parts))
}

/// `text` (the host's words, which may quote the target) with every one of `parts`
/// ([`secret_parts`], computed once per target) replaced by `***` ([`sdk_url::scrub`], unquoted).
#[must_use]
pub fn scrub(text: &str, parts: &[String]) -> String {
    sdk_url::scrub(text, parts.to_vec(), false)
}

#[cfg(test)]
#[path = "../tests/net_guard_tests.rs"]
mod tests;
