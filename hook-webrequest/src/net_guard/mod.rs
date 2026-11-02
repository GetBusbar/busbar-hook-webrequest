// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SSRF guard the `webrequest` forwarder applies to its operator-configured target URL.

use crate::owners::{ParsedUrl, Parts, Text};
use crate::ALIAS;
use busbar_contract::abi::sdk::url as sdk_url;
use busbar_contract::net::{
    embedded_ipv4, ipv4_is_internal, ipv6_is_internal, is_alternate_ipv4_encoding, IpAddr,
    Ipv6Addr, METADATA_HOSTS,
};

/// IPv6 site-local `fec0::/10`. Deprecated by RFC 3879 but still routed on plenty of real networks,

pub fn is_site_local_v6(addr: &Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfec0
}

/// True iff `host` is an alternate (non-dotted-quad) IPv4 encoding that unambiguously denotes the

pub fn is_alternate_loopback_v4(host: &str) -> bool {
    if !host.contains('.') {
        if let Some(hex) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X")) {
            return u32::from_str_radix(hex, 16).ok() == Some(0x7f00_0001);
        }
        if let Some(oct) = host.strip_prefix('0').filter(|_| host.len() > 1) {
            if let Ok(v) = u32::from_str_radix(oct, 8) {
                return v == 0x7f00_0001;
            }
        }
        if let Ok(v) = host.parse::<u32>() {
            return v == 0x7f00_0001;
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

fn ip_is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4().is_some_and(|v4| v4.is_loopback()),
    }
}

/// SSRF block predicate for the target URL: identical to a full internal check EXCEPT loopback and the

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

fn ip_is_internal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && ipv4_is_internal(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return false;
            }
            if let Some(v4) = embedded_ipv4(v6) {
                return !v4.is_loopback() && ipv4_is_internal(&v4);
            }
            ipv6_is_internal(v6) || is_site_local_v6(v6)
        }
    }
}

/// The URL's host with the IPv6 `[...]` brackets and a single trailing FQDN-root `.` stripped, so the

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

/// Validate the operator-configured target URL against the SSRF guard, returning the canonicalized URL

pub fn validate_target_url(raw: &str) -> Result<url::Url, String> {
    refuse_target_url(raw).map_err(|reason| format!("{ALIAS}: {reason}"))
}

/// [`validate_target_url`] with the refusal's reason WITHOUT the `webrequest: ` prefix, for a caller

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

#[must_use]
pub fn ambiguous_url(raw: &str) -> Option<String> {
    let (shown, from_path) = match ParsedUrl::parse(raw) {
        Ok(parsed) => (
            echo_of(&echoable_scheme(parsed.scheme()), "://***"),
            Text(parsed[url::Position::BeforePath..].to_string()),
        ),
        Err(_) => (echo_of(&scheme_of(raw), ":***"), Text(raw.to_string())),
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

fn echoable_scheme(scheme: &str) -> String {
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        scheme.to_ascii_lowercase()
    } else {
        "***".to_string()
    }
}

/// The scheme `raw` starts with (up to its first `:`), echoable per [`echoable_scheme`]; a url

fn scheme_of(raw: &str) -> String {
    echoable_scheme(raw.split_once(':').map_or("", |(scheme, _)| scheme))
}

/// Replace any `user[:pass]@` userinfo on `url` with `***@`. One step of [`reportable_url`], which is

pub fn mask_userinfo(url: &url::Url) -> String {
    display_url(url, false, false, false)
}

/// The target URL in a form that is safe to echo ANYWHERE: the ONE masker every URL echo in this

pub fn reportable_url(url: &url::Url) -> String {
    display_url(url, false, true, true)
}

/// The target URL as a `Debug` rendering or a log line names it: [`reportable_url`] with the path

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

#[must_use]
pub fn secret_parts(url: &url::Url) -> Vec<String> {
    let mut parts = Parts(vec![
        url.as_str().to_string(),
        mask_userinfo(url),
        reportable_url(url),
    ]);
    if !matches!(url.path(), "" | "/") {
        parts.0.push(url.path().to_string());

        parts.0.extend(
            url.path()
                .split('/')
                .filter(|part| !part.is_empty())
                .map(str::to_owned),
        );
    }
    if let Some(q) = url.query().filter(|q| !q.is_empty()) {
        parts.0.push(q.to_string());
        for field in q.split('&') {
            if let Some((_, value)) = field.split_once('=') {
                if !value.is_empty() {
                    parts.0.push(value.to_string());

                    if value.contains('+') {
                        parts.0.push(value.replace('+', " "));
                    }
                }
            }
        }
    }
    if let Some(p) = url.password() {
        parts.0.push(p.to_string());
    }
    parts.0.push(url.username().to_string());

    if let Some(value) = crate::wire::basic_authorization(url) {
        parts
            .0
            .extend(value.strip_prefix("Basic ").map(str::to_owned));
        parts.0.push(value);
    }
    sdk_url::and_decoded(parts.into_vec())
}

/// `text` (the host's words, which may quote the target) with every one of `parts`

#[must_use]
pub fn scrub(text: &str, parts: &[String]) -> String {
    sdk_url::scrub(text, parts.to_vec(), false)
}

#[cfg(test)]
mod tests;
