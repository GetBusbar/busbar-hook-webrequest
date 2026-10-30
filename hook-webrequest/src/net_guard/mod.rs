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
//! The retired `WebhookPolicy` validated its sidecar URL with `observability::validate_routing_webhook_url`,
//! which reused the OTLP carve-out: link-local / IMDS / RFC1918 / CGNAT / cloud-metadata are BLOCKED,
//! but loopback / `localhost` are ALLOWED (a hook sidecar is typically co-located on loopback), and
//! plaintext `http://` is permitted ONLY for a loopback host. This module keeps that policy bit-for-bit
//! so a hook currently on `route: webhook` can migrate by pointing this plugin at the same URL.
//!
//! ## Shared predicates
//!
//! The context-free address predicates (`is_cgnat_shared_v4`, `is_unique_local_v6`,
//! `is_link_local_v6`, `embedded_ipv4`, `is_alternate_ipv4_encoding`) and the cloud-metadata host
//! list are the contract's (`busbar_contract::net`), the same ones the host's own guard reads. Only
//! the policy lives here: loopback sidecars are carved out. The tests pin this module's verdicts
//! against fixed vectors.
//!
//! Note also: these predicates validate the URL's literal host text at open/configure time. Name
//! resolution, the resolved-address check and the address pin (DNS rebinding / TOCTOU) belong to the
//! host's loopback-allowed egress class, which every connection this plugin opens goes through.

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

/// True iff `host` is an alternate (non-dotted-quad) IPv4 encoding that unambiguously denotes the
/// loopback address `127.0.0.1` (decimal `2130706433`, hex `0x7f000001`, octal `017700000001`, or a
/// short-dotted `127.1` / `127.0.1`). Used to permit the loopback-sidecar exception while still
/// blocking every OTHER alternate-encoded internal target. Conservative: anything it cannot positively
/// confirm as loopback is treated as non-loopback (and therefore blocked). Mirrors
/// `observability::is_alternate_loopback_v4`.
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
/// This inspects the URL's literal host TEXT only and never resolves a name: this plugin opens no
/// socket and resolves nothing. A NAME that resolves to an internal address is refused by the host's
/// loopback-allowed egress class when the connection is opened, which also pins the
/// approved addresses. The check here is total (no I/O, no failure mode), so it runs at
/// open/configure and rejects the IP-literal spellings before anything reaches the host.
pub fn host_is_blocked(url: &url::Url) -> bool {
    let Some(host) = host_of(url) else {
        return true; // a URL with no host is unusable as a target
    };
    if METADATA_HOSTS.iter().any(|m| host.eq_ignore_ascii_case(m)) {
        return true;
    }
    if is_alternate_ipv4_encoding(&host) {
        return !is_alternate_loopback_v4(&host);
    }
    match host.parse::<IpAddr>() {
        // The ONE internal-address rule over an IP literal (every v4/v6 spelling of one address
        // gets one answer).
        Ok(ip) => ip_is_internal(&ip),
        // DNS name: metadata names blocked above; `localhost` and any external host allowed.
        Err(_) => false,
    }
}

/// The internal-address predicate over the literal host [`host_is_blocked`] parsed, the loopback
/// carve-out for sidecars included.
fn ip_is_internal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_loopback() && ipv4_is_internal(v4),
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return false; // `::1` loopback sidecar — allowed
            }
            if let Some(v4) = embedded_ipv4(v6) {
                return !v4.is_loopback() && ipv4_is_internal(&v4);
            }
            ipv6_is_internal(v6) || is_site_local_v6(v6)
        }
    }
}

/// The URL's host with the IPv6 `[...]` brackets and a single trailing FQDN-root `.` stripped, so the
/// predicates see the same canonical form the OTLP/webhook guard did. Returns `None` for a hostless URL.
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
/// string on success or a stable, credential-free error on rejection. Accepts `https://` for any
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
    let url = url::Url::parse(raw).map_err(|e| format!("settings.url is not a valid URL: {e}"))?;
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
    Ok(url)
}

/// The ambiguous-URL refusal (without the `webrequest: ` prefix): `Some(the refusal)` when `raw`
/// carries an `@` after its host, `https://tok/en@hooks.example/x` or `https://u:123/x@host/…`, a
/// credential holding an unescaped `/`, `?` or `#`, which a parser reads as host `tok` (or `u`,
/// port `123`) and a path, so the credential would be dialled as a host. An `@` meant for the path
/// is written `%40`. The refusal shows the url with everything before its last `@` cut, never the
/// credential. A url that does not parse is read the same way by hand: the text after `://`, from
/// its first `/`, `?` or `#`, is what a parser would take for the path. The words are the SDK's
/// ([`sdk_url::ambiguous_url`]) in this plugin's shape, `settings.url ...`.
#[must_use]
pub fn ambiguous_url(raw: &str) -> Option<String> {
    let refusal = match url::Url::parse(raw) {
        Ok(parsed) => sdk_url::ambiguous_url(raw, &parsed[url::Position::BeforePath..]),
        Err(_) => {
            let (_, rest) = raw.split_once("://")?;
            let tail = &rest[rest.find(['/', '?', '#'])?..];
            sdk_url::ambiguous_url(raw, tail)
        }
    }?;
    Some(match refusal.strip_prefix("settings: url ") {
        Some(rest) => format!("settings.url {rest}"),
        None => refusal,
    })
}

/// Replace any `user[:pass]@` userinfo on `url` with `***@`. One step of [`reportable_url`], which is
/// what every URL echo uses; this alone leaves a `?token=` query in place.
///
/// Operates on the ALREADY-PARSED [`url::Url`] rather than doing textual `find("://")` surgery on
/// the raw input string. This matters: WHATWG URL parsing (which both `url::Url::parse` and every
/// real HTTP client use) silently strips embedded TAB/CR/LF from a URL before establishing the scheme
/// separator, so a raw string like `"https:\t//svc:hunter2@10.0.0.1/route"` parses and connects
/// completely normally (host `10.0.0.1`, userinfo `svc:hunter2`) even though the LITERAL substring
/// `"://"` never appears in it. A textual mask keyed on `raw.find("://")` misses that case entirely —
/// it is a silent no-op — and the unmasked credential then lands verbatim in the SSRF-rejection error
/// string. Masking the parsed `Url`'s username/password fields directly is correct regardless of what
/// whitespace or control characters the raw input used to spell the scheme separator.
///
/// Not the SDK's textual [`sdk_url::cut_userinfo`]: that cuts to the LAST `@`, which over-cuts a
/// url echoed as parsed; a url with an `@` after its host never gets here ([`ambiguous_url`]).
pub fn mask_userinfo(url: &url::Url) -> String {
    if url.username().is_empty() && url.password().is_none() {
        return url.to_string();
    }
    let mut masked = url.clone();
    // `set_username`/`set_password` fail only for cannot-be-a-base URLs (e.g. `mailto:`), which never
    // reach here (the scheme is already checked to be http/https) — the error is not actionable if it
    // ever did occur, so it's fine to ignore.
    let _ = masked.set_password(None);
    let _ = masked.set_username("***");
    masked.to_string()
}

/// The target URL in a form that is safe to echo ANYWHERE: the ONE masker every URL echo in this
/// crate goes through (the `status` surface and every `validate_target_url` error go through [`loggable_url`], which
/// is this with the path cut).
///
/// `mask_userinfo` alone is not enough. It masks credentials in the userinfo, but a sidecar that
/// authenticates by query parameter (`?token=...`) is a common enough shape that echoing the raw
/// query would leak the credential into the admin API, every status snapshot, and the logs. So the
/// query is redacted to a marker rather than reproduced.
///
/// The fragment goes too: it never reaches the wire on an HTTP request, so it can only be noise or
/// an accident, and there is no reason to echo it.
pub fn reportable_url(url: &url::Url) -> String {
    let mut safe = url.clone();
    safe.set_fragment(None);
    let had_query = safe.query().is_some();
    safe.set_query(None);
    let base = mask_userinfo(&safe);
    if had_query {
        format!("{base}?<redacted>")
    } else {
        base
    }
}

/// The target URL as a `Debug` rendering or a log line names it: [`reportable_url`] with the path
/// cut too (`/***`), for a sidecar may take its key in the path as well as the query.
#[must_use]
pub fn loggable_url(url: &url::Url) -> String {
    let mut safe = url.clone();
    if !matches!(safe.path(), "" | "/") {
        safe.set_path("/***");
    }
    reportable_url(&safe)
}

/// Every part of `url` that can carry a credential, each also percent-decoded
/// ([`sdk_url::and_decoded`]): the URL as written and as echoed, its path, query, username and
/// password. What [`scrub`] cuts (longest first, empty parts dropped).
#[must_use]
pub fn secret_parts(url: &url::Url) -> Vec<String> {
    let mut parts = vec![
        url.as_str().to_string(),
        mask_userinfo(url),
        reportable_url(url),
    ];
    if !matches!(url.path(), "" | "/") {
        parts.push(url.path().to_string());
    }
    if let Some(q) = url.query().filter(|q| !q.is_empty()) {
        parts.push(q.to_string());
    }
    if let Some(p) = url.password() {
        parts.push(p.to_string());
    }
    parts.push(url.username().to_string());
    sdk_url::and_decoded(parts)
}

/// `text` (the host's words, which may quote the target) with every one of `parts`
/// ([`secret_parts`], computed once per target) replaced by `***` ([`sdk_url::scrub`], unquoted).
#[must_use]
pub fn scrub(text: &str, parts: &[String]) -> String {
    sdk_url::scrub(text, parts.to_vec(), false)
}

#[cfg(test)]
mod tests;
