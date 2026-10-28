// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settings document, the validated [`Target`], and `configure`'s commit-on-ack merge.

use crate::net_guard;
use serde::Deserialize;
use std::time::Duration;

/// Default per-op wall-clock timeout when the operator does not set `timeout_ms`. Tight on purpose: a
/// gate is on the request path, so a slow target must fail fast (the engine then applies `on_error`).
pub const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// Upper bound an operator-supplied `timeout_ms` is clamped to: the engine's reference hook budget. A
/// fat-fingered large value can at worst make an op run as long as the engine already budgets for a
/// hook, never past it.
pub const MAX_TIMEOUT_MS: u64 = DEFAULT_TIMEOUT_MS;

/// The settings keys the forwarder reads. Any other key is ignored (refusing it would break
/// existing documents), and never silently: the door logs it ([`unknown_keys`]).
pub const KEYS: [&str; 2] = ["url", "timeout_ms"];

/// The keys of a settings object the forwarder does not read, each as the warning the door logs.
#[must_use]
pub fn unknown_keys(settings: &serde_json::Map<String, serde_json::Value>) -> Vec<String> {
    settings
        .keys()
        .filter(|k| !KEYS.contains(&k.as_str()))
        .map(|k| format!("webrequest: ignoring unknown setting '{k}' (the settings are {KEYS:?})"))
        .collect()
}

/// [`unknown_keys`] over a settings document as `open` reads it; none for a document that is not
/// a JSON object (`open` refuses those).
#[must_use]
pub fn unknown_keys_in(settings: &[u8]) -> Vec<String> {
    match serde_json::from_slice::<serde_json::Value>(settings) {
        Ok(serde_json::Value::Object(map)) => unknown_keys(&map),
        _ => Vec::new(),
    }
}

/// The plugin's settings (the operator-owned `settings:` map, passed at `open` and re-pushed on
/// `configure`).
#[derive(Deserialize, Default)]
struct Config {
    url: String,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

/// The forwarding target: a validated URL and its timeout, taken together so `configure` swaps both
/// atomically. Its `Debug` names the URL as a log line does ([`net_guard::loggable_url`]): userinfo,
/// path and query masked.
#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    /// The validated URL every op envelope is POSTed to.
    pub url: url::Url,
    /// The wall-clock bound of one op, in `[1ms, MAX_TIMEOUT_MS]`.
    pub timeout: Duration,
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target")
            .field("url", &net_guard::loggable_url(&self.url))
            .field("timeout", &self.timeout)
            .finish()
    }
}

/// Bound an operator timeout to `[1ms, MAX_TIMEOUT_MS]`.
#[must_use]
pub fn clamp_timeout(ms: u64) -> Duration {
    Duration::from_millis(ms.clamp(1, MAX_TIMEOUT_MS))
}

impl Target {
    fn validate(cfg: &Config) -> Result<Self, String> {
        if cfg.url.trim().is_empty() {
            return Err("webrequest: settings.url is required".to_string());
        }
        let url = net_guard::validate_target_url(&cfg.url)?;
        Ok(Self {
            url,
            timeout: clamp_timeout(cfg.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
        })
    }

    /// The `(host, port)` the one connection need is opened to: the URL's host with its IPv6 brackets
    /// stripped, and its port (the scheme's default when the URL names none).
    #[must_use]
    pub fn endpoint(&self) -> (String, u16) {
        let host = self.url.host_str().unwrap_or("");
        let host = host.strip_prefix('[').unwrap_or(host);
        let host = host.strip_suffix(']').unwrap_or(host);
        (
            host.to_string(),
            self.url.port_or_known_default().unwrap_or(443),
        )
    }

    /// Whether the hop is TLS (`https`); plaintext is only ever a loopback sidecar.
    #[must_use]
    pub fn is_tls(&self) -> bool {
        self.url.scheme().eq_ignore_ascii_case("https")
    }
}

/// `open`: the settings document to a [`Target`]. An empty document, a malformed one, a missing URL or a
/// blocked URL is a fail-closed load error, never a live forwarder.
///
/// # Errors
/// The refusal text.
pub fn open(settings: &[u8]) -> Result<Target, String> {
    let text = std::str::from_utf8(settings)
        .map_err(|e| format!("webrequest: invalid plugin config: {e}"))?;
    let config: Config = if text.trim().is_empty() {
        Config::default()
    } else {
        serde_json::from_str(text).map_err(|e| format!("webrequest: invalid plugin config: {e}"))?
    };
    Target::validate(&config)
}

/// `configure`: merge a pushed settings map over the live target, commit-on-ack. Each key is
/// independently optional (absent = leave the live value); a key that is PRESENT but wrong-typed or
/// blocked NACKs the WHOLE push and commits neither.
///
/// `Ok(None)`: ACK, nothing changes. `Ok(Some(t))`: ACK, `t` is the new live target. `Err(reason)`: NACK,
/// the live target is untouched (`reason` is the NACK text).
///
/// # Errors
/// The NACK reason.
pub fn configure(
    live: &Target,
    settings: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<Target>, String> {
    let new_url = match settings.get("url") {
        None => None,
        Some(v) => match v.as_str() {
            None => {
                return Err(format!(
                "webrequest: configure() rejected: settings.url is present but not a string ({v})"
            ))
            }
            Some(raw) => Some(
                net_guard::validate_target_url(raw)
                    .map_err(|reason| format!("webrequest: configure() rejected: {reason}"))?,
            ),
        },
    };
    let new_timeout = match settings.get("timeout_ms") {
        None => None,
        Some(v) => match v.as_u64() {
            Some(ms) => Some(clamp_timeout(ms)),
            None => {
                return Err(format!(
                    "webrequest: configure() rejected: settings.timeout_ms is present but not a non-negative integer ({v})"
                ))
            }
        },
    };
    if new_url.is_none() && new_timeout.is_none() {
        return Ok(None);
    }
    let mut next = live.clone();
    if let Some(url) = new_url {
        next.url = url;
    }
    if let Some(timeout) = new_timeout {
        next.timeout = timeout;
    }
    Ok(Some(next))
}
