// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settings document, the validated [`Target`], and `configure`'s commit-on-ack merge.

use crate::owners::{ParsedUrl, Text};
use crate::{net_guard, ALIAS, TIMEOUT_CLAMPED};
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
        .map(|k| unknown_warning(k))
        .collect()
}

fn unknown_warning(key: &str) -> String {
    format!(
        "{ALIAS}: ignoring unknown setting '{}' (the settings are {KEYS:?})",
        key.escape_debug()
    )
}

/// Diagnostics retained by the same typed parse that validates the target. Unknown values are
/// skipped, not materialized; names wipe on drop and are sorted/deduplicated as the old map was.
/// This does not change the upstream serde_json scratch-buffer wiping deferral.
#[derive(Default)]
pub(crate) struct Diagnostics {
    unknown: zeroize::Zeroizing<Vec<String>>,
    timeout_ms: Option<u64>,
}

impl Diagnostics {
    pub(crate) fn log(&self) {
        for key in self.unknown.iter() {
            tracing::warn!("{}", unknown_warning(key));
        }
        if let Some(warning) = self.timeout_ms.and_then(clamp_warning) {
            tracing::warn!(diag = %TIMEOUT_CLAMPED, "{warning}");
        }
    }
}

#[derive(Default)]
struct Config {
    url: Text,
    diagnostics: Diagnostics,
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct ConfigVisitor;
        impl<'de> serde::de::Visitor<'de> for ConfigVisitor {
            type Value = Config;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a settings object")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Config, M::Error> {
                let mut cfg = Config::default();
                let (mut url_seen, mut timeout_seen) = (false, false);
                while let Some(key) = map.next_key::<String>()? {
                    let mut key = Text::new(key);
                    match key.as_str() {
                        "url" if !url_seen => {
                            cfg.url = Text::new(map.next_value()?);
                            url_seen = true;
                        }
                        "timeout_ms" if !timeout_seen => {
                            cfg.diagnostics.timeout_ms = map.next_value()?;
                            timeout_seen = true;
                        }
                        "url" => return Err(serde::de::Error::duplicate_field("url")),
                        "timeout_ms" => {
                            return Err(serde::de::Error::duplicate_field("timeout_ms"))
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                            cfg.diagnostics.unknown.push(std::mem::take(&mut *key));
                        }
                    }
                }
                cfg.diagnostics.unknown.sort();
                cfg.diagnostics.unknown.dedup_by(|a, b| {
                    if a == b {
                        zeroize::Zeroize::zeroize(a);
                        true
                    } else {
                        false
                    }
                });
                Ok(cfg)
            }
        }
        de.deserialize_map(ConfigVisitor)
    }
}

/// The forwarding target: a validated URL and its timeout, taken together so `configure` swaps both
/// atomically. Its `Debug` names the URL as a log line does ([`net_guard::loggable_url`]): userinfo,
/// path and query masked.
#[derive(Clone, PartialEq, Eq)]
pub struct Target {
    /// The validated URL every op envelope is POSTed to.
    pub url: url::Url,
    /// The url text as the operator wrote it, which `status` echoes under `url` so the engine's
    /// value-comparing drift check sees the desired settings (the parsed `url` is canonicalised).
    /// Never logged: every log line names the URL through [`net_guard::loggable_url`].
    pub url_text: String,
    /// The `timeout_ms` as the operator wrote it (`Null` when absent or null), which `status` echoes
    /// under `timeout_ms` for the same reason as `url_text`: the effective `timeout` is defaulted or
    /// clamped, so reporting it would show drift against a desired `null` or out-of-range value.
    pub timeout_text: serde_json::Value,
    /// The wall-clock bound of one op, in `[1ms, MAX_TIMEOUT_MS]`.
    pub timeout: Duration,
}

impl Drop for Target {
    fn drop(&mut self) {
        crate::owners::wipe_url(&mut self.url);
        drop(busbar_contract::abi::sdk::cred::Held::new(std::mem::take(
            &mut self.url_text,
        )));
    }
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
    fn validate(cfg: &Config, timeout_text: serde_json::Value) -> Result<Self, String> {
        if cfg.url.trim().is_empty() {
            return Err(format!("{ALIAS}: settings.url is required"));
        }
        let url = net_guard::validate_target_url(&cfg.url)?;
        Ok(Self {
            url,
            url_text: cfg.url.to_string(),
            timeout_text,
            timeout: clamp_timeout(cfg.diagnostics.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS)),
        })
    }
}

/// The warning for a `timeout_ms` outside `[1, MAX_TIMEOUT_MS]`, which is still clamped.
fn clamp_warning(ms: u64) -> Option<String> {
    let clamped = clamp_timeout(ms).as_millis();
    (u128::from(ms) != clamped).then(|| {
        format!(
            "{ALIAS}: settings.timeout_ms {ms} is outside [1, {MAX_TIMEOUT_MS}] and is clamped to {clamped}"
        )
    })
}

/// Log ignored keys and a clamped timeout for an acknowledged configuration push.
pub fn log_warnings(settings: &serde_json::Map<String, serde_json::Value>) {
    for warning in unknown_keys(settings) {
        tracing::warn!("{warning}");
    }
    if let Some(warning) = settings
        .get("timeout_ms")
        .and_then(serde_json::Value::as_u64)
        .and_then(clamp_warning)
    {
        tracing::warn!(diag = %TIMEOUT_CLAMPED, "{warning}");
    }
}

/// `open`: the settings document to a [`Target`]. An empty document, a malformed one, a missing URL or a
/// blocked URL is a fail-closed load error, never a live forwarder.
///
/// # Errors
/// The refusal text.
pub fn open(settings: &[u8]) -> Result<Target, String> {
    open_with_diagnostics(settings).map(|(target, _)| target)
}

pub(crate) fn open_with_diagnostics(settings: &[u8]) -> Result<(Target, Diagnostics), String> {
    let text = std::str::from_utf8(settings)
        .map_err(|e| format!("{ALIAS}: invalid plugin config: {e}"))?;
    let config: Config = if text.trim().is_empty() {
        Config::default()
    } else {
        if !text.trim_start().starts_with('{') {
            return Err(format!(
                "{ALIAS}: invalid plugin config: settings must be a JSON object"
            ));
        }
        serde_json::from_str(text).map_err(|e| {
            if e.is_data() {
                format!(
                    "{ALIAS}: invalid plugin config: settings.url must be a string; settings.timeout_ms must be a non-negative integer or null; each may be given at most once"
                )
            } else {
                format!("{ALIAS}: invalid plugin config: {e}")
            }
        })?
    };
    let timeout_text = config
        .diagnostics
        .timeout_ms
        .map_or(serde_json::Value::Null, serde_json::Value::from);
    let target = Target::validate(&config, timeout_text)?;
    Ok((target, config.diagnostics))
}

/// The NACK text for `why`.
pub(crate) fn nack(why: &str) -> String {
    format!("{ALIAS}: configure() rejected: {why}")
}

/// `configure`: merge a pushed settings map over the live target, commit-on-ack. Each key is
/// independently optional (absent, or a `null` `timeout_ms`, leaves the live value); a key that is
/// PRESENT but wrong-typed or blocked NACKs the WHOLE push and commits neither.
///
/// `Ok(None)`: ACK, nothing changes. `Ok(Some(t))`: ACK, `t` is the new live target. `Err(reason)`:
/// NACK, the live target is untouched (`reason` is the NACK text).
///
/// # Errors
/// The NACK reason.
pub fn configure(
    live: &Target,
    settings: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<Target>, String> {
    let new_url = match settings.get("url") {
        None => None,
        Some(v) => {
            let raw = v
                .as_str()
                .ok_or_else(|| nack("settings.url is present but not a string"))?;
            Some((
                ParsedUrl::new(net_guard::refuse_target_url(raw).map_err(|reason| nack(&reason))?),
                Text::new(raw.to_string()),
            ))
        }
    };

    let new_timeout = match settings.get("timeout_ms") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => {
            let ms = v.as_u64().ok_or_else(|| {
                nack("settings.timeout_ms is present but not a non-negative integer")
            })?;
            Some(clamp_timeout(ms))
        }
    };
    if new_url.is_none() && new_timeout.is_none() {
        return Ok(None);
    }
    let mut next = live.clone();
    if let Some((parsed, mut text)) = new_url {
        crate::owners::wipe_url(&mut next.url);
        next.url = parsed.into_url();
        drop(busbar_contract::abi::sdk::cred::Held::new(std::mem::take(
            &mut next.url_text,
        )));
        next.url_text = std::mem::take(&mut *text);
    }
    if let Some(timeout) = new_timeout {
        next.timeout = timeout;
        next.timeout_text = settings["timeout_ms"].clone();
    }
    Ok(Some(next))
}

#[cfg(test)]
#[path = "tests/config_diagnostics_tests.rs"]
mod diagnostics_tests;
