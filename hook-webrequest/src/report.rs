// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The `describe` and `status` documents: the forwarder's OWN self-description and observed state
//! (neither is proxied to the target). No prompt or user content is ever surfaced here.

use crate::config::Target;

/// `describe`: the forwarder's config schema (`url` + `timeout_ms`).
#[must_use]
pub fn describe() -> serde_json::Value {
    serde_json::json!({
        "schema": {
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The https:// (or loopback http://) URL each hook op envelope is POSTed to."
                },
                "timeout_ms": {
                    "type": "integer",
                    "description": "Per-op wall-clock timeout in milliseconds (default 5000, clamped to [1, 5000] — cannot exceed the engine's reference hook budget)."
                }
            }
        }
    })
}

/// `status`: the live target, reported under the SAME `url` key the operator pushes (the engine's drift
/// check compares by name), with userinfo masked and the query redacted so a `?token=` never reaches the
/// operator-visible admin surface.
#[must_use]
pub fn status(live: &Target) -> serde_json::Value {
    serde_json::json!({
        "status": {
            "settings": {
                "url": crate::net_guard::reportable_url(&live.url),
                "target_host": live.url.host_str().unwrap_or(""),
                "timeout_ms": live.timeout.as_millis() as u64
            },
            "metrics": []
        }
    })
}
