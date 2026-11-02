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

/// `status`: the live target, reported under the SAME `url` key the operator pushes, with the url text
/// as the operator wrote it. The engine's drift check compares the reported VALUE against the desired
/// one, so a masked or canonicalised url would report drift on every poll for a hook running exactly
/// its desired settings. The reported bag never leaves the drift check (only key names do), so the
/// url is not masked here; every log line still names it through [`crate::net_guard::loggable_url`].
#[must_use]
pub fn status(live: &Target) -> serde_json::Value {
    serde_json::json!({
        "status": {
            "settings": {
                "url": live.url_text,
                "target_host": live.url.host_str().unwrap_or(""),
                "timeout_ms": live.timeout.as_millis() as u64
            },
            "metrics": []
        }
    })
}
