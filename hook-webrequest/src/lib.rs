// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **`webrequest`** hook's logic: a transparent HTTP forwarder that POSTs each hook op envelope
//! (`decide`/`transform`/`notify`) to an operator-configured URL and returns the capped JSON reply
//! verbatim. Busbar's own reply normalizers parse that reply, so this is a network relay, never a second
//! copy of the hook wire semantics.
//!
//! Everything here but the door is a PURE function over bytes. The plugin opens no socket, dials
//! nothing, does no TLS and runs no runtime: the connection to the endpoint is a declared need the
//! host serves (the loopback-allowed egress class: https or loopback plaintext, the node's own
//! ports refused), and the door drives it with these functions:
//!
//! * [`config`] — the settings document, the [`config::Target`], and `configure`'s commit-on-ack merge;
//! * [`wire`] — the op envelope and the HTTP/1.1 request bytes;
//! * [`reply`] — the response reader: the status rule, the 64 KiB body cap, the depth guard, and the
//!   per-op meaning of a failure (`decide` and `transform` fail, so the operator's `on_error`
//!   applies; `notify` swallows);
//! * [`report`] — the `describe` and `status` documents;
//! * [`net_guard`] — the textual half of the SSRF guard, kept so every refusal text is stable;
//! * [`door`] — the hook kind's door over all of it (`door::door`): what a busbar build that links
//!   this crate registers, and what the droppable cdylib (`busbar-hook-webrequest-plugin`) exports.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod door;
pub mod net_guard;
pub mod reply;
pub mod report;
pub mod wire;

/// The package name a signed tarball of this plugin states (`manifest.name`).
pub const NAME: &str = "busbar-hook-webrequest";

/// The alias a hook reference names this plugin by (`module: webrequest`).
pub const ALIAS: &str = "webrequest";

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod door_tests;
#[cfg(test)]
#[path = "tests/echo_tests.rs"]
mod echo_tests;
#[cfg(test)]
#[path = "tests/reply_tests.rs"]
mod reply_tests;
#[cfg(test)]
#[path = "tests/report_tests.rs"]
mod report_tests;
#[cfg(test)]
#[path = "tests/wire_tests.rs"]
mod wire_tests;
