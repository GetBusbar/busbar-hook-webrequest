// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **`webrequest`** hook's logic: a transparent HTTP forwarder that POSTs each hook op envelope
//! (`decide`/`transform`/`notify`) to an operator-configured URL and returns the capped JSON reply
//! verbatim. Busbar's own reply lowering (`busbar-contract`'s `abi::sdk::hook`) parses that reply, so
//! this is a network relay, never a second copy of the hook wire semantics.
//!
//! Everything here but the door is a PURE function over bytes. The plugin opens no socket, dials
//! nothing, does no TLS and runs no runtime: the connection to the endpoint is a declared need the
//! host serves (the loopback-allowed egress class: https or loopback plaintext, the node's own
//! ports refused), and the door drives it with these functions:
//!
//! * [`config`] — the settings document, the [`config::Target`], and `configure`'s commit-on-ack merge;
//! * [`wire`] — the request's method, target and fields;
//! * [`reply`] — the response reader: the status rule, the 64 KiB body cap, the depth guard, and the
//!   per-op meaning of a failure (`decide` and `transform` fail, so the operator's `on_error`
//!   applies; `notify` swallows);
//! * [`report`] — the `describe` and `status` documents;
//! * [`net_guard`] — the textual half of the SSRF guard, kept so every refusal text is stable;
//! * [`door`] — the hook kind's door over all of it (`door::door`): what a busbar build that links
//!   this crate registers, and what the droppable cdylib (`busbar-hook-webrequest-plugin`) exports.

#![cfg_attr(not(all(test, target_os = "linux")), forbid(unsafe_code))]
#![deny(missing_docs)]

/// The alias as a literal, so a fixed text can `concat!` it.
macro_rules! alias_lit {
    () => {
        "webrequest"
    };
}

pub(crate) mod config;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub(crate) mod door;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub(crate) mod net_guard;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
mod owners;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub(crate) mod reply;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub(crate) mod report;
// busbar:request-path
#[cfg_attr(
    not(test),
    deny(
        clippy::disallowed_macros,
        clippy::disallowed_methods,
        clippy::disallowed_types,
        clippy::redundant_clone,
        clippy::format_push_string,
        clippy::needless_collect,
        clippy::or_fun_call,
        clippy::needless_pass_by_value,
        clippy::allow_attributes,
        clippy::allow_attributes_without_reason
    )
)]
pub(crate) mod wire;

/// The package name a signed tarball of this plugin states (`manifest.name`).
pub const NAME: &str = "busbar-hook-webrequest";

/// The catalogue code a failed `decide` or `transform` is raised under (declared in `declares.json`).
pub(crate) const FORWARD_FAILED: &str = "BUSBAR-7151";
/// The catalogue code a dropped `notify` is raised under.
pub(crate) const NOTIFY_DROPPED: &str = "BUSBAR-7152";
/// The catalogue code a refused `configure` is raised under.
pub(crate) const CONFIGURE_REFUSED: &str = "BUSBAR-7153";
/// The catalogue code a clamped `timeout_ms` is raised under.
pub(crate) const TIMEOUT_CLAMPED: &str = "BUSBAR-7154";

/// The alias a hook reference names this plugin by (`module: webrequest`).
pub const ALIAS: &str = alias_lit!();

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
#[cfg(test)]
#[path = "tests/custody_tests.rs"]
mod custody_tests;
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

#[cfg(all(test, target_os = "linux"))]
#[path = "tests/owner_custody_tests.rs"]
mod owner_custody_tests;

/// The validated entry and generated registration descriptor.
pub use door::{door, MACRO_DOOR};

#[cfg(all(test, target_os = "linux"))]
#[path = "tests/target_custody.rs"]
mod target_custody;

// Owner-controlled source paths are consumed only by the assembled application tests.
