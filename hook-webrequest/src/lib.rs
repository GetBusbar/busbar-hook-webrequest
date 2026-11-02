// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **`webrequest`** hook's logic: a transparent HTTP forwarder that POSTs each hook op envelope

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod config;
pub mod door;
pub mod net_guard;
mod owners;
pub mod reply;
pub mod report;
pub mod wire;

/// The package name a signed tarball of this plugin states (`manifest.name`).
pub const NAME: &str = "busbar-hook-webrequest";

/// The catalogue code a failed `decide` or `transform` is raised under (declared in `declares.json`).
pub const FORWARD_FAILED: &str = "BUSBAR-7151";
/// The catalogue code a dropped `notify` is raised under.
pub const NOTIFY_DROPPED: &str = "BUSBAR-7152";
/// The catalogue code a refused `configure` is raised under.
pub const CONFIGURE_REFUSED: &str = "BUSBAR-7153";
/// The catalogue code a clamped `timeout_ms` is raised under.
pub const TIMEOUT_CLAMPED: &str = "BUSBAR-7154";

/// The alias a hook reference names this plugin by (`module: webrequest`).
pub const ALIAS: &str = "webrequest";

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
