// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **webrequest forwarder as a droppable busbar plugin** — the `cdylib` a signed tarball of the
//! forwarder carries (`kind: hook`, alias `webrequest`).
//!
//! The logic crate re-exported whole, and its door (`busbar_hook_webrequest::door`) exported as
//! this image's ONE symbol, `busbar_plugin_door` (`export_door!`). The logic crate holds no `unsafe`
//! and exports nothing, so a build that links it carries no door symbol.

#![deny(unsafe_code)]

pub use busbar_hook_webrequest::{door, MACRO_DOOR};

/// The exported door, behind `dropped-in` (the cdylib build only): the macro's `#[unsafe(no_mangle)]` symbol
/// is the one export, and needs no `unsafe_code` allowance.
#[cfg(feature = "dropped-in")]
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
mod exported {
    busbar_contract::export_door!(busbar_hook_webrequest::door);
}
