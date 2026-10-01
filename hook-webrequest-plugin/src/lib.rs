// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **webrequest forwarder as a droppable busbar plugin** — the `cdylib` a signed tarball of the
//! forwarder carries (`kind: hook`, alias `webrequest`).
//!
//! The logic crate re-exported whole, and its door (`busbar_hook_webrequest::door::door`) exported as
//! this image's ONE symbol, `busbar_plugin_door` (`export_door!`, THE DESIGN §11.4). The logic crate
//! holds no `unsafe` and exports nothing, so a build that links it carries no door symbol.

#![deny(unsafe_code)]

pub use busbar_hook_webrequest::*;

/// The exported door: the macro's `#[no_mangle]` symbol is the one exemption.
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_hook_webrequest::door::door);
}
