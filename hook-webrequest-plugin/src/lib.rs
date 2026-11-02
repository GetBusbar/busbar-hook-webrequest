// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **webrequest forwarder as a droppable busbar plugin** — the `cdylib` a signed tarball of the

#![deny(unsafe_code)]

pub use busbar_hook_webrequest::*;

/// The exported door, behind `dropped-in` (the cdylib build only): the macro's `#[no_mangle]` symbol is
#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_hook_webrequest::door::door);
}
