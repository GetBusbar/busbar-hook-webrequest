// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOTH-WAYS CONFORMANCE of `busbar-hook-webrequest`: busbar's PUBLISHED suite
//! (`busbar_plugin_loader::conformance_suite!`, at the busbar commit this repo pins in `.busbar-ref`),
//! run by this repo. It loads the LINKED door (the logic crate's `door::door`) and the BUILT cdylib
//! (`busbar-hook-webrequest-plugin`) through busbar's real plugin loader and drives both with the
//! hook kind's script over `conformance.json`; the forwarder's one outbound need is served by the
//! suite's far end (the plugin holds no socket and no TLS). The forwarder's own wire proofs (the 1.5.5
//! envelope byte for byte, the red arms, the socket ban) are `forwarder.rs`.

busbar_plugin_loader::conformance_suite! {
    door: busbar_hook_webrequest::door::door,
    cdylib: "busbar_hook_webrequest_plugin",
    inputs: include_str!("conformance.json"),
}
