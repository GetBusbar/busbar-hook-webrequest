// SPDX-License-Identifier: Apache-2.0
//! Resolve settings through the production host API and actual loaded declaration.
#[path = "../../../testing/settings/resolution.rs"]
mod resolution;

pub fn resolve_settings(
    plugin: &busbar_plugin_loader::dispatch::Plugin<
        busbar_plugin_loader::dispatch::kinds::hook::Hook,
    >,
    bytes: &[u8],
    resolve: impl Fn(&busbar_contract::secret_ref::SecretRef) -> Result<String, String> + Send + Sync,
) -> Result<Vec<u8>, String> {
    resolution::resolve(
        bytes,
        plugin.name(),
        plugin.secret_refs(),
        plugin.reference_fields(),
        resolve,
    )
}
