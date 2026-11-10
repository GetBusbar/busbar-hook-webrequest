// SPDX-License-Identifier: Apache-2.0
//! Exercise host settings resolution with explicitly admitted source metadata.
use busbar_contract::{
    abi::mechanism::door::REWRITE_SUGAR,
    config_time::ConfigScope,
    plugin_settings::{Resolution, Settings},
    secret::SecretResolve,
    secret_ref::{SecretRef, Sugars},
    Secret,
};

struct Resolver<F>(F);
impl<F: Fn(&SecretRef) -> Result<String, String> + Send + Sync> SecretResolve for Resolver<F> {
    fn resolve(&self, _: &SecretRef) -> Result<Secret<Vec<u8>>, String> {
        Err("test resolver requires config-time text resolution".into())
    }
    fn resolve_string(&self, _: &SecretRef) -> Result<Secret<String>, String> {
        Err("test resolver requires config-time text resolution".into())
    }
    fn resolve_string_at_config(
        &self,
        reference: &SecretRef,
        _: &ConfigScope,
    ) -> Result<Secret<String>, String> {
        (self.0)(reference).map(Secret::new)
    }
}

pub fn resolve(
    bytes: &[u8],
    owner: &str,
    secrets: &[String],
    references: &[String],
    resolver: impl Fn(&SecretRef) -> Result<String, String> + Send + Sync,
) -> Result<Vec<u8>, String> {
    let mut sources = Sugars::default();
    // These fixture owners explicitly admit the authoring forms used by this suite.
    // The SDK does not know any source implementation or implicitly enable shorthand.
    for (word, owner, key) in [
        ("env", "fixture-environment", "name"),
        ("file", "fixture-file", "path"),
    ] {
        sources.declare(owner, &[(REWRITE_SUGAR, word.into(), key.into())])?;
    }
    let settings: Settings = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let held = settings.resolve(
        &Resolution {
            owner,
            secrets,
            references,
            sources: &sources,
        },
        &Resolver(resolver),
        &ConfigScope::config_time(),
    )?;
    held.encode()
        .map(|bytes| bytes.into_exposed(&busbar_contract::plugin::TestKernelSeal))
        .map_err(|e| e.to_string())
}
