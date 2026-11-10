// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

fn main() -> std::io::Result<()> {
    use std::path::PathBuf;
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest dir"))
        .canonicalize()?;
    let package = std::env::var("CARGO_PKG_NAME").expect("package name");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").expect("output dir"));
    let mut body = String::new();
    for name in [
        "admin_config_history_and_overlay",
        "admin_hook_crud_contracts",
        "admin_hook_overlay_reset",
        "admin_hook_read_metadata",
        "admin_hook_replacement",
        "admin_hook_settings_ack",
        "admin_hook_timeout",
        "admin_scope_ladder",
    ] {
        let source = manifest.join(format!("tests/admin_application/{name}.rs"));
        if source.canonicalize()? != source {
            return Err(std::io::Error::other(
                "test source must be the owner's own declared path, without symlink escapes",
            ));
        }
        body.push_str(&format!(
            "        #[path = {source:?}]\n        mod admin_application_{name};\n"
        ));
        println!("cargo::rerun-if-changed={}", source.display());
    }
    let migration = manifest.join("tests/root/migration_table.rs");
    if migration.canonicalize()? != migration {
        return Err(std::io::Error::other(
            "test source must remain in its owner",
        ));
    }
    println!("cargo::rerun-if-changed={}", migration.display());
    std::fs::write(
        output.join("context_test_source.rs"),
        format!(
            "#[doc(hidden)]\n#[macro_export]\nmacro_rules! __busbar_context_tests {{\n    \
             (admin_application, {package:?}) => {{\n{body}    }};\n    (migration_table_hook, {package:?}) => {{ include!({migration:?}); }};\n}}\n"
        ),
    )?;
    println!(
        "cargo::rerun-if-changed={}",
        manifest.join("Cargo.toml").display()
    );
    Ok(())
}
