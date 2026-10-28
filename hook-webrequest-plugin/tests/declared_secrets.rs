// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECLARED SECRET FIELD (OWNER RULING, CHIP-REVIEW-v4 change 2): the hook's `url` can carry a
//! credential (its userinfo becomes `Authorization: Basic`), so the Statement declares it. A
//! `{env:}` reference there resolves in place, as the kernel resolves it; one anywhere else is
//! refused. The linked door is loaded the way the host binds a hook.

use std::sync::Arc;

use busbar_plugin_loader::dispatch::kinds::hook::Hook;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink, Plugin,
};
use busbar_test_kit::conformance::settings_as_the_kernel_resolves;

#[path = "support/conformance_host.rs"]
mod conformance_host;

fn linked() -> (Plugin<Hook>, Arc<Dispatcher>) {
    let d = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let bind = Bind {
        instance: Arc::from("webrequest-declared-secrets"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::Host(conformance_host::host(d.conn_waker(), None)),
    };
    let row = LinkedRow::of(busbar_hook_webrequest::door::door).expect("the row renders");
    (load_linked::<Hook>(&row, bind).expect("the door loads"), d)
}

#[test]
fn a_reference_at_the_declared_url_resolves_as_the_kernel_resolves_it() {
    let (p, _d) = linked();
    let out = settings_as_the_kernel_resolves(
        &p,
        br#"{"url":{"env":"WEBREQUEST_URL_FOR_TEST"},"timeout_ms":500}"#,
        |_, _| Ok("https://user:pw@hooks.example/route".to_string()),
    )
    .expect("`url` is declared as a secret field");
    let v: serde_json::Value = serde_json::from_slice(&out).expect("json");
    assert_eq!(v["url"], "https://user:pw@hooks.example/route");
    assert_eq!(v["timeout_ms"], 500);
}

#[test]
fn a_reference_at_an_undeclared_field_is_refused() {
    let (p, _d) = linked();
    let e = settings_as_the_kernel_resolves(
        &p,
        br#"{"url":"https://hooks.example/route","timeout_ms":{"env":"X"}}"#,
        |_, _| Ok("500".to_string()),
    )
    .expect_err("`timeout_ms` is not a declared secret field");
    assert!(e.contains("did not declare it as a secret"), "{e}");
}
