// SPDX-License-Identifier: Apache-2.0

#[test]
fn historical_conversion_reads_former_names_by_current_alias() {
    install();
    assert_eq!(
        busbar_migrations::config::migration_table::former_names("webrequest"),
        ["busbar-webrequest"]
    );
    assert!(
        busbar_migrations::config::migration_table::former_names("planted-never-renamed")
            .is_empty()
    );
}
