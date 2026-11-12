// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::sdk::migrate::{Migrate, MigrateNeed, Migrated, MigrationAnswer};
use serde_json::{json, Value};

use super::LdapMigration;

/// The settings a sealed [`Migrated`] carries, read back under the dev-only test kernel seal.
fn settings_of(answer: &Migrated) -> serde_json::Value {
    let seal = busbar_contract::caps::KernelSeal::acquire_for_kernel();
    serde_json::to_value(
        busbar_contract::abi::sdk::migrate::MigrationAnswer::from(answer.clone()).authoring(&seal),
    )
    .expect("migrated settings serialize")
}

fn old_settings() -> Value {
    json!({
        "url": "ldaps://directory.example",
        "bind_dn_template": "uid={username},dc=example",
        "base_dn": "dc=example",
        "user_search_filter": "uid={username}",
        "bind_service_dn": "cn=service,dc=example",
        "bind_service_password": "MIGRATION_SECRET_CANARY"
    })
}

fn door_migrate(settings: &Value, from: &str) -> MigrationAnswer {
    busbar_plugin_loader::dispatch::migrate::migrate_door(
        busbar_plugin_loader::dispatch::load::raw(crate::door::door),
        settings,
        from,
    )
    .expect("the linked door migrates with no live instance")
    .expect("LDAP declares a migrator")
}

// Compare the guarded answer with known fixture data without opening its settings.
fn assert_settings(answer: &MigrationAnswer, settings: Value) {
    assert_eq!(
        answer,
        &MigrationAnswer::from(Migrated::new(
            settings,
            answer.report.clone(),
            answer.needs.clone()
        ))
    );
}

#[test]
fn released_settings_migrate_through_the_door_without_disclosing_the_password() {
    let old = old_settings();
    let migrated = door_migrate(&old, "1.5.5");
    assert_eq!(migrated.report.len(), 2);
    assert!(migrated.report[1].starts_with("settings.bind_service_password:"));
    assert!(!migrated
        .report
        .join("\n")
        .contains("MIGRATION_SECRET_CANARY"));
    assert_eq!(
        migrated.needs,
        vec![MigrateNeed::ExternalizeSecret {
            path: vec!["bind_service_password".into()]
        }]
    );
    assert!(!serde_json::to_string(&migrated.needs)
        .unwrap()
        .contains("MIGRATION_SECRET_CANARY"));
    let mut expected = old;
    expected["user_search_filter"] = json!("(uid={username})");
    assert_settings(&migrated, expected);
}

#[test]
fn references_are_preserved_and_a_second_migration_is_a_no_op() {
    for reference in [
        json!({"module": "source-fixture", "settings": {"name": "LDAP_BIND_PASSWORD"}}),
        json!({"module": "source-fixture", "settings": {"path": "/run/secrets/ldap"}}),
        json!({"module": "source-fixture", "settings": {"path": "directory", "key": "password"}}),
    ] {
        let mut old = old_settings();
        old["bind_service_password"] = reference.clone();
        let first = door_migrate(&old, "1.5.5");
        let mut expected = old;
        expected["user_search_filter"] = json!("(uid={username})");
        assert_settings(&first, expected.clone());
        assert!(first.needs.is_empty());
        let second = door_migrate(&expected, "1.5.5");
        assert_eq!(second, MigrationAnswer::from(Migrated::unchanged(expected)));
    }
}

#[test]
fn only_valid_historical_bare_items_are_wrapped() {
    for bare in [
        "uid={username}",
        "uid=*{username}*",
        "uid>={username}",
        "uid:dn:caseExactMatch:={username}",
        ":dn:2.5.13.5:={username}",
    ] {
        let original = json!({"user_search_filter": bare});
        let migrated = LdapMigration::migrate(original, "1.5.5");
        assert_eq!(
            settings_of(&migrated)["user_search_filter"],
            format!("({bare})")
        );
        assert_eq!(migrated.report.len(), 1);
        assert!(!migrated.report[0].starts_with("TODO"));
    }
    for unknown in [
        json!("uid={username})"),
        json!("(&(uid={username})"),
        // A bare AND, OR or NOT was never a 1.5.5 item: it failed every login, so wrapping it
        // would silently give it a meaning (NOT matches everyone but the user).
        json!("!(uid={username})"),
        json!("&(uid={username})(objectClass=person)"),
        json!("|(uid={username})(mail={username})"),
        json!("uid=someone"),
        json!("{username}=alice"),
        json!("CANARY{username}"),
        json!(42),
        json!({"unknown": "CANARY"}),
    ] {
        let original = json!({"user_search_filter": unknown});
        let migrated = LdapMigration::migrate(original.clone(), "1.5.5");
        assert_eq!(settings_of(&migrated), original);
        assert_eq!(migrated.report.len(), 1);
        assert!(migrated.report[0].starts_with("TODO settings.user_search_filter:"));
        assert!(!migrated.report[0].contains("CANARY"));
    }
}

#[test]
fn current_and_unknown_versions_do_not_get_historical_conversion() {
    for version in ["1.6.0", "2.0.0", "1.5.4", "", "unknown"] {
        let original = old_settings();
        assert_eq!(
            door_migrate(&original, version),
            MigrationAnswer::from(Migrated::unchanged(original))
        );
    }
    let mut original = old_settings();
    original
        .as_object_mut()
        .unwrap()
        .remove("bind_service_password");
    assert!(crate::LdapModule::validate_settings(&serde_json::to_vec(&original).unwrap()).is_err());
    let migrated = door_migrate(&original, "1.5.5");
    original["user_search_filter"] = json!("(uid={username})");
    assert_settings(&migrated, original.clone());
    assert!(crate::LdapModule::validate_settings(&serde_json::to_vec(&original).unwrap()).is_ok());
}

#[test]
fn unsafe_password_shapes_remain_unchanged_with_private_todos() {
    for password in [
        json!({"inline": "CANARY"}),
        json!(false),
        // Context-free parsing does not infer an owner for legacy shorthand.
        json!({"env": "CANARY_ENV"}),
        json!({"file": "/private/CANARY_FILE"}),
    ] {
        let original = json!({"bind_service_password": password});
        let migrated = door_migrate(&original, "1.5.5");
        assert_settings(&migrated, original);
        assert_eq!(migrated.report.len(), 1);
        assert!(migrated.report[0].starts_with("TODO settings.bind_service_password:"));
        assert!(!migrated.report[0].contains("CANARY"));
        assert!(migrated.needs.is_empty());
    }
}

#[test]
fn literal_password_bytes_are_retained_only_in_settings_until_the_host_lifts_them() {
    for (password, todo) in [
        ("none", false),
        ("", true),
        ("CANARY\npassword", true),
        ("päss密碼 ${VAR}", false),
    ] {
        let original = json!({"bind_service_password": password});
        let migrated = door_migrate(&original, "1.5.5");
        assert_settings(&migrated, original);
        assert_eq!(
            migrated.needs,
            vec![MigrateNeed::ExternalizeSecret {
                path: vec!["bind_service_password".into()]
            }]
        );
        assert_eq!(
            migrated.report.iter().any(|line| line.starts_with("TODO")),
            todo,
            "{password:?}"
        );
        assert!(!migrated.report.join("\n").contains("CANARY"));
        assert!(!migrated.report.join("\n").contains("${VAR}"));
        // The host fulfills the need before publishing the config. Its actual file handling
        // is covered by the host's tests; this verifies the plugin's post-lift idempotence.
        // The host writes the admitted path source's canonical module/settings reference.
        let lifted = json!({"bind_service_password": {
            "module": "source-fixture", "settings": {"path": "/private/ldap-secret"}
        }});
        assert_eq!(
            door_migrate(&lifted, "1.5.5"),
            MigrationAnswer::from(Migrated::unchanged(lifted))
        );
    }
}

/// Only the released baseline converts, in either spelling the host reports it; any other source
/// version (a near miss included) is handed back unchanged with nothing to report.
#[test]
fn only_the_released_baseline_converts() {
    for from in ["1.5.5", "v1.5.5"] {
        let migrated = LdapMigration::migrate(old_settings(), from);
        assert_eq!(
            settings_of(&migrated)["user_search_filter"],
            "(uid={username})",
            "{from}"
        );
        assert_eq!(migrated.needs.len(), 1, "{from}");
    }
    for from in [
        "", "1.5.4", "v1.5.4", "1.5.5.1", "1.5.50", "V1.5.5", "1.6.0",
    ] {
        assert_eq!(
            LdapMigration::migrate(old_settings(), from),
            Migrated::unchanged(old_settings()),
            "{from:?}"
        );
    }
}

/// A 1.5.5 settings value that is not an object is left as it is, with one TODO asking for one.
#[test]
fn settings_that_are_not_an_object_are_left_with_a_todo() {
    for settings in [Value::Null, json!([]), json!("ldaps://directory.example")] {
        let migrated = LdapMigration::migrate(settings.clone(), "1.5.5");
        assert_eq!(settings_of(&migrated), settings);
        assert_eq!(migrated.report.len(), 1, "{settings}");
        assert!(
            migrated.report[0].starts_with("TODO settings: "),
            "{settings}"
        );
        assert!(migrated.needs.is_empty());
    }
}

/// An explicit null filter or service password is already current: nothing changes or is reported.
#[test]
fn null_filter_and_password_are_unchanged_and_unreported() {
    let settings = json!({
        "url": "ldaps://directory.example",
        "user_search_filter": null,
        "bind_service_password": null
    });
    assert_eq!(
        LdapMigration::migrate(settings.clone(), "1.5.5"),
        Migrated::unchanged(settings)
    );
}
