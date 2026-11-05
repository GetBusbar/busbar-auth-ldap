// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::sdk::migrate::{Migrate, MigrateNeed, Migrated};
use serde_json::{json, Value};

use super::LdapMigration;

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

fn door_migrate(settings: &Value, from: &str) -> Migrated {
    busbar_plugin_loader::dispatch::migrate::migrate_door(
        busbar_plugin_loader::dispatch::load::raw(crate::door::door),
        settings,
        from,
    )
    .expect("the linked door migrates with no live instance")
    .expect("LDAP declares a migrator")
}

#[test]
fn released_settings_migrate_through_the_door_without_disclosing_the_password() {
    let old = old_settings();
    let migrated = door_migrate(&old, "1.5.5");
    assert_eq!(migrated.settings["user_search_filter"], "(uid={username})");
    assert_eq!(
        migrated.settings["bind_service_password"],
        old["bind_service_password"]
    );
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
    assert_eq!(migrated.settings, expected);
}

#[test]
fn references_are_preserved_and_a_second_migration_is_a_no_op() {
    for reference in [
        json!({"env": "LDAP_BIND_PASSWORD"}),
        json!({"file": "/run/secrets/ldap"}),
        json!({"module": "vault", "settings": {"path": "directory", "key": "password"}}),
    ] {
        let mut old = old_settings();
        old["bind_service_password"] = reference.clone();
        let first = door_migrate(&old, "1.5.5");
        assert_eq!(first.settings["bind_service_password"], reference);
        let second = door_migrate(&first.settings, "1.5.5");
        assert_eq!(second, Migrated::unchanged(first.settings));
    }
}

#[test]
fn only_valid_historical_bare_items_are_wrapped() {
    for bare in [
        "uid={username}",
        "uid=*{username}*",
        "uid>={username}",
        "uid:dn:caseExactMatch:={username}",
    ] {
        let original = json!({"user_search_filter": bare});
        let migrated = LdapMigration::migrate(original, "1.5.5");
        assert_eq!(migrated.settings["user_search_filter"], format!("({bare})"));
        assert_eq!(migrated.report.len(), 1);
        assert!(!migrated.report[0].starts_with("TODO"));
    }
    for unknown in [
        json!("uid={username})"),
        json!("(&(uid={username})"),
        json!("uid=someone"),
        json!("{username}=alice"),
        json!("CANARY{username}"),
        json!(42),
        json!({"unknown": "CANARY"}),
    ] {
        let original = json!({"user_search_filter": unknown});
        let migrated = LdapMigration::migrate(original.clone(), "1.5.5");
        assert_eq!(migrated.settings, original);
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
            Migrated::unchanged(original)
        );
    }
    let mut original = old_settings();
    original
        .as_object_mut()
        .unwrap()
        .remove("bind_service_password");
    assert!(crate::LdapModule::validate_settings(&serde_json::to_vec(&original).unwrap()).is_err());
    let migrated = door_migrate(&original, "1.5.5");
    assert!(
        crate::LdapModule::validate_settings(&serde_json::to_vec(&migrated.settings).unwrap())
            .is_ok()
    );
}

#[test]
fn unsafe_password_shapes_remain_unchanged_with_private_todos() {
    for password in [json!({"inline": "CANARY"}), json!(false)] {
        let original = json!({"bind_service_password": password});
        let migrated = door_migrate(&original, "1.5.5");
        assert_eq!(migrated.settings, original);
        assert_eq!(migrated.report.len(), 1);
        assert!(migrated.report[0].starts_with("TODO settings.bind_service_password:"));
        assert!(!migrated.report[0].contains("CANARY"));
        assert!(migrated.needs.is_empty());
    }
}

#[test]
fn literal_password_bytes_are_retained_only_in_settings_until_the_host_lifts_them() {
    for password in ["none", "", "CANARY\npassword", "päss密碼 ${VAR}"] {
        let original = json!({"bind_service_password": password});
        let migrated = door_migrate(&original, "1.5.5");
        assert_eq!(migrated.settings, original);
        assert_eq!(
            migrated.needs,
            vec![MigrateNeed::ExternalizeSecret {
                path: vec!["bind_service_password".into()]
            }]
        );
        assert_eq!(
            migrated.report.iter().any(|line| line.starts_with("TODO")),
            password.is_empty() || password.chars().any(char::is_control)
        );
        assert!(!migrated.report.join("\n").contains("CANARY"));
        assert!(!migrated.report.join("\n").contains("${VAR}"));
        // The host fulfills the need before publishing the config. Its actual file handling
        // is covered by the host's tests; this verifies the plugin's post-lift idempotence.
        let lifted = json!({"bind_service_password": {"file": "/private/ldap-secret"}});
        assert_eq!(door_migrate(&lifted, "1.5.5"), Migrated::unchanged(lifted));
    }
}
