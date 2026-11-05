// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed schema and the real lifecycle validator agree on representative settings.

use super::*;
use serde_json::{json, Value};

fn check(cases: &[(Value, bool)]) {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).expect("schema JSON");
    let validator = jsonschema::validator_for(&schema).expect("valid settings schema");
    assert_eq!(STATEMENT.settings_schema.ptr, SETTINGS_SCHEMA.as_ptr());
    assert_eq!(STATEMENT.settings_schema.len, SETTINGS_SCHEMA.len());
    assert_eq!(
        STATEMENT.settings_schema.fmt,
        busbar_contract::abi::mechanism::call::BLOB_JSON
    );
    for (settings, accepted) in cases {
        let bytes = serde_json::to_vec(settings).expect("settings JSON");
        assert_eq!(
            validator.is_valid(settings),
            *accepted,
            "schema: {settings}"
        );
        assert_eq!(
            <Ldap as Life>::validate(&bytes).is_ok(),
            *accepted,
            "lifecycle: {settings}"
        );
    }
}

#[test]
fn settings_schema_matches_ldap_lifecycle() {
    let minimal = json!({"url":"ldaps://directory.example","bind_dn_template":"uid={username},dc=example","base_dn":"dc=example"});
    check(&[
        (minimal.clone(), true),
        (json!({}), false),
        (json!([]), false),
    ]);
    for (key, value, accepted) in [
        ("bind_dn_template", json!("uid=someone"), false),
        ("bind_dn_template", json!("{username}@example"), false),
        ("base_dn", json!(""), true),
        ("group_attr", json!("\u{2003}"), false),
        ("role_from", json!("dn"), true),
        ("role_from", json!("CN"), false),
        ("timeout_secs", json!(0), false),
        ("timeout_secs", json!(1), true),
        ("timeout_secs", json!(120), true),
        ("timeout_secs", json!(121), false),
        ("start_tls", Value::Null, false),
        ("bind_service_password", Value::Null, true),
        ("bind_service_password", json!("secret"), false),
        ("unknown", Value::Null, false),
    ] {
        let mut settings = minimal.clone();
        settings[key] = value;
        check(&[(settings, accepted)]);
    }
    let mut search = minimal.clone();
    search["user_search_filter"] = json!("(uid={username})");
    check(&[(search.clone(), false)]);
    search["bind_service_dn"] = json!("cn=service,dc=example");
    search["bind_dn_template"] = json!("{username}@example");
    // Validate deliberately needs no resolved secret; open obtains it from the host.
    check(&[(search.clone(), true)]);
    search["bind_service_dn"] = json!(" ");
    check(&[(search, false)]);
    let cfg: crate::LdapConfig = serde_json::from_value(minimal).unwrap();
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let props = &schema["properties"];
    assert_eq!(props["group_attr"]["default"], cfg.group_attr);
    assert_eq!(props["timeout_secs"]["default"], cfg.timeout_secs);
    assert_eq!(props["start_tls"]["default"], cfg.start_tls);
    assert_eq!(
        props["allow_insecure_transport"]["default"],
        cfg.allow_insecure_transport
    );
    assert_eq!(props["role_from"]["default"], "cn");
    assert_eq!(cfg.role_from, crate::RoleFrom::Cn);
    assert_eq!(props["bind_service_password"]["writeOnly"], true);
}
