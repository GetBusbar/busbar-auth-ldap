// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The signed schema and the real lifecycle validator agree on representative settings.

#[path = "../../testing/settings/integer_token.rs"]
mod settings_profile;

use super::*;
use serde_json::{json, Value};

fn check(cases: &[(Value, bool)]) {
    let schema: Value = serde_json::from_slice(SETTINGS_SCHEMA).expect("schema JSON");
    let validator = settings_profile::validator(&schema).expect("valid settings schema");
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
        ("url", json!(" "), false),
        ("url", json!(1), false),
        ("group_attr", json!(1), false),
        ("user_search_filter", json!("(uid=fixed)"), false),
        ("ca_cert_pem", json!(1), false),
        ("ca_cert_pem", Value::Null, true),
        ("allow_insecure_transport", json!("yes"), false),
        ("allow_insecure_transport", json!(true), true),
        // An explicit null is absent: direct bind, with no service DN needed.
        ("user_search_filter", Value::Null, true),
        ("bind_service_dn", Value::Null, true),
    ] {
        let mut settings = minimal.clone();
        settings[key] = value;
        check(&[(settings, accepted)]);
    }
    // Each required key, missing alone, is refused by both.
    for key in ["url", "bind_dn_template", "base_dn"] {
        let mut settings = minimal.clone();
        settings.as_object_mut().unwrap().remove(key);
        check(&[(settings, false)]);
    }
    let mut search = minimal.clone();
    search["user_search_filter"] = json!("(uid={username})");
    check(&[(search.clone(), false)]);
    search["bind_service_dn"] = json!("cn=service,dc=example");
    search["bind_dn_template"] = json!("{username}@example");
    // Validate deliberately needs no resolved secret; open obtains it from the host.
    check(&[(search.clone(), true)]);
    // The placeholder alone refuses, the service DN present.
    let mut fixed = search.clone();
    fixed["user_search_filter"] = json!("(uid=fixed)");
    check(&[(fixed, false)]);
    search["bind_service_dn"] = Value::Null;
    check(&[(search.clone(), false)]);
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

#[test]
fn settings_schema_integer_tokens_match_native_parser() {
    let schema: serde_json::Value = serde_json::from_slice(SETTINGS_SCHEMA).unwrap();
    let profile = settings_profile::validator(&schema).unwrap();
    let standard = jsonschema::validator_for(&schema).unwrap();
    assert_eq!(schema["x-busbar-settings-profile"], "integer-token-v1");
    for (pointer, template, integer, kind) in [(
        r#"/properties/timeout_secs"#,
        r#"{"url":"ldaps://directory.example","bind_dn_template":"uid={username},dc=example","base_dn":"dc=example","timeout_secs":TOKEN}"#,
        "1",
        "unsigned",
    )] {
        assert_eq!(
            schema.pointer(pointer).unwrap()["x-busbar-integer-token"],
            kind
        );
        for (token, accepted) in [
            (integer.to_string(), true),
            (format!("{integer}.0"), false),
            (format!("{integer}e0"), false),
            (format!("{integer}E+0"), false),
        ] {
            let text = template.replace("TOKEN", &token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert!(
                standard.is_valid(&value),
                "standard mathematical integer: {text}"
            );
            assert_eq!(profile.is_valid(&value), accepted, "profile: {text}");
            assert_eq!(
                <Ldap as Life>::validate(text.as_bytes()).is_ok(),
                accepted,
                "native: {text}"
            );
        }
        // Do not infer signed negative-zero behavior from a regular expression:
        // the profile must agree with the actual lifecycle parser.
        for token in [
            "null",
            "0",
            "-0",
            "-0.0",
            "0e0",
            "-1",
            "18446744073709551616",
        ] {
            let text = template.replace("TOKEN", token);
            let value: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(
                profile.is_valid(&value),
                <Ldap as Life>::validate(text.as_bytes()).is_ok(),
                "native sign/range: {text}"
            );
        }
    }
}
