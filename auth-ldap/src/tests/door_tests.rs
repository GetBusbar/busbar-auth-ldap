// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's own pieces: the settings blob `validate`/`open`/`refresh` parse, the submitted-field

use super::{
    clock_ns, field, keep_reached, take_reached, unreadable, Ldap, Reached, Release, Run, ALIAS,
    FORM, NAME, NEED, NEEDS, NEED_ANCHORED, SECRET_REFS, STATEMENT, TAIL,
};
use crate::LdapModule;
use busbar_contract::abi::auth::{
    CAP_INBOUND, CAP_LOGIN, CAP_OUTBOUND, FACT_CACHEABLE, LOGIN_KIND_CREDENTIAL,
};
use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::door::MARK_BLOCKS;
use busbar_contract::abi::sdk::life::Life;

const MINIMAL: &str = r#"{
    "url": "ldaps://ad.corp.example:636",
    "bind_dn_template": "uid={username},ou=people,dc=corp,dc=example",
    "base_dn": "dc=corp,dc=example"
}"#;

#[test]
fn settings_refuse_an_empty_blob() {
    for blob in ["", "   "] {
        let e = LdapModule::from_settings(blob.as_bytes())
            .err()
            .expect("an empty blob is refused");
        assert!(e.starts_with("settings: "), "{e}");
    }
}

#[test]
fn no_settings_read_in_the_fleet_form() {
    let e = LdapModule::from_settings(b"").err().expect("refused");
    assert_eq!(
        e,
        "settings: none provided; requires url, bind_dn_template, base_dn"
    );
}

#[test]
fn settings_refuse_malformed_json() {
    let e = LdapModule::from_settings(b"{ not json")
        .err()
        .expect("malformed JSON is refused");
    assert!(e.starts_with("settings: "), "{e}");
}

#[test]
fn settings_refuse_missing_required_fields() {
    assert!(LdapModule::from_settings(br#"{"url":"ldaps://x"}"#).is_err());
}

#[test]
fn settings_accept_a_minimal_config() {
    assert!(LdapModule::from_settings(MINIMAL.as_bytes()).is_ok());
    assert!(Ldap::validate(MINIMAL.as_bytes()).is_ok());
}

/// A direct-bind UPN template (`{username}@corp.example`) is not a DN, so the group read off the
#[test]
fn settings_refuse_a_direct_bind_upn_template() {
    let blob = br#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "{username}@corp.example",
        "base_dn": "dc=corp,dc=example"
    }"#;
    let r = Ldap::validate(blob).expect_err("refused");
    assert!(r.text().is_some_and(|t| t.contains("is not a DN")), "{r:?}");
}

#[test]
fn a_refused_refresh_keeps_the_running_module() {
    let ldap = Ldap::open(MINIMAL.as_bytes(), &[], 1).expect("opens");
    let before = ldap.module();
    assert!(ldap.refresh(b"", &[], 2).is_err());
    assert!(std::sync::Arc::ptr_eq(&before, &ldap.module()));
    assert!(ldap.refresh(MINIMAL.as_bytes(), &[], 3).is_ok());
    assert!(!std::sync::Arc::ptr_eq(&before, &ldap.module()));
}

#[test]
fn a_field_is_found_by_its_declared_name_and_must_be_text() {
    let fields: [(&[u8], &[u8]); 3] = [
        (b"username", b"alice"),
        (b"password", b"\xff\xfe"),
        (b"other", b"x"),
    ];
    assert_eq!(field(&fields, "username"), Some("alice"));
    assert_eq!(field(&fields, "password"), None, "non-UTF-8 is no value");
    assert_eq!(field(&fields, "missing"), None);
}

#[test]
fn a_field_that_is_not_text_is_refused_in_its_own_words() {
    let bad_password: [(&[u8], &[u8]); 2] = [(b"username", b"alice"), (b"password", b"\xff")];
    assert_eq!(
        unreadable(&bad_password),
        Some("the password field is not UTF-8")
    );
    let bad_username: [(&[u8], &[u8]); 2] = [(b"username", b"\xfe"), (b"password", b"pw")];
    assert_eq!(
        unreadable(&bad_username),
        Some("the username field is not UTF-8")
    );
    let fine: [(&[u8], &[u8]); 1] = [(b"username", b"alice")];
    assert_eq!(
        unreadable(&fine),
        None,
        "an absent field is not this refusal"
    );
}

#[test]
fn a_failing_host_clock_says_why() {
    use busbar_contract::abi::sdk::conn::ConnFailure;
    use std::task::Poll;
    let reading = busbar_contract::abi::host::service::ClockReading {
        size: 0,
        _reserved: 0,
        wall_ns: 1,
        mono_ns: 42,
    };
    assert_eq!(clock_ns(Poll::Ready(Ok(reading))), Ok(42));
    let e = clock_ns(Poll::Ready(Err(ConnFailure::Failed("clock broke".into())))).unwrap_err();
    assert!(e.contains("clock broke"), "{e}");
    let e = clock_ns(Poll::Ready(Err(ConnFailure::Fault))).unwrap_err();
    assert!(e.contains("faulted"), "{e}");
    let e = clock_ns(Poll::Pending).unwrap_err();
    assert!(e.contains("pended"), "{e}");
}

/// The Statement states a credential login that never blocks (no `MARK_BLOCKS`: every call is
#[test]
fn the_statement_states_a_non_blocking_credential_login_over_one_need() {
    assert_eq!(TAIL.caps, CAP_LOGIN);
    assert_eq!(TAIL.caps & CAP_OUTBOUND, 0);
    assert_eq!(TAIL.login_kind, LOGIN_KIND_CREDENTIAL);
    assert_eq!(STATEMENT.marks & MARK_BLOCKS, 0, "no call blocks");
    assert_eq!(STATEMENT.rewrites_len(), 1);
    assert_eq!((NAME, ALIAS), ("busbar-auth-ldap", "ldap"));
    assert_eq!(FORM.len(), 2);

    assert_eq!(
        (STATEMENT.needs_ptr(), STATEMENT.needs_len()),
        (NEEDS.as_ptr(), 2)
    );
    for need in NEEDS {
        assert_eq!(need.direction, DIRECTION_OUTBOUND);
        assert_eq!(need.egress_class, EGRESS_OPERATOR_INFRASTRUCTURE);
        assert!(!need.transport.is_absent());
        assert!(
            need.target_from.is_absent(),
            "the target is named per login"
        );
    }

    assert!(
        NEEDS[NEED as usize].trust_from.is_absent(),
        "the public need: the connector's own trust"
    );
    assert!(
        !NEEDS[NEED_ANCHORED as usize].trust_from.is_absent(),
        "the anchored need: the operator's private CA on top of the public roots"
    );

    assert_eq!(STATEMENT.secret_refs_len(), 1);
    assert!(!SECRET_REFS[0].is_absent());
}

#[test]
fn a_literal_service_password_refuses_boot() {
    let literal = br#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(uid={username})",
        "bind_service_dn": "cn=svc,dc=corp,dc=example",
        "bind_service_password": "hunter2"
    }"#;
    for secrets in [&[b"resolved".as_slice()][..], &[]] {
        let e = LdapModule::from_settings_with(literal, secrets)
            .err()
            .expect("a literal refuses boot");
        assert!(e.starts_with("settings.bind_service_password: "), "{e}");
        assert!(!e.contains("hunter2"), "{e}");
    }
    let r = Ldap::validate(literal).expect_err("a literal refuses validate");
    assert!(
        r.text()
            .is_some_and(|t| t.contains("settings.bind_service_password: ")),
        "{r:?}"
    );

    let referenced = br#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(uid={username})",
        "bind_service_dn": "cn=svc,dc=corp,dc=example"
    }"#;
    let m = LdapModule::from_settings_with(referenced, &[b"resolved".as_slice()]).expect("opens");
    assert_eq!(
        m.cfg
            .bind_service_password
            .as_ref()
            .map(crate::tests::cred_text)
            .as_deref(),
        Some("resolved")
    );
    let e = LdapModule::from_settings_with(referenced, &[b"\xff".as_slice()])
        .err()
        .expect("refused");
    assert!(e.contains("not UTF-8"), "{e}");
}

fn who(id: &str) -> busbar_contract::auth::Principal {
    busbar_contract::auth::Principal::from_id(id)
}

/// An abandoned ticket's kept identity goes with the next op on its slot; other slots stay, and the
#[test]
fn a_later_generation_on_the_slot_drops_the_abandoned_identity() {
    let mut reached = Reached::default();
    keep_reached(&mut reached, 8, (3, 1), who("abandoned"), None);
    keep_reached(&mut reached, 8, (4, 1), who("other-slot"), None);
    keep_reached(&mut reached, 8, (3, 2), who("mine"), None);
    let got = take_reached(&mut reached, (3, 2), None);
    assert_eq!(got.map(|p| p.id), Some("mine".to_string()));
    assert!(
        !reached.map.contains_key(&(3, 1)),
        "the abandoned entry must go"
    );
    assert!(
        !reached.map.contains_key(&(3, 2)),
        "the call's own key must be taken"
    );
    assert!(
        reached.map.contains_key(&(4, 1)),
        "another slot's entry must stay"
    );
    assert_eq!(reached.map.len(), 1);
}

/// A call on no ticket (generation 0, never minted) proves nothing about slot 0: a kept identity on
#[test]
fn a_ticketless_call_leaves_slot_zeros_kept_identity() {
    let mut reached = Reached::default();
    keep_reached(&mut reached, 8, (0, 5), who("kept"), None);
    assert!(take_reached(&mut reached, (0, 0), None).is_none());
    assert!(
        reached.map.contains_key(&(0, 5)),
        "a ticketless call dropped slot 0's identity"
    );
}

/// THE REACHED MAP IS BOUNDED (auth standard S3): at the cap the OLDEST kept identity goes, never
#[test]
fn the_reached_map_is_bounded_and_evicts_the_oldest() {
    let mut reached = Reached::default();
    for slot in 0..20 {
        keep_reached(&mut reached, 16, (slot, 1), who(&format!("u{slot}")), None);
    }
    assert_eq!(reached.map.len(), 16, "bounded at the cap");
    for slot in 0..4 {
        assert!(
            !reached.map.contains_key(&(slot, 1)),
            "slot {slot}: the oldest go first"
        );
    }
    for slot in 4..20 {
        assert!(
            reached.map.contains_key(&(slot, 1)),
            "slot {slot}: the newest stay"
        );
    }

    keep_reached(&mut reached, 16, (19, 1), who("again"), None);
    assert_eq!(reached.map.len(), 16);
    assert!(reached.map.contains_key(&(4, 1)));
}

#[test]
fn a_kept_identity_expires_after_the_ttl() {
    let ttl = super::REACHED_TTL_NS;
    let t0 = 1_000_000_000_u64;
    let mut reached = Reached::default();
    keep_reached(&mut reached, 8, (1, 1), who("fresh"), Some(t0));
    assert_eq!(
        take_reached(&mut reached, (1, 1), Some(t0 + ttl - 1)).map(|p| p.id),
        Some("fresh".to_string()),
        "within the TTL it answers its re-call"
    );
    keep_reached(&mut reached, 8, (2, 1), who("stale"), Some(t0));
    assert!(
        take_reached(&mut reached, (2, 1), Some(t0 + ttl)).is_none(),
        "past the TTL it is gone"
    );
    keep_reached(&mut reached, 8, (3, 1), who("abandoned"), Some(t0));
    keep_reached(&mut reached, 8, (4, 1), who("new"), Some(t0 + ttl));
    assert!(
        !reached.map.contains_key(&(3, 1)),
        "an expired entry is swept on the next keep"
    );
    assert_eq!(reached.map.len(), 1);
}

/// LDAP is a login method and judges no bearer credential on the data plane: its tail states the
#[test]
fn the_tail_states_the_login_family_alone() {
    assert_eq!(TAIL.caps, CAP_LOGIN);
    assert_eq!(TAIL.caps & CAP_INBOUND, 0);
    assert_eq!(TAIL.facts & FACT_CACHEABLE, 0);
    assert_eq!(TAIL.inbound_points, 0);
}

/// Search-then-bind settings whose service password is a secret reference (no literal in the
#[test]
fn validate_accepts_search_then_bind_whose_password_is_a_secret() {
    let blob = br#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(uid={username})",
        "bind_service_dn": "cn=svc,dc=corp,dc=example"
    }"#;
    assert!(
        Ldap::validate(blob).is_ok(),
        "{:?}",
        Ldap::validate(blob).err()
    );
    assert!(Ldap::open(blob, &[b"resolved".as_slice()], 1).is_ok());
    let e = Ldap::open(blob, &[], 1).err().expect("no password at open");
    assert!(
        e.text()
            .is_some_and(|t| t.contains("bind_service_password")),
        "{e:?}"
    );
    let empty = br#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(uid={username})",
        "bind_service_dn": "cn=svc,dc=corp,dc=example",
        "bind_service_password": ""
    }"#;
    assert!(Ldap::validate(empty).is_err(), "an explicit empty literal");

    let no_dn = br#"{
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(uid={username})"
    }"#;
    assert!(Ldap::validate(no_dn).is_err(), "no bind_service_dn");
}

/// A settings value of the wrong type is refused WITHOUT quoting it (it may be a secret pasted
#[test]
fn a_mistyped_setting_is_refused_without_echoing_its_value() {
    for blob in [
        r#"{"url":"ldaps://x","bind_dn_template":"uid={username},dc=x","base_dn":"dc=x","timeout_secs":"hunter2"}"#,
        r#"{"url":"ldaps://x","bind_dn_template":"uid={username},dc=x","base_dn":"dc=x","start_tls":"hunter2"}"#,
        r#"{"url":"ldaps://x","bind_dn_template":"uid={username},dc=x","base_dn":"dc=x","bind_service_password":{"v":"hunter2"}}"#,
    ] {
        let e = LdapModule::from_settings(blob.as_bytes())
            .err()
            .expect("refused");
        assert!(!e.contains("hunter2"), "the value is echoed: {e}");
        assert!(e.starts_with("settings."), "{e}");
        let r = Ldap::validate(blob.as_bytes()).expect_err("refused");
        assert!(!format!("{r:?}").contains("hunter2"), "{r:?}");
    }
    let e = LdapModule::from_settings(br#"{"url":"ldaps://x"}"#)
        .err()
        .expect("refused");
    assert!(e.contains("missing field `bind_dn_template`"), "{e}");
    let e = LdapModule::from_settings(
        br#"{"url":"ldaps://x","bind_dn_template":"uid={username},dc=x","base_dn":"dc=x","bogus":"hunter2"}"#,
    )
    .err()
    .expect("refused");
    assert!(e.contains("unknown field `bogus`"), "{e}");
    assert!(!e.contains("hunter2"), "{e}");
}

#[test]
fn a_begun_logins_password_is_the_chips_from_the_submitted_field() {
    let module = std::sync::Arc::new(LdapModule::from_settings(MINIMAL.as_bytes()).unwrap());
    let fields: [(&[u8], &[u8]); 3] = [
        (b"other", b"x"),
        (b"password", b"s3cret-pw"),
        (b"username", b"alice"),
    ];
    let run = super::begin(std::sync::Arc::clone(&module), &fields, None);
    assert_eq!(run.username.as_deref(), Some("alice"));
    assert_eq!(
        run.password
            .as_ref()
            .map(crate::tests::cred_text)
            .as_deref(),
        Some("s3cret-pw")
    );
    assert!(run.stream.is_none() && !run.conv.opened());
    let only_user: [(&[u8], &[u8]); 1] = [(b"username", b"alice")];
    let run = super::begin(module, &only_user, None);
    assert!(run.password.is_none(), "a password not submitted is none");
}

/// A cancelled login releases its owned stream; a login with no stream releases nothing.
#[test]
fn a_given_up_login_releases_its_stream() {
    use std::sync::{Arc, Mutex};
    let released = Arc::new(Mutex::new(Vec::new()));
    let module = std::sync::Arc::new(LdapModule::from_settings(MINIMAL.as_bytes()).unwrap());
    let run = |stream: Option<u64>| {
        let released = Arc::clone(&released);
        Run {
            module: Arc::clone(&module),
            username: None,
            password: None,
            conv: crate::conversation::Conversation::new(),
            stream,
            at: 0,
            release: Some(Release::new(move |s| released.lock().unwrap().push(s))),
        }
    };
    drop(run(Some(7)));
    assert_eq!(
        *released.lock().unwrap(),
        vec![7],
        "a given-up stream is released"
    );
    drop(run(None));
    assert_eq!(
        *released.lock().unwrap(),
        vec![7],
        "no stream, nothing to release"
    );
}

/// THE REFUSAL LINES (auth standard S2): every settings refusal is one or more lines in the
mod refusal_lines {
    use super::*;
    use busbar_contract::abi::mechanism::lifecycle::check_validate_refusal;
    use serde_json::{json, Value};

    fn base() -> Value {
        json!({
            "url": "ldaps://ad.corp.example:636",
            "bind_dn_template": "uid={username},ou=people,dc=corp,dc=example",
            "base_dn": "dc=corp,dc=example"
        })
    }

    fn with(changes: Value) -> Vec<u8> {
        let mut v = base();
        for (k, x) in changes.as_object().expect("an object") {
            v[k] = x.clone();
        }
        serde_json::to_vec(&v).expect("json")
    }

    /// `validate`'s refusal text for `blob`, held to the contract's shape and equal to `open`'s.
    fn refused(blob: &[u8]) -> String {
        let r = Ldap::validate(blob).expect_err("refused");
        let text = r.text().expect("a reason").to_string();
        assert!(check_validate_refusal(text.as_bytes()).is_ok(), "{text:?}");
        for line in text.split('\n') {
            assert!(
                line.starts_with("settings"),
                "not instance-relative: {line:?}"
            );
        }
        let o = Ldap::open(blob, &[], 1).err().expect("open refuses too");
        assert_eq!(
            o.text(),
            Some(text.as_str()),
            "validate and open say the same"
        );
        text
    }

    #[test]
    fn every_settings_refusal_is_an_instance_relative_line() {
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (b"".to_vec(), "settings: "),
            (b"{ not json".to_vec(), "settings: "),
            (
                br#"{"url":"ldaps://x"}"#.to_vec(),
                "settings: missing field `bind_dn_template`",
            ),
            (
                with(json!({"bogus": "hunter2"})),
                "settings: unknown field `bogus`",
            ),
            (
                with(json!({"timeout_secs": "hunter2"})),
                "settings.timeout_secs: invalid type",
            ),
            (
                with(json!({"bind_dn_template": "uid=fixed,dc=x"})),
                "settings.bind_dn_template: must contain the `{username}` placeholder",
            ),
            (
                with(json!({"bind_dn_template": "{username}@corp.example"})),
                "settings.bind_dn_template: is not a DN",
            ),
            (
                with(json!({"timeout_secs": 0})),
                "settings.timeout_secs: must be at least 1",
            ),
            (
                with(json!({"group_attr": " "})),
                "settings.group_attr: must not be empty",
            ),
            (with(json!({"url": ""})), "settings.url: must not be empty"),
            (
                with(json!({"url": "https://ad.corp.example"})),
                "settings.url: ",
            ),
            (with(json!({"url": "ldaps://"})), "settings.url: "),
            (
                with(json!({"url": "ldap://ad.corp.example:389"})),
                "settings.url: plaintext ldap://",
            ),
            (
                with(json!({"user_search_filter": "(uid=fixed)", "bind_service_dn": "cn=svc"})),
                "settings.user_search_filter: must contain the `{username}` placeholder",
            ),
            (
                with(json!({"user_search_filter": "(uid={username})"})),
                "settings.bind_service_dn: ",
            ),
            (
                with(json!({
                    "user_search_filter": "(uid={username})",
                    "bind_service_dn": "cn=svc",
                    "bind_service_password": ""
                })),
                "settings.bind_service_password: must be a secret reference",
            ),
        ];
        for (blob, want) in cases {
            let text = refused(&blob);
            assert!(text.contains(want), "want {want:?} in {text:?}");
            assert!(!text.contains("hunter2"), "a value is echoed: {text:?}");
        }
    }

    #[test]
    fn several_refusals_are_several_lines() {
        let text = refused(&with(json!({"timeout_secs": 0, "group_attr": ""})));
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(
            lines,
            [
                "settings.timeout_secs: must be at least 1",
                "settings.group_attr: must not be empty"
            ],
            "{text:?}"
        );
    }

    #[test]
    fn a_missing_or_non_utf8_service_secret_names_the_secret() {
        let blob = with(json!({
            "user_search_filter": "(uid={username})",
            "bind_service_dn": "cn=svc,dc=corp,dc=example"
        }));
        let e = Ldap::open(&blob, &[], 1).err().expect("no password");
        assert_eq!(
            e.text(),
            Some("secrets: `bind_service_password` is not set")
        );
        let e = Ldap::open(&blob, &[b"\xff".as_slice()], 1)
            .err()
            .expect("not UTF-8");
        assert_eq!(
            e.text(),
            Some("secrets: `bind_service_password` is not UTF-8")
        );
    }
}

/// CA-1 / SEC-LDAPCA: a private directory CA (`ca_cert_pem`) is SUPPORTED. A blob that holds a
mod private_ca {
    use super::*;
    use busbar_contract::abi::sdk::life::Life;

    fn blob(extra: serde_json::Value) -> Vec<u8> {
        let mut v: serde_json::Value = serde_json::from_str(MINIMAL).expect("json");
        for (k, x) in extra.as_object().expect("object") {
            v[k] = x.clone();
        }
        serde_json::to_vec(&v).expect("json")
    }

    fn pem() -> &'static str {
        busbar_test_kit::conformance_host::anchors()
    }

    #[test]
    fn a_private_ca_is_accepted_and_anchors_the_dial() {
        let with_ca = blob(serde_json::json!({"ca_cert_pem": pem()}));
        assert!(
            Ldap::validate(&with_ca).is_ok(),
            "{:?}",
            Ldap::validate(&with_ca).err()
        );
        let m = LdapModule::from_settings(&with_ca).expect("opens");
        assert_eq!(m.need(), NEED_ANCHORED);
        let m = LdapModule::from_settings(MINIMAL.as_bytes()).expect("opens");
        assert_eq!(m.need(), NEED);
        let starttls = blob(serde_json::json!({
            "url": "ldap://ad.corp.example:389",
            "start_tls": true,
            "ca_cert_pem": pem()
        }));
        assert_eq!(
            LdapModule::from_settings(&starttls).expect("opens").need(),
            NEED_ANCHORED
        );
    }

    #[test]
    fn a_ca_cert_pem_with_no_certificate_is_refused_by_name() {
        for bad in [
            "",
            "-----BEGIN CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
            "hunter2",
        ] {
            let r = Ldap::validate(&blob(serde_json::json!({"ca_cert_pem": bad})))
                .expect_err("refused");
            let text = r.text().expect("a reason");
            assert!(
                text.starts_with("settings.ca_cert_pem: "),
                "{bad:?}: {text}"
            );
            assert!(!text.contains("hunter2"), "{text}");
        }
    }
}

mod reached_clock_callbacks {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::sync::mpsc::{self, Sender};
    use std::time::Duration;

    use busbar_contract::abi::auth::{slot as auth_slot, CompleteLoginIn, IdentifyOut, Ops};
    use busbar_contract::abi::host::service::{ClockNowIn, ClockReading};
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::{slot as life_slot, OpenIn, OpenOut};
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::sdk::life::Held;
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
    use busbar_test_kit::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
    use busbar_test_kit::test_support::reply;
    use busbar_test_kit::test_support::test_in::TestIn;
    use busbar_test_kit::test_support::{zeroed, DoorView};

    thread_local! {
        static PROBE: RefCell<Option<Sender<Sender<bool>>>> = const { RefCell::new(None) };
        static SAMPLES: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
        static RETAINED: Cell<bool> = const { Cell::new(false) };
    }

    struct Clock;
    impl FakeService for Clock {
        type In = ClockNowIn;
        fn serve(call: &mut ServiceCall<ClockNowIn>) -> Outcome {
            let unlocked = PROBE.with(|probe| {
                let probe = probe.borrow();
                probe
                    .as_ref()
                    .and_then(|ask| {
                        let (reply, result) = mpsc::channel();
                        ask.send(reply).ok()?;
                        result.recv_timeout(Duration::from_secs(2)).ok()
                    })
                    .unwrap_or(false)
            });
            SAMPLES.with(|samples| samples.borrow_mut().push(unlocked));
            call.put(
                |i| &i.reading,
                ClockReading {
                    size: std::mem::size_of::<ClockReading>() as u32,
                    _reserved: 0,
                    wall_ns: 42,
                    mono_ns: 42,
                },
            );
            Outcome::Ready
        }
    }

    struct Armed;
    impl Drop for Armed {
        fn drop(&mut self) {
            PROBE.with(|probe| probe.borrow_mut().take());
        }
    }

    struct ObserveComplete;
    impl SafeSlot for ObserveComplete {
        type In = CompleteLoginIn;
        type Out = IdentifyOut;
        type State = Held<Ldap>;
        fn call(
            instance: Instance<'_, Held<Ldap>>,
            input: Lent<'_, CompleteLoginIn>,
            out: Out<'_, IdentifyOut>,
        ) -> Outcome {
            let held = instance.get().expect("the opened LDAP state");
            let ticket = instance.ticket();
            let key = (ticket.slot, ticket.generation);
            keep_reached(
                &mut held.life().reached.lock().unwrap(),
                super::super::REACHED_MAX,
                key,
                who("cached-alice"),
                Some(42),
            );
            std::thread::scope(|scope| {
                let (ask, requests) = mpsc::channel::<Sender<bool>>();
                scope.spawn(move || {
                    while let Ok(reply) = requests.recv() {
                        let unlocked = held.life().reached.try_lock().is_ok();
                        let _ = reply.send(unlocked);
                    }
                });
                PROBE.with(|probe| *probe.borrow_mut() = Some(ask));
                let armed = Armed;
                let answer = crate::door::CompleteLogin::call(instance, input, out);
                drop(armed);
                RETAINED.with(|retained| {
                    retained.set(held.life().reached.try_lock().ok().is_some_and(|reached| {
                        reached
                            .map
                            .get(&key)
                            .is_some_and(|(_, _, p)| p.id == "cached-alice")
                    }))
                });
                answer
            })
        }
    }

    mod fixture {
        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::auth::Ops,
            statement: crate::door::STATEMENT,
            lifecycle: life(crate::door::Ldap),
            kind_ops: {
                complete_login: busbar_contract::abi::sdk::Safe<super::ObserveComplete>,
            },
        }
    }

    #[test]
    fn both_reached_cache_clock_callbacks_run_without_the_reached_lock() {
        SAMPLES.with(|samples| samples.borrow_mut().clear());
        RETAINED.with(|retained| retained.set(false));
        let view = DoorView::of(fixture::MACRO_DOOR);
        let host = FakeHost::new().serve(fake::host::CLOCK_NOW, Clock);
        let open = host.lend_in(
            TestIn::<OpenIn>::new()
                .set(|i| &i.head.op, life_slot::OPEN)
                .settings(MINIMAL.as_bytes()),
        );
        let mut opened = reply::call_hosted_in(
            view.op::<Ops>(|ops| &ops.head.open).unwrap(),
            None,
            &open,
            zeroed::<OpenOut>(),
        );
        assert_eq!(opened.outcome, Outcome::Ready);
        let instance = opened.take_instance().expect("the LDAP instance");
        let input = TestIn::<CompleteLoginIn>::new()
            .set(|i| &i.head.op, auth_slot::COMPLETE_LOGIN)
            .set(
                |i| &i.head.ticket,
                Ticket {
                    slot: 3,
                    generation: 1,
                },
            );
        let answer = reply::call_in(
            view.op::<Ops>(|ops| &ops.complete_login).unwrap(),
            Some(&instance),
            &input,
            zeroed::<IdentifyOut>(),
        );
        let closed = reply::close_in(
            view.op::<Ops>(|ops| &ops.head.close).unwrap(),
            instance,
            &TestIn::<InHead>::new().set(|i| &i.op, life_slot::CLOSE),
            zeroed::<OutHead>(),
        );
        assert_eq!(closed.outcome, Outcome::Ready);
        assert_eq!(
            answer.outcome,
            Outcome::Failed,
            "the empty identity buffer requires a re-call"
        );
        assert!(answer.out.needed_bytes > 0, "the real identity writer ran");
        assert!(
            RETAINED.with(Cell::get),
            "the short-answer identity was retained for its re-call"
        );
        assert_eq!(
            SAMPLES.with(|samples| samples.borrow().clone()),
            [true, true],
            "the take and keep clock callbacks both observed the reached map unlocked"
        );
    }
}

mod timeout_stream_release {
    use busbar_contract::abi::auth::{
        slot as auth_slot, CompleteLoginIn, IdentifyOut, NamedValue, Ops, LOGIN_OUTAGE,
    };
    use busbar_contract::abi::host::conn::connector::{EstablishIn, IoIn, StreamIn};
    use busbar_contract::abi::host::service::{ClockNowIn, ClockReading};
    use busbar_contract::abi::mechanism::call::{
        AbiStr, Blob, InHead, OutHead, Outcome, BLOB_SECRET,
    };
    use busbar_contract::abi::mechanism::lifecycle::{slot as life_slot, OpenIn, OpenOut};
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_test_kit::test_support::fake::{self, FakeHost, FakeService, ServiceCall};
    use busbar_test_kit::test_support::{reply, test_in::TestIn, zeroed, DoorView};
    use std::cell::{Cell, RefCell};

    thread_local! {
        static NOW: Cell<u64> = const { Cell::new(0) };
        static CLOSES: RefCell<Vec<(u64, Ticket)>> = const { RefCell::new(Vec::new()) };
        static READS: Cell<u32> = const { Cell::new(0) };
    }
    struct Clock;
    impl FakeService for Clock {
        type In = ClockNowIn;
        fn serve(call: &mut ServiceCall<ClockNowIn>) -> Outcome {
            call.put(
                |i| &i.reading,
                ClockReading {
                    size: std::mem::size_of::<ClockReading>() as u32,
                    _reserved: 0,
                    wall_ns: 0,
                    mono_ns: NOW.with(Cell::get),
                },
            );
            Outcome::Ready
        }
    }
    struct Establish;
    impl FakeService for Establish {
        type In = EstablishIn;
        fn serve(call: &mut ServiceCall<EstablishIn>) -> Outcome {
            call.set_value(71);
            Outcome::Ready
        }
    }
    struct Write;
    impl FakeService for Write {
        type In = IoIn;
        fn serve(call: &mut ServiceCall<IoIn>) -> Outcome {
            call.set_len(call.input().len as u64);
            Outcome::Ready
        }
    }
    struct Read;
    impl FakeService for Read {
        type In = IoIn;
        fn serve(_: &mut ServiceCall<IoIn>) -> Outcome {
            READS.with(|reads| reads.set(reads.get() + 1));
            Outcome::Pending
        }
    }
    struct Close;
    impl FakeService for Close {
        type In = StreamIn;
        fn serve(call: &mut ServiceCall<StreamIn>) -> Outcome {
            CLOSES.with(|closes| {
                closes
                    .borrow_mut()
                    .push((call.input().stream, call.input().head.handle.ticket))
            });

            if call.input().head.handle.ticket != Ticket::NONE {
                Outcome::Failed
            } else {
                Outcome::Ready
            }
        }
    }
    #[test]
    fn a_timed_out_pending_read_releases_the_stream_without_replaying_its_handle() {
        NOW.with(|now| now.set(0));
        READS.with(|reads| reads.set(0));
        CLOSES.with(|closes| closes.borrow_mut().clear());
        let host = FakeHost::new()
            .serve(fake::host::CLOCK_NOW, Clock)
            .serve(fake::conn::ESTABLISH, Establish)
            .serve(fake::conn::WRITE, Write)
            .serve(fake::conn::READ, Read)
            .serve(fake::conn::CLOSE, Close);
        let view = DoorView::of(crate::door::MACRO_DOOR);
        let settings = br#"{"url":"ldap://127.0.0.1","bind_dn_template":"uid={username},dc=x","base_dn":"dc=x","timeout_secs":1}"#;
        let open = host.lend_in(
            TestIn::<OpenIn>::new()
                .set(|i| &i.head.op, life_slot::OPEN)
                .settings(settings),
        );
        let mut opened = reply::call_hosted_in(
            view.op::<Ops>(|ops| &ops.head.open).unwrap(),
            None,
            &open,
            zeroed::<OpenOut>(),
        );
        assert_eq!(opened.outcome, Outcome::Ready);
        let instance = opened.take_instance().unwrap();
        let submitted = [
            NamedValue {
                name: AbiStr::of("username"),
                value: Blob::of(b"alice").with_flags(BLOB_SECRET),
            },
            NamedValue {
                name: AbiStr::of("password"),
                value: Blob::of(b"pw").with_flags(BLOB_SECRET),
            },
        ];
        let input = TestIn::<CompleteLoginIn>::new()
            .set(|i| &i.head.op, auth_slot::COMPLETE_LOGIN)
            .set(
                |i| &i.head.ticket,
                Ticket {
                    slot: 2,
                    generation: 1,
                },
            )
            .list(|i| &i.submitted, |i| &i.submitted_len, &submitted);
        let op = view.op::<Ops>(|ops| &ops.complete_login).unwrap();
        let first = reply::call_in(op, Some(&instance), &input, zeroed::<IdentifyOut>());
        NOW.with(|now| now.set(1_000_000_000));
        let timed_out = reply::call_in(op, Some(&instance), &input, zeroed::<IdentifyOut>());
        let closed = reply::close_in(
            view.op::<Ops>(|ops| &ops.head.close).unwrap(),
            instance,
            &TestIn::<InHead>::new().set(|i| &i.op, life_slot::CLOSE),
            zeroed::<OutHead>(),
        );
        assert_eq!(closed.outcome, Outcome::Ready);
        assert_eq!(first.outcome, Outcome::Pending);
        assert_eq!(timed_out.outcome, Outcome::Ready);
        assert_eq!(timed_out.out.verdict, LOGIN_OUTAGE);
        assert_eq!(
            READS.with(Cell::get),
            1,
            "timeout never reissues the abandoned read"
        );
        assert_eq!(
            CLOSES.with(|closes| closes.borrow().clone()),
            [(71, Ticket::NONE)],
            "one synchronous stream release, independent of the pending service handle"
        );
    }
}
