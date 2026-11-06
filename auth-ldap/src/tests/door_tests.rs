// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's own pieces: the settings blob `validate`/`open`/`refresh` parse, the submitted-field
//! lookup, and the Statement's facts. The table itself is driven through the real loader in the
//! plugin crate's `tests/conformance.rs` (linked and dropped in).

use super::{
    clock_ns, field, keep_reached, mid_call_reading, take_reached, unreadable, Ldap, Reached,
    Release, Run, ALIAS, FORM, NAME, NEED, NEEDS, NEED_ANCHORED, SECRET_REFS, STATEMENT, TAIL,
};
use crate::LdapModule;
use busbar_contract::abi::auth::{CAP_LOGIN, CAP_OUTBOUND, FACT_CACHEABLE, LOGIN_KIND_CREDENTIAL};
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
fn settings_accept_a_minimal_config() {
    assert!(LdapModule::from_settings(MINIMAL.as_bytes()).is_ok());
    assert!(Ldap::validate(MINIMAL.as_bytes()).is_ok());
}

/// A direct-bind UPN template (`{username}@corp.example`) is not a DN, so the group read off the
/// bound entry could never succeed; `validate` refuses it.
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

/// A host clock that fails between messages is said at warn, once for the entry of the op however
/// many messages it misses, and the deadline falls back to the entry's own reading (`None`).
#[test]
fn a_clock_failing_between_messages_is_said_once() {
    let cap = crate::diagnostics::Diagnostics::default();
    let mut said = false;
    let readings = tracing::subscriber::with_default(cap.subscriber(), || {
        [
            mid_call_reading(Ok(7), &mut said),
            mid_call_reading(Err("the host clock failed: broke".into()), &mut said),
            mid_call_reading(Err("the host clock failed: broke".into()), &mut said),
        ]
    });
    assert_eq!(readings, [Some(7), None, None]);
    assert_eq!(cap.count("clock-failed"), 1, "{:?}", cap.messages());
    assert!(cap.contains("broke"), "{:?}", cap.messages());
}

/// The Statement states a credential login that never blocks (no `MARK_BLOCKS`: every call is
/// Ready or Pending), its ONE need (outbound, a raw `tcp` stream, operator-infrastructure, the
/// target named per login), and the service password as its one secret reference.
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
/// call's own key answers its identity.
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
/// that slot stays for its own re-call.
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
/// the rest and never all of them, so an in-flight short answer awaiting its re-call survives a
/// flood of abandoned ones.
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
/// login family alone (no `CAP_INBOUND`, so `verify` is never called and answers REFUSED), and no
/// `FACT_CACHEABLE` (a fact about verify answers it does not give), as busbar-auth-github's.
#[test]
fn the_tail_states_the_login_family_alone() {
    assert_eq!(TAIL.facts & FACT_CACHEABLE, 0);
    assert_eq!(TAIL.inbound_points, 0);
}

/// Search-then-bind settings whose service password is a secret reference (no literal in the
/// settings) validate: `validate` is handed no secrets, so the password-presence rule is `open`'s,
/// where the resolved secret is known. `open` with no secret still refuses; an explicit empty
/// literal is refused by both.
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
/// into the wrong key); a missing or unknown key is still named.
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
    assert!(run.stream.is_none());
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
/// contract's instance-relative form (`settings[.<key>]: <reason>`, joined by `\n`, holding
/// `check_validate_refusal`), the same at `validate` and `open`, and never a value.
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

    /// A literal service password is one refusal line among the others, not the only one said.
    #[test]
    fn a_literal_service_password_is_one_line_among_the_others() {
        let text = refused(&with(
            json!({"bind_service_password": "hunter2", "timeout_secs": 0}),
        ));
        let lines: Vec<&str> = text.split('\n').collect();
        assert_eq!(lines.len(), 2, "{text:?}");
        assert!(
            lines[0].starts_with("settings.bind_service_password: must be a secret reference"),
            "{text:?}"
        );
        assert_eq!(lines[1], "settings.timeout_secs: must be at least 1");
        assert!(!text.contains("hunter2"), "a value is echoed: {text:?}");
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
/// certificate validates, and the module dials on the ANCHORED need (whose `trust_from` hands the
/// connector that CA, on top of the public roots, for both `ldaps://` and STARTTLS); without it,
/// the public need. A `ca_cert_pem` that holds no certificate is refused by name, never accepted
/// and ignored.
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
        include_str!("ca.pem")
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

    use busbar_contract::abi::auth::{slot as auth_slot, CompleteLoginIn, IdentifyOut};
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::lifecycle::{slot as life_slot, OpenIn, OpenOut};
    use busbar_contract::abi::sdk::life::Held;
    use busbar_contract::abi::sdk::test_support::zeroed;
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
    use busbar_contract::conn::{
        ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
        PieceKind, Ticket as ConnTicket,
    };
    use busbar_contract::services::{
        Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList,
        Snapshot, Stored, TrustKeyRef, UNSERVED,
    };
    use busbar_contract::transport::ConnFacts;
    use busbar_plugin_loader::dispatch::kinds::auth::Auth;
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
    };
    use std::net::TcpStream;
    use std::sync::{Arc, Mutex};

    thread_local! {
        static PROBE: RefCell<Option<Sender<Sender<bool>>>> = const { RefCell::new(None) };
        static SAMPLES: RefCell<Vec<bool>> = const { RefCell::new(Vec::new()) };
        static RETAINED: Cell<bool> = const { Cell::new(false) };
    }

    #[derive(Default)]
    struct Clock {
        streams: ConnSlab<Mutex<TcpStream>>,
    }
    impl HostServices for Clock {
        fn now(&self) -> Reading {
            let unlocked = PROBE.with(|probe| {
                probe
                    .borrow()
                    .as_ref()
                    .and_then(|ask| {
                        let (reply, result) = mpsc::channel();
                        ask.send(reply).ok()?;
                        result.recv_timeout(Duration::from_secs(60)).ok()
                    })
                    .unwrap_or(false)
            });
            SAMPLES.with(|samples| samples.borrow_mut().push(unlocked));
            Reading {
                wall_ns: 42,
                mono_ns: 42,
            }
        }
        fn dest_judge(&self, _dest: &str, _class: u32, _flags: u32, _later: Option<Later>) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_get(&self, _caller: &Caller, _kind: &str, _key: &[u8], _later: Later) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_list(&self, _caller: &Caller, _list: RecordsList, _later: Later) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn records_claim(
            &self,
            _caller: &Caller,
            _kind: &str,
            _key: &[u8],
            _ttl_ms: u64,
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn sign(&self, _caller: &Caller, _data: &[u8]) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_sight(
            &self,
            _caller: &Caller,
            _counterparty: &str,
            _hash: &str,
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn trust_unreached(&self, _caller: &Caller, _counterparty: &str) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_sight_item(
            &self,
            _caller: &Caller,
            _counterparty: &str,
            _item: &str,
            _digest: &str,
        ) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_decide(
            &self,
            _caller: &Caller,
            _key: TrustKeyRef<'_>,
            _expected: Option<&str>,
            _approve: bool,
        ) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_state(&self, _caller: &Caller, _counterparty: &str) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_serves(
            &self,
            _caller: &Caller,
            _counterparty: &str,
            _item: Option<&str>,
            _digest: Option<&str>,
        ) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_due(&self, _caller: &Caller) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn trust_verify(
            &self,
            _caller: &Caller,
            _counterparty: &str,
            _payload: &[u8],
            _signatures: &[u8],
        ) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn entitlement_check(&self, _caller: &Caller, _unit: Option<u64>, _target: &str) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn session_emit(&self, _caller: &Caller, _session: u64, _bytes: &[u8]) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn ticket_mint(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _ttl_secs: u64,
            _record: &[u8],
        ) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn ticket_take(&self, _caller: &Caller, _unit: Option<u64>) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn random_fill(&self, _len: u64) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn records_secret(&self, _kind: &str, _id: &str, _later: Later) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn unit_nest(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _ask: NestAsk,
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_open(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _kind: &str,
            _record: &[u8],
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_find(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _reference: &[u8],
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_settle(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _handle: u64,
            _record: &[u8],
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn work_resume(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _handle: u64,
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn disk_append(&self, _dest: &DiskDest, _bytes: Vec<u8>, _later: Later) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn verify_lookup(&self, _caller: &Caller, _key: &[u8], _later: Later) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn verify_store(
            &self,
            _caller: &Caller,
            _key: &[u8],
            _entry: &[u8],
            _ttl_ms: u64,
        ) -> Stored {
            Stored::refused(UNSERVED)
        }
        fn content_scan(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _content: &[u8],
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn hook_call(
            &self,
            _caller: &Caller,
            _unit: Option<u64>,
            _ask: HookAsk,
            _later: Later,
        ) -> Ran {
            Ran::Now(Stored::refused(UNSERVED))
        }
        fn snapshot_read(&self, _caller: &Caller, _scope: u32) -> Snapshot {
            Snapshot::Refused(UNSERVED)
        }
    }

    impl Conns for Clock {
        fn open(
            &self,
            owner: InstanceId,
            need: NeedId,
            desc: &OpenDesc<'_>,
        ) -> Result<ConnId, ConnError> {
            use std::net::ToSocketAddrs;
            self.streams.check_need(owner, need)?;
            let host = desc
                .target
                .rsplit_once(':')
                .map(|(host, _)| host)
                .ok_or(ConnError::Refused)?;
            if !host.eq_ignore_ascii_case("localhost")
                && !host
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback())
            {
                return Err(ConnError::Refused);
            }
            let address = desc
                .target
                .to_socket_addrs()
                .map_err(|_| ConnError::Refused)?
                .find(|at| {
                    at.ip().is_loopback()
                        && (desc.within.is_empty() || desc.within.contains(&at.ip()))
                })
                .ok_or(ConnError::Refused)?;
            let timeout = if desc.timeout_ms == 0 {
                Duration::from_secs(5)
            } else {
                Duration::from_millis(desc.timeout_ms)
            };
            let tcp = std::net::TcpStream::connect_timeout(&address, timeout)
                .map_err(|_| ConnError::Closed)?;
            tcp.set_read_timeout(Some(Duration::from_millis(5)))
                .map_err(|_| ConnError::Closed)?;
            tcp.set_write_timeout(Some(Duration::from_millis(5)))
                .map_err(|_| ConnError::Closed)?;
            self.streams.insert(owner, need, Mutex::new(tcp))
        }
        fn write(
            &self,
            owner: InstanceId,
            conn: ConnId,
            bytes: &[u8],
            _: bool,
            _: bool,
        ) -> Result<usize, ConnError> {
            use std::io::Write;
            let (_, tcp) = self.streams.get(owner, conn)?;
            let mut tcp = tcp.lock().unwrap();
            tcp.write(bytes).map_err(|_| ConnError::Closed)
        }
        fn read(
            &self,
            owner: InstanceId,
            conn: ConnId,
            _: ConnTicket,
            buf: &mut [u8],
        ) -> Result<Piece, ConnError> {
            use std::io::Read;
            let (_, tcp) = self.streams.get(owner, conn)?;
            let len = tcp
                .lock()
                .unwrap()
                .read(buf)
                .map_err(|_| ConnError::Closed)?;
            Ok(Piece {
                kind: if len == 0 {
                    PieceKind::Completion
                } else {
                    PieceKind::Body
                },
                stream: busbar_contract::ids::StreamId(0),
                len,
                end: len == 0,
                status: None,
                status_code: None,
                reason: None,
                status_namespace: None,
                declared_len: None,
                fault: None,
                retry_after_secs: None,
            })
        }
        fn wait(
            &self,
            owner: InstanceId,
            set: &[ConnId],
            _: ConnTicket,
        ) -> Result<usize, ConnError> {
            for conn in set {
                self.streams.get(owner, *conn)?;
            }
            Err(ConnError::Refused)
        }
        fn facts(&self, owner: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
            self.streams.get(owner, conn)?;
            Ok(ConnFacts::default())
        }
        fn close(&self, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
            let tcp = self.streams.remove(owner, conn)?;
            let tcp = tcp.lock().unwrap();
            tcp.shutdown(std::net::Shutdown::Both)
                .map_err(|_| ConnError::Closed)
        }
    }
    impl DeclaredConns for Clock {
        fn serves_scheme(&self, scheme: &str) -> bool {
            scheme == "tcp"
        }
        fn declare(
            &self,
            owner: InstanceId,
            need: NeedId,
            spec: &busbar_contract::abi::mechanism::rendering::ReadNeed,
            target: Option<&str>,
            trust: Option<&str>,
        ) -> Result<(), ConnError> {
            if spec.direction != DIRECTION_OUTBOUND
                || spec.transport != "tcp"
                || !spec.auth.is_empty()
                || !spec.target_from.is_empty()
                || !spec.trust_from.is_empty()
                || target.is_some()
                || trust.is_some()
            {
                return Err(ConnError::Refused);
            }
            self.streams.declare(owner, need);
            Ok(())
        }
        fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
            self.streams.check_need(owner, need).ok().map(|()| Ok(()))
        }
        fn open_request(
            &self,
            owner: InstanceId,
            need: NeedId,
            desc: &OpenDesc<'_>,
            secure: bool,
            dial_timeout_ms: u64,
        ) -> Result<ConnId, ConnError> {
            let mut dial = desc.clone();
            if dial_timeout_ms != 0 {
                dial.timeout_ms = if desc.timeout_ms == 0 {
                    dial_timeout_ms
                } else {
                    dial_timeout_ms.min(desc.timeout_ms)
                };
            }
            Conns::open_with_security(self, owner, need, &dial, secure)
        }
        fn forget(&self, owner: InstanceId) {
            self.streams.forget(owner);
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
        use crate::door::{BeginLogin, NotServed};
        use busbar_contract::abi::auth::{
            FieldsIn, FieldsOut, IdentifyOut, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn,
            OutboundReadyOut, VerifyIn,
        };
        use busbar_contract::abi::sdk::Safe;

        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::auth::Ops,
            statement: crate::door::STATEMENT,
            lifecycle: life(crate::door::Ldap),
            kind_ops: {
                verify: Safe<NotServed<VerifyIn, IdentifyOut>>,
                begin_login: Safe<BeginLogin>,
                complete_login: Safe<super::ObserveComplete>,
                open_outbound: Safe<NotServed<OpenOutboundIn, OpenOutboundOut>>,
                outbound_ready: Safe<NotServed<OutboundReadyIn, OutboundReadyOut>>,
                fields: Safe<NotServed<FieldsIn, FieldsOut>>,
            },
        }
    }

    #[test]
    fn both_reached_cache_clock_callbacks_run_without_the_reached_lock() {
        SAMPLES.with(|samples| samples.borrow_mut().clear());
        RETAINED.with(|retained| retained.set(false));
        let host = Arc::new(Clock::default());
        let d = Dispatcher::with_services(DispatchConfig::default(), host.clone());
        let p = load_linked::<Auth>(
            &LinkedRow::of_macro(fixture::MACRO_DOOR).unwrap(),
            Bind {
                instance: "ldap-private-cache-lock".into(),
                max_inflight_cap: 8,
                sink: Arc::new(NoSink),
                dispatcher: d.adopter(),
                conns: ConnTable::Host(host),
            },
        )
        .unwrap();
        let secret = [busbar_contract::abi::mechanism::call::Blob::of(b"")];
        let mut open: Frame<OpenIn, OpenOut> = Frame::new(zeroed(), zeroed());
        open.input.settings = busbar_contract::abi::mechanism::call::Blob {
            fmt: busbar_contract::abi::mechanism::call::BLOB_JSON,
            ..busbar_contract::abi::mechanism::call::Blob::of(MINIMAL.as_bytes())
        };
        open.input.secrets = secret.as_ptr();
        open.input.secrets_len = secret.len();
        open.input.generation = 1;
        assert_eq!(p.call(life_slot::OPEN, &mut open).outcome, Outcome::Ready);
        let inline = d.inline_ticket().expect("registered cache inline ticket");
        let ticket = inline.ticket();
        let mut input: Frame<CompleteLoginIn, IdentifyOut> = Frame::new(zeroed(), zeroed());
        let answer = p.call_inline(ticket, false, auth_slot::COMPLETE_LOGIN, &mut input);
        let mut close: Frame<InHead, OutHead> = Frame::new(zeroed(), zeroed());
        assert_eq!(p.call(life_slot::CLOSE, &mut close).outcome, Outcome::Ready);
        assert_eq!(
            answer.outcome,
            Outcome::Failed,
            "the empty identity buffer requires a re-call; crossings={} error={}",
            p.inner.crossings.load(std::sync::atomic::Ordering::SeqCst),
            String::from_utf8_lossy(answer.error.as_deref().unwrap_or_default())
        );
        assert!(input.out.needed_bytes > 0, "the real identity writer ran");
        assert!(
            RETAINED.with(Cell::get),
            "the short-answer identity was retained for its re-call"
        );
        assert_eq!(
            SAMPLES.with(|samples| samples.borrow().clone()),
            [true, true],
            "the take and keep clock callbacks both observed the reached map unlocked"
        );
        drop(answer);
        drop(inline);
    }
}

#[test]
fn hardening_submitted_password_controls_refused() {
    for password in [
        "secret\0tail",
        "secret\ttail",
        "secret\ntail",
        "secret\u{7f}tail",
        "secret\u{85}tail",
    ] {
        assert_eq!(
            unreadable(&[(b"password", password.as_bytes())]),
            Some("the password field contains a control character")
        );
    }
    assert_eq!(
        unreadable(&[(b"password", " päss密碼 🔐 ".as_bytes())]),
        None
    );
}
