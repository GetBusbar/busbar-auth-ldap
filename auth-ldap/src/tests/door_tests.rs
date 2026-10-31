// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's own pieces: the settings blob `validate`/`open`/`refresh` parse, the submitted-field
//! lookup, and the Statement's facts. The table itself is driven through the real loader in the
//! plugin crate's `tests/conformance.rs` (linked and dropped in).

use super::{
    clock_ns, closed, field, keep_reached, take_reached, unreadable, Ldap, Reached, Release, Run,
    ALIAS, FORM, NAME, NEED, NEEDS, NEED_ANCHORED, SECRET_REFS, STATEMENT, TAIL,
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

/// KIND B7: no settings at all read in the fleet's one form, naming what is required.
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

/// L5: a field submitted but not UTF-8 is refused in its own words, not as "not submitted" (the
/// verdict is the same bad credential); a field absent, or text, is not this refusal.
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

/// L5: a host clock that answers a failure says which, instead of collapsing into "no clock".
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
    // The strings themselves (`tcp`, `settings.ca_cert_pem`, the secret reference) are read off
    // the rendered Statement in the plugin crate's conformance test, without `unsafe`.
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

/// L6 (S1): the service password is a secret REFERENCE, never a literal. busbar resolves the
/// reference and lifts the key out of the settings into `OpenIn.secrets`, so a
/// `bind_service_password` the plugin finds IN its settings is a literal that bypassed that: it
/// refuses `validate` and boot, naming the key and never the value. The resolved secret is the
/// password.
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
    // Re-keeping a key already held evicts nothing.
    keep_reached(&mut reached, 16, (19, 1), who("again"), None);
    assert_eq!(reached.map.len(), 16);
    assert!(reached.map.contains_key(&(4, 1)));
}

/// KIND-REVIEW D6: the reached map is bounded AND time-expired: an identity kept for a re-call that
/// never comes (its slot never reused) goes after `REACHED_TTL_NS` (10 minutes) on the host's clock,
/// swept on the next keep or take; within it, it answers its re-call.
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
    assert_eq!(TAIL.caps, CAP_LOGIN);
    assert_eq!(TAIL.caps & CAP_INBOUND, 0);
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
    // The other settings-only rules still hold at validate.
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

/// T8: the run `drive` begins from the submitted fields ([`super::begin`], what `drive` calls)
/// holds the username as text and the password as the chip's credential, captured from the
/// submitted bytes; a field not submitted is none, and the run holds no stream yet.
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

/// M7: a parked login holding an established stream that is given up (its op cancelled, a fresh
/// op on its ticket, the instance closed: the SDK drops what was parked) releases the stream
/// through the host; and a finish-path close the op's connector answered PENDING is handed to the
/// same release rather than dropped. A close the connector answered closes it once.
#[test]
fn a_given_up_or_pending_close_releases_the_stream() {
    use std::sync::{Arc, Mutex};
    use std::task::Poll;
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

    let mut pending = run(Some(9));
    closed(&mut pending, Poll::Pending);
    drop(pending);
    assert_eq!(
        *released.lock().unwrap(),
        vec![7, 9],
        "a pending close is handed to the release"
    );
    let mut done = run(Some(11));
    closed(&mut done, Poll::Ready(Ok(())));
    drop(done);
    assert_eq!(
        *released.lock().unwrap(),
        vec![7, 9],
        "a stream the op's close closed is not closed twice"
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
