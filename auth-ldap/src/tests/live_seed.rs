// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The live OpenLDAP directory the module's live tests share: where it is (`BUSBAR_TEST_LDAP_URL`),
//! and the seed (alice, her group, the admin bind). Included by the logic crate's `live_tests` and
//! by the plugin crate's `tests/e2e.rs`.

pub const BASE_DN: &str = "dc=example,dc=org";
pub const ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
pub const ADMIN_PW: &str = "adminpassword";
pub const ALICE_DN: &str = "uid=alice,ou=people,dc=example,dc=org";
pub const ALICE_PW: &str = "alicepassword";

fn ldap_url() -> Option<String> {
    match std::env::var("BUSBAR_TEST_LDAP_URL") {
        Ok(u) if !u.trim().is_empty() => Some(u.trim().to_string()),
        _ => None,
    }
}

/// The live directory's URL, or `None` to skip (loudly) outside CI. Under CI an unset URL panics,
/// like [`plugin_path`]'s unbuilt-cdylib guard: the service arm is supposed to provide it.
pub fn live_ldap_url() -> Option<String> {
    let url = ldap_url();
    if url.is_none() {
        if std::env::var_os("CI").is_some() {
            panic!(
                "BUSBAR_TEST_LDAP_URL is unset under CI: the plugin-ci `service: openldap` arm must \
                 provide the OpenLDAP service container"
            );
        }
        eprintln!(
            "skip: BUSBAR_TEST_LDAP_URL unset — ldap live e2e needs the OpenLDAP service container \
             (set by the plugin-ci `service: openldap` arm). Skipping (local, no docker)."
        );
    }
    url
}

/// Seed the test directory over LDAP (idempotent): ou=people, ou=groups, uid=alice (bindable
/// userPassword + a `seeAlso` group-DN the plugin reads as membership), and cn=admins with alice as a
/// member — the in-test equivalent of scripts/fixtures/auth-ldap/seed.ldif. Uses `seeAlso` (a
/// standard DN-syntax attribute seeded directly on the user) so the group→role mapping is deterministic
/// on any OpenLDAP WITHOUT the operational `memberOf` overlay; the plugin's `group_attr` points at it.
pub fn seed_directory(url: &str) {
    use ldap3::{LdapConn, Scope, SearchEntry};
    // The OpenLDAP service container takes a few seconds to create its base suffix; retry the admin
    // bind until it is ready (or give up loudly after ~60s).
    let mut ldap = None;
    for _ in 0..60 {
        if let Ok(mut c) = LdapConn::new(url) {
            if c.simple_bind(ADMIN_DN, ADMIN_PW)
                .is_ok_and(|r| r.success().is_ok())
            {
                ldap = Some(c);
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
    let mut ldap =
        ldap.expect("OpenLDAP admin bind never succeeded (check LDAP_ADMIN_PASSWORD / base)");

    // Confirm the container auto-created the base suffix from its env before we add children.
    ldap.search(BASE_DN, Scope::Base, "(objectClass=*)", vec!["dn"])
        .and_then(|r| r.success())
        .unwrap_or_else(|e| {
            panic!("base suffix {BASE_DN} must exist (set LDAP_DOMAIN=example.org): {e}")
        });

    let add =
        |ldap: &mut LdapConn, dn: &str, attrs: Vec<(&str, std::collections::HashSet<&str>)>| {
            match ldap.add(dn, attrs).and_then(|r| r.success()) {
                Ok(_) => {}
                // 68 = entryAlreadyExists — a rerun against a warm container is fine.
                Err(ldap3::LdapError::LdapResult { result }) if result.rc == 68 => {}
                Err(e) => panic!("seed add {dn} failed: {e}"),
            }
        };
    add(
        &mut ldap,
        "ou=people,dc=example,dc=org",
        vec![
            ("objectClass", ["organizationalUnit"].into()),
            ("ou", ["people"].into()),
        ],
    );
    add(
        &mut ldap,
        "ou=groups,dc=example,dc=org",
        vec![
            ("objectClass", ["organizationalUnit"].into()),
            ("ou", ["groups"].into()),
        ],
    );
    add(
        &mut ldap,
        ALICE_DN,
        vec![
            ("objectClass", ["inetOrgPerson"].into()),
            ("uid", ["alice"].into()),
            ("cn", ["Alice Example"].into()),
            ("sn", ["Example"].into()),
            ("userPassword", [ALICE_PW].into()),
            ("seeAlso", ["cn=admins,ou=groups,dc=example,dc=org"].into()),
        ],
    );
    add(
        &mut ldap,
        "cn=admins,ou=groups,dc=example,dc=org",
        vec![
            ("objectClass", ["groupOfNames"].into()),
            ("cn", ["admins"].into()),
            ("member", [ALICE_DN].into()),
        ],
    );

    // Prove the seed landed the way the plugin will read it: alice carries seeAlso=cn=admins,...
    let (entries, _) = ldap
        .search(ALICE_DN, Scope::Base, "(objectClass=*)", vec!["seeAlso"])
        .and_then(|r| r.success())
        .expect("read alice back");
    let e = SearchEntry::construct(entries.into_iter().next().expect("alice present"));
    assert!(
        e.attrs
            .get("seeAlso")
            .is_some_and(|v| v.iter().any(|s| s.starts_with("cn=admins"))),
        "alice must carry the seeAlso group DN the plugin maps to role 'admins'"
    );
    let _ = ldap.unbind();
}
