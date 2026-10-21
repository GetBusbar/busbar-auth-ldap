// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The module's codec against a LIVE OpenLDAP directory (the CI `service: openldap` arm): the
//! library module driven directly over a plaintext test stream, in both directory shapes. The
//! logic crate's only public item is its door, so this runs here, beside the code it drives; the
//! real busbar boot is the plugin crate's `tests/e2e.rs`.

#[path = "live_seed.rs"]
mod live_seed;

use crate::conversation::{Conversation, Wire};
use crate::{LdapConfig, LdapModule, Login};
use live_seed::{live_ldap_url, seed_directory, ADMIN_DN, ADMIN_PW, ALICE_DN, ALICE_PW, BASE_DN};

/// THE TEST'S OWN STREAM to the live directory: a plaintext TCP socket in this test only (the
/// shipped plugin opens none; its stream is the host connector's). Every call answers at once.
struct TestStream(Option<std::net::TcpStream>);

impl Wire for TestStream {
    fn establish(&mut self, target: &str) -> std::task::Poll<Result<(), String>> {
        let s = std::net::TcpStream::connect(target).map_err(|e| e.to_string());
        std::task::Poll::Ready(s.and_then(|s| {
            s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .map_err(|e| e.to_string())?;
            self.0 = Some(s);
            Ok(())
        }))
    }
    fn secure(&mut self) -> std::task::Poll<Result<(), String>> {
        std::task::Poll::Ready(Err("the test stream is plaintext".into()))
    }
    fn write(&mut self, bytes: &[u8]) -> std::task::Poll<Result<usize, String>> {
        use std::io::Write as _;
        let s = self.0.as_mut().expect("established");
        std::task::Poll::Ready(s.write(bytes).map_err(|e| e.to_string()))
    }
    fn read(&mut self, buf: &mut [u8]) -> std::task::Poll<Result<usize, String>> {
        use std::io::Read as _;
        let s = self.0.as_mut().expect("established");
        std::task::Poll::Ready(s.read(buf).map_err(|e| e.to_string()))
    }
}

/// Run one credential login on the library module directly (no busbar boot): the module's codec
/// over the test's own stream.
fn live_login(settings: serde_json::Value, username: &str, password: &str) -> Login {
    let cfg: LdapConfig = serde_json::from_value(settings).expect("live ldap settings parse");
    let module = LdapModule::new(cfg).expect("live ldap settings are valid");
    let mut conv = Conversation::new();
    let mut stream = TestStream(None);
    match module.login_over(&mut conv, &mut stream, Some(username), Some(password), None) {
        std::task::Poll::Ready(login) => login,
        std::task::Poll::Pending => panic!("the test stream never pends"),
    }
}

/// The module's codec against the live directory, in BOTH directory shapes: direct bind and
/// search-then-bind (service bind, Subtree user lookup under base_dn, re-bind as the found DN). Each
/// must Identify alice with the canonical principal id and exactly the role her `seeAlso` group maps
/// to (`admins`), and must Reject a wrong password.
#[test]
fn ldap_module_binds_live_in_both_modes_and_maps_the_group() {
    let Some(url) = live_ldap_url() else {
        return;
    };
    seed_directory(&url);

    let direct = serde_json::json!({
        "url": url,
        "bind_dn_template": "uid={username},ou=people,dc=example,dc=org",
        "base_dn": BASE_DN,
        "group_attr": "seeAlso",
    });
    let search = serde_json::json!({
        "url": url,
        "bind_dn_template": "uid={username},ou=people,dc=example,dc=org",
        "base_dn": BASE_DN,
        "group_attr": "seeAlso",
        "user_search_filter": "(uid={username})",
        "bind_service_dn": ADMIN_DN,
        "bind_service_password": ADMIN_PW,
    });
    for (mode, settings) in [("direct bind", direct), ("search-then-bind", search)] {
        let principal = match live_login(settings.clone(), "alice", ALICE_PW) {
            Login::Identity(p) => p,
            other => panic!("{mode}: alice with her password must Identify, got {other:?}"),
        };
        assert_eq!(principal.id, format!("ldap:{ALICE_DN}"), "{mode}");
        assert_eq!(
            principal.roles,
            vec!["admins".to_string()],
            "{mode}: alice's seeAlso group must map to the role 'admins'"
        );
        assert_eq!(
            live_login(settings, "alice", "wrong-password"),
            Login::BadCredential,
            "{mode}: a wrong password must be rejected"
        );
    }
}
