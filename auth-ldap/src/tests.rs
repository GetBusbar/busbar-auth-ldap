// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Unit tests for the PURE surface of the LDAP module: config parsing, bind-DN templating +
//! injection defense, LDAP filter escaping, the group-DN → role normalization, and the bind logic
//! over a fake directory. The codec and the conversation over a stream have their own files
//! (`tests/codec_tests.rs`, `tests/conversation_tests.rs`); the live BIND is the plugin's e2e.

use crate::groups::{escape_filter, first_cn, roles_from_group_dns, validate_username};
use crate::{
    principal_id, BindError, DirEntry, Io, LdapBackend, LdapConfig, LdapModule, Login, RoleFrom,
    SearchScope,
};
use busbar_contract::abi::sdk::cred::{Cred, SealedWrite};
use std::collections::HashMap;

impl LdapModule {
    /// The module from a settings blob with no lent secret.
    pub(crate) fn from_settings(settings: &[u8]) -> Result<Self, String> {
        Self::from_settings_with(settings, &[])
    }

    /// The bind logic over a fake directory (whose `connect` is the trait's no-op).
    pub(crate) fn bind_and_identify_on<B: LdapBackend>(
        &self,
        ldap: &mut B,
        username: &str,
        password: &str,
    ) -> Result<busbar_contract::auth::Principal, BindError> {
        self.bind_and_identify(ldap, username, &cred(password))
    }

    /// [`LdapModule::login_over`] with the submitted password as text, held as the door holds it.
    pub(crate) fn login_text<W: crate::conversation::Wire>(
        &self,
        conv: &mut crate::conversation::Conversation,
        wire: &mut W,
        username: Option<&str>,
        password: Option<&str>,
        now_ns: Option<u64>,
    ) -> std::task::Poll<Login> {
        let password = password.map(cred);
        self.login_over(conv, wire, username, password.as_ref(), now_ns)
    }
}

/// A credential holding `text`, as the door holds a submitted password.
pub(crate) fn cred(text: &str) -> Cred {
    busbar_contract::abi::sdk::test_support::chip::cred(text)
}

/// The text a credential carries, read back off the chip's BIND message as the wire takes it.
pub(crate) fn cred_text(c: &Cred) -> String {
    let mut w = SealedWrite::message(c.ldap_simple_bind(1, ""));
    let mut bytes = Vec::new();
    let sent: std::task::Poll<Result<(), ()>> =
        busbar_contract::abi::sdk::test_support::chip::drive_sealed(&mut w, |b| {
            bytes.extend_from_slice(b);
            std::task::Poll::Ready(Ok(b.len()))
        });
    assert!(sent.is_ready(), "the BIND is written whole");
    // `... 04 00 80 <len> <password>`: the empty DN, then the simple credential, last.
    let at = bytes
        .windows(3)
        .position(|w| w == [0x04, 0x00, 0x80])
        .expect("a simple BIND")
        + 3;
    let (len, from) = match bytes[at] {
        n if n < 0x80 => (usize::from(n), at + 1),
        0x81 => (usize::from(bytes[at + 1]), at + 2),
        _ => (
            usize::from(bytes[at + 1]) << 8 | usize::from(bytes[at + 2]),
            at + 3,
        ),
    };
    String::from_utf8(bytes[from..from + len].to_vec()).expect("a test password is text")
}

fn base_cfg() -> LdapConfig {
    serde_json::from_value(serde_json::json!({
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},ou=people,dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example"
    }))
    .expect("valid config parses")
}

#[test]
fn config_defaults_apply() {
    let cfg = base_cfg();
    assert_eq!(cfg.group_attr, "memberOf");
    assert_eq!(cfg.role_from, RoleFrom::Cn);
    assert_eq!(cfg.timeout_secs, 10);
    assert!(!cfg.start_tls);
}

#[test]
fn config_rejects_unknown_field() {
    // deny_unknown_fields: a typo'd knob fails config parse, not silently ignored.
    let r: Result<LdapConfig, _> = serde_json::from_value(serde_json::json!({
        "url": "ldaps://x", "bind_dn_template": "uid={username},dc=x", "base_dn": "dc=x",
        "grp_attr": "memberOf"
    }));
    assert!(r.is_err(), "unknown field must be rejected");
}

#[test]
fn new_requires_username_placeholder() {
    let mut cfg = base_cfg();
    cfg.bind_dn_template = "uid=fixed,dc=corp,dc=example".to_string();
    assert!(LdapModule::new(cfg).is_err());
}

/// Direct bind: the expanded template is the Base DN of the group read, so a template that can
/// never expand to a DN (an AD UPN, no `=`) would bind every user and then fail every group read.
/// `new()` refuses it at boot; search-then-bind (where the DN comes from the search) still accepts it.
#[test]
fn new_refuses_a_direct_bind_template_that_is_not_a_dn() {
    let mut cfg = base_cfg();
    cfg.bind_dn_template = "{username}@corp.example".to_string();
    assert!(
        LdapModule::new(cfg).is_err(),
        "a direct-bind template with no `=` can never name the entry the groups are read from"
    );

    let mut cfg = search_cfg();
    cfg.bind_dn_template = "{username}@corp.example".to_string();
    assert!(
        LdapModule::new(cfg).is_ok(),
        "search-then-bind takes the DN from the search, so the template is not read as a DN"
    );
}

/// `timeout_secs: 0` expires every connect and operation at once; `new()` refuses it at boot.
#[test]
fn new_refuses_a_zero_timeout() {
    let mut cfg = base_cfg();
    cfg.timeout_secs = 0;
    assert!(LdapModule::new(cfg).is_err());
}

/// A blank `group_attr` reads back no groups, so every login would bind no roles; refused at boot.
#[test]
fn new_refuses_an_empty_group_attr() {
    for attr in ["", "  "] {
        let mut cfg = base_cfg();
        cfg.group_attr = attr.to_string();
        assert!(LdapModule::new(cfg).is_err(), "group_attr {attr:?}");
    }
}

/// An empty `base_dn` is a working search base on some directories (the AD Global Catalog on
/// 3268/3269 and OpenLDAP with `olcDefaultSearchBase` serve a subtree search from base ""), so
/// `new()` accepts it in both modes, as 1.5.5 did.
#[test]
fn new_accepts_an_empty_base_dn() {
    let mut cfg = search_cfg();
    cfg.base_dn = String::new();
    assert!(LdapModule::new(cfg).is_ok(), "search-then-bind");
    let mut cfg = base_cfg();
    cfg.base_dn = String::new();
    assert!(LdapModule::new(cfg).is_ok(), "direct bind");
}

#[test]
fn search_then_bind_requires_service_dn() {
    let mut cfg = base_cfg();
    cfg.user_search_filter = Some("(sAMAccountName={username})".to_string());
    // bind_service_dn missing → error
    assert!(LdapModule::new(cfg).is_err());
}

/// A `user_search_filter` without the `{username}` placeholder would look up the same entry for
/// every login; `new()` refuses it.
#[test]
fn new_requires_search_filter_placeholder() {
    let mut cfg = search_cfg();
    cfg.user_search_filter = Some("(objectClass=person)".to_string());
    assert!(LdapModule::new(cfg).is_err());
}

/// M3: a `user_search_filter` that does not parse would fail every login as an outage; it is
/// refused at `validate` and `open`, by name (never quoting the template), and so is one nested
/// past the parser's depth bound.
#[test]
fn an_unparseable_search_filter_is_refused_by_name() {
    for bad in [
        "(sAMAccountName={username}".to_string(),
        "sAMAccountName={username})".to_string(),
        "((uid={username}))".to_string(),
        format!("{}(uid={{username}}){}", "(!".repeat(40), ")".repeat(40)),
    ] {
        let mut cfg = search_cfg();
        cfg.user_search_filter = Some(bad.clone());
        let Err(e) = LdapModule::new(cfg) else {
            panic!("{bad:?} is refused at open");
        };
        assert!(e.contains("settings.user_search_filter: "), "{e}");
        assert!(!e.contains("username}"), "the template is not quoted: {e}");
        let blob = serde_json::json!({
            "url": "ldaps://ad.corp.example:636",
            "bind_dn_template": "uid={username},dc=corp,dc=example",
            "base_dn": "dc=corp,dc=example",
            "user_search_filter": bad,
            "bind_service_dn": "cn=svc,dc=corp,dc=example",
        })
        .to_string();
        let e = LdapModule::validate_settings(blob.as_bytes()).expect_err("refused at validate");
        assert!(e.contains("settings.user_search_filter: "), "{e}");
    }
}

/// With a search filter set, a service DN but NO password would make `simple_bind(dn,
/// "")` an UNAUTHENTICATED bind. `new()` must require the password too.
#[test]
fn search_then_bind_requires_service_password() {
    let mut cfg = base_cfg();
    cfg.user_search_filter = Some("(sAMAccountName={username})".to_string());
    cfg.bind_service_dn = Some("cn=svc,dc=corp,dc=example".to_string());
    // bind_service_password absent → unauthenticated-bind guard fires
    assert!(
        LdapModule::new(cfg).is_err(),
        "search-then-bind without a service password must be rejected"
    );
}

/// A service DN with an EMPTY-STRING password still yields `simple_bind(dn, "")`, which is an
/// unauthenticated bind. Checking `is_none()` alone is not enough: `new()` must also reject a
/// present-but-empty service password.
#[test]
fn search_then_bind_rejects_empty_service_password() {
    let mut cfg = base_cfg();
    cfg.user_search_filter = Some("(sAMAccountName={username})".to_string());
    cfg.bind_service_dn = Some("cn=svc,dc=corp,dc=example".to_string());
    cfg.bind_service_password = Some(serde_json::from_value(serde_json::json!("")).unwrap());
    assert!(
        LdapModule::new(cfg).is_err(),
        "an empty-string service password is an unauthenticated bind and must be rejected"
    );
}

/// A plaintext `ldap://` URL to a NON-loopback host with no STARTTLS sends the
/// service and end-user credentials in cleartext. `new()` must reject it by default...
#[test]
fn insecure_ldap_nonloopback_rejected() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://ad.corp.example:389".to_string();
    assert!(
        LdapModule::new(cfg).is_err(),
        "plaintext ldap:// to a non-loopback host must be rejected by default"
    );
}

/// ...unless the operator explicitly opts out with `allow_insecure_transport`.
#[test]
fn insecure_ldap_allowed_with_optout() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://ad.corp.example:389".to_string();
    cfg.allow_insecure_transport = true;
    assert!(
        LdapModule::new(cfg).is_ok(),
        "the explicit allow_insecure_transport opt-out must be honored"
    );
}

/// STARTTLS over `ldap://` is encrypted, so the plaintext guard must not fire.
#[test]
fn ldap_with_starttls_allowed() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://ad.corp.example:389".to_string();
    cfg.start_tls = true;
    assert!(LdapModule::new(cfg).is_ok(), "STARTTLS must not be blocked");
}

/// Implicit LDAPS is encrypted — never blocked.
#[test]
fn ldaps_is_allowed() {
    let mut cfg = base_cfg();
    cfg.url = "ldaps://ad.corp.example:636".to_string();
    assert!(LdapModule::new(cfg).is_ok(), "ldaps:// must not be blocked");
}

/// A loopback host stays on the box — plaintext to it is not exposed on the network.
#[test]
fn loopback_ldap_allowed() {
    for host in ["127.0.0.1", "localhost", "[::1]"] {
        let mut cfg = base_cfg();
        cfg.url = format!("ldap://{host}:389");
        assert!(
            LdapModule::new(cfg).is_ok(),
            "plaintext ldap:// to loopback host {host} must be allowed"
        );
    }
}

/// A userinfo component must not let a loopback-looking prefix bypass the plaintext guard.
/// `ldap://127.0.0.1:389@evil.com` dials `evil.com` in cleartext (the userinfo is `127.0.0.1:389`),
/// so the host is `evil.com` and the config must be REJECTED — not read as loopback.
#[test]
fn userinfo_loopback_prefix_is_treated_as_remote() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://127.0.0.1:389@evil.com".to_string();
    assert!(
        LdapModule::new(cfg).is_err(),
        "a loopback-looking userinfo prefix must not bypass the plaintext-transport guard"
    );
}

/// The guard must end the authority where the dialer does ('/', '?' or '#'): otherwise
/// `ldap://evil.example?x@127.0.0.1` reads as loopback while the dial lands on `evil.example`.
#[test]
fn query_or_fragment_cannot_hide_a_remote_host_behind_a_loopback_userinfo() {
    for url in [
        "ldap://evil.example?x@127.0.0.1",
        "ldap://evil.example#@localhost",
        "ldap://evil.example/p?x@127.0.0.1",
        "ldap://evil.example:389?@[::1]",
    ] {
        assert!(crate::is_insecure_transport(url, false), "{url}");
        let mut cfg = base_cfg();
        cfg.url = url.to_string();
        assert!(
            LdapModule::new(cfg).is_err(),
            "{url} must be refused without allow_insecure_transport"
        );
    }
}

/// The guard's host is the host the dialer dials, for every URL shape.
#[test]
fn the_guards_host_is_the_dialers_host() {
    for url in [
        "ldap://evil.example?x@127.0.0.1",
        "ldap://evil.example#@localhost",
        "ldap://127.0.0.1:389@evil.com",
        "ldap://user:pw@dir.example:1389/dc=x?sub",
        "ldap://[::1]:389/",
        "ldap://[::1]?a@b",
        "ldaps://ad.corp.example",
        "ldap://localhost/",
        "ldap://a@b@c.example#f",
    ] {
        let dialed = crate::conversation::Endpoint::parse(url, false)
            .unwrap_or_else(|e| panic!("{url}: {e}"))
            .host;
        assert_eq!(crate::host_of(url), dialed, "{url}");
    }
}

/// The `ldaps://` scheme check must not panic on a URL whose multi-byte UTF-8 char straddles
/// byte index 8 (a byte-boundary slice would panic; a plugin must never crash the host on any config).
#[test]
fn insecure_transport_check_does_not_panic_on_multibyte_url() {
    let mut cfg = base_cfg();
    cfg.url = "ldap://é.example:389".to_string(); // 'é' (2 bytes) straddles index 7-8
                                                  // Must return a Result (reject as insecure), never panic.
    assert!(
        LdapModule::new(cfg).is_err(),
        "a plaintext ldap:// to a non-loopback multibyte host must reject without panicking"
    );
}

/// `ca_cert_pem` must hold a certificate: a fragment is refused at boot, never accepted and ignored.
#[test]
fn new_rejects_a_ca_cert_pem_with_no_certificate() {
    let mut cfg = base_cfg();
    cfg.ca_cert_pem = Some("-----BEGIN CERTIFICATE-----\n...".to_string());
    assert!(
        LdapModule::new(cfg).is_err(),
        "a ca_cert_pem holding no certificate must be rejected, not silently ignored"
    );
}

/// The service-account password must never appear in a `Debug` dump of the config: `LdapConfig`
/// derives `Debug`, so the field has to carry its own redaction.
#[test]
fn service_password_redacted_in_debug() {
    let cfg: LdapConfig = serde_json::from_value(serde_json::json!({
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(sAMAccountName={username})",
        "bind_service_dn": "cn=svc,dc=corp,dc=example",
        "bind_service_password": "super-secret-pw"
    }))
    .expect("config with a service password deserializes");
    let dbg = format!("{cfg:?}");
    assert!(
        !dbg.contains("super-secret-pw"),
        "service password must not leak in Debug: {dbg}"
    );
    assert!(dbg.contains("[REDACTED]"), "expected a redaction marker");
}

#[test]
fn bind_dn_templating_substitutes_username() {
    let m = LdapModule::new(base_cfg()).unwrap();
    assert_eq!(
        m.bind_dn_for("alice").unwrap(),
        "uid=alice,ou=people,dc=corp,dc=example"
    );
}

#[test]
fn bind_dn_rejects_injection_username() {
    let m = LdapModule::new(base_cfg()).unwrap();
    // A username trying to break out of its RDN must be rejected, not templated in.
    for bad in [
        "alice,dc=corp,dc=example",
        "a=b",
        "x\\,y",
        "semi;colon",
        "with\0nul",
        "plus+sign",
        "quo\"te",
        "less<than",
        "greater>than",
    ] {
        assert!(
            m.bind_dn_for(bad).is_err(),
            "username {bad:?} should be rejected"
        );
    }
}

/// RFC 4514 §2.4 must-escape positions: a leading or trailing space and a leading '#'. A lenient
/// directory binds `alice` for `alice `, so accepting them would mint a second principal id for
/// one directory entry.
#[test]
fn bind_dn_rejects_rfc4514_must_escape_positions() {
    let m = LdapModule::new(base_cfg()).unwrap();
    for bad in [" alice", "alice ", "#61", " "] {
        assert!(
            m.bind_dn_for(bad).is_err(),
            "username {bad:?} should be rejected"
        );
    }
    // Inside the value these are ordinary characters.
    for ok in ["alice smith", "a#b"] {
        assert!(
            m.bind_dn_for(ok).is_ok(),
            "username {ok:?} should be allowed"
        );
    }
}

/// T2: a LONE backslash (trailing, or the whole username) is refused too: templated into a DN it
/// would escape the template's next character (`uid=a\,ou=...` reads as one RDN value).
#[test]
fn a_lone_backslash_username_is_refused() {
    for bad in ["\\", "alice\\", "\\alice", "a\\b"] {
        assert!(validate_username(bad).is_err(), "{bad:?} is refused");
    }
    let m = LdapModule::new(base_cfg()).unwrap();
    assert!(m.bind_dn_for("alice\\").is_err());
}

/// T1: a BIND password goes out only where it is safe. For an `ldaps://` URL or `start_tls` it is
/// SECURE-REQUIRED (the chip refuses to write it on a stream the host connector does not report
/// secured), the service password and the user's alike; a plain `ldap://` URL to a non-loopback
/// host with no STARTTLS never reaches a bind at all (refused at `validate` and boot) unless the
/// operator opts out, and only then does the password go out unsecured.
#[test]
fn bind_passwords_are_secure_required_and_plaintext_never_binds() {
    let pw = cred("pw");
    let ldaps = LdapModule::new(search_cfg()).unwrap();
    assert!(ldaps.guarded(&pw).secure_required(), "ldaps://");
    let svc = ldaps.cfg.bind_service_password.as_ref().expect("set");
    assert!(ldaps.guarded(svc).secure_required(), "the service password");

    let mut cfg = base_cfg();
    cfg.url = "ldap://ad.corp.example:389".to_string();
    cfg.start_tls = true;
    assert!(
        LdapModule::new(cfg).unwrap().guarded(&pw).secure_required(),
        "start_tls"
    );

    let mut plain = base_cfg();
    plain.url = "ldap://ad.corp.example:389".to_string();
    let e = LdapModule::new(plain.clone())
        .err()
        .expect("plaintext to a remote host never opens");
    assert!(e.starts_with("settings.url: "), "{e}");
    let blob = serde_json::json!({
        "url": plain.url,
        "bind_dn_template": plain.bind_dn_template,
        "base_dn": plain.base_dn,
    })
    .to_string();
    assert!(LdapModule::validate_settings(blob.as_bytes()).is_err());

    plain.allow_insecure_transport = true;
    let opted = LdapModule::new(plain).unwrap();
    assert!(
        !opted.guarded(&pw).secure_required(),
        "only the explicit opt-out sends it unsecured"
    );
}

#[test]
fn username_validation_allows_normal_names() {
    for ok in ["alice", "alice.smith", "a_b-c", "user@corp.example"] {
        assert!(validate_username(ok).is_ok(), "{ok} should be allowed");
    }
    // '@' allowed (AD UPN), but DN specials are not.
    assert!(validate_username("bad,name").is_err());
}

#[test]
fn filter_escaping_neutralizes_metachars() {
    assert_eq!(escape_filter("a*b"), "a\\2ab");
    assert_eq!(escape_filter("a(b)c"), "a\\28b\\29c");
    assert_eq!(escape_filter("a\\b"), "a\\5cb");
    assert_eq!(escape_filter("plain"), "plain");
}

#[test]
fn first_cn_extracts_leading_cn() {
    assert_eq!(
        first_cn("CN=engineers,OU=Groups,DC=corp,DC=example").as_deref(),
        Some("engineers")
    );
    // case-insensitive attribute name
    assert_eq!(first_cn("cn=sre,dc=x").as_deref(), Some("sre"));
    // escaped comma inside the CN value is preserved as a literal comma
    assert_eq!(
        first_cn("CN=Smith\\, Alice,OU=People,DC=x").as_deref(),
        Some("Smith, Alice")
    );
    assert_eq!(first_cn("OU=nope,DC=x"), None);
}

/// `\XX` hex-pair DN escapes (RFC 4514) must be resolved, not left literal. Consecutive
/// hex bytes decode together as UTF-8.
#[test]
fn first_cn_unescapes_hex_pairs() {
    // `\41` → 'A'
    assert_eq!(first_cn("CN=\\41,DC=x").as_deref(), Some("A"));
    // a multi-byte char encoded as two hex escapes: `\C3\A9` → 'é'
    assert_eq!(first_cn("CN=caf\\C3\\A9,DC=x").as_deref(), Some("café"));
    // single-char escapes still work alongside hex ones
    assert_eq!(
        first_cn("CN=A\\,\\42,DC=x").as_deref(),
        Some("A,B") // `\,` → ',', `\42` → 'B'
    );
}

#[test]
fn roles_cn_mode_maps_and_dedups() {
    let dns = vec![
        "CN=engineers,OU=Groups,DC=corp,DC=example".to_string(),
        "CN=sre,OU=Groups,DC=corp,DC=example".to_string(),
        // Same CN under a different OU path: dedups after CN extraction.
        "CN=engineers,OU=Other,DC=corp,DC=example".to_string(),
    ];
    let roles = roles_from_group_dns(&dns, RoleFrom::Cn);
    assert_eq!(roles, vec!["engineers".to_string(), "sre".to_string()]);
}

/// The default `cn` mode keeps the directory's case, exactly as v1.0.3 (busbar 1.5.5) did. A 1.5.5
/// config keys `role_bindings` by that spelling (`Engineers:` for `CN=Engineers`); folding the case
/// would make every such key miss after an upgrade, and the user would silently hold no role.
#[test]
fn roles_cn_mode_keeps_the_directorys_case() {
    let dns = vec![
        "CN=Engineers,OU=Groups,DC=corp,DC=example".to_string(),
        "CN=SRE,OU=Groups,DC=corp,DC=example".to_string(),
        "cn=Platform-Eng,ou=groups,dc=corp,dc=example".to_string(),
        // No CN RDN: the trimmed value, case kept.
        " OU=Ops,DC=corp,DC=example ".to_string(),
    ];
    let roles = roles_from_group_dns(&dns, RoleFrom::Cn);
    assert_eq!(
        roles,
        vec![
            "Engineers".to_string(),
            "SRE".to_string(),
            "Platform-Eng".to_string(),
            "OU=Ops,DC=corp,DC=example".to_string(),
        ],
        "a CN maps to a role in the directory's own case, as in busbar 1.5.5"
    );
}

#[test]
fn roles_dn_mode_lowercases_full_dn() {
    let dns = vec!["CN=Engineers,OU=Groups,DC=Corp,DC=Example".to_string()];
    let roles = roles_from_group_dns(&dns, RoleFrom::Dn);
    assert_eq!(roles, vec!["cn=engineers,ou=groups,dc=corp,dc=example"]);
}

#[test]
fn roles_empty_when_no_groups() {
    assert!(roles_from_group_dns(&[], RoleFrom::Cn).is_empty());
}

// ── The credential flow ─────────────────────────────────────────────────────────────────────────

/// A wire the test never expects to be touched.
struct Untouched;

impl crate::conversation::Wire for Untouched {
    fn establish(&mut self, _: &str) -> std::task::Poll<Result<(), String>> {
        panic!("a refused credential never reaches the wire")
    }
    fn secure(&mut self) -> std::task::Poll<Result<(), String>> {
        panic!("a refused credential never reaches the wire")
    }
    fn write(&mut self, _: &[u8]) -> std::task::Poll<Result<usize, String>> {
        panic!("a refused credential never reaches the wire")
    }
    fn read(&mut self, _: &mut [u8]) -> std::task::Poll<Result<usize, String>> {
        panic!("a refused credential never reaches the wire")
    }
    fn write_sealed(&mut self, _: &mut SealedWrite) -> std::task::Poll<Result<(), String>> {
        panic!("a refused credential never reaches the wire")
    }
}

/// `login_over` refuses absent credentials and an empty (anonymous-bind) password without ever
/// reaching the wire. The happy path (real bind -> Identity) is the conversation's tests and e2e.
#[test]
fn login_refuses_missing_or_empty_credentials() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let login = |u: Option<&str>, p: Option<&str>| {
        let mut conv = crate::conversation::Conversation::new();
        m.login_text(&mut conv, &mut Untouched, u, p, None)
    };
    use std::task::Poll::Ready;
    assert_eq!(login(None, None), Ready(Login::BadCredential));
    assert_eq!(login(Some("alice"), None), Ready(Login::BadCredential));
    assert_eq!(login(Some("alice"), Some("")), Ready(Login::BadCredential));
}

/// LDAP is a `Credential` method: it has no confidential-client `client_secret`. The config type has
/// no such field, and `deny_unknown_fields` rejects one if an operator configures it — the
/// structural "client_secret must be absent" guarantee for a Credential method.
#[test]
fn config_rejects_client_secret() {
    let r: Result<LdapConfig, _> = serde_json::from_value(serde_json::json!({
        "url": "ldaps://x",
        "bind_dn_template": "uid={username},dc=x",
        "base_dn": "dc=x",
        "client_secret": "should-not-exist-for-ldap"
    }));
    assert!(
        r.is_err(),
        "a Credential method must have no client_secret slot"
    );
}

// ── Fake-backend coverage of the bind path ───────────────────────────────────────────────────────

/// A scriptable in-memory [`LdapBackend`] standing in for a live directory, so the post-connect bind
/// logic — result-code handling, ambiguity, group cap, roles, principal id — is unit-testable.
#[derive(Default)]
struct FakeLdap {
    /// A bind whose password equals this string returns `reject_rc` (49, invalidCredentials, when
    /// unset); all others 0.
    reject_password: Option<String>,
    /// The result code a `reject_password` bind returns; `None` means 49.
    reject_rc: Option<u32>,
    /// Entries returned by the Subtree (search-then-bind user lookup) search.
    search_entries: Vec<DirEntry>,
    /// Group values returned on the Base (group read) search.
    group_values: Vec<String>,
    /// The attribute name under which `group_values` are returned.
    group_attr: String,
    /// Every bind DN attempted, in order.
    binds: Vec<String>,
    /// Every search filter the module actually sent, in order, so the RFC 4515 escaping is tested
    /// AS APPLIED (`the_user_search_filter_is_escaped_as_applied_not_just_in_isolation`).
    filters: Vec<String>,
    /// Every bind attempted as `(dn, password)`, in order.
    ///
    /// The DN alone is not enough to catch the sharpest failure this module could have: on the
    /// search-then-bind path, binding the USER's DN with the SERVICE account's password would
    /// authenticate anyone who merely exists in the directory, and a fake that records only DNs
    /// cannot tell that apart from a correct bind. See
    /// `search_then_bind_authenticates_with_the_submitted_password`.
    bind_pairs: Vec<(String, String)>,
    /// Every search issued, in order, as `(base, scope, attrs)` with scope `"base"` or `"subtree"`,
    /// so a test can assert WHICH entry the group read targets and WHICH attribute it asks for.
    searches: Vec<(String, &'static str, Vec<String>)>,
    /// Set once `unbind` is called.
    unbound: bool,
    /// Inject a TRANSPORT failure (`Err`) from `simple_bind` when the bind DN equals this — models a
    /// connect/TLS/timeout error, distinct from a non-zero result code. Lets each service-bind and
    /// user-bind Directory→Reject branch be exercised independently.
    bind_err_on: Option<String>,
    /// Inject a TRANSPORT failure (`Err`) from the Subtree (search-then-bind user lookup) search.
    subtree_err: bool,
    /// Inject a TRANSPORT failure (`Err`) from the Base (group read) search.
    base_err: bool,
    /// The Base (group read) search answers no entry at all (an ACL hiding the bound user's own
    /// entry).
    base_empty: bool,
    /// The DN the Base (group read) search answers its entry under, as the directory spells it;
    /// unset, the DN the user bound as.
    entry_dn: Option<String>,
}

impl LdapBackend for FakeLdap {
    fn simple_bind(&mut self, dn: &str, password: &Cred) -> Result<u32, Io> {
        let password = cred_text(password);
        let password = password.as_str();
        self.binds.push(dn.to_string());
        self.bind_pairs.push((dn.to_string(), password.to_string()));
        if self.bind_err_on.as_deref() == Some(dn) {
            return Err(format!("transport failure binding {dn}").into());
        }
        let rc = if self.reject_password.as_deref() == Some(password) {
            self.reject_rc.unwrap_or(49)
        } else {
            0
        };
        Ok(rc)
    }

    fn search(
        &mut self,
        base: &str,
        scope: SearchScope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<DirEntry>, Io> {
        let label = match scope {
            SearchScope::Base => "base",
            SearchScope::Subtree => "subtree",
        };
        self.searches.push((
            base.to_string(),
            label,
            attrs.iter().map(|a| a.to_string()).collect(),
        ));
        match scope {
            // search-then-bind user lookup
            SearchScope::Subtree => {
                self.filters.push(filter.to_string());
                if self.subtree_err {
                    return Err("transport failure on user search".to_string().into());
                }
                Ok(self.search_entries.clone())
            }
            // group read off the bound user entry
            SearchScope::Base => {
                if self.base_err {
                    return Err("transport failure on group read".to_string().into());
                }
                if self.base_empty {
                    return Ok(Vec::new());
                }
                let mut attrs = HashMap::new();
                if !self.group_values.is_empty() {
                    attrs.insert(self.group_attr.clone(), self.group_values.clone());
                }
                Ok(vec![DirEntry {
                    dn: self
                        .entry_dn
                        .clone()
                        .or_else(|| self.binds.last().cloned())
                        .unwrap_or_default(),
                    attrs,
                }])
            }
        }
    }

    fn unbind(&mut self) -> Result<(), Io> {
        self.unbound = true;
        Ok(())
    }
}

fn search_cfg() -> LdapConfig {
    serde_json::from_value(serde_json::json!({
        "url": "ldaps://ad.corp.example:636",
        "bind_dn_template": "uid={username},dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "user_search_filter": "(sAMAccountName={username})",
        "bind_service_dn": "cn=svc,dc=corp,dc=example",
        "bind_service_password": "svc-secret"
    }))
    .expect("valid search-then-bind config parses")
}

/// A wrong password → non-zero bind rc → `InvalidCredentials`.
#[test]
fn bind_wrong_password_is_invalid_credentials() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let mut fake = FakeLdap {
        reject_password: Some("wrongpw".to_string()),
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "wrongpw");
    assert!(matches!(r, Err(BindError::InvalidCredentials)));
}

/// OWNER RULING (non-49 user bind): a user-bind result code is an OUTAGE only when it names a
/// server or session condition that fails for every user (51 busy, 52 unavailable, ...: the logged
/// `Directory` arm, carrying no credential). Every other non-zero code (48, 53, 32, ... and a code
/// RFC 4511 does not name) is a refusal of THIS bind: `Rejected` with its code, which `login_over`
/// answers as a bad credential. This test asserted the old ruling (every non-49 code a `Directory`
/// failure); 51 and 52 still assert the outage.
#[test]
fn a_non_49_user_bind_rc_is_an_outage_only_for_a_server_condition() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let bind = |rc: u32| {
        let mut fake = FakeLdap {
            reject_password: Some("pw-secret".to_string()),
            reject_rc: Some(rc),
            group_attr: "memberOf".to_string(),
            ..Default::default()
        };
        m.bind_and_identify_on(&mut fake, "alice", "pw-secret")
    };
    for rc in [51, 52] {
        match bind(rc) {
            Err(BindError::Directory(e)) => {
                assert!(e.contains(&format!("rc={rc}")), "got {e:?}");
                assert!(!e.contains("pw-secret"), "the password leaked: {e:?}");
            }
            r => panic!("rc {rc} should be a Directory failure, got {r:?}"),
        }
    }
    for rc in [48, 50, 53, 32, 19, 34, 999] {
        match bind(rc) {
            Err(BindError::Rejected { rc: got }) => assert_eq!(got, rc),
            r => panic!("rc {rc} should be a Rejected bind, got {r:?}"),
        }
    }
}

/// The outage set is an explicit list of server/session conditions; anything else is not one.
#[test]
fn the_outage_codes_are_the_server_conditions() {
    for rc in [1, 2, 3, 7, 8, 10, 11, 12, 13, 14, 51, 52, 54, 71, 80] {
        assert!(crate::is_outage(rc), "rc {rc} is a server condition");
    }
    for rc in [
        0,
        4,
        5,
        6,
        16,
        19,
        32,
        34,
        48,
        49,
        50,
        53,
        64,
        68,
        88,
        122,
        999,
        u32::MAX,
    ] {
        assert!(!crate::is_outage(rc), "rc {rc} is not an outage");
    }
}

/// A search that matches nothing → `InvalidCredentials`, without ever
/// attempting the user bind.
#[test]
fn search_no_match_is_invalid_credentials() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![], // no user found
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "ghost", "pw");
    assert!(matches!(r, Err(BindError::InvalidCredentials)));
}

/// A successful search-then-bind returns `Identify`
/// with the CN-mapped roles and a principal id keyed on the resolved DN, lowercased.
#[test]
fn successful_bind_identifies_with_roles_and_normalized_id() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Alice,OU=People,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        group_values: vec![
            "CN=engineers,OU=Groups,DC=corp,DC=example".to_string(),
            "CN=sre,OU=Groups,DC=corp,DC=example".to_string(),
        ],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let p = m
        .bind_and_identify_on(&mut fake, "Alice", "right-pw")
        .expect("bind should succeed");
    assert_eq!(p.id, "ldap:cn=alice,ou=people,dc=corp,dc=example");
    assert_eq!(p.roles, vec!["engineers".to_string(), "sre".to_string()]);
    assert!(fake.unbound, "connection should be unbound on success");
    // The user lookup runs under base_dn; the group read is a Base read of the resolved user DN
    // (not base_dn), asking for exactly the configured group attribute.
    assert_eq!(
        fake.searches,
        vec![
            (
                "dc=corp,dc=example".to_string(),
                "subtree",
                vec!["dn".to_string()],
            ),
            (
                "CN=Alice,OU=People,DC=corp,DC=example".to_string(),
                "base",
                vec!["memberOf".to_string()],
            ),
        ]
    );
}

/// The group attribute is the CONFIGURED one, both in the request and when reading the entry back:
/// with `group_attr: seeAlso` the values the directory returns under `seeAlso` become the roles.
#[test]
fn a_configured_group_attr_is_requested_and_read() {
    let mut cfg = base_cfg();
    cfg.group_attr = "seeAlso".to_string();
    let m = LdapModule::new(cfg).unwrap();
    let mut fake = FakeLdap {
        group_values: vec!["cn=admins,ou=groups,dc=corp,dc=example".to_string()],
        group_attr: "seeAlso".to_string(),
        ..Default::default()
    };
    let p = m.bind_and_identify_on(&mut fake, "alice", "pw").unwrap();
    assert_eq!(p.roles, vec!["admins".to_string()]);
    assert_eq!(
        fake.searches,
        vec![(
            "uid=alice,ou=people,dc=corp,dc=example".to_string(),
            "base",
            vec!["seeAlso".to_string()],
        )]
    );
}

/// The group attribute is matched case-insensitively (RFC 4512 §2.5): `group_attr: memberof` reads the
/// values a server returns under `memberOf`, instead of silently yielding no roles.
#[test]
fn the_group_attr_is_matched_case_insensitively() {
    let mut cfg = base_cfg();
    cfg.group_attr = "memberof".to_string();
    let m = LdapModule::new(cfg).unwrap();
    let mut fake = FakeLdap {
        group_values: vec!["cn=admins,ou=groups,dc=corp,dc=example".to_string()],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let p = m.bind_and_identify_on(&mut fake, "alice", "pw").unwrap();
    assert_eq!(p.roles, vec!["admins".to_string()]);
}

/// M2: Active Directory answers a multi-valued attribute past its MaxValRange (1500) as a RANGED
/// description, `memberOf;range=0-1499`. The group attribute is matched ignoring options, so the
/// values returned are read (fail-safe: fewer roles than the user holds), and the truncation is
/// logged at warn; a final range (`;range=0-*`) is the whole attribute and is read silently.
#[test]
fn a_ranged_group_attribute_is_read_and_its_truncation_warned() {
    use busbar_test_kit::warn_capture::WarnCapture;
    let m = LdapModule::new(base_cfg()).unwrap();
    let read = |attr: &str| {
        let mut fake = FakeLdap {
            group_values: vec!["CN=engineers,OU=Groups,DC=corp,DC=example".to_string()],
            group_attr: attr.to_string(),
            ..Default::default()
        };
        let cap = WarnCapture::default();
        let p = tracing::subscriber::with_default(cap.clone(), || {
            m.bind_and_identify_on(&mut fake, "alice", "pw")
        })
        .expect("binds");
        (p.roles, cap)
    };
    let (roles, cap) = read("memberOf;range=0-1499");
    assert_eq!(roles, vec!["engineers".to_string()]);
    assert!(cap.contains("range=0-1499"), "{:?}", cap.messages());
    assert!(cap.contains("truncated"), "{:?}", cap.messages());
    let (roles, cap) = read("memberOf;range=0-*");
    assert_eq!(roles, vec!["engineers".to_string()]);
    assert!(!cap.contains("truncated"), "{:?}", cap.messages());
}

/// M5: a user entry that carries no group attribute at all logs in with no roles, and says so at
/// warn (a misnamed `group_attr` is otherwise a silent no-roles login for everyone).
#[test]
fn an_absent_group_attribute_is_warned() {
    use busbar_test_kit::warn_capture::WarnCapture;
    let m = LdapModule::new(base_cfg()).unwrap();
    let mut fake = FakeLdap::default();
    let cap = WarnCapture::default();
    let p = tracing::subscriber::with_default(cap.clone(), || {
        m.bind_and_identify_on(&mut fake, "alice", "pw")
    })
    .expect("binds");
    assert!(p.roles.is_empty());
    assert!(
        cap.contains("group attribute is absent"),
        "{:?}",
        cap.messages()
    );
    assert!(cap.contains("group_attr=memberOf"), "{:?}", cap.messages());
    assert!(
        !cap.contains("alice"),
        "the DN leaked: {:?}",
        cap.messages()
    );
}

/// A search matching >1 entry is AMBIGUOUS and must be rejected, not silently bound to
/// the first match.
#[test]
fn ambiguous_search_is_rejected() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![
            DirEntry {
                dn: "CN=Alice1,DC=corp,DC=example".to_string(),
                attrs: HashMap::new(),
            },
            DirEntry {
                dn: "CN=Alice2,DC=corp,DC=example".to_string(),
                attrs: HashMap::new(),
            },
        ],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(
        matches!(r, Err(BindError::InvalidCredentials)),
        "two matches must be rejected as ambiguous"
    );
}

/// Two username casings resolve to the SAME principal id (direct-template mode).
#[test]
fn username_casing_yields_same_principal_id() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let id_for = |u: &str| {
        let mut fake = FakeLdap {
            group_attr: "memberOf".to_string(),
            ..Default::default()
        };
        m.bind_and_identify_on(&mut fake, u, "pw").unwrap().id
    };
    assert_eq!(id_for("Alice"), id_for("alice"));
    assert_eq!(
        id_for("alice"),
        "ldap:uid=alice,ou=people,dc=corp,dc=example"
    );
    // and the pure helper is stable under casing directly
    assert_eq!(
        principal_id("uid=Alice,DC=X"),
        principal_id("uid=alice,dc=x")
    );
}

/// M1: a direct-bind principal is the bound entry's DN AS THE DIRECTORY RETURNS IT (the group
/// read's objectName), not the typed spelling: `John  Smith` (two spaces) and `John Smith` bind the
/// same entry on a directory that matches insignificant spaces away, so they are one principal.
#[test]
fn the_principal_is_the_dn_the_directory_returns() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let id_for = |u: &str| {
        let mut fake = FakeLdap {
            entry_dn: Some("uid=John Smith,ou=People,dc=corp,dc=example".to_string()),
            ..Default::default()
        };
        m.bind_and_identify_on(&mut fake, u, "pw").unwrap().id
    };
    assert_eq!(
        id_for("John  Smith"),
        "ldap:uid=john smith,ou=people,dc=corp,dc=example"
    );
    assert_eq!(id_for("John  Smith"), id_for("john smith"));
}

/// M1: when the group read answers no entry (an ACL hides it), the principal falls back to the
/// bound DN normalised for case-ignore matching (RFC 4518: case folded, insignificant spaces
/// collapsed), so the typed spacing still mints one principal.
#[test]
fn with_no_entry_the_principal_is_the_bound_dn_normalised() {
    let m = LdapModule::new(base_cfg()).unwrap();
    let id_for = |u: &str| {
        let mut fake = FakeLdap {
            base_empty: true,
            ..Default::default()
        };
        m.bind_and_identify_on(&mut fake, u, "pw").unwrap().id
    };
    assert_eq!(id_for("John  Smith"), id_for("John Smith"));
    assert_eq!(
        id_for("John   Smith"),
        "ldap:uid=john smith,ou=people,dc=corp,dc=example"
    );
    // Search-then-bind normalises the found DN the same way.
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=John  Smith,OU=People,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        base_empty: true,
        ..Default::default()
    };
    let p = m.bind_and_identify_on(&mut fake, "jsmith", "pw").unwrap();
    assert_eq!(p.id, "ldap:cn=john smith,ou=people,dc=corp,dc=example");
}

/// An oversized `memberOf` is capped so a hostile directory cannot exhaust memory.
#[test]
fn group_values_are_capped() {
    let m = LdapModule::new(base_cfg()).unwrap();
    // 5000 DISTINCT group CNs — more than the 4096 cap.
    let vals: Vec<String> = (0..5000)
        .map(|i| format!("CN=g{i},DC=corp,DC=example"))
        .collect();
    let mut fake = FakeLdap {
        group_values: vals,
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let p = m.bind_and_identify_on(&mut fake, "alice", "pw").unwrap();
    assert_eq!(p.roles.len(), 4096, "group values must be capped at 4096");
}

// ── every Directory→Reject branch actually rejects ───────────────────────────────────────────────
// The fake injects transport errors, so each operational-failure branch yields `Directory` (which
// `login` answers as `Outage`), never `Identify`.

/// A transport failure on the SERVICE bind is Directory→Reject.
#[test]
fn service_bind_error_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        bind_err_on: Some("cn=svc,dc=corp,dc=example".to_string()),
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

/// A NON-ZERO service-bind result code (rejected service creds) is Directory→Reject.
#[test]
fn service_bind_nonzero_rc_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        // the service password is "svc-secret"; make that bind return rc 49
        reject_password: Some("svc-secret".to_string()),
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

/// A transport failure on the USER SEARCH is Directory→Reject.
#[test]
fn user_search_error_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        subtree_err: true,
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

/// A transport failure on the USER bind (service bind + search succeed first) is Directory→Reject.
#[test]
fn user_bind_error_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Alice,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        bind_err_on: Some("CN=Alice,DC=corp,DC=example".to_string()),
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

/// A transport failure on the GROUP READ (after a successful user bind) is Directory→Reject.
#[test]
fn group_read_error_rejects() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Alice,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        base_err: true,
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(matches!(r, Err(BindError::Directory(_))), "got {r:?}");
}

// ── the search-then-bind path validates username / resolved DN ───────────────────────────────────

/// An EMPTY username in the search path must be rejected — even when an entry would otherwise match
/// — instead of proceeding to a bind. (Without the guard the matching entry below yields `Identify`.)
#[test]
fn search_path_rejects_empty_username() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Someone,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "", "pw");
    assert!(
        matches!(r, Err(BindError::InvalidCredentials)),
        "empty username in the search path must be rejected, got {r:?}"
    );
}

/// A search that resolves to an EMPTY DN must not be bound (an empty DN + password is an anonymous
/// bind on many directories). (Without the guard this binds `("", "pw")` and yields `Identify`.)
#[test]
fn search_path_rejects_empty_resolved_dn() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: String::new(),
            attrs: HashMap::new(),
        }],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    let r = m.bind_and_identify_on(&mut fake, "alice", "pw");
    assert!(
        matches!(r, Err(BindError::InvalidCredentials)),
        "an empty resolved DN must be rejected before binding, got {r:?}"
    );
}

/// `principal_id` must be Unicode-aware. `to_ascii_lowercase` leaves non-ASCII
/// letters untouched, so two Unicode casings of the same name mint two distinct `ldap:` principals.
/// A Unicode-aware `to_lowercase` collapses them to one canonical id.
#[test]
fn unicode_username_casing_yields_same_principal_id() {
    // 'Ä' vs 'ä': identical under to_lowercase, but to_ascii_lowercase leaves 'Ä' unchanged.
    assert_eq!(principal_id("uid=Ä,dc=x"), principal_id("uid=ä,dc=x"));
    // 'İ'/'i' style non-ASCII casing likewise collapses.
    assert_eq!(
        principal_id("cn=ÉLODIE,dc=x"),
        principal_id("cn=élodie,dc=x")
    );
}

/// On the search-then-bind path, the USER bind must present the SUBMITTED password.
///
/// The service account binds first, to find the user's entry; if the second bind reused the
/// SERVICE password instead of the end user's, every bind would succeed for anyone who merely exists
/// in the directory: a full authentication bypass with a normal-looking principal.
///
/// Asserts the ORDER and the CREDENTIALS of both binds, so neither "the service bind was skipped"
/// nor "the user bind used the wrong secret" can slip through.
#[test]
fn search_then_bind_authenticates_with_the_submitted_password() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Alice,OU=People,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    m.bind_and_identify_on(&mut fake, "Alice", "alices-own-password")
        .expect("bind should succeed");

    assert_eq!(
        fake.bind_pairs.len(),
        2,
        "search-then-bind is exactly two binds: service, then user: {:?}",
        fake.bind_pairs
    );
    let (svc_dn, svc_pw) = &fake.bind_pairs[0];
    let (user_dn, user_pw) = &fake.bind_pairs[1];

    assert_eq!(svc_dn, "cn=svc,dc=corp,dc=example");
    assert_eq!(
        svc_pw, "svc-secret",
        "the FIRST bind is the service account, with the service password"
    );

    assert_eq!(user_dn, "CN=Alice,OU=People,DC=corp,DC=example");
    assert_eq!(
        user_pw, "alices-own-password",
        "the SECOND bind must present the END USER's submitted password — reusing the service \
         password here authenticates anyone who exists in the directory"
    );
    assert_ne!(
        user_pw, svc_pw,
        "the user bind must not reuse the service credential"
    );
}

/// The RFC 4515 escaping must hold AS APPLIED, not merely as a pure function.
///
/// `escape_filter` had its own unit test, but the fake backend discarded the filter argument, so
/// deleting the `escape_filter` call at the call site left every test in this file green. That is
/// LDAP filter injection: a username like `*)(uid=*` would close the intended filter and open a
/// wildcard, turning "find this one user" into "match everything" — and on a directory where the
/// search then returns a single entry, into binding as somebody else entirely.
///
/// The module's own ambiguity guard limits the damage (more than one match is rejected), which is
/// exactly why this needs its own test: the guard would mask the injection rather than reveal it.
#[test]
fn the_user_search_filter_is_escaped_as_applied_not_just_in_isolation() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let mut fake = FakeLdap {
        search_entries: vec![DirEntry {
            dn: "CN=Alice,OU=People,DC=corp,DC=example".to_string(),
            attrs: HashMap::new(),
        }],
        group_attr: "memberOf".to_string(),
        ..Default::default()
    };
    // Every metacharacter RFC 4515 requires escaping, in one username.
    let hostile = r"*)(uid=*))(|(x=\ ";
    let _ = m.bind_and_identify_on(&mut fake, hostile, "pw");

    let sent = fake
        .filters
        .first()
        .expect("the module must have issued a user search");
    assert!(
        !sent.contains("*)(uid=*"),
        "the injection payload reached the directory verbatim -- the filter is not escaped at the \
         call site: {sent}"
    );
    for esc in ["\\2a", "\\28", "\\29", "\\5c"] {
        assert!(
            sent.contains(esc),
            "expected the {esc} escape in the applied filter: {sent}"
        );
    }
}

// ── Credential-echo canaries ────────────────────────────────────────────

const CANARY: &str = "CANARYa6d215";

/// A config whose URL carries a userinfo password.
fn userinfo_cfg(url: &str, allow_insecure: bool) -> LdapConfig {
    serde_json::from_value(serde_json::json!({
        "url": url,
        "bind_dn_template": "uid={username},ou=people,dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
        "allow_insecure_transport": allow_insecure
    }))
    .expect("valid config parses")
}

/// Every message and field logged while `f` runs.
fn logged_text(f: impl FnOnce()) -> String {
    use std::sync::{Arc, Mutex};
    use tracing::field::{Field, Visit};
    use tracing::span::{Attributes, Id, Record};
    use tracing::{Event, Metadata, Subscriber};
    struct Capture(Arc<Mutex<String>>);
    struct Text(String);
    impl Visit for Text {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.push_str(&format!(" {}={value:?}", field.name()));
        }
    }
    impl Subscriber for Capture {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &Event<'_>) {
            let mut t = Text(String::new());
            event.record(&mut t);
            self.0.lock().unwrap().push_str(&format!("{}\n", t.0));
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }
    let text = Arc::new(Mutex::new(String::new()));
    tracing::subscriber::with_default(Capture(Arc::clone(&text)), f);
    let t = text.lock().unwrap().clone();
    t
}

/// A directory that cannot be reached: `connect` fails, nothing else is ever asked.
struct Unreachable;

impl LdapBackend for Unreachable {
    fn connect(&mut self) -> Result<(), Io> {
        Err(Io::Failed("connection refused".to_string()))
    }
    fn simple_bind(&mut self, _: &str, _: &Cred) -> Result<u32, Io> {
        unreachable!("no bind without a connection")
    }
    fn search(
        &mut self,
        _: &str,
        _: SearchScope,
        _: &str,
        _: &[&str],
    ) -> Result<Vec<DirEntry>, Io> {
        unreachable!("no search without a connection")
    }
    fn unbind(&mut self) -> Result<(), Io> {
        Ok(())
    }
}

/// The plaintext-transport refusal never carries the URL's userinfo.
#[test]
fn the_plaintext_refusal_never_quotes_the_url_password() {
    let url = format!("ldap://svc:{CANARY}@ad.corp.example:389");
    let Err(e) = LdapModule::new(userinfo_cfg(&url, false)) else {
        panic!("plaintext is refused");
    };
    assert!(!e.contains(CANARY), "the refusal carried the password: {e}");
    assert!(e.starts_with("settings.url: "), "the key is named: {e}");
}

/// The `allow_insecure_transport` warning never logs the URL's userinfo.
#[test]
fn the_insecure_transport_warning_never_logs_the_url_password() {
    let url = format!("ldap://svc:{CANARY}@ad.corp.example:389");
    let text = logged_text(|| {
        assert!(
            LdapModule::new(userinfo_cfg(&url, true)).is_ok(),
            "opted out"
        );
    });
    assert!(
        text.contains("allow_insecure_transport"),
        "the warning is logged: {text}"
    );
    assert!(
        !text.contains(CANARY),
        "the warning carried the password: {text}"
    );
}

/// A failed connect's logged directory failure never carries the URL's userinfo.
#[test]
fn a_connect_failure_never_carries_the_url_password() {
    let url = format!("ldaps://svc:{CANARY}@ad.corp.example:636");
    let Ok(m) = LdapModule::new(userinfo_cfg(&url, false)) else {
        panic!("ldaps opens");
    };
    match m.bind_and_identify_on(&mut Unreachable, "alice", "pw") {
        Err(BindError::Directory(e)) => {
            assert!(!e.contains(CANARY), "the failure carried the password: {e}");
            assert!(e.starts_with("connect "), "1.5.5's prefix is kept: {e}");
        }
        r => panic!("a failed connect is a directory failure, got {r:?}"),
    }
}

/// A.3: `LdapConfig` derives `Debug`, and printed the URL with its userinfo.
#[test]
fn debug_of_the_config_never_prints_the_url_password() {
    let url = format!("ldaps://svc:{CANARY}@ad.corp.example:636");
    let cfg = userinfo_cfg(&url, false);
    for text in [format!("{cfg:?}"), format!("{cfg:#?}")] {
        assert!(!text.contains(CANARY), "Debug carried the password: {text}");
        assert!(text.contains("ad.corp.example"), "{text}");
    }
}

// ── every refusal is explained; nothing is silent ───────────────────────────────────────────────

mod logging {
    use super::*;
    use busbar_test_kit::warn_capture::WarnCapture;

    /// Run `f` under an INFO-and-above capture: what it answered, and the capture.
    fn captured<T>(f: impl FnOnce() -> T) -> (T, WarnCapture) {
        let cap = WarnCapture::capturing_debug();
        let got = tracing::subscriber::with_default(cap.clone(), f);
        (got, cap)
    }

    fn entry(dn: &str) -> DirEntry {
        DirEntry {
            dn: dn.to_string(),
            attrs: HashMap::new(),
        }
    }

    /// A search that matches nothing is a refused credential, and says so (never the password).
    #[test]
    fn no_search_match_is_logged() {
        let m = LdapModule::new(search_cfg()).unwrap();
        let mut fake = FakeLdap::default();
        let (r, cap) = captured(|| m.bind_and_identify_on(&mut fake, "ghost", "pw-s3cret"));
        assert!(matches!(r, Err(BindError::InvalidCredentials)), "{r:?}");
        assert!(cap.contains("no search match"), "{:?}", cap.messages());
        assert!(cap.contains("module=ldap"), "{:?}", cap.messages());
        assert!(!cap.contains("pw-s3cret"), "{:?}", cap.messages());
        assert!(!cap.contains("ghost"), "{:?}", cap.messages());
    }

    /// LDO D10: the bound user's own entry read back as NO entry (an ACL hides it) is not silent:
    /// the login still answers the identity with no roles, and warns that the groups were unread.
    #[test]
    fn a_group_read_with_no_entry_is_logged_at_warn() {
        let m = LdapModule::new(base_cfg()).unwrap();
        let mut fake = FakeLdap {
            group_attr: "memberOf".to_string(),
            base_empty: true,
            ..Default::default()
        };
        let cap = WarnCapture::default();
        let r = tracing::subscriber::with_default(cap.clone(), || {
            m.bind_and_identify_on(&mut fake, "alice", "pw-s3cret")
        });
        let p = r.expect("the bind identifies");
        assert!(p.roles.is_empty());
        assert!(
            cap.contains("group read returned no entry"),
            "{:?}",
            cap.messages()
        );
        assert!(cap.contains("module=ldap"), "{:?}", cap.messages());
        assert!(
            !cap.contains("alice"),
            "the DN leaked: {:?}",
            cap.messages()
        );
    }

    /// An ambiguous user search is a refusal: logged once at info, nothing at warn.
    #[test]
    fn an_ambiguous_search_is_logged_at_info() {
        let m = LdapModule::new(search_cfg()).unwrap();
        let fake = || FakeLdap {
            search_entries: vec![entry("uid=a,dc=x"), entry("uid=b,dc=x")],
            ..Default::default()
        };
        let (r, cap) = captured(|| m.bind_and_identify_on(&mut fake(), "alice", "pw-s3cret"));
        assert!(matches!(r, Err(BindError::InvalidCredentials)), "{r:?}");
        assert_eq!(cap.count("ambiguous"), 1, "{:?}", cap.messages());
        let warn = WarnCapture::default();
        tracing::subscriber::with_default(warn.clone(), || {
            m.bind_and_identify_on(&mut fake(), "alice", "pw-s3cret")
        })
        .ok();
        assert!(warn.messages().is_empty(), "{:?}", warn.messages());
    }

    /// A search that resolves to an empty DN is refused before any bind, and says so.
    #[test]
    fn an_empty_dn_is_logged() {
        let m = LdapModule::new(search_cfg()).unwrap();
        let mut fake = FakeLdap {
            search_entries: vec![entry("")],
            ..Default::default()
        };
        let (r, cap) = captured(|| m.bind_and_identify_on(&mut fake, "alice", "pw-s3cret"));
        assert!(matches!(r, Err(BindError::InvalidCredentials)), "{r:?}");
        assert!(cap.contains("empty DN"), "{:?}", cap.messages());
        assert!(!cap.contains("pw-s3cret"), "{:?}", cap.messages());
    }

    /// An empty username on the search path, and a username the DN template refuses, are each
    /// explained (and the username itself is not logged).
    #[test]
    fn a_refused_username_is_logged() {
        let m = LdapModule::new(search_cfg()).unwrap();
        let (r, cap) = captured(|| m.bind_and_identify_on(&mut FakeLdap::default(), "", "pw"));
        assert!(matches!(r, Err(BindError::InvalidCredentials)), "{r:?}");
        assert!(cap.contains("empty username"), "{:?}", cap.messages());

        let m = LdapModule::new(base_cfg()).unwrap();
        let (r, cap) =
            captured(|| m.bind_and_identify_on(&mut FakeLdap::default(), "admin,dc=evil", "pw"));
        assert!(matches!(r, Err(BindError::InvalidCredentials)), "{r:?}");
        assert!(
            cap.contains("not allowed in a bind DN"),
            "{:?}",
            cap.messages()
        );
        assert!(!cap.contains("admin,dc=evil"), "{:?}", cap.messages());
    }

    /// A missing field and an empty password are refused before the wire, each explained.
    #[test]
    fn a_missing_or_empty_credential_is_logged() {
        let m = LdapModule::new(base_cfg()).unwrap();
        let login = |u: Option<&str>, p: Option<&str>| {
            let mut conv = crate::conversation::Conversation::new();
            m.login_text(&mut conv, &mut Untouched, u, p, Some(0))
        };
        let (r, cap) = captured(|| login(Some("alice"), None));
        assert_eq!(r, std::task::Poll::Ready(Login::BadCredential));
        assert!(cap.contains("not submitted"), "{:?}", cap.messages());
        let (r, cap) = captured(|| login(Some("alice"), Some("")));
        assert_eq!(r, std::task::Poll::Ready(Login::BadCredential));
        assert!(cap.contains("empty password"), "{:?}", cap.messages());
    }

    /// A wrong password (rc 49) is an end-user decline, explained at info.
    #[test]
    fn a_wrong_password_is_logged() {
        let m = LdapModule::new(base_cfg()).unwrap();
        let mut fake = FakeLdap {
            reject_password: Some("wr0ng-pw".to_string()),
            ..Default::default()
        };
        let (r, cap) = captured(|| m.bind_and_identify_on(&mut fake, "alice", "wr0ng-pw"));
        assert!(matches!(r, Err(BindError::InvalidCredentials)), "{r:?}");
        assert!(cap.contains("invalidCredentials"), "{:?}", cap.messages());
        assert!(!cap.contains("wr0ng-pw"), "{:?}", cap.messages());
    }

    /// No host clock: the login refuses an untimed directory call (an outage, explained at warn)
    /// rather than bind with no deadline; nothing reaches the wire.
    #[test]
    fn no_host_clock_is_an_outage() {
        let m = LdapModule::new(base_cfg()).unwrap();
        let cap = WarnCapture::default();
        let got = tracing::subscriber::with_default(cap.clone(), || {
            let mut conv = crate::conversation::Conversation::new();
            m.login_text(&mut conv, &mut Untouched, Some("alice"), Some("pw"), None)
        });
        assert_eq!(got, std::task::Poll::Ready(Login::Outage));
        assert!(
            cap.contains("no host clock: refusing an untimed directory call"),
            "{:?}",
            cap.messages()
        );
    }
}

/// The service password is the chip's credential, holding exactly the configured text.
#[test]
fn the_service_password_is_held_by_the_chip() {
    let m = LdapModule::new(search_cfg()).unwrap();
    let pw = m.cfg.bind_service_password.as_ref().expect("set");
    assert_eq!(cred_text(pw), "svc-secret");
}
