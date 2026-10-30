// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE LOGIN'S CONVERSATION over a scripted stream that plays the directory: every stream service
//! may pend first, and the login resumes from the same [`Conversation`] until it answers. The
//! bytes that reach the stream are the codec's, each request exactly once (nothing is sent twice
//! across a replay); `ldaps://` secures before the first byte, StartTLS after its extended
//! response; and the signed differences fail closed as an outage.

use std::collections::VecDeque;
use std::task::Poll;

use super::{Conversation, Endpoint, Security, Wire};
use crate::{ber, codec, LdapConfig, LdapModule, Login};
use busbar_contract::abi::sdk::cred::SealedWrite;

/// What the scripted directory saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Establish(String),
    Secure,
}

/// THE DIRECTORY, as a stream: `replies` are handed out in order (one per read, or `chunk` bytes
/// at a time); with `pend` every service answers PENDING once before it answers.
#[derive(Default)]
struct Directory {
    replies: VecDeque<Vec<u8>>,
    written: Vec<u8>,
    seen: Vec<Seen>,
    pend: bool,
    pended: u32,
    owed: bool,
    write_chunk: Option<usize>,
    refuse_establish: Option<String>,
    hold: bool,
    secure_error: Option<String>,
}

impl Directory {
    fn new(replies: Vec<Vec<u8>>) -> Self {
        Self {
            replies: replies.into(),
            ..Self::default()
        }
    }

    /// Once the replies run out the stream stays open and a read pends (no EOF), so only a
    /// fail-closed path can answer.
    fn held(mut self) -> Self {
        self.hold = true;
        self
    }

    fn pending(mut self) -> Self {
        self.pend = true;
        self
    }

    /// PENDING once per service when `pend` is set.
    fn wait(&mut self) -> bool {
        if !self.pend {
            return false;
        }
        self.owed = !self.owed;
        if self.owed {
            self.pended += 1;
        }
        self.owed
    }
}

impl Wire for Directory {
    fn establish(&mut self, target: &str) -> Poll<Result<(), String>> {
        if self.wait() {
            return Poll::Pending;
        }
        self.seen.push(Seen::Establish(target.to_string()));
        match self.refuse_establish.clone() {
            Some(e) => Poll::Ready(Err(e)),
            None => Poll::Ready(Ok(())),
        }
    }

    fn secure(&mut self) -> Poll<Result<(), String>> {
        if self.wait() {
            return Poll::Pending;
        }
        if let Some(e) = self.secure_error.clone() {
            return Poll::Ready(Err(e));
        }
        self.seen.push(Seen::Secure);
        Poll::Ready(Ok(()))
    }

    fn write(&mut self, bytes: &[u8]) -> Poll<Result<usize, String>> {
        if self.wait() {
            return Poll::Pending;
        }
        let n = self.write_chunk.unwrap_or(bytes.len()).min(bytes.len());
        self.written.extend_from_slice(&bytes[..n]);
        Poll::Ready(Ok(n))
    }

    fn write_sealed(&mut self, w: &mut SealedWrite) -> Poll<Result<(), String>> {
        busbar_contract::abi::sdk::test_support::chip::drive_sealed(w, |b| self.write(b))
    }

    fn read(&mut self, buf: &mut [u8]) -> Poll<Result<usize, String>> {
        if self.wait() {
            return Poll::Pending;
        }
        let Some(mut next) = self.replies.pop_front() else {
            if self.hold {
                return Poll::Pending;
            }
            return Poll::Ready(Ok(0));
        };
        let n = next.len().min(buf.len());
        buf[..n].copy_from_slice(&next[..n]);
        if n < next.len() {
            next.drain(..n);
            self.replies.push_front(next);
        }
        Poll::Ready(Ok(n))
    }
}

// ── replies, built with the BER writer ───────────────────────────────────────────────────────────

fn message(id: i64, op: Vec<u8>) -> Vec<u8> {
    let mut content = Vec::new();
    ber::int(&mut content, ber::INTEGER, id);
    content.extend_from_slice(&op);
    ber::element(ber::SEQUENCE, &content)
}

fn result(rc: i64) -> Vec<u8> {
    let mut r = Vec::new();
    ber::int(&mut r, ber::ENUMERATED, rc);
    ber::tlv(&mut r, ber::OCTET_STRING, b"");
    ber::tlv(&mut r, ber::OCTET_STRING, b"");
    r
}

fn bind_response(id: i64, rc: i64) -> Vec<u8> {
    message(id, ber::element(0x61, &result(rc)))
}

fn done(id: i64, rc: i64) -> Vec<u8> {
    message(id, ber::element(0x65, &result(rc)))
}

fn extended(id: i64, rc: i64) -> Vec<u8> {
    message(id, ber::element(0x78, &result(rc)))
}

fn entry(id: i64, dn: &str, attr: &str, values: &[&str]) -> Vec<u8> {
    let mut vals = Vec::new();
    for v in values {
        ber::tlv(&mut vals, ber::OCTET_STRING, v.as_bytes());
    }
    let mut a = Vec::new();
    ber::tlv(&mut a, ber::OCTET_STRING, attr.as_bytes());
    ber::tlv(&mut a, ber::SET, &vals);
    let mut op = Vec::new();
    ber::tlv(&mut op, ber::OCTET_STRING, dn.as_bytes());
    ber::tlv(&mut op, ber::SEQUENCE, &ber::element(ber::SEQUENCE, &a));
    message(id, ber::element(0x64, &op))
}

// ── the module ───────────────────────────────────────────────────────────────────────────────────

const ALICE: &str = "uid=alice,ou=people,dc=corp,dc=example";

fn module(url: &str, extra: serde_json::Value) -> LdapModule {
    let mut cfg = serde_json::json!({
        "url": url,
        "bind_dn_template": "uid={username},ou=people,dc=corp,dc=example",
        "base_dn": "dc=corp,dc=example",
    });
    if let (Some(c), Some(e)) = (cfg.as_object_mut(), extra.as_object()) {
        c.extend(e.clone());
    }
    let cfg: LdapConfig = serde_json::from_value(cfg).expect("config parses");
    LdapModule::new(cfg).expect("config is valid")
}

/// Drive one login to its answer, re-entering on every PENDING with the same conversation: the
/// answer and how many entries it took.
fn login(m: &LdapModule, dir: &mut Directory, password: &str) -> (Login, u32) {
    let mut conv = Conversation::new();
    for entries in 1..=200 {
        if let Poll::Ready(l) = m.login_text(&mut conv, dir, Some("alice"), Some(password), Some(0))
        {
            return (l, entries);
        }
    }
    panic!("the login never answered");
}

fn direct_bytes(group_attr: &str) -> Vec<u8> {
    [
        chip_bind(1, ALICE, "pw").to_vec(),
        codec::search(
            2,
            ALICE,
            codec::SCOPE_BASE,
            "(objectClass=*)",
            &[group_attr],
        )
        .unwrap(),
        codec::unbind(3),
    ]
    .concat()
}

#[test]
fn a_direct_bind_identifies_with_its_groups_over_a_pending_stream() {
    let m = module("ldap://127.0.0.1:3389", serde_json::json!({}));
    let mut dir = Directory::new(vec![
        bind_response(1, 0),
        entry(
            2,
            ALICE,
            "memberOf",
            &["cn=Engineers,ou=g,dc=corp", "cn=SRE,ou=g,dc=corp"],
        ),
        done(2, 0),
    ])
    .pending();
    let (got, entries) = login(&m, &mut dir, "pw");
    let Login::Identity(p) = got else {
        panic!("alice binds: {got:?}");
    };
    assert_eq!(p.id, format!("ldap:{ALICE}"));
    assert_eq!(p.roles, vec!["Engineers".to_string(), "SRE".to_string()]);
    assert!(dir.pended >= 6, "every service pended once: {}", dir.pended);
    assert_eq!(entries, dir.pended + 1);
    // Each request reached the stream exactly once, across every replay.
    assert_eq!(dir.written, direct_bytes("memberOf"));
    assert_eq!(dir.seen, vec![Seen::Establish("127.0.0.1:3389".into())]);
}

#[test]
fn a_request_taken_a_few_bytes_at_a_time_goes_out_whole() {
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let mut dir = Directory::new(vec![bind_response(1, 0), done(2, 0)]).pending();
    dir.write_chunk = Some(3);
    let (got, _) = login(&m, &mut dir, "pw");
    assert!(matches!(got, Login::Identity(_)), "{got:?}");
    assert_eq!(dir.written, direct_bytes("memberOf"));
    assert_eq!(dir.seen, vec![Seen::Establish("127.0.0.1:389".into())]);
}

#[test]
fn a_reply_split_across_reads_is_read_whole() {
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let all = [bind_response(1, 0), done(2, 0)].concat();
    let replies: Vec<Vec<u8>> = all.chunks(2).map(<[u8]>::to_vec).collect();
    let mut dir = Directory::new(replies).pending();
    assert!(matches!(login(&m, &mut dir, "pw").0, Login::Identity(_)));
}

#[test]
fn rc_49_is_a_bad_credential_and_another_code_an_outage() {
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let mut dir = Directory::new(vec![bind_response(1, 49)]);
    assert_eq!(login(&m, &mut dir, "wrong").0, Login::BadCredential);
    let mut dir = Directory::new(vec![bind_response(1, 52)]);
    assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage);
}

#[test]
fn a_failed_group_read_is_an_outage() {
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let mut dir = Directory::new(vec![bind_response(1, 0), done(2, 32)]);
    assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage);
}

#[test]
fn ldaps_is_secured_before_the_first_byte() {
    let m = module("ldaps://ad.corp.example", serde_json::json!({}));
    let mut dir = Directory::new(vec![bind_response(1, 0), done(2, 0)]).pending();
    assert!(matches!(login(&m, &mut dir, "pw").0, Login::Identity(_)));
    assert_eq!(
        dir.seen,
        vec![Seen::Establish("ad.corp.example:636".into()), Seen::Secure]
    );
    assert_eq!(dir.written, direct_bytes("memberOf"));
}

#[test]
fn start_tls_sends_the_extended_request_then_secures() {
    let m = module(
        "ldap://ad.corp.example",
        serde_json::json!({"start_tls": true}),
    );
    let mut dir = Directory::new(vec![extended(1, 0), bind_response(2, 0), done(3, 0)]).pending();
    assert!(matches!(login(&m, &mut dir, "pw").0, Login::Identity(_)));
    assert_eq!(
        dir.seen,
        vec![Seen::Establish("ad.corp.example:389".into()), Seen::Secure]
    );
    let want = [
        codec::start_tls(1),
        chip_bind(2, ALICE, "pw").to_vec(),
        codec::search(
            3,
            ALICE,
            codec::SCOPE_BASE,
            "(objectClass=*)",
            &["memberOf"],
        )
        .unwrap(),
        codec::unbind(4),
    ]
    .concat();
    assert_eq!(dir.written, want);
}

/// A MITM appends forged bind replies to the plaintext StartTLS success: whatever arrived before
/// the upgrade is never honoured after it (CVE-2011-0411's class), so the login is an outage and
/// no bind is ever sent.
#[test]
fn data_sent_with_the_start_tls_response_is_never_honoured() {
    let m = module(
        "ldap://ad.corp.example",
        serde_json::json!({"start_tls": true}),
    );
    let forged = [
        extended(1, 0),
        bind_response(2, 0),
        entry(3, ALICE, "memberOf", &["cn=admins,dc=corp"]),
        done(3, 0),
    ]
    .concat();
    let mut dir = Directory::new(vec![forged]);
    assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage);
    assert_eq!(dir.written, codec::start_tls(1), "no bind request is sent");
    assert!(!dir.seen.contains(&Seen::Secure), "never secured");
}

#[test]
fn a_refused_start_tls_never_secures_and_never_binds() {
    let m = module(
        "ldap://ad.corp.example",
        serde_json::json!({"start_tls": true}),
    );
    let mut dir = Directory::new(vec![extended(1, 2)]);
    assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage);
    assert_eq!(
        dir.seen,
        vec![Seen::Establish("ad.corp.example:389".into())]
    );
    assert_eq!(dir.written, codec::start_tls(1));
}

#[test]
fn search_then_bind_speaks_in_1_5_5s_order() {
    let m = module(
        "ldap://127.0.0.1",
        serde_json::json!({
            "user_search_filter": "(uid={username})",
            "bind_service_dn": "cn=svc,dc=corp,dc=example",
            "bind_service_password": "svc-pw",
        }),
    );
    let mut dir = Directory::new(vec![
        bind_response(1, 0),
        entry(2, ALICE, "dn", &[]),
        done(2, 0),
        bind_response(3, 0),
        entry(4, ALICE, "memberOf", &["cn=admins,dc=corp"]),
        done(4, 0),
    ])
    .pending();
    let (got, _) = login(&m, &mut dir, "pw");
    let Login::Identity(p) = got else {
        panic!("{got:?}");
    };
    assert_eq!(p.roles, vec!["admins".to_string()]);
    let want = [
        chip_bind(1, "cn=svc,dc=corp,dc=example", "svc-pw").to_vec(),
        codec::search(
            2,
            "dc=corp,dc=example",
            codec::SCOPE_SUBTREE,
            "(uid=alice)",
            &["dn"],
        )
        .unwrap(),
        chip_bind(3, ALICE, "pw").to_vec(),
        codec::search(
            4,
            ALICE,
            codec::SCOPE_BASE,
            "(objectClass=*)",
            &["memberOf"],
        )
        .unwrap(),
        codec::unbind(5),
    ]
    .concat();
    assert_eq!(dir.written, want);
}

/// A search keeps at most two entries (the module needs only whether a second exists); the rest
/// are read and dropped, and a user search matching several is still ambiguous: a bad credential.
#[test]
fn a_search_keeps_at_most_two_entries() {
    use crate::{LdapBackend, SearchScope};
    let many = |n: i64| -> Vec<Vec<u8>> {
        let mut r = vec![bind_response(1, 0)];
        for i in 0..n {
            r.push(entry(2, &format!("uid=u{i},dc=x"), "dn", &[]));
        }
        r.push(done(2, 0));
        r
    };
    let mut dir = Directory::new(many(5));
    let mut conv = Conversation::new();
    let mut over = super::Over::new(&mut conv, &mut dir, "ldap://127.0.0.1", false, None, 10);
    over.connect().expect("connects");
    over.simple_bind("cn=svc,dc=x", &crate::tests::cred("pw"))
        .expect("binds");
    let got = over
        .search("dc=x", SearchScope::Subtree, "(uid=alice)", &["dn"])
        .expect("searches");
    assert_eq!(got.len(), 2, "kept only two of five");

    let m = module(
        "ldap://127.0.0.1",
        serde_json::json!({
            "user_search_filter": "(uid={username})",
            "bind_service_dn": "cn=svc,dc=x",
            "bind_service_password": "svc-pw",
        }),
    );
    let mut dir = Directory::new(many(5));
    assert_eq!(login(&m, &mut dir, "pw").0, Login::BadCredential);
}

/// 1.5.5 panicked reading a referral as an entry; it is an outage now.
#[test]
fn a_search_reference_fails_closed() {
    let m = module(
        "ldap://127.0.0.1",
        serde_json::json!({
            "user_search_filter": "(uid={username})",
            "bind_service_dn": "cn=svc,dc=x",
            "bind_service_password": "svc-pw",
        }),
    );
    let reference = message(
        2,
        ber::element(0x73, &ber::element(0x04, b"ldap://elsewhere/")),
    );
    let mut dir = Directory::new(vec![bind_response(1, 0), reference]).held();
    assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage);
}

/// SIGNED DIFFERENCES 1–3, through the conversation: a malformed reply, an overrunning nested
/// length and a reply past the cap are each an outage, never a panic or a wait.
#[test]
fn the_signed_differences_fail_closed_as_an_outage() {
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let malformed = message(1, ber::element(0x61, &ber::element(0x04, b"")));
    let overrun = message(1, vec![0x61, 0x7f, 0x0a, 0x01, 0x00]);
    let past_cap = [&[0x30, 0x84][..], &(16_u32 * 1024 * 1024).to_be_bytes()[..]].concat();
    for reply in [malformed, overrun, past_cap] {
        let mut dir = Directory::new(vec![reply.clone()]).held();
        assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage, "{reply:02x?}");
    }
    // A directory that closes the stream before answering is an outage too.
    let mut dir = Directory::new(Vec::new());
    assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage);
    // So is a notice of disconnection (message id 0).
    let mut dir = Directory::new(vec![extended(0, 52)]).held();
    assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage);
}

/// SIGNED DIFFERENCE 1, the URL half: a hostless URL never dials (1.5.5 panicked). It is refused
/// at boot, `validate` included, as a `settings.url` line (it was an outage on every login); an
/// unknown scheme reads in 1.5.5's words.
#[test]
fn a_hostless_url_is_refused_before_any_dial() {
    for url in [
        "ldap://",
        "ldap:///dc=x",
        "ldaps://:636",
        "ldap://user@:389",
    ] {
        let cfg: LdapConfig = serde_json::from_value(serde_json::json!({
            "url": url,
            "bind_dn_template": "uid={username},ou=people,dc=corp,dc=example",
            "base_dn": "dc=corp,dc=example",
            "allow_insecure_transport": true,
        }))
        .expect("config parses");
        let e = LdapModule::new(cfg).err().expect("refused at boot");
        assert!(e.starts_with("settings.url: "), "{url}: {e}");
    }
    assert_eq!(
        Endpoint::parse("ldapi://%2fvar%2frun", false),
        Err("unknown LDAP URL scheme: ldapi".to_string())
    );
    assert_eq!(
        Endpoint::parse("ldap://", false),
        Err("the URL names no host".to_string())
    );
}

#[test]
fn an_endpoint_reads_its_target_and_security() {
    for (url, tls, target, host, security) in [
        ("ldap://h", false, "h:389", "h", Security::Plain),
        ("ldap://h:1389", false, "h:1389", "h", Security::Plain),
        ("ldaps://h", false, "h:636", "h", Security::Implicit),
        (
            "ldap://ad.corp:1389",
            false,
            "ad.corp:1389",
            "ad.corp",
            Security::Plain,
        ),
        (
            "LDAPS://ad.corp",
            false,
            "ad.corp:636",
            "ad.corp",
            Security::Implicit,
        ),
        (
            "ldaps://ad.corp",
            true,
            "ad.corp:636",
            "ad.corp",
            Security::Implicit,
        ),
        (
            "ldap://ad.corp/dc=x?uid",
            true,
            "ad.corp:389",
            "ad.corp",
            Security::StartTls,
        ),
        (
            "ldap://[::1]:3389",
            false,
            "[::1]:3389",
            "::1",
            Security::Plain,
        ),
        ("ldap://[::1]", false, "[::1]:389", "::1", Security::Plain),
        // Userinfo is not the host: the dial lands where the plaintext guard looked.
        (
            "ldap://127.0.0.1:389@evil.example",
            false,
            "evil.example:389",
            "evil.example",
            Security::Plain,
        ),
    ] {
        let e = Endpoint::parse(url, tls).unwrap_or_else(|e| panic!("{url}: {e}"));
        assert_eq!(
            (e.target.as_str(), e.host.as_str(), e.security),
            (target, host, security),
            "{url}"
        );
    }
    assert!(Endpoint::parse("ldap://h:99999", false).is_err());
    assert!(Endpoint::parse("h:389", false).is_err());
}

/// An operation gives up `timeout_secs` after it begins: a directory that never answers is an
/// outage once the clock passes the deadline, and the conversation states that deadline.
#[test]
fn a_directory_that_never_answers_is_an_outage_after_the_timeout() {
    let m = module("ldap://127.0.0.1", serde_json::json!({"timeout_secs": 2}));
    let mut conv = Conversation::new();
    let start = 5_000_000_000_u64;
    assert_eq!(
        m.login_text(&mut conv, &mut Mute, Some("alice"), Some("pw"), Some(start)),
        Poll::Pending
    );
    assert_eq!(conv.deadline_ns(), Some(start + 2_000_000_000));
    assert_eq!(
        m.login_text(
            &mut conv,
            &mut Mute,
            Some("alice"),
            Some("pw"),
            Some(start + 1_999_999_999)
        ),
        Poll::Pending,
        "not before the deadline"
    );
    assert_eq!(
        m.login_text(
            &mut conv,
            &mut Mute,
            Some("alice"),
            Some("pw"),
            Some(start + 2_000_000_000)
        ),
        Poll::Ready(Login::Outage)
    );
}

/// A directory on a clock: the first service of each directory operation (the dial, then each
/// reply) pends, and the caller's clock moves `step_ns` on that wake.
struct Slow {
    dir: Directory,
    owed: bool,
}

impl Wire for Slow {
    fn establish(&mut self, target: &str) -> Poll<Result<(), String>> {
        self.owed = !self.owed;
        if self.owed {
            return Poll::Pending;
        }
        self.dir.establish(target)
    }
    fn secure(&mut self) -> Poll<Result<(), String>> {
        self.dir.secure()
    }
    fn write(&mut self, bytes: &[u8]) -> Poll<Result<usize, String>> {
        self.dir.write(bytes)
    }
    fn write_sealed(&mut self, w: &mut SealedWrite) -> Poll<Result<(), String>> {
        busbar_contract::abi::sdk::test_support::chip::drive_sealed(w, |b| self.write(b))
    }

    fn read(&mut self, buf: &mut [u8]) -> Poll<Result<usize, String>> {
        self.owed = !self.owed;
        if self.owed {
            return Poll::Pending;
        }
        self.dir.read(buf)
    }
}

/// `timeout_secs` bounds each directory operation, as 1.5.5 did (the connect, and each bind and
/// search): a login whose operations each take 0.6 of it completes, though together they take more.
#[test]
fn the_timeout_bounds_each_operation_not_the_whole_login() {
    let m = module("ldap://127.0.0.1", serde_json::json!({"timeout_secs": 10}));
    let mut slow = Slow {
        dir: Directory::new(vec![
            bind_response(1, 0),
            [
                entry(2, ALICE, "memberOf", &["cn=admins,dc=corp"]),
                done(2, 0),
            ]
            .concat(),
        ]),
        owed: false,
    };
    let mut conv = Conversation::new();
    let mut now = 1_000_000_000_u64;
    let mut got = None;
    for _ in 0..20 {
        match m.login_text(&mut conv, &mut slow, Some("alice"), Some("pw"), Some(now)) {
            Poll::Ready(l) => {
                got = Some(l);
                break;
            }
            Poll::Pending => now += 6_000_000_000,
        }
    }
    let Some(Login::Identity(p)) = got else {
        panic!("every operation was inside its own timeout: {got:?}");
    };
    assert_eq!(p.roles, vec!["admins".to_string()]);
    assert!(
        now >= 1_000_000_000 + 3 * 6_000_000_000,
        "three operations waited"
    );
}

/// The order 1.5.5 had (seam 6): the connection is opened before the DN template refuses a
/// username, so a refused username is still a bad credential, after the dial.
#[test]
fn a_username_the_dn_template_refuses_is_refused_after_the_dial() {
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let mut dir = Directory::new(Vec::new());
    let mut conv = Conversation::new();
    let got = m.login_text(&mut conv, &mut dir, Some("admin,dc=x"), Some("pw"), Some(0));
    assert_eq!(got, Poll::Ready(Login::BadCredential));
    assert_eq!(dir.seen, vec![Seen::Establish("127.0.0.1:389".into())]);
    assert!(dir.written.is_empty(), "no bind is sent for it");
    assert!(conv.opened(), "the caller closes what was opened");
    // A dial the stream refuses is an outage.
    let mut dir = Directory::new(Vec::new());
    dir.refuse_establish = Some("the connection was refused".into());
    let mut conv = Conversation::new();
    let got = m.login_text(&mut conv, &mut dir, Some("alice"), Some("pw"), Some(0));
    assert_eq!(got, Poll::Ready(Login::Outage));
    assert!(!conv.opened());
}

/// Opens, takes every byte, never answers.
struct Mute;

impl Wire for Mute {
    fn establish(&mut self, _: &str) -> Poll<Result<(), String>> {
        Poll::Ready(Ok(()))
    }
    fn secure(&mut self) -> Poll<Result<(), String>> {
        Poll::Ready(Ok(()))
    }
    fn write(&mut self, b: &[u8]) -> Poll<Result<usize, String>> {
        Poll::Ready(Ok(b.len()))
    }
    fn write_sealed(&mut self, w: &mut SealedWrite) -> Poll<Result<(), String>> {
        busbar_contract::abi::sdk::test_support::chip::drive_sealed(w, |b| self.write(b))
    }

    fn read(&mut self, _: &mut [u8]) -> Poll<Result<usize, String>> {
        Poll::Pending
    }
}

/// The timeout answers as 1.5.5 answered an ldap3 operation timeout: an outage (1.5.5's Reject),
/// its text the operation's prefix then `timeout: deadline has elapsed` (`LdapError::Timeout`).
#[test]
fn a_timeout_reads_in_1_5_5s_words() {
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let (t0, late) = (1_000_000_000_u64, 1_000_000_000_u64 + 10_000_000_000);
    let mut mute = Mute;
    let mut conv = Conversation::new();
    let mut over = super::Over::new(
        &mut conv,
        &mut mute,
        "ldap://127.0.0.1",
        false,
        Some(t0),
        10,
    );
    assert!(matches!(
        m.bind_and_identify_on(&mut over, "alice", "pw"),
        Err(crate::BindError::Pending)
    ));
    let mut over = super::Over::new(
        &mut conv,
        &mut mute,
        "ldap://127.0.0.1",
        false,
        Some(late),
        10,
    );
    match m.bind_and_identify_on(&mut over, "alice", "pw") {
        Err(crate::BindError::Directory(e)) => assert_eq!(e, "bind: timeout: deadline has elapsed"),
        other => panic!("{other:?}"),
    }
    // A connect that pends past its deadline: the connect's prefix, as 1.5.5's connect timeout.
    struct Dialing;
    impl Wire for Dialing {
        fn establish(&mut self, _: &str) -> Poll<Result<(), String>> {
            Poll::Pending
        }
        fn secure(&mut self) -> Poll<Result<(), String>> {
            Poll::Pending
        }
        fn write(&mut self, _: &[u8]) -> Poll<Result<usize, String>> {
            Poll::Pending
        }
        fn write_sealed(&mut self, w: &mut SealedWrite) -> Poll<Result<(), String>> {
            busbar_contract::abi::sdk::test_support::chip::drive_sealed(w, |b| self.write(b))
        }

        fn read(&mut self, _: &mut [u8]) -> Poll<Result<usize, String>> {
            Poll::Pending
        }
    }
    let mut dialing = Dialing;
    let mut conv = Conversation::new();
    let mut over = super::Over::new(
        &mut conv,
        &mut dialing,
        "ldap://127.0.0.1",
        false,
        Some(t0),
        10,
    );
    assert!(matches!(
        m.bind_and_identify_on(&mut over, "alice", "pw"),
        Err(crate::BindError::Pending)
    ));
    let mut over = super::Over::new(
        &mut conv,
        &mut dialing,
        "ldap://127.0.0.1",
        false,
        Some(late),
        10,
    );
    match m.bind_and_identify_on(&mut over, "alice", "pw") {
        Err(crate::BindError::Directory(e)) => {
            assert_eq!(e, "connect ldap://127.0.0.1: timeout: deadline has elapsed");
        }
        other => panic!("{other:?}"),
    }
}

/// The resolved service password (the kernel's secret, over the settings literal) is what the
/// service bind sends, and it appears in no error text the login logs and not in the module's
/// `Debug`: a failed service bind, a malformed reply and a closed stream are each checked.
#[test]
fn the_resolved_service_secret_reaches_only_the_bind() {
    const SECRET: &str = "s3cr3t-resolved";
    let settings = serde_json::json!({
        "url": "ldap://127.0.0.1",
        "bind_dn_template": "uid={username},dc=x",
        "base_dn": "dc=x",
        "user_search_filter": "(uid={username})",
        "bind_service_dn": "cn=svc,dc=x",
        "bind_service_password": "literal",
    })
    .to_string();
    let m =
        LdapModule::from_settings_with(settings.as_bytes(), &[SECRET.as_bytes()]).expect("opens");
    assert!(!format!("{:?}", m.cfg).contains(SECRET), "Debug leaks it");
    let malformed = message(1, ber::element(0x61, &ber::element(0x04, b"")));
    for replies in [vec![bind_response(1, 52)], vec![malformed], Vec::new()] {
        let mut dir = Directory::new(replies);
        let mut conv = Conversation::new();
        let mut over = super::Over::new(&mut conv, &mut dir, "ldap://127.0.0.1", false, None, 10);
        match m.bind_and_identify_on(&mut over, "alice", "pw") {
            Err(crate::BindError::Directory(e)) => assert!(!e.contains(SECRET), "{e}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            dir.written,
            chip_bind(1, "cn=svc,dc=x", SECRET).to_vec(),
            "the bind sends it"
        );
    }
}

/// The BIND request in flight holds the cleartext password: a `Debug` of the conversation (it is
/// `pub`) must never print it.
#[test]
fn a_conversation_in_flight_never_debug_prints_the_password() {
    const PW: &str = "hunter2-s3cret";
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let mut dir = Directory::new(vec![bind_response(1, 0), done(2, 0)]).pending();
    let mut conv = Conversation::new();
    let mut held = false;
    for _ in 0..200 {
        let answer = m.login_text(&mut conv, &mut dir, Some("alice"), Some(PW), Some(0));
        held |= conv.doing.as_ref().is_some_and(|d| d.sealed.is_some());
        let shown = format!("{conv:?}");
        assert!(!shown.contains(PW), "the password is in: {shown}");
        // `Debug` of a byte slice prints its bytes as decimals: the password's, too, is a leak.
        let digits = format!("{:?}", PW.as_bytes());
        let digits = digits.trim_matches(['[', ']']);
        assert!(
            !shown.contains(digits),
            "the password's bytes are in: {shown}"
        );
        if answer.is_ready() {
            break;
        }
    }
    assert!(held, "the bind request was never held in flight");
}

/// A SearchResultEntry and its SearchResultDone arrive in ONE read (the normal wire shape): the
/// second message must survive the first's decode, and the stream holds open after it so a lost
/// message pends instead of reading as EOF.
#[test]
fn two_messages_in_one_read_are_both_read() {
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let both = [
        entry(2, ALICE, "memberOf", &["cn=Engineers,ou=g,dc=corp"]),
        done(2, 0),
    ]
    .concat();
    let mut dir = Directory::new(vec![bind_response(1, 0), both]).held();
    let Login::Identity(p) = login(&m, &mut dir, "pw").0 else {
        panic!("alice binds");
    };
    assert_eq!(p.roles, vec!["Engineers".to_string()]);
}

/// A TLS handshake the connector fails (`ldaps://`, or StartTLS after the directory agreed) is an
/// outage that never puts the BIND on the wire.
#[test]
fn a_failed_secure_is_an_outage_and_never_binds() {
    let m = module("ldaps://ad.corp.example", serde_json::json!({}));
    let mut dir = Directory::new(vec![bind_response(1, 0), done(2, 0)]).held();
    dir.secure_error = Some("tls handshake failed".to_string());
    assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage);
    assert!(dir.written.is_empty(), "wrote: {:02x?}", dir.written);

    let m = module(
        "ldap://ad.corp.example",
        serde_json::json!({"start_tls": true}),
    );
    let mut dir = Directory::new(vec![extended(1, 0), bind_response(2, 0), done(3, 0)]).held();
    dir.secure_error = Some("tls handshake failed".to_string());
    assert_eq!(login(&m, &mut dir, "pw").0, Login::Outage);
    assert_eq!(
        dir.written,
        codec::start_tls(1),
        "only the StartTLS request"
    );
}

/// OWNER RULING (non-49 user bind), through `login_over` so the verdict is the one the door
/// answers: a code naming a server/session condition is an outage; every other non-zero code is
/// the same bad credential as a wrong password, logged ONCE at info (a refusal, auth standard S5;
/// nothing at warn) with the directory's real result (its code and RFC 4511 name), never the
/// password and never the DN. An outage code is logged at warn.
#[test]
fn a_non_49_user_bind_is_a_bad_credential_unless_the_server_is_failing() {
    use busbar_test_kit::warn_capture::WarnCapture;
    const PW: &str = "hunter2-s3cret";
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    for rc in [48_u32, 50, 53, 32, 19, 999] {
        let cap = WarnCapture::capturing_debug();
        let mut dir = Directory::new(vec![bind_response(1, i64::from(rc))]);
        let (got, _) = tracing::subscriber::with_default(cap.clone(), || login(&m, &mut dir, PW));
        assert_eq!(got, Login::BadCredential, "rc {rc}");
        assert!(
            cap.contains(&format!("rc={rc}")),
            "rc {rc}: {:?}",
            cap.messages()
        );
        assert!(
            cap.contains(&format!("result={}", codec::rc_name(rc))),
            "rc {rc}: {:?}",
            cap.messages()
        );
        assert!(cap.contains("module=ldap"), "{:?}", cap.messages());
        assert!(
            !cap.contains(PW),
            "the password leaked: {:?}",
            cap.messages()
        );
        assert!(!cap.contains(ALICE), "the DN leaked: {:?}", cap.messages());
        assert_eq!(
            cap.count(&format!("rc={rc}")),
            1,
            "logged once: {:?}",
            cap.messages()
        );
        let warn = WarnCapture::default();
        let mut dir = Directory::new(vec![bind_response(1, i64::from(rc))]);
        tracing::subscriber::with_default(warn.clone(), || login(&m, &mut dir, PW));
        assert!(
            warn.messages().is_empty(),
            "rc {rc} at warn: {:?}",
            warn.messages()
        );
    }
    let cap = WarnCapture::capturing_debug();
    let mut dir = Directory::new(vec![bind_response(1, 53)]);
    tracing::subscriber::with_default(cap.clone(), || login(&m, &mut dir, PW));
    assert!(cap.contains("unwillingToPerform"), "{:?}", cap.messages());
    for rc in [51_i64, 52, 80, 8] {
        let warn = WarnCapture::default();
        let mut dir = Directory::new(vec![bind_response(1, rc)]);
        let (got, _) = tracing::subscriber::with_default(warn.clone(), || login(&m, &mut dir, PW));
        assert_eq!(got, Login::Outage, "rc {rc}");
        assert!(
            warn.contains(&format!("rc={rc}")),
            "an outage at warn: {:?}",
            warn.messages()
        );
    }
}

/// The BIND in flight is the chip's sealed message: the plugin holds no password bytes of its own.
#[test]
fn the_bind_in_flight_is_the_chips_sealed_message() {
    let m = module("ldap://127.0.0.1", serde_json::json!({}));
    let mut dir = Directory::new(vec![bind_response(1, 0), done(2, 0)]).pending();
    let mut conv = Conversation::new();
    let mut held = false;
    for _ in 0..200 {
        let answer = m.login_text(&mut conv, &mut dir, Some("alice"), Some("pw"), Some(0));
        if let Some(d) = conv.doing.as_ref().filter(|d| d.sealed.is_some()) {
            assert!(d.out.is_empty(), "a BIND carries no public bytes");
            held = true;
        }
        if answer.is_ready() {
            break;
        }
    }
    assert!(held, "a BIND was held in flight");
}

/// The chip's BIND message for `dn` with `password`, as the wire carries it.
fn chip_bind(id: i32, dn: &str, password: &str) -> Vec<u8> {
    let mut w = SealedWrite::message(crate::tests::cred(password).ldap_simple_bind(id, dn));
    let mut bytes = Vec::new();
    let sent: Poll<Result<(), ()>> =
        busbar_contract::abi::sdk::test_support::chip::drive_sealed(&mut w, |b| {
            bytes.extend_from_slice(b);
            Poll::Ready(Ok(b.len()))
        });
    assert!(sent.is_ready(), "the BIND is written whole");
    bytes
}
