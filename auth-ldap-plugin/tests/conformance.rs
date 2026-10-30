// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE LDAP DOOR, BOTH WAYS IN** — the LDAP module's linked + dropped-in conformance on the auth
//! kind's door (THE DESIGN §11), run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! THE PUBLISHED SUITE (busbar-plugin-loader's `conformance` feature, at the pin): the linked door
//! and the built cdylib, each through the one loader, driven by the auth kind's script over the
//! inputs `conformance.json` names: the tail states the login family alone (`CAP_LOGIN`: LDAP
//! judges no bearer credential, so `verify` is an undeclared op that must answer REFUSED), the
//! credential login (`begin_login`'s form; `complete_login` SUBMITTED on a ticket, the suite's
//! user's credential an identity, a wrong password refused), exact crossing counts, the two folds equal,
//! its RED arms.
//!
//! THE HOST (ARCHITECT Q-P4-9): the module's one `tcp` need is served by busbar's own connector,
//! composed as the root composes it (`conformance_host`, rendered by the fleet template), and the
//! module asks for STARTTLS (`start_tls`): it sends the StartTLS extended request in the clear, the
//! suite's TLS front answers it ([`start_tls`]) and handshakes with a certificate that chains to the
//! suite's test CA, the anchors only the HOST's TLS is handed (`tls:`); the module then asks the
//! connector to secure the stream (`upgrade_secure`), and the front carries the secured connection
//! to the live directory (plugin-ci's `openldap` service, `BUSBAR_TEST_LDAP_URL`). So every login
//! proves the module's connection is secured by the host, verified against the anchors.
//!
//! THE RED ARMS of this repo's own, same file: the Statement declares its one need and secret
//! reference and never blocks; a directory that takes the connection and never answers is an
//! outage at the login's deadline; and THE BAN ([`net_ban`]): the shipped closure holds no socket
//! crate and no TLS stack.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use busbar_auth_ldap::door::MACRO_DOOR;
use busbar_contract::abi::auth::{
    slot, CompleteLoginIn, IdentifyOut, IdentityBuf, NamedValue, IDENTITY_BUF_BYTES,
    IDENTITY_GROUPS, LOGIN_OUTAGE,
};
use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, Span, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::MARK_BLOCKS;
use busbar_contract::abi::mechanism::rendering;
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{now_ns, DispatchConfig, Dispatcher, Frame, LinkedRow};
use busbar_test_kit::conformance::{self, Leg, Subject};

#[path = "support/conformance_host.rs"]
mod conformance_host;

#[path = "support/net_ban.rs"]
mod net_ban;

busbar_test_kit::conformance_suite! {
    door: busbar_auth_ldap::door::MACRO_DOOR,
    cdylib: "busbar_auth_ldap_plugin",
    inputs: include_str!("conformance.json"),
    host: host,
    tls: conformance_host::anchors(),
}

/// The live directory's address (`BUSBAR_TEST_LDAP_URL`'s authority; the service container's
/// default when unset).
fn upstream() -> &'static str {
    static AT: OnceLock<String> = OnceLock::new();
    AT.get_or_init(|| {
        let url = std::env::var("BUSBAR_TEST_LDAP_URL").unwrap_or_default();
        url.split_once("://")
            .map(|(_, rest)| rest)
            .and_then(|rest| rest.split('/').next())
            .filter(|at| !at.is_empty())
            .unwrap_or("127.0.0.1:389")
            .to_owned()
    })
}

/// The StartTLS extended operation's name (RFC 4511 §4.14.1).
const START_TLS_OID: &[u8] = b"1.3.6.1.4.1.1466.20037";

/// One BER element off `tcp`: its tag and its content.
fn element(tcp: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut head = [0_u8; 2];
    tcp.read_exact(&mut head).ok()?;
    let len = if head[1] & 0x80 == 0 {
        usize::from(head[1])
    } else {
        let n = usize::from(head[1] & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let mut wide = [0_u8; 4];
        tcp.read_exact(&mut wide[4 - n..]).ok()?;
        u32::from_be_bytes(wide) as usize
    };
    if len > 64 * 1024 {
        return None;
    }
    let mut content = vec![0_u8; len];
    tcp.read_exact(&mut content).ok()?;
    Some((head[0], content))
}

/// The first element inside `content`: its whole encoding and the rest.
fn first(content: &[u8]) -> Option<(&[u8], &[u8])> {
    let len = *content.get(1)?;
    if len & 0x80 != 0 {
        return None;
    }
    let end = 2 + usize::from(len);
    (content.len() >= end).then(|| content.split_at(end))
}

/// LDAP's cleartext negotiation: the client's StartTLS extended request (an `LDAPMessage` whose
/// protocol op is `[APPLICATION 23]` naming [`START_TLS_OID`]) answered with a successful
/// `[APPLICATION 24]` extended response on the same message id; anything else is not a TLS client.
fn start_tls(tcp: &mut TcpStream) -> bool {
    let Some((0x30, message)) = element(tcp) else {
        return false;
    };
    let Some((id, op)) = first(&message) else {
        return false;
    };
    if id.first() != Some(&0x02) || op.first() != Some(&0x77) {
        return false;
    }
    if !op.windows(START_TLS_OID.len()).any(|w| w == START_TLS_OID) {
        return false;
    }
    // ExtendedResponse: resultCode success, matchedDN "", diagnosticMessage "", responseName.
    let mut response = vec![0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00, 0x8a];
    response.push(START_TLS_OID.len() as u8);
    response.extend_from_slice(START_TLS_OID);
    let mut body = id.to_vec();
    body.push(0x78);
    body.push(response.len() as u8);
    body.extend_from_slice(&response);
    let mut out = vec![0x30, body.len() as u8];
    out.extend_from_slice(&body);
    tcp.write_all(&out).is_ok()
}

/// The live directory's administrator (the service container's own, from its env).
const ADMIN_DN: &str = "cn=admin,dc=example,dc=org";
const ADMIN_PW: &str = "adminpassword";

/// The entry the suite logs in as, and its password (`conformance.json`'s login).
const USER_DN: &str = "cn=conformance,dc=example,dc=org";
const USER_PW: &str = "conformance-password";

/// How long the suite waits for a named live directory to take its administrator's bind. A service
/// container's port answers before its slapd serves (the runner's port proxy accepts at once), and
/// the image bootstraps its suffix before the first bind succeeds.
const DIRECTORY_WAIT: Duration = Duration::from_secs(180);

/// The live directory at `at`, bound as its administrator, retried until `until`.
///
/// # Errors
///
/// The last refusal, naming `at`, once `until` has passed with no bind taken.
fn admin_bound(at: &str, until: Instant) -> Result<ldap3::LdapConn, String> {
    let settings = ldap3::LdapConnSettings::new().set_conn_timeout(Duration::from_secs(5));
    loop {
        let tried = ldap3::LdapConn::with_settings(settings.clone(), &format!("ldap://{at}"))
            .and_then(|mut ldap| {
                let bound = ldap
                    .with_timeout(Duration::from_secs(5))
                    .simple_bind(ADMIN_DN, ADMIN_PW)
                    .and_then(|r| r.success());
                bound.map(|_| ldap)
            });
        match tried {
            Ok(ldap) => return Ok(ldap),
            Err(e) if Instant::now() >= until => {
                return Err(format!(
                    "the live directory at {at} took no bind as {ADMIN_DN}: {e}"
                ))
            }
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
}

/// The suite's user in the live directory, added once over plaintext LDAP on loopback by the
/// administrator (`ldap3`, a dev-only client; the module speaks its own codec): the container makes
/// its base suffix and its root DN, but no entry the module could read groups off. With
/// `BUSBAR_TEST_LDAP_URL` set the directory must take the administrator's bind within
/// [`DIRECTORY_WAIT`], or the suite stops here naming it (never a login that reads an outage); the
/// wait is made once, and every later test that asks is refused at once with the same words. With
/// no directory named (a macOS runner) it is one try and nothing is added; the live arms, skipped
/// there, would read an outage.
fn seed_user() {
    static SEEDED: OnceLock<Result<(), String>> = OnceLock::new();
    let seeded = SEEDED.get_or_init(|| {
        let named = std::env::var_os("BUSBAR_TEST_LDAP_URL").is_some();
        let until = Instant::now()
            + if named {
                DIRECTORY_WAIT
            } else {
                Duration::ZERO
            };
        let mut ldap = match admin_bound(upstream(), until) {
            Ok(ldap) => ldap,
            Err(e) if named => return Err(e),
            Err(_) => return Ok(()),
        };
        let attrs = vec![
            (
                "objectClass",
                ["simpleSecurityObject", "organizationalRole"].into(),
            ),
            ("cn", ["conformance"].into()),
            ("userPassword", [USER_PW].into()),
        ];
        let added = match ldap.add(USER_DN, attrs).and_then(|r| r.success()) {
            // 68 = entryAlreadyExists: a rerun against a warm directory.
            Ok(_) => Ok(()),
            Err(ldap3::LdapError::LdapResult { result }) if result.rc == 68 => Ok(()),
            Err(e) => Err(format!("the suite's user {USER_DN} cannot be added: {e}")),
        };
        let _ = ldap.unbind();
        added
    });
    if let Err(e) = seeded {
        panic!("{e}");
    }
}

/// The host the suite binds the module over, with the TLS front its settings name already
/// listening and the suite's user in the directory behind it.
fn host(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    seed_user();
    conformance_host::tls_front(start_tls, upstream());
    conformance_host::host(wake, anchors)
}

/// RED: the Statement declares the module's TWO needs (each an outbound `tcp` stream of the
/// operator-infrastructure egress class, its target named per login: the public one on the
/// connector's own trust, the anchored one on `settings.ca_cert_pem`) and its ONE secret reference, and states no call that blocks; the dropped-in library
/// states the same Statement.
#[test]
fn red_the_statement_declares_a_public_and_an_anchored_stream_and_never_blocks() {
    let stated = LinkedRow::of_macro(MACRO_DOOR)
        .expect("the linked door renders")
        .statement;
    let read = rendering::read(&stated).expect("the rendering reads");
    assert_eq!(read.needs.len(), 2);
    for need in &read.needs {
        assert_eq!(need.direction, DIRECTION_OUTBOUND);
        assert_eq!(need.egress_class, EGRESS_OPERATOR_INFRASTRUCTURE);
        assert_eq!(need.transport, "tcp");
        assert!(need.target_from.is_empty());
    }
    assert!(
        read.needs[0].trust_from.is_empty(),
        "the connector's own trust"
    );
    assert_eq!(
        read.needs[1].trust_from, "settings.ca_cert_pem",
        "the private CA"
    );
    assert_eq!(read.secret_refs, vec!["bind_service_password".to_string()]);
    assert_eq!(read.marks & MARK_BLOCKS, 0, "no call blocks");
    let subject = Subject::of_macro(MACRO_DOOR, "busbar_auth_ldap_plugin", "{}");
    assert_eq!(subject.stated(), stated);
}

/// A loopback listener that takes every connection and never answers (the connections are held
/// open); its address.
fn silent_directory() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
    let at = listener.local_addr().expect("its address").to_string();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for tcp in listener.incoming().flatten() {
            held.push(tcp);
        }
    });
    at
}

/// RED: a directory whose port takes the connection and drops it (a service container's port proxy
/// with no slapd behind it yet, or none at all) takes no administrator's bind: the seed waits it out
/// to the deadline, then names the directory, instead of leaving the suite's login to read an
/// outage.
#[test]
fn red_a_directory_port_with_no_directory_behind_it_is_named_at_the_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
    let at = listener.local_addr().expect("its address").to_string();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            drop(tcp);
        }
    });
    let started = Instant::now();
    let Err(refused) = admin_bound(&at, started + Duration::from_secs(2)) else {
        panic!("a bind was taken where no directory answers");
    };
    let took = started.elapsed();
    assert!(
        refused.starts_with(&format!(
            "the live directory at {at} took no bind as {ADMIN_DN}: "
        )),
        "{refused}"
    );
    assert!(
        took >= Duration::from_secs(2) && took < Duration::from_secs(15),
        "the refusal comes at the deadline: {took:?}"
    );
}

/// THE MEMORY ONE `complete_login` LENDS THE PLUGIN: the submitted form fields and the host's
/// identity buffer, lent whole to the op (THE DESIGN §2) so its pointers stay valid however the
/// call ends.
struct LoginLend {
    _fields: [Vec<u8>; 2],
    named: Vec<NamedValue>,
    bytes: Vec<u8>,
    groups: Vec<Span>,
}

// SAFETY: the raw pointers in `named` point into `_fields`, owned by the same `LoginLend` (their
// heap buffers never move); nothing mutates it once its frame is built but the plugin's writes into
// `bytes` and `groups`, which the host reads only after the op completes.
unsafe impl Send for LoginLend {}
// SAFETY: as above.
unsafe impl Sync for LoginLend {}

/// One credential login SUBMITTED on a ticket (as the host submits it) and awaited: the answer and
/// the verdict it names. Everything the frame names is in a [`LoginLend`] the op owns (the suite's
/// lending submit, `conformance::on_ticket_frame`).
fn login(
    p: &busbar_plugin_loader::dispatch::Plugin<Auth>,
    d: &Dispatcher,
    username: &str,
    password: &str,
) -> String {
    // SAFETY: the `fields` Vec<u8>s live in `LoginLend` for the call.
    #[allow(unused_unsafe)]
    let secret =
        |b: &[u8]| unsafe { Blob::from_raw_parts(b.as_ptr(), b.len(), BLOB_OCTETS, BLOB_SECRET) };
    let fields = [username.as_bytes().to_vec(), password.as_bytes().to_vec()];
    let named = vec![
        NamedValue {
            name: AbiStr::of_bytes(b"username"),
            value: secret(&fields[0]),
        },
        NamedValue {
            name: AbiStr::of_bytes(b"password"),
            value: secret(&fields[1]),
        },
    ];
    let mut lend = Box::new(LoginLend {
        _fields: fields,
        named,
        bytes: vec![0_u8; IDENTITY_BUF_BYTES],
        groups: vec![Span { offset: 0, len: 0 }; IDENTITY_GROUPS as usize],
    });
    let mut f: Frame<CompleteLoginIn, IdentifyOut> =
        Frame::new(conformance::input(), conformance::output());
    f.input.submitted = lend.named.as_ptr();
    f.input.submitted_len = lend.named.len();
    f.input.out_buf = IdentityBuf {
        buf: lend.bytes.as_mut_ptr(),
        buf_cap: lend.bytes.len(),
        groups: lend.groups.as_mut_ptr(),
        groups_cap: lend.groups.len() as u32,
        _reserved: 0,
    };
    let lend: Arc<LoginLend> = Arc::from(lend);
    let deadline = now_ns().saturating_add(Duration::from_secs(30).as_nanos() as u64);
    let (called, frame) = conformance::on_ticket_frame(
        p,
        d,
        slot::COMPLETE_LOGIN,
        f,
        DeadlineClass::Call,
        deadline,
        lend as busbar_plugin_loader::dispatch::Lent,
    );
    let verdict = match frame {
        Some(f) if called.outcome == Outcome::Ready => f.out.verdict.to_string(),
        _ => "none".to_string(),
    };
    format!("{:?} verdict={verdict}", called.outcome)
}

/// Host services offering the clock alone (the dispatcher's own timebase), refusing the rest (busbar's
/// shared test double answers every other service unserved): the login arms its deadline off the
/// host's clock, as the kernel serves it.
struct ClockOnly;

impl busbar_contract::services::double::ServicesDouble for ClockOnly {
    fn now(&self) -> busbar_contract::services::Reading {
        busbar_contract::services::Reading {
            wall_ns: 0,
            mono_ns: now_ns(),
        }
    }
}

/// RED: a directory that takes the connection and never answers (and so never wakes the ticket) is
/// an OUTAGE once the login's `timeout_secs` pass — the op's own deadline resumes it; nothing blocks
/// and nothing waits forever. Through the host's connector, both legs.
#[test]
fn red_a_directory_that_never_answers_is_an_outage_at_the_deadline() {
    let at = silent_directory();
    let settings = serde_json::json!({
        "url": format!("ldap://{at}"),
        "bind_dn_template": "cn={username},dc=example,dc=org",
        "base_dn": "dc=example,dc=org",
        "timeout_secs": 1,
    })
    .to_string();
    let inputs = serde_json::json!({ "settings": serde_json::from_str::<serde_json::Value>(&settings).unwrap() })
        .to_string();
    let s = Subject::of_macro(MACRO_DOOR, "busbar_auth_ldap_plugin", &inputs)
        .with_host(conformance_host::host)
        .with_anchors(conformance_host::anchors());
    for leg in [Leg::Linked, Leg::Dropped] {
        let d = Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            Arc::new(ClockOnly),
        ));
        let p = conformance::load::<Auth>(&s, leg, s.bind(&d, "ldap-silent"))
            .unwrap_or_else(|e| panic!("{leg:?}: the door loads: {e}"));
        let opened = conformance::open(&p, settings.as_bytes());
        assert_eq!(opened.outcome, Outcome::Ready, "{leg:?}: open");
        let started = Instant::now();
        let got = login(&p, &d, "conformance", USER_PW);
        assert_eq!(got, format!("Ready verdict={LOGIN_OUTAGE}"), "{leg:?}");
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(900) && took < Duration::from_secs(15),
            "{leg:?}: the outage comes at the deadline: {took:?}"
        );
        assert_eq!(
            conformance::close(&p).outcome,
            Outcome::Ready,
            "{leg:?}: close"
        );
    }
}
