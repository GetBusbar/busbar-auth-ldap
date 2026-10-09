// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE LDAP DOOR, BOTH WAYS IN** — the LDAP module's linked + dropped-in conformance on the auth
//! kind's door (THE DESIGN §11), run against the busbar rev this repo pins (`.busbar-ref`).
//!
//! THE PUBLISHED SUITE (busbar-plugin-loader's `conformance` feature, at the pin): the linked door
//! and the built cdylib, each through the one loader, driven by the auth kind's script over the
//! inputs `conformance.json` names: `verify` (always PASS: LDAP judges no bearer credential), the
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

use busbar_auth_ldap::door::door;
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
use busbar_plugin_loader::conformance::{self, Leg, Subject};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{now_ns, DispatchConfig, Dispatcher, Frame, LinkedRow};

#[path = "support/conformance_host.rs"]
mod conformance_host;

#[path = "support/net_ban.rs"]
mod net_ban;

busbar_plugin_loader::conformance_suite! {
    door: busbar_auth_ldap::door::door,
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

/// The suite's user in the live directory, added once over plaintext LDAP on loopback by the
/// administrator (`ldap3`, a dev-only client; the module speaks its own codec): the container makes
/// its base suffix and its root DN, but no entry the module could read groups off. Best effort: with
/// no directory (a macOS runner) nothing is added, and the live arms, skipped there, would read an
/// outage.
fn seed_user() {
    static SEEDED: OnceLock<()> = OnceLock::new();
    SEEDED.get_or_init(|| {
        let Ok(mut ldap) = ldap3::LdapConn::new(&format!("ldap://{}", upstream())) else {
            return;
        };
        if !ldap
            .simple_bind(ADMIN_DN, ADMIN_PW)
            .is_ok_and(|r| r.success().is_ok())
        {
            return;
        }
        let attrs = vec![
            (
                "objectClass",
                ["simpleSecurityObject", "organizationalRole"].into(),
            ),
            ("cn", ["conformance"].into()),
            ("userPassword", [USER_PW].into()),
        ];
        match ldap.add(USER_DN, attrs).and_then(|r| r.success()) {
            // 68 = entryAlreadyExists: a rerun against a warm directory.
            Ok(_) => {}
            Err(ldap3::LdapError::LdapResult { result }) if result.rc == 68 => {}
            Err(e) => panic!("the suite's user {USER_DN} cannot be added: {e}"),
        }
        let _ = ldap.unbind();
    });
}

/// The host the suite binds the module over, with the TLS front its settings name already
/// listening and the suite's user in the directory behind it.
fn host(
    wake: Arc<dyn Fn(u64) + Send + Sync>,
    anchors: Option<&str>,
) -> Arc<dyn busbar_contract::conn::DeclaredConns> {
    seed_user();
    conformance_host::tls_front(start_tls, upstream());
    conformance_host::host(wake, anchors)
}

/// RED: the Statement declares the module's ONE need (an outbound `tcp` stream of the
/// operator-infrastructure egress class, its target named per login, its trust the connector's
/// own) and its ONE secret reference, and states no call that blocks; the dropped-in library
/// states the same Statement.
#[test]
fn red_the_statement_declares_one_operator_infrastructure_stream_and_never_blocks() {
    let stated = LinkedRow::of(door)
        .expect("the linked door renders")
        .statement;
    let read = rendering::read(&stated).expect("the rendering reads");
    assert_eq!(read.needs.len(), 1);
    let need = &read.needs[0];
    assert_eq!(need.direction, DIRECTION_OUTBOUND);
    assert_eq!(need.egress_class, EGRESS_OPERATOR_INFRASTRUCTURE);
    assert_eq!(need.transport, "tcp");
    assert!(need.target_from.is_empty());
    assert!(
        need.trust_from.is_empty(),
        "the connector's own trust: the module refuses ca_cert_pem"
    );
    assert_eq!(read.secret_refs, vec!["bind_service_password".to_string()]);
    assert_eq!(read.marks & MARK_BLOCKS, 0, "no call blocks");
    let subject = Subject::new(door, "busbar_auth_ldap_plugin", "{}");
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

/// One credential login SUBMITTED on a ticket (as the host submits it) and awaited: the answer and
/// the verdict it names.
fn login(
    p: &busbar_plugin_loader::dispatch::Plugin<Auth>,
    d: &Dispatcher,
    username: &str,
    password: &str,
) -> String {
    let secret = |b: &[u8]| Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    };
    let named = [
        NamedValue {
            name: AbiStr::over(b"username"),
            value: secret(username.as_bytes()),
        },
        NamedValue {
            name: AbiStr::over(b"password"),
            value: secret(password.as_bytes()),
        },
    ];
    let mut bytes = vec![0_u8; IDENTITY_BUF_BYTES];
    let mut groups = vec![Span { offset: 0, len: 0 }; IDENTITY_GROUPS as usize];
    let mut f: Frame<CompleteLoginIn, IdentifyOut> =
        Frame::new(conformance::input(), conformance::output());
    f.input.submitted = named.as_ptr();
    f.input.submitted_len = named.len();
    f.input.out_buf = IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let deadline = now_ns().saturating_add(Duration::from_secs(30).as_nanos() as u64);
    let (called, frame) =
        conformance::on_ticket_frame(p, d, slot::COMPLETE_LOGIN, f, DeadlineClass::Call, deadline);
    let verdict = match frame {
        Some(f) if called.outcome == Outcome::Ready => f.out.verdict.to_string(),
        _ => "none".to_string(),
    };
    format!("{:?} verdict={verdict}", called.outcome)
}

/// Host services offering the clock alone (the dispatcher's own timebase), refusing the rest: the
/// login arms its deadline off the host's clock, as the kernel serves it.
struct ClockOnly;

impl busbar_contract::services::HostServices for ClockOnly {
    fn now(&self) -> busbar_contract::services::Reading {
        busbar_contract::services::Reading {
            wall_ns: 0,
            mono_ns: now_ns(),
        }
    }
    fn dest_judge(
        &self,
        _: &str,
        _: u32,
        _: u32,
        _: Option<busbar_contract::services::Later>,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn records_get(
        &self,
        _: &busbar_contract::services::Caller,
        _: &str,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn records_list(
        &self,
        _: &busbar_contract::services::Caller,
        _: busbar_contract::services::RecordsList,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn records_claim(
        &self,
        _: &busbar_contract::services::Caller,
        _: &str,
        _: &[u8],
        _: u64,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn sign(
        &self,
        _: &busbar_contract::services::Caller,
        _: &[u8],
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn trust_sight(
        &self,
        _: &busbar_contract::services::Caller,
        _: &str,
        _: &str,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn trust_due(
        &self,
        _: &busbar_contract::services::Caller,
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn trust_verify(
        &self,
        _: &busbar_contract::services::Caller,
        _: &str,
        _: &[u8],
        _: &[u8],
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn entitlement_check(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: &str,
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn random_fill(&self, _: u64) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn records_secret(
        &self,
        _: &str,
        _: &str,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn unit_nest(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: busbar_contract::services::NestAsk,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn work_open(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: &str,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn work_find(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn work_settle(
        &self,
        _: &busbar_contract::services::Caller,
        _: u64,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn work_resume(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: u64,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn disk_append(
        &self,
        _: &busbar_contract::services::DiskDest,
        _: Vec<u8>,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn verify_lookup(
        &self,
        _: &busbar_contract::services::Caller,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn verify_store(
        &self,
        _: &busbar_contract::services::Caller,
        _: &[u8],
        _: &[u8],
        _: u64,
    ) -> busbar_contract::services::Stored {
        busbar_contract::services::Stored::refused("no")
    }
    fn content_scan(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: &[u8],
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn hook_call(
        &self,
        _: &busbar_contract::services::Caller,
        _: Option<u64>,
        _: busbar_contract::services::HookAsk,
        _: busbar_contract::services::Later,
    ) -> busbar_contract::services::Ran {
        busbar_contract::services::Ran::Now(busbar_contract::services::Stored::refused("no"))
    }
    fn snapshot_read(
        &self,
        _: &busbar_contract::services::Caller,
        _: u32,
    ) -> busbar_contract::services::Snapshot {
        busbar_contract::services::Snapshot::Refused("no")
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
    let s = Subject::new(door, "busbar_auth_ldap_plugin", &inputs)
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
