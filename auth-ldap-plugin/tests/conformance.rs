// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **ONE LDAP DOOR, BOTH WAYS IN** — the LDAP module's linked + dropped-in conformance on the auth
//! kind's door, run against the busbar rev this repo pins (`.busbar-ref`): the linked door and the
//! built cdylib, each through the one loader. The tail states the login family alone (`CAP_LOGIN`:
//! LDAP judges no bearer credential, so `verify` is an undeclared op that must answer REFUSED), the
//! credential login (`begin_login`'s form; `complete_login` SUBMITTED on a ticket, the user's
//! credential an identity, a wrong password refused), exact crossing counts, and the two loads
//! answer alike.
//!
//! THE HOST: the module's `tcp` need is served by busbar's own connector (`conformance_host`), and
//! the module asks for STARTTLS (`start_tls`): it sends the StartTLS extended request in the clear,
//! the test's TLS front answers it ([`start_tls`]) and handshakes with a certificate that chains to
//! the test CA, the anchors only the HOST's TLS is handed; the module then asks the connector to
//! secure the stream (`upgrade_secure`), and the front carries the secured connection to the live
//! directory (`BUSBAR_TEST_LDAP_URL`). So every login proves the module's connection is secured by
//! the host, verified against the anchors.
//!
//! THE RED ARMS: the Statement declares its needs and secret reference and never blocks; a
//! directory that takes the connection and never answers is an outage at the login's deadline; and
//! THE BAN ([`net_ban`]): the shipped closure holds no socket crate and no TLS stack.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use busbar_auth_ldap::MACRO_DOOR;
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
use busbar_contract::abi::mechanism::call::{InHead, OutHead, BLOB_JSON};
use busbar_contract::abi::mechanism::door::MARK_BLOCKS;
use busbar_contract::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::rendering;
use busbar_contract::abi::sdk::door::{blank_in as input, blank_out as output};
use busbar_plugin_loader::dispatch::kinds::auth::Auth;
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, Bind, Called, ConnTable, NoSink, Plugin,
};
use busbar_plugin_loader::dispatch::{now_ns, DispatchConfig, Dispatcher, Frame, LinkedRow};

#[path = "support/artifact.rs"]
mod artifact;

#[derive(Clone, Copy, Debug)]
enum Leg {
    Linked,
    Dropped,
}

fn bind(d: &Dispatcher, name: &str) -> Bind {
    Bind {
        instance: Arc::from(name),
        max_inflight_cap: 1024,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: ConnTable::NoNeeds,
    }
}

fn load(leg: Leg, binding: Bind) -> Plugin<Auth> {
    let row = LinkedRow::of_macro(MACRO_DOOR).expect("the actual LDAP door renders");
    match leg {
        Leg::Linked => load_linked::<Auth>(&row, binding),
        Leg::Dropped => load_dropped::<Auth>(&artifact::plugin_path(), &row.statement, binding),
    }
    .expect("the actual LDAP door loads")
}

fn open(p: &Plugin<Auth>, settings: &[u8]) -> Called {
    open_with(p, settings, &[])
}

/// `open` handed `secrets` as the kernel resolves the Statement's `secret_refs`.
fn open_with(p: &Plugin<Auth>, settings: &[u8], secrets: &[Blob]) -> Called {
    let mut f: Frame<OpenIn, OpenOut> = Frame::new(input(), output());
    f.input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    f.input.secrets = secrets.as_ptr();
    f.input.secrets_len = secrets.len();
    f.input.generation = 1;
    p.call(life::OPEN, &mut f)
}

fn close(p: &Plugin<Auth>) -> Called {
    let mut f: Frame<InHead, OutHead> = Frame::new(input(), output());
    p.call(life::CLOSE, &mut f)
}

#[path = "support/conformance_host.rs"]
mod conformance_host;

#[path = "support/net_ban.rs"]
mod net_ban;

#[path = "support/sealed_replay.rs"]
mod sealed_replay;

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

/// The entry the suite logs in as, and its password.
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
/// no directory named it is one try against the default loopback directory and nothing is added
/// when none answers; the live arms then read an outage, so a run without a directory must name
/// one (`BUSBAR_TEST_LDAP_URL`; on macOS, `tests/support/macos-ldap.sh` starts one and names it).
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
/// the verdict it names. Everything the frame names is in a [`LoginLend`] the op owns.
fn login_answer(
    p: &busbar_plugin_loader::dispatch::Plugin<Auth>,
    d: &Dispatcher,
    username: &str,
    password: &str,
) -> (String, String) {
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
    let mut f: Frame<CompleteLoginIn, IdentifyOut> = Frame::new(input(), output());
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
    let ticket = d.mint(0).expect("LDAP login ticket");
    let done = d
        .submit_lent(
            p,
            ticket,
            slot::COMPLETE_LOGIN,
            f,
            DeadlineClass::Call,
            deadline,
            lend.clone() as busbar_plugin_loader::dispatch::Lent,
        )
        .wait_done();
    d.recycle(ticket);
    assert_eq!(done.lease, 0, "login verdict is never leased");
    if done.outcome == Outcome::Ready {
        assert!(
            done.error.as_deref().unwrap_or_default().is_empty(),
            "READY login carries no error"
        );
    }
    for secret in [USER_PW, "wrong-password"] {
        assert!(
            !lend
                .bytes
                .windows(secret.len())
                .any(|b| b == secret.as_bytes()),
            "credential in login output buffer"
        );
    }
    let frame = done.frame;
    let verdict = match frame {
        Some(f) if done.outcome == Outcome::Ready => f.out.verdict.to_string(),
        _ => "none".to_string(),
    };
    let subject = frame
        .filter(|_| done.outcome == Outcome::Ready)
        .map(|f| {
            let span = f.out.identity.subject;
            if span.offset == busbar_contract::abi::auth::SPAN_ABSENT {
                return String::new();
            }
            let start = span.offset as usize;
            String::from_utf8(
                lend.bytes
                    .get(start..start + span.len as usize)
                    .expect("identity stays in the host buffer")
                    .to_vec(),
            )
            .expect("identity is UTF-8")
        })
        .unwrap_or_default();
    (format!("{:?} verdict={verdict}", done.outcome), subject)
}

fn login(p: &Plugin<Auth>, d: &Dispatcher, username: &str, password: &str) -> String {
    login_answer(p, d, username, password).0
}

/// Host services offering the clock alone (the dispatcher's own timebase), refusing the rest (busbar's
/// shared test double answers every other service unserved): the login arms its deadline off the
/// host's clock, as the kernel serves it.
struct ClockOnly;

use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Stored,
    TrustKeyRef, UNSERVED,
};

impl HostServices for ClockOnly {
    fn now(&self) -> Reading {
        busbar_contract::services::Reading {
            wall_ns: 0,
            mono_ns: now_ns(),
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
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn trust_decide(
        &self,
        _caller: &Caller,
        _ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        _key: TrustKeyRef<'_>,
        _expected: Option<&str>,
        _approve: bool,
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
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
        _later: Later,
    ) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
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
    fn unit_nest(&self, _caller: &Caller, _unit: Option<u64>, _ask: NestAsk, _later: Later) -> Ran {
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
    fn verify_store(&self, _caller: &Caller, _key: &[u8], _entry: &[u8], _ttl_ms: u64) -> Stored {
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
    fn hook_call(&self, _caller: &Caller, _unit: Option<u64>, _ask: HookAsk, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
    fn snapshot_read(&self, _caller: &Caller, _scope: u32, _later: Later) -> Ran {
        Ran::Now(Stored::refused(UNSERVED))
    }
}

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
    for leg in [Leg::Linked, Leg::Dropped] {
        let d = Arc::new(Dispatcher::with_services(
            DispatchConfig::default(),
            Arc::new(ClockOnly),
            busbar_contract::services::test_caller_binding(),
        ));
        let p = load(
            leg,
            Bind {
                conns: ConnTable::Host(conformance_host::host(
                    d.conn_waker(),
                    Some(conformance_host::anchors()),
                )),
                ..bind(&d, "ldap-silent")
            },
        );
        let opened = open(&p, settings.as_bytes());
        assert_eq!(opened.outcome, Outcome::Ready, "{leg:?}: open");
        let started = Instant::now();
        let got = login(&p, &d, "conformance", USER_PW);
        assert_eq!(got, format!("Ready verdict={LOGIN_OUTAGE}"), "{leg:?}");
        let took = started.elapsed();
        assert!(
            took >= Duration::from_millis(900) && took < Duration::from_secs(15),
            "{leg:?}: the outage comes at the deadline: {took:?}"
        );
        assert_eq!(close(&p).outcome, Outcome::Ready, "{leg:?}: close");
    }
}

/// A submitted password holding a control character is refused at the door as a bad credential,
/// before any directory is dialled (README: the credential form rejects them before capturing
/// them or opening a directory connection).
#[test]
fn a_control_character_password_is_refused_before_the_dial() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
    listener
        .set_nonblocking(true)
        .expect("a non-blocking listener");
    let at = listener.local_addr().expect("its address").to_string();
    let settings = serde_json::json!({
        "url": format!("ldap://{at}"),
        "bind_dn_template": "cn={username},dc=example,dc=org",
        "base_dn": "dc=example,dc=org",
        "timeout_secs": 1,
    })
    .to_string();
    let d = Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(ClockOnly),
        busbar_contract::services::test_caller_binding(),
    ));
    let p = load(
        Leg::Linked,
        Bind {
            conns: ConnTable::Host(conformance_host::host(
                d.conn_waker(),
                Some(conformance_host::anchors()),
            )),
            ..bind(&d, "ldap-control-password")
        },
    );
    assert_eq!(open(&p, settings.as_bytes()).outcome, Outcome::Ready);
    for password in ["secret\0tail", "secret\ntail", "secret\u{7f}tail"] {
        assert_eq!(
            login(&p, &d, "conformance", password),
            format!(
                "Ready verdict={}",
                busbar_contract::abi::auth::LOGIN_BAD_CREDENTIAL
            ),
            "{password:?}"
        );
    }
    assert!(
        matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "no directory connection was made"
    );
    assert_eq!(close(&p).outcome, Outcome::Ready);
}

// Every count comes from the actual loader crossing gate. Network resumption may
// add RESUME invocations; each new submitted operation still enters exactly once.
fn counted<T>(p: &Plugin<Auth>, expected: u64, call: impl FnOnce() -> T) -> T {
    counted_step(p, expected, false, call)
}
fn counted_login<T>(p: &Plugin<Auth>, call: impl FnOnce() -> T) -> T {
    counted_step(p, 1, true, call)
}
fn counted_step<T>(p: &Plugin<Auth>, expected: u64, dialing: bool, call: impl FnOnce() -> T) -> T {
    let before = (p.test_invocations().0, p.test_invocations().1);
    let answer = call();
    let after = (p.test_invocations().0, p.test_invocations().1);
    if dialing {
        assert!(
            after.1 > before.1,
            "each configured LDAP dialing step actually RESUMEs"
        );
    }
    if !dialing {
        assert_eq!(after.1 - before.1, 0, "non-dialing LDAP step never resumes");
    }
    assert_eq!(
        (after.0 - before.0) - (after.1 - before.1),
        expected,
        "actual LDAP first invocations; total/resume before={before:?} after={after:?}"
    );
    answer
}

#[derive(Default)]
struct Heard(std::sync::Mutex<Vec<String>>);
impl busbar_plugin_loader::dispatch::EnvelopeSink for Heard {
    fn metric(&self, m: busbar_plugin_loader::dispatch::Metric<'_>) {
        self.0.lock().unwrap().push(format!(
            "metric {} {} {} {:?}",
            m.family, m.kind, m.value, m.labels
        ));
    }
    fn diag(&self, d: busbar_plugin_loader::dispatch::Diagnostic<'_>) {
        self.0.lock().unwrap().push(format!(
            "diag {} {} {:?} {}",
            d.id,
            d.severity,
            d.name,
            String::from_utf8_lossy(d.text)
        ));
    }
    fn dropped(&self, why: busbar_plugin_loader::dispatch::Dropped) {
        self.0.lock().unwrap().push(format!("dropped {why:?}"));
    }
}

fn settings() -> Vec<u8> {
    let mut v: serde_json::Value = conformance_inputs();
    v["settings"]["ca_cert_pem"] = conformance_host::anchors().into();
    serde_json::to_vec(&v["settings"]).unwrap()
}

fn live_bind(d: &Dispatcher, name: &str) -> Bind {
    Bind {
        conns: ConnTable::Host(host(d.conn_waker(), Some(conformance_host::anchors()))),
        ..bind(d, name)
    }
}

fn validate(p: &Plugin<Auth>, settings: &[u8]) -> Called {
    use busbar_contract::abi::mechanism::lifecycle::ValidateIn;
    let mut f: Frame<ValidateIn, OutHead> = Frame::new(input(), output());
    f.input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    p.call(life::VALIDATE, &mut f)
}

// Retain the complete call result in both the linked/dropped comparison and privacy scan.
fn called_text(c: &Called) -> String {
    format!(
        "{:?} lease={} recall={} {}",
        c.outcome,
        c.lease,
        c.recall.is_some(),
        String::from_utf8_lossy(c.error.as_deref().unwrap_or_default())
    )
}

fn direct_script(leg: Leg) -> (Vec<String>, Vec<String>) {
    use busbar_contract::abi::auth::{
        self, BeginLoginIn, BeginLoginOut, FieldsIn, FieldsOut, OpenOutboundIn, OpenOutboundOut,
        OutboundReadyIn, OutboundReadyOut, VerifyIn,
    };
    use busbar_contract::abi::mechanism::lifecycle::{RefreshIn, TickIn, TickOut};
    let d = Dispatcher::with_services(
        DispatchConfig::default(),
        Arc::new(ClockOnly),
        busbar_contract::services::test_caller_binding(),
    );
    let heard = Arc::new(Heard::default());
    let p = load(
        leg,
        Bind {
            sink: heard.clone(),
            ..live_bind(&d, "ldap-direct")
        },
    );
    assert_eq!(p.test_invocations().0, 0);
    assert_eq!(p.test_invocations().1, 0);
    let tail = p
        .context::<busbar_plugin_loader::dispatch::kinds::auth::AuthFacts>()
        .expect("auth facts");
    assert_eq!(tail.caps, auth::CAP_LOGIN);
    assert_eq!(tail.login_kind, auth::LOGIN_KIND_CREDENTIAL);
    assert_eq!(p.name(), "busbar-auth-ldap");
    assert_eq!(p.max_inflight(), 64);
    let mut lines = vec![format!(
        "facts {:?} {} max_inflight={} caps={} facts={} login_kind={} carriers={:?}",
        p.kind(),
        p.name(),
        p.max_inflight(),
        tail.caps,
        tail.facts,
        tail.login_kind,
        tail.carriers
    )];
    let inputs: serde_json::Value = conformance_inputs();
    let settings = settings();
    for bad in inputs["auth"]["bad_settings"].as_array().unwrap() {
        let bytes = if let Some(text) = bad.as_str() {
            text.as_bytes().to_vec()
        } else {
            serde_json::to_vec(bad).unwrap()
        };
        for c in [
            counted(&p, 1, || validate(&p, &bytes)),
            counted(&p, 1, || open(&p, &bytes)),
        ] {
            assert_eq!(c.outcome, Outcome::Failed);
            assert!(!c.error.as_deref().unwrap_or_default().is_empty());
            assert_eq!(c.lease, 0);
            lines.push(format!("bad {}", called_text(&c)));
        }
    }
    let validated = counted(&p, 1, || validate(&p, &settings));
    assert_eq!(validated.outcome, Outcome::Ready);
    lines.push(format!("validate {}", called_text(&validated)));
    let opened = counted(&p, 1, || open(&p, &settings));
    assert_eq!(opened.outcome, Outcome::Ready);
    lines.push(format!("open {}", called_text(&opened)));
    let ready_count = u64::from(p.has_ready());
    let ready = counted(&p, ready_count, || p.ready(&d, Duration::from_secs(10)));
    lines.push(format!("ready has_ready={} {ready:?}", p.has_ready()));
    ready.expect("LDAP ready");
    let mut verify: Frame<VerifyIn, IdentifyOut> = Frame::new(input(), output());
    let verified = counted(&p, 1, || p.call(slot::VERIFY, &mut verify));
    assert_eq!(verified.outcome, Outcome::Refused);
    lines.push(format!("verify undeclared {}", called_text(&verified)));
    let mut begin: Frame<BeginLoginIn, BeginLoginOut> = Frame::new(input(), output());
    begin.input.redirect_uri = AbiStr::of_bytes(b"https://node.example/auth/login");
    begin.input.state = AbiStr::of_bytes(b"conformance-state");
    let begun = counted(&p, 1, || p.call(slot::BEGIN_LOGIN, &mut begin));
    assert_eq!(begun.outcome, Outcome::Ready);
    assert_eq!(begun.lease, 0);
    lines.push(format!("begin_login {}", called_text(&begun)));
    assert_eq!(begin.out.shape, auth::BEGIN_FORM);
    assert_eq!(begin.out.form_len, 2);
    // SAFETY: READY holds the actual plugin's form for the answer's lifetime; it
    // is copied before the instance is closed.
    let fields = unsafe { std::slice::from_raw_parts(begin.out.form, begin.out.form_len) };
    let form: Vec<_> = fields
        .iter()
        .map(|field| {
            // SAFETY: the validated READY form's strings are plugin-owned and live here.
            let name = unsafe { std::slice::from_raw_parts(field.name.ptr, field.name.len) };
            (
                String::from_utf8(name.to_vec()).unwrap(),
                field.kind,
                field.required,
            )
        })
        .collect();
    assert_eq!(
        form,
        vec![
            ("username".into(), auth::FORM_TEXT, 1),
            ("password".into(), auth::FORM_PASSWORD, 1)
        ]
    );
    lines.push(format!("form {form:?}"));
    let accepted = counted_login(&p, || login_answer(&p, &d, "conformance", USER_PW));
    assert_eq!(
        accepted,
        (
            format!("Ready verdict={}", auth::LOGIN_IDENTITY),
            "ldap:cn=conformance,dc=example,dc=org".into()
        )
    );
    lines.push(format!("login {accepted:?}"));
    let rejected = counted_login(&p, || login(&p, &d, "conformance", "wrong-password"));
    assert_eq!(
        rejected,
        format!("Ready verdict={}", auth::LOGIN_BAD_CREDENTIAL)
    );
    lines.push(rejected);
    let mut outbound: Frame<OpenOutboundIn, OpenOutboundOut> = Frame::new(input(), output());
    let answer = counted(&p, 1, || p.call(slot::OPEN_OUTBOUND, &mut outbound));
    assert_eq!(answer.outcome, Outcome::Refused);
    lines.push(format!("open_outbound undeclared {}", called_text(&answer)));
    let mut outbound_ready: Frame<OutboundReadyIn, OutboundReadyOut> =
        Frame::new(input(), output());
    let answer = counted(&p, 1, || p.call(slot::OUTBOUND_READY, &mut outbound_ready));
    assert_eq!(answer.outcome, Outcome::Refused);
    lines.push(format!(
        "outbound_ready undeclared {}",
        called_text(&answer)
    ));
    let mut fields: Frame<FieldsIn, FieldsOut> = Frame::new(input(), output());
    let answer = counted(&p, 1, || p.call(slot::FIELDS, &mut fields));
    assert_eq!(answer.outcome, Outcome::Refused);
    lines.push(format!("fields undeclared {}", called_text(&answer)));
    let mut tick: Frame<TickIn, TickOut> = Frame::new(input(), output());
    tick.input.now_ns = 1;
    let ticked = counted(&p, 1, || p.call(life::TICK, &mut tick));
    assert_eq!(ticked.outcome, Outcome::Ready);
    lines.push(format!(
        "tick {} next={}",
        called_text(&ticked),
        tick.out.next_tick_ns
    ));
    let mut refresh: Frame<RefreshIn, OutHead> = Frame::new(input(), output());
    refresh.input.settings = Blob {
        ptr: settings.as_ptr(),
        len: settings.len(),
        fmt: BLOB_JSON,
        flags: 0,
    };
    refresh.input.generation = 2;
    let refreshed = counted(&p, 1, || p.call(life::REFRESH, &mut refresh));
    assert_eq!(refreshed.outcome, Outcome::Ready);
    lines.push(format!("refresh {}", called_text(&refreshed)));
    let closed = counted(&p, 1, || close(&p));
    assert_eq!(closed.outcome, Outcome::Ready);
    lines.push(format!("close {}", called_text(&closed)));
    assert_eq!(
        d.stats().deadline_without_wake,
        0,
        "every LDAP wait was woken"
    );
    let envelope = heard.0.lock().unwrap().clone();
    // A settings value no refusal, log or diagnostic may quote: a line of the CA's body.
    let configured: serde_json::Value = serde_json::from_slice(&settings).unwrap();
    let ca_line = configured["ca_cert_pem"]
        .as_str()
        .unwrap()
        .lines()
        .find(|line| line.len() > 32 && !line.starts_with("-----"))
        .expect("the CA has a body");
    for text in lines.iter().chain(envelope.iter()) {
        for secret in [USER_PW, "wrong-password"] {
            assert!(!text.contains(secret), "credential escaped: {text}");
        }
        assert!(!text.contains(ca_line), "a settings value escaped: {text}");
    }
    (lines, envelope)
}

#[test]
fn the_linked_and_the_dropped_in_door_are_one_plugin() {
    let actual =
        busbar_plugin_loader::dispatch::load::door_addresses_of_library(&artifact::plugin_path())
            .expect("the actual LDAP cdylib loads")
            .expect("the actual LDAP cdylib exports its door");
    let linked = busbar_auth_ldap::door();
    assert_ne!(
        actual.0, linked as *const Door as usize,
        "dropped and linked door addresses differ"
    );
    assert_ne!(
        actual.1,
        linked.parts().ops as usize,
        "dropped and linked operation tables differ"
    );
    assert_eq!(direct_script(Leg::Linked), direct_script(Leg::Dropped));
}

/// The configured service secret, like the user's password, never crosses back: a search-then-bind
/// instance handed the directory administrator's password as its `bind_service_password` secret
/// logs a user in and refuses a wrong password, a wrong service secret answers an outage, and no
/// answer, refusal, log line, metric or diagnostic carries either password.
#[test]
fn no_configured_credential_crosses_back() {
    use busbar_contract::abi::auth::{LOGIN_BAD_CREDENTIAL, LOGIN_IDENTITY};
    for leg in [Leg::Linked, Leg::Dropped] {
        for (service_pw, user_pw, verdict) in [
            (ADMIN_PW, USER_PW, LOGIN_IDENTITY),
            (ADMIN_PW, "wrong-password", LOGIN_BAD_CREDENTIAL),
            ("wrong-service-password", USER_PW, LOGIN_OUTAGE),
        ] {
            let d = Dispatcher::with_services(
                DispatchConfig::default(),
                Arc::new(ClockOnly),
                busbar_contract::services::test_caller_binding(),
            );
            let heard = Arc::new(Heard::default());
            let p = load(
                leg,
                Bind {
                    sink: heard.clone(),
                    ..live_bind(&d, "ldap-service-secret")
                },
            );
            let mut v: serde_json::Value = conformance_inputs();
            v["settings"]["ca_cert_pem"] = conformance_host::anchors().into();
            v["settings"]["user_search_filter"] = "(cn={username})".into();
            v["settings"]["bind_service_dn"] = ADMIN_DN.into();
            let settings = serde_json::to_vec(&v["settings"]).unwrap();
            let secrets = [Blob::of(service_pw.as_bytes()).with_flags(BLOB_SECRET)];
            let opened = open_with(&p, &settings, &secrets);
            assert_eq!(opened.outcome, Outcome::Ready, "{}", called_text(&opened));
            if p.has_ready() {
                p.ready(&d, Duration::from_secs(10)).expect("LDAP ready");
            }
            let (answer, subject) = login_answer(&p, &d, "conformance", user_pw);
            assert_eq!(
                answer,
                format!("Ready verdict={verdict}"),
                "{leg:?} service={service_pw} user={user_pw}"
            );
            if verdict == LOGIN_IDENTITY {
                assert_eq!(subject, "ldap:cn=conformance,dc=example,dc=org");
            }
            let closed = close(&p);
            assert_eq!(closed.outcome, Outcome::Ready);
            let lines = [called_text(&opened), answer, subject, called_text(&closed)];
            let envelope = heard.0.lock().unwrap().clone();
            for text in lines.iter().chain(envelope.iter()) {
                for secret in [service_pw, user_pw] {
                    assert!(!text.contains(secret), "a credential crossed back: {text}");
                }
            }
        }
    }
}

#[test]
fn the_declared_needs_are_the_statements() {
    let row = LinkedRow::of_macro(MACRO_DOOR).unwrap();
    let read = rendering::read(&row.statement).unwrap();
    let declared: serde_json::Value =
        serde_json::from_str(include_str!("../../auth-ldap/declares.json")).unwrap();
    let mut actual: Vec<_> = read
        .needs
        .iter()
        .map(|need| need.transport.as_str())
        .collect();
    actual.sort();
    actual.dedup();
    let mut named: Vec<_> = declared["needs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    named.sort();
    named.dedup();
    assert_eq!(named, actual);
    let mut diagnostics: Vec<_> = declared["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    diagnostics.sort_unstable();
    let mut stated: Vec<_> = read.diag_ids.iter().map(String::as_str).collect();
    stated.sort_unstable();
    assert_eq!(
        diagnostics, stated,
        "declares.json names the Statement's diagnostics"
    );
}

#[test]
fn the_suite_runs_in_the_profile_it_was_asked_to() {
    assert!(!(cfg!(debug_assertions) && std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some()));
}

use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_plugin_loader::dispatch::{rendering_of, LoadError};
fn row(door: DoorFn) -> LinkedRow {
    LinkedRow::of(door).expect("actual LDAP Statement")
}
fn network_bind(d: &Dispatcher) -> Bind {
    Bind {
        conns: ConnTable::Host(conformance_host::host(
            d.conn_waker(),
            Some(conformance_host::anchors()),
        )),
        ..bind(d, "ldap-negative")
    }
}
#[test]
fn a_changed_statement_is_refused_linked_and_dropped() {
    use busbar_plugin_loader::dispatch::LoadError;
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let honest = rendering_of(busbar_auth_ldap::door).unwrap();
    let statement = rendering_of(another_version_door)
        .expect("the actual LDAP door with another version renders");
    rendering::read(&statement).expect("the mismatched Statement remains valid rendering");
    assert_ne!(
        statement, honest,
        "only a different valid Statement is refused"
    );
    let row = LinkedRow {
        statement: statement.clone(),
        door: busbar_plugin_loader::dispatch::load::raw(busbar_auth_ldap::door),
    };
    assert_eq!(
        load_linked::<Auth>(&row, network_bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
    assert_eq!(
        load_dropped::<Auth>(&artifact::plugin_path(), &statement, network_bind(&d)).err(),
        Some(LoadError::StatementMismatch)
    );
}

#[test]
fn the_door_refuses_every_other_kind_linked_and_dropped() {
    use busbar_plugin_loader::dispatch::kinds::{
        export::Export, hook::Hook, plane::Plane, secret::Secret, store_v4::StoreV4 as Store,
        transport::Transport,
    };
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let row = row(busbar_auth_ldap::door);
    let path = artifact::plugin_path();
    assert_eq!(
        load_linked::<Export>(&row, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Export
        })
    );
    assert_eq!(
        load_dropped::<Export>(&path, &row.statement, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Export
        })
    );
    assert_eq!(
        load_linked::<Hook>(&row, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Hook
        })
    );
    assert_eq!(
        load_dropped::<Hook>(&path, &row.statement, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Hook
        })
    );
    assert_eq!(
        load_linked::<Plane>(&row, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Plane
        })
    );
    assert_eq!(
        load_dropped::<Plane>(&path, &row.statement, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Plane
        })
    );
    assert_eq!(
        load_linked::<Secret>(&row, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Secret
        })
    );
    assert_eq!(
        load_dropped::<Secret>(&path, &row.statement, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Secret
        })
    );
    assert_eq!(
        load_linked::<Store>(&row, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Store
        })
    );
    assert_eq!(
        load_dropped::<Store>(&path, &row.statement, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Store
        })
    );
    assert_eq!(
        load_linked::<Transport>(&row, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Transport
        })
    );
    assert_eq!(
        load_dropped::<Transport>(&path, &row.statement, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::ManifestKind {
            stated: busbar_contract::abi::mechanism::KindCode::Auth,
            want: busbar_contract::abi::mechanism::KindCode::Transport
        })
    );
}

extern "C" fn wrong_abi_door<const UP: bool>() -> &'static Door {
    let real = busbar_auth_ldap::door();
    let abi = if UP {
        real.kind_abi() + 1
    } else {
        real.kind_abi().wrapping_sub(1)
    };
    // SAFETY: preserve every pointer and its lifetime, changing only the refused ABI number.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            kind_abi: abi,
            ..real.parts()
        })
    }))
}

#[test]
fn another_kind_abi_is_refused() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    for door in [wrong_abi_door::<true> as DoorFn, wrong_abi_door::<false>] {
        let host = busbar_auth_ldap::door().kind_abi();
        let abi = door().kind_abi();
        let want = busbar_plugin_loader::dispatch::LoadError::KindAbi {
            kind: busbar_contract::abi::mechanism::KindCode::Auth,
            door: abi,
            host,
        };
        assert_eq!(rendering_of(door).err(), Some(want.clone()));
        let refused = LinkedRow::of(door)
            .and_then(|r| load_linked::<Auth>(&r, network_bind(&d)))
            .err()
            .unwrap();
        assert_eq!(refused, want);
        assert!(refused.to_string().contains("rebuild"));
        let mut statement = rendering_of(busbar_auth_ldap::door).unwrap();
        let at = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 8;
        statement[at..at + 4].copy_from_slice(&door().kind_abi().to_le_bytes());
        assert_eq!(
            load_dropped::<Auth>(&artifact::plugin_path(), &statement, network_bind(&d)).err(),
            Some(busbar_plugin_loader::dispatch::LoadError::ManifestKindAbi { stated: abi, host })
        );
    }
}

static READY_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
unsafe extern "C" fn failing_ready(
    _: *mut std::ffi::c_void,
    _: *const std::ffi::c_void,
    out: *mut std::ffi::c_void,
) -> busbar_contract::abi::mechanism::call::RawOutcome {
    READY_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let failed = busbar_contract::abi::mechanism::call::RawOutcome::of(Outcome::Failed);
    // SAFETY: READY receives the host's live OutHead.
    unsafe {
        let head = &mut *out.cast::<busbar_contract::abi::mechanism::call::OutHead>();
        head.outcome = failed;
        head.error = AbiStr::of_bytes(b"LDAP readiness witness refused");
    }
    failed
}
extern "C" fn failing_ready_door() -> &'static Door {
    // SAFETY: retain this product's static data and substitute one call-convention callback.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            ready: Some(failing_ready),
            ..busbar_auth_ldap::door().parts()
        })
    }))
}

#[test]
fn red_a_failing_ready_refuses_the_boot() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let p = load_linked::<Auth>(&row(failing_ready_door), network_bind(&d)).unwrap();
    assert_eq!(
        counted(&p, 1, || open(&p, &settings())).outcome,
        Outcome::Ready
    );
    let why = counted(&p, 1, || p.ready(&d, Duration::from_secs(5))).unwrap_err();
    assert_eq!(
        why,
        format!(
            "plugin '{}' ready failed: LDAP readiness witness refused",
            p.name()
        )
    );
    assert_eq!(READY_CALLS.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn red_a_networked_door_with_no_connection_table_is_refused() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let row = LinkedRow::of_macro(MACRO_DOOR).unwrap();
    let wanted = LoadError::NoConnectionTable {
        plugin: "busbar-auth-ldap".into(),
        needs: 2,
    };
    for refused in [
        load_linked::<Auth>(&row, bind(&d, "ldap-no-table")).err(),
        load_dropped::<Auth>(
            &artifact::plugin_path(),
            &row.statement,
            bind(&d, "ldap-no-table"),
        )
        .err(),
    ] {
        let refused = refused.expect("serving LDAP without a connection table refuses");
        assert_eq!(refused, wanted);
        assert!(refused.to_string().contains("plugin 'busbar-auth-ldap'"));
    }
    load_linked::<Auth>(
        &row,
        Bind {
            conns: ConnTable::Probe,
            ..bind(&d, "ldap-probe")
        },
    )
    .expect("probe needs no serving table");
    for leg in [Leg::Linked, Leg::Dropped] {
        load(leg, network_bind(&d));
    }
}

mod custody {
    use super::*;
    use busbar_contract::abi::host::conn::connector::{service, EstablishIn, IoIn, StreamIn};
    use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
    use busbar_contract::abi::mechanism::call::RawOutcome;
    use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
    use busbar_contract::conn::ConnError;
    use busbar_plugin_loader::dispatch::conn_services::CONN_SLOTS;
    use std::os::raw::c_void;
    fn head(op: u32, size: usize) -> ServiceHead {
        ServiceHead {
            size: u32::try_from(size).unwrap_or(u32::MAX),
            op,
            handle: CompletionHandle {
                ticket: Ticket::NONE,
                seq: 0,
                _reserved: 0,
            },
        }
    }

    fn out() -> ServiceOut {
        // SAFETY: a plain repr(C) value of integers and a NULL/0 string: all-zero is valid.
        let mut out: ServiceOut = unsafe { std::mem::zeroed() };
        out.size = std::mem::size_of::<ServiceOut>() as u32;
        out
    }

    fn answered(raw: RawOutcome, o: &ServiceOut) -> (Outcome, u64, String) {
        let text = if o.error.ptr.is_null() {
            String::new()
        } else {
            // SAFETY: the host's text, `'static` (interned) or held for the call.
            String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) })
                .into_owned()
        };
        (raw.outcome(), o.value, text)
    }

    fn establish(p: &Plugin<Auth>, need: u32, target: &str) -> (Outcome, u64, String) {
        let none = AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        };
        let i = EstablishIn {
            head: head(service::ESTABLISH, std::mem::size_of::<EstablishIn>()),
            need,
            timeout_ms: 5_000,
            target: AbiStr {
                ptr: target.as_ptr(),
                len: target.len(),
            },
            within: none,
            member: none,
        };
        let mut o = out();
        let f = CONN_SLOTS.establish.expect("the host offers ESTABLISH");
        // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
        let raw = unsafe {
            f(
                p.test_host_context(),
                std::ptr::from_ref(&i).cast::<c_void>(),
                &mut o,
            )
        };
        answered(raw, &o)
    }

    fn io(p: &Plugin<Auth>, stream: u64, write: bool) -> (Outcome, u64, String) {
        let mut buf = *b"x";
        let (op, f) = if write {
            (service::WRITE, CONN_SLOTS.write)
        } else {
            (service::READ, CONN_SLOTS.read)
        };
        let i = IoIn {
            head: head(op, std::mem::size_of::<IoIn>()),
            stream,
            buf: buf.as_mut_ptr(),
            len: buf.len(),
        };
        let mut o = out();
        // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
        let raw = unsafe {
            f.expect("the host offers READ and WRITE")(
                p.test_host_context(),
                std::ptr::from_ref(&i).cast::<c_void>(),
                &mut o,
            )
        };
        answered(raw, &o)
    }

    fn close_stream(p: &Plugin<Auth>, stream: u64) -> (Outcome, u64, String) {
        let i = StreamIn {
            head: head(service::CLOSE, std::mem::size_of::<StreamIn>()),
            stream,
        };
        let mut o = out();
        // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
        let raw = unsafe {
            CONN_SLOTS.close.expect("the host offers CLOSE")(
                p.test_host_context(),
                std::ptr::from_ref(&i).cast::<c_void>(),
                &mut o,
            )
        };
        answered(raw, &o)
    }

    #[test]
    fn ldap_connections_refuse_undeclared_needs_and_other_instances() {
        let d = Dispatcher::new(
            DispatchConfig::default(),
            busbar_contract::services::test_caller_binding(),
        );
        let table = Arc::new(sealed_replay::Carrier::new(d.conn_waker(), false, false));
        for leg in [Leg::Linked, Leg::Dropped] {
            let owner = load(
                leg,
                Bind {
                    conns: ConnTable::Host(table.clone()),
                    ..bind(&d, "ldap-owner")
                },
            );
            let other = load(
                leg,
                Bind {
                    conns: ConnTable::Host(table.clone()),
                    ..bind(&d, "ldap-other")
                },
            );
            owner.test_in_host_operation(|| {
                let (outcome, stream, text) = establish(&owner, 0, "localhost:389");
                assert_eq!(outcome, Outcome::Ready, "{text}");
                assert_eq!(io(&owner, stream, true).0, Outcome::Ready);
                for need in [2, u32::MAX] {
                    let (outcome, _, text) = establish(&owner, need, "localhost:389");
                    assert_eq!(
                        (outcome, text.as_str()),
                        (Outcome::Refused, ConnError::UndeclaredNeed.text())
                    );
                }
                for answer in [
                    io(&other, stream, true),
                    io(&other, stream, false),
                    close_stream(&other, stream),
                ] {
                    assert_eq!(
                        (answer.0, answer.2.as_str()),
                        (Outcome::Refused, ConnError::NotOwner.text())
                    );
                }
                assert_eq!(io(&owner, stream, true).0, Outcome::Ready);
                assert_eq!(close_stream(&owner, stream).0, Outcome::Ready);
            });
        }
    }
}

extern "C" fn wrong_layout_door<const ZERO: bool>() -> &'static Door {
    let real = busbar_auth_ldap::door();
    // SAFETY: only the rejected fingerprint is changed; all product pointers stay static.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            layout: if ZERO { 0 } else { real.layout() ^ 1 },
            ..real.parts()
        })
    }))
}

#[test]
fn red_a_door_built_against_another_kind_layout_is_refused() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let honest = LinkedRow::of_macro(MACRO_DOOR).unwrap();
    for door in [
        wrong_layout_door::<false> as DoorFn,
        wrong_layout_door::<true>,
    ] {
        let refused = rendering_of(door).unwrap_err();
        let LoadError::KindLayout {
            kind, stated, host, ..
        } = &refused
        else {
            panic!("{refused:?}")
        };
        assert_eq!(*kind, busbar_contract::abi::mechanism::KindCode::Auth);
        assert_eq!(*stated, door().layout());
        assert_eq!(*host, busbar_auth_ldap::door().layout());
        assert!(refused
            .to_string()
            .contains("rebuild against this busbar-contract"));
        assert_eq!(
            load_linked::<Auth>(
                &LinkedRow {
                    statement: honest.statement.clone(),
                    door: busbar_plugin_loader::dispatch::load::raw(door),
                },
                network_bind(&d)
            )
            .err(),
            Some(refused.clone())
        );
        assert_eq!(
            LinkedRow::of(door)
                .and_then(|row| load_linked::<Auth>(&row, network_bind(&d)))
                .err(),
            Some(refused)
        );
    }
    for leg in [Leg::Linked, Leg::Dropped] {
        load(leg, network_bind(&d));
    }
}

#[test]
fn ldap_has_no_plane_transport_or_outbound_family() {
    use busbar_contract::abi::{auth, mechanism::KindCode};
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    for leg in [Leg::Linked, Leg::Dropped] {
        let p = load(leg, network_bind(&d));
        assert_eq!(p.kind(), KindCode::Auth);
        let facts = p
            .context::<busbar_plugin_loader::dispatch::kinds::auth::AuthFacts>()
            .unwrap();
        assert_eq!(facts.caps, auth::CAP_LOGIN);
        assert_eq!(facts.login_kind, auth::LOGIN_KIND_CREDENTIAL);
        assert!(facts.styles.is_empty());
        assert_eq!(facts.caps & auth::CAP_OUTBOUND, 0, "no outbound family");
        assert_eq!(
            facts.caps & auth::CAP_INBOUND,
            0,
            "no data-plane (inbound) family"
        );
    }
}

extern "C" fn another_version_door() -> &'static Door {
    let real = busbar_auth_ldap::door();
    // SAFETY: real's Statement points at immutable static product data; copy it and change only version.
    let mut statement = unsafe { *real.statement() };
    statement.version = AbiStr::of_bytes(b"99.0.0");
    let statement = Box::leak(Box::new(statement));
    // SAFETY: the replacement Statement and all original door pointers remain static.
    Box::leak(Box::new(unsafe {
        Door::__from_parts(DoorParts {
            statement: std::ptr::from_ref(statement),
            ..real.parts()
        })
    }))
}
#[test]
fn a_restated_version_does_not_match_the_honest_row() {
    let d = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let row = LinkedRow {
        statement: rendering_of(busbar_auth_ldap::door).unwrap(),
        door: busbar_plugin_loader::dispatch::load::raw(another_version_door),
    };
    assert_eq!(
        load_linked::<Auth>(&row, network_bind(&d)).err(),
        Some(busbar_plugin_loader::dispatch::LoadError::StatementMismatch)
    );
}

fn conformance_inputs() -> serde_json::Value {
    let front = conformance_host::tls_front(start_tls, upstream());
    serde_json::from_str(
        &include_str!("conformance.json").replace(conformance_host::FAR_END, front),
    )
    .expect("conformance settings with the actual bound relay address")
}
