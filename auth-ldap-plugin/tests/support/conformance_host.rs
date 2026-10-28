// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// RENDERED by `busbar-release plugin heal busbar-auth-ldap` from GetBusbar/busbar-release
// template/conformance-host/, because this repo's declares file states network needs (`needs`:
// `tcp`); a hand edit is overwritten by the next sync.

//! **THE SUITE'S HOST CONNECTION TABLE, IN THIS PLUGIN'S OWN TEST** (ARCHITECT Q-P4-9 (d)). busbar
//! keeps only the neutral seam (`busbar_test_kit::conformance::Host`, the suite's `host:` and
//! `tls:` arguments); this adapter serves it with busbar's test kit's stream table
//! ([`TcpConns`]), the plugin reaching the network only through the host's connection slots over
//! the ABI, as every plugin does. No transport plugin's crate is linked: a plugin depends on no
//! other plugin's code (the memory-ABI rule), and busbar at the pin links no framer.
//!
//! * the table dials the REAL local endpoints the suite's settings name (`host:port`), never the
//!   network beyond loopback;
//! * `upgrade_secure` runs the connector's own client TLS (`busbar_core_connector::tls`), trusting
//!   the platform roots plus the suite's TEST trust anchors (`tls:`), never handed to the plugin: no
//!   plugin holds a key, a certificate or a TLS type (TRANSPORT-STACK (1));
//! * a parked read wakes the plugin's ticket through the leg dispatcher's conn waker.
//!
//! [`far_end`] is a TLS far end at [`FAR_END`] whose certificate chains to [`anchors`] (busbar's
//! test kit, `busbar_core_connector::test_support`): the plugin's `conformance.json` settings name
//! it, and its `answer` speaks the plugin's protocol. Its own tests, below, run with the suite:
//! a TLS upgrade verifies against the anchors, and is REFUSED with the anchors withheld (RED).
//!
//! The plugin's `tests/conformance.rs` mounts this file and names it:
//!
//! ```ignore
//! #[path = "support/conformance_host.rs"]
//! mod conformance_host;
//!
//! busbar_test_kit::conformance_suite! {
//!     door: …, cdylib: …, inputs: include_str!("conformance.json"),
//!     host: conformance_host::host,
//!     tls: conformance_host::anchors(),
//! }
//! ```
//!
//! with the dev-dependencies the root `Cargo.toml` states (`{ workspace = true }`):
//! `busbar-test-kit`, `busbar-core-connector`, `rustls`.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use busbar_contract::abi::host::conn::connector::{
    DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE,
};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::conn::{
    ConnError, ConnId, DeclaredConns, InstanceId, NeedId, OpenDesc, PieceKind, NO_TICKET,
};
use busbar_contract::transport::EgressTrust;
use busbar_core_connector::test_support::{private_ca, ServerTls, StdServerSession, TestCa};
use busbar_test_kit::tcp_conns::{SecureDial, SecuredSock, TcpConns};

/// Where [`far_end`] listens: loopback, a port of this repo's own.
pub const FAR_END: &str = "localhost:41859";

/// The suite's test CA: [`anchors`] is its certificate, [`far_end`] serves a leaf it signed.
fn ca() -> &'static TestCa {
    static CA: OnceLock<TestCa> = OnceLock::new();
    CA.get_or_init(private_ca)
}

/// THE SUITE'S TEST TRUST ANCHORS (PEM), for `conformance_suite!`'s `tls:`.
#[must_use]
pub fn anchors() -> &'static str {
    &ca().ca_pem
}

/// THE HOST CONNECTION TABLE (`busbar_test_kit::conformance::Host`): one per leg.
///
/// # Panics
/// The anchors do not parse, or the connector's client TLS does not build.
#[must_use]
pub fn host(
    wake: busbar_contract::conn::ConnWake,
    anchors: Option<&str>,
) -> Arc<dyn DeclaredConns> {
    let trust = EgressTrust {
        extra_anchors: anchors.map(pem_certs).unwrap_or_default(),
        ..EgressTrust::default()
    };
    let tls = busbar_core_connector::tls::client::build_client_config(&trust)
        .unwrap_or_else(|e| panic!("the host's connection security does not build: {e}"));
    Arc::new(TcpConns::with_tls(wake, Arc::new(HostTls(Arc::new(tls)))))
}

/// The connector's client TLS, as the table's [`SecureDial`]: the handshake runs to completion on
/// the blocking socket, verified against the trust it was built with.
struct HostTls(Arc<rustls::ClientConfig>);

impl SecureDial for HostTls {
    fn secure(
        &self,
        server: &str,
        verify_off: bool,
        mut tcp: TcpStream,
    ) -> std::io::Result<Box<dyn SecuredSock>> {
        if verify_off {
            // The suite's needs always verify; an unverified upgrade is not served here.
            return Err(std::io::Error::other("an unverified upgrade is not served"));
        }
        let name = rustls::pki_types::ServerName::try_from(server.to_owned())
            .map_err(|e| std::io::Error::other(format!("server name {server:?}: {e}")))?;
        let mut session = rustls::ClientConnection::new(Arc::clone(&self.0), name)
            .map_err(std::io::Error::other)?;
        while session.is_handshaking() {
            session.complete_io(&mut tcp)?;
        }
        Ok(Box::new(Secured(rustls::StreamOwned::new(session, tcp))))
    }
}

/// One secured stream.
struct Secured(rustls::StreamOwned<rustls::ClientConnection, TcpStream>);

impl Read for Secured {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Secured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

impl SecuredSock for Secured {
    fn tcp(&self) -> &TcpStream {
        self.0.get_ref()
    }

    fn close(&mut self) {
        self.0.conn.send_close_notify();
        let _ = self.0.flush();
        let _ = self.0.sock.shutdown(std::net::Shutdown::Both);
    }
}

/// Every certificate in `pem`, DER.
fn pem_certs(pem: &str) -> Vec<Vec<u8>> {
    let certs = busbar_core_connector::test_support::certs_from_pem(pem);
    assert!(
        !certs.is_empty(),
        "the suite's trust anchors hold no certificate"
    );
    certs
}

// ---- the far end ----

/// What a far end answers a connection: given every byte it has read so far, the bytes to send
/// back and close (`Some`), or `None` to read on.
pub type Answer = fn(&[u8]) -> Option<Vec<u8>>;

/// THE SUITE'S TLS FAR END at [`FAR_END`] (started once; later calls are no-ops): every connection's
/// handshake is busbar's test kit's, with a `localhost` certificate [`anchors`] trusts, and its
/// bytes are answered by `answer`.
///
/// # Panics
/// [`FAR_END`] cannot be bound.
pub fn far_end(answer: Answer) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let listener = TcpListener::bind(FAR_END)
            .unwrap_or_else(|e| panic!("the suite's far end cannot bind {FAR_END}: {e}"));
        serve(listener, answer);
    });
}

/// Serve `listener` over TLS with a leaf the test CA signed, answering each connection by `answer`.
fn serve(listener: TcpListener, answer: Answer) {
    let tls = ServerTls::new(&[ca().leaf_der.clone()], &ca().key_der, None, &[])
        .unwrap_or_else(|e| panic!("the suite's far end has no TLS identity: {e}"));
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { return };
            let tls = tls.clone();
            std::thread::spawn(move || {
                if let Ok(mut s) = tls.accept_std(tcp) {
                    if s.handshake_ok() {
                        reply(&mut s, answer);
                    }
                }
            });
        }
    });
}

fn reply(s: &mut StdServerSession, answer: Answer) {
    let mut seen = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        if let Some(out) = answer(&seen) {
            let _ = s.write_all(&out);
            let _ = s.flush();
            s.close();
            return;
        }
        match s.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => seen.extend_from_slice(&buf[..n]),
        }
    }
}

/// A far end's cleartext negotiation before TLS (a protocol's own StartTLS: Postgres's
/// `SSLRequest` answered `S`, LDAP's StartTLS extended operation, ...): `true` = go on to TLS.
pub type Preamble = fn(&mut TcpStream) -> bool;

/// THE SUITE'S TLS FRONT at [`FAR_END`] (started once; later calls are no-ops): each connection's
/// cleartext `preamble` runs, then the TLS handshake (busbar's test kit, a `localhost` certificate
/// [`anchors`] trusts), then its bytes are carried both ways to the REAL backend at `upstream`
/// (the plugin's live service, in the clear on loopback). What it proves: the plugin's own
/// connection is secured by the HOST's TLS against the suite's anchors.
///
/// # Panics
/// [`FAR_END`] cannot be bound.
pub fn tls_front(preamble: Preamble, upstream: &'static str) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let listener = TcpListener::bind(FAR_END)
            .unwrap_or_else(|e| panic!("the suite's TLS front cannot bind {FAR_END}: {e}"));
        let tls = ServerTls::new(&[ca().leaf_der.clone()], &ca().key_der, None, &[])
            .unwrap_or_else(|e| panic!("the suite's TLS front has no TLS identity: {e}"));
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let Ok(tcp) = tcp else { return };
                let tls = tls.clone();
                std::thread::spawn(move || front(tcp, &tls, preamble, upstream));
            }
        });
    });
}

/// One connection through the TLS front: preamble, handshake, then both directions carried until
/// either side ends.
fn front(mut tcp: TcpStream, tls: &ServerTls, preamble: Preamble, upstream: &str) {
    if !preamble(&mut tcp) {
        return;
    }
    let Ok(ctl) = tcp.try_clone() else { return };
    let Ok(mut s) = tls.accept_std(tcp) else {
        return;
    };
    if !s.handshake_ok() {
        return;
    }
    let Ok(mut up) = TcpStream::connect(upstream) else {
        return;
    };
    let tick = Some(Duration::from_millis(2));
    if ctl.set_read_timeout(tick).is_err() || up.set_read_timeout(tick).is_err() {
        return;
    }
    let idle = |e: &std::io::Error| {
        matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )
    };
    let mut buf = [0_u8; 16 * 1024];
    loop {
        match s.read(&mut buf) {
            Ok(0) => return,
            Ok(n) => {
                if up.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
            Err(e) if idle(&e) => {}
            Err(_) => return,
        }
        match up.read(&mut buf) {
            Ok(0) => {
                s.close();
                return;
            }
            Ok(n) => {
                if s.write_all(&buf[..n]).and_then(|()| s.flush()).is_err() {
                    return;
                }
            }
            Err(e) if idle(&e) => {}
            Err(_) => return,
        }
    }
}

// ---- the host's own proof, run with the suite ----

const OWNER: InstanceId = InstanceId(7);

fn need(transport: &str, class: u32) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: class,
        transport: transport.to_owned(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 0,
    }
}

/// `f` until it answers other than PENDING, as a plugin's re-entries on its ticket would.
fn settle<T>(mut f: impl FnMut() -> Result<T, ConnError>) -> Result<T, ConnError> {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        match f() {
            Err(ConnError::Pending) if Instant::now() < until => {
                std::thread::sleep(Duration::from_millis(2));
            }
            answered => return answered,
        }
    }
}

/// Read `id` to its completion (or `want` body bytes): its fields pieces' count and its body.
fn drain(c: &dyn DeclaredConns, id: ConnId, want: usize) -> (usize, Vec<u8>) {
    let (mut fields, mut body) = (0, Vec::new());
    let mut buf = [0_u8; 256];
    while body.len() < want {
        let Ok(p) = settle(|| c.read(OWNER, id, NO_TICKET, &mut buf)) else {
            break;
        };
        match p.kind {
            PieceKind::Fields => fields += 1,
            PieceKind::Body => body.extend_from_slice(&buf[..p.len]),
            PieceKind::Completion => break,
            PieceKind::HookReply => {}
        }
    }
    (fields, body)
}

/// Five bytes back for five bytes in: the TLS echo the host's own proof dials.
fn echo(seen: &[u8]) -> Option<Vec<u8>> {
    (seen.len() >= 5).then(|| seen[..5].to_vec())
}

/// A raw `tcp` stream to a TLS echo, upgraded through the host's TLS: what came back.
fn upgraded_echo(c: &dyn DeclaredConns, far: &str) -> Result<Vec<u8>, ConnError> {
    c.declare(
        OWNER,
        NeedId(0),
        &need("tcp", EGRESS_OPERATOR_INFRASTRUCTURE),
        None,
        None,
    )?;
    let id = settle(|| {
        c.open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: far,
                timeout_ms: 5_000,
                ..OpenDesc::default()
            },
        )
    })?;
    settle(|| c.upgrade_secure(OWNER, id, Some("localhost"), None, false, NO_TICKET))?;
    let mut at = 0;
    while at < 5 {
        at += settle(|| c.write(OWNER, id, &b"hello"[at..], false, false))?;
    }
    let (_, body) = drain(c, id, 5);
    let _ = c.close(OWNER, id);
    Ok(body)
}

/// A TLS echo on a port of its own; its address.
fn tls_echo() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a local listener");
    let at = listener.local_addr().expect("its address").to_string();
    serve(listener, echo);
    at
}

/// THE HOST'S TLS TRUSTS THE SUITE'S TEST ANCHORS: a stream to a far end whose certificate chains
/// to the test CA is upgraded and round-trips (the anchors went to the host, never to the plugin).
#[test]
fn the_hosts_tls_upgrade_verifies_against_the_suites_test_anchors() {
    let c = host(Arc::new(|_, _| {}), Some(anchors()));
    assert_eq!(
        upgraded_echo(c.as_ref(), &tls_echo()),
        Ok(b"hello".to_vec())
    );
}

/// RED: the same upgrade with the anchors withheld is refused: the platform roots alone do not
/// trust the test CA.
#[test]
fn red_with_the_anchors_withheld_the_hosts_tls_upgrade_is_refused() {
    let c = host(Arc::new(|_, _| {}), None);
    let answer = upgraded_echo(c.as_ref(), &tls_echo());
    assert!(answer.is_err(), "upgraded over an untrusted CA: {answer:?}");
}
