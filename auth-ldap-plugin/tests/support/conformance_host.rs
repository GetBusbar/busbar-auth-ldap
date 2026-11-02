// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Test-side socket I/O for the actual LDAP directory. No LDAP requests or replies are invented.
use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, ConnWake, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc,
    Piece, PieceKind, Ticket,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::{CertFacts, ConnFacts, EgressTrust};
use busbar_core_connector::test_support::certs_from_pem;
use busbar_core_connector::DialJudge;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
#[path = "ldap_tls.rs"]
mod ldap_tls;
pub use ldap_tls::anchors;
pub const FAR_END: &str = "localhost:41859";

pub fn tls_front(preamble: fn(&mut TcpStream) -> bool, upstream: &'static str) {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| ldap_tls::start(FAR_END, preamble, upstream));
}

#[derive(Clone)]
struct Need {
    answer: Result<(), ConnError>,
    target: Option<String>,
    class: u32,
    anchors: Option<String>,
}
enum Wire {
    Plain(TcpStream),
    Secure(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}
struct Socket {
    first_read: bool,
    wire: Option<Wire>,
    server: String,
    tls: Arc<rustls::ClientConfig>,
    facts: Option<ConnFacts>,
}
struct DirectoryIo {
    wake: ConnWake,
    needs: Mutex<BTreeMap<(InstanceId, NeedId), Need>>,
    sockets: ConnSlab<Mutex<Socket>>,
    anchors: Option<String>,
    judge: Option<Arc<dyn DialJudge>>,
}

pub fn host(wake: ConnWake, anchors: Option<&str>) -> Arc<dyn DeclaredConns> {
    Arc::new(DirectoryIo {
        wake,
        needs: Mutex::default(),
        sockets: ConnSlab::default(),
        anchors: anchors.map(str::to_owned),
        judge: None,
    })
}
pub fn guarded_host(wake: ConnWake, anchors: Option<&str>) -> Arc<dyn DeclaredConns> {
    // The production destination policy's default blocks private destinations; operator
    // infrastructure retains its production exception and metadata is still refused.
    let dest = Arc::new(busbar_core_connector::process::GuardJudge::new(
        busbar_core_connector::guard::Guard::default(),
        Arc::new(busbar_core_connector::guard::SystemResolver),
    ));
    Arc::new(DirectoryIo {
        wake,
        needs: Mutex::default(),
        sockets: ConnSlab::default(),
        anchors: anchors.map(str::to_owned),
        judge: Some(busbar_core_connector::process::judge(dest, &[])),
    })
}
fn io_error(e: std::io::Error) -> ConnError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => ConnError::Pending,
        _ => ConnError::Closed,
    }
}
impl DirectoryIo {
    fn wake_later(&self, owner: InstanceId, ticket: Ticket) {
        let wake = self.wake.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(2));
            wake(owner, ticket);
        });
    }
}
impl Conns for DirectoryIo {
    fn open(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let n = self
            .needs
            .lock()
            .unwrap()
            .get(&(owner, need))
            .cloned()
            .ok_or(ConnError::UndeclaredNeed)?;
        n.answer?;
        if n.target.as_deref().is_some_and(|t| t != desc.target) {
            return Err(ConnError::Refused);
        }
        let extra_anchors = match n.anchors.as_deref() {
            Some(pem) => {
                busbar_core_connector::tls::client::operator_ca_config(pem.as_bytes())
                    .map_err(|_| ConnError::Refused)?;
                certs_from_pem(pem)
            }
            None => Vec::new(),
        };
        let tls = Arc::new(
            busbar_core_connector::tls::client::build_client_config(&EgressTrust {
                extra_anchors,
                ..EgressTrust::default()
            })
            .map_err(|_| ConnError::Refused)?,
        );
        let at = if let Some(judge) = &self.judge {
            let (tx, rx) = std::sync::mpsc::channel();
            judge
                .judge_dial(
                    desc.target,
                    n.class,
                    Box::new(move |v| {
                        let _ = tx.send(v);
                    }),
                )
                .unwrap_or_else(|| rx.recv_timeout(Duration::from_secs(10)).unwrap_or(Err(0)))
                .map_err(|_| ConnError::Refused)?
        } else {
            desc.target
                .to_socket_addrs()
                .map_err(|_| ConnError::Fault)?
                .find(|a| a.ip().is_loopback())
                .ok_or(ConnError::Refused)?
        };
        if !desc.within.is_empty() && !desc.within.contains(&at.ip()) {
            return Err(ConnError::Refused);
        }
        let tcp = TcpStream::connect_timeout(
            &at,
            Duration::from_millis(if desc.timeout_ms == 0 {
                5000
            } else {
                desc.timeout_ms
            }),
        )
        .map_err(io_error)?;
        tcp.set_read_timeout(Some(Duration::from_millis(2)))
            .map_err(io_error)?;
        tcp.set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(io_error)?;
        self.sockets.insert(
            owner,
            need,
            Mutex::new(Socket {
                first_read: true,
                wire: Some(Wire::Plain(tcp)),
                server: desc
                    .target
                    .rsplit_once(':')
                    .map_or(desc.target, |v| v.0)
                    .to_owned(),
                tls,
                facts: None,
            }),
        )
    }
    fn write(
        &self,
        owner: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        let (_, socket) = self.sockets.get(owner, conn)?;
        let mut socket = socket.lock().unwrap();
        let n = match socket.wire.as_mut().ok_or(ConnError::Closed)? {
            Wire::Plain(s) => s.write(bytes),
            Wire::Secure(s) => s.write(bytes).and_then(|n| s.flush().map(|()| n)),
        };
        n.map_err(io_error)
    }
    fn read(
        &self,
        owner: InstanceId,
        conn: ConnId,
        ticket: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        let (_, socket) = self.sockets.get(owner, conn)?;
        let mut socket = socket.lock().unwrap();
        // Model host scheduling at the first actual socket read: return PENDING with a
        // registered ticket wake before delivering directory bytes on the resumed call.
        if socket.first_read {
            socket.first_read = false;
            self.wake_later(owner, ticket);
            return Err(ConnError::Pending);
        }
        let n = match socket.wire.as_mut().ok_or(ConnError::Closed)? {
            Wire::Plain(s) => s.read(buf),
            Wire::Secure(s) => s.read(buf),
        }
        .map_err(io_error);
        let n = match n {
            Err(ConnError::Pending) => {
                self.wake_later(owner, ticket);
                return Err(ConnError::Pending);
            }
            other => other?,
        };
        Ok(Piece {
            kind: if n == 0 {
                PieceKind::Completion
            } else {
                PieceKind::Body
            },
            stream: StreamId(0),
            len: n,
            end: true,
            status: None,
            status_code: None,
            reason: None,
            status_namespace: None,
            declared_len: None,
            fault: None,
            retry_after_secs: None,
        })
    }
    fn wait(&self, owner: InstanceId, set: &[ConnId], ticket: Ticket) -> Result<usize, ConnError> {
        for id in set {
            self.sockets.get(owner, *id)?;
        }
        self.wake_later(owner, ticket);
        Err(ConnError::Pending)
    }
    fn facts(&self, owner: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        let (_, socket) = self.sockets.get(owner, conn)?;
        let socket = socket.lock().unwrap();
        match socket.wire.as_ref() {
            Some(Wire::Secure(_)) => socket.facts.clone().ok_or(ConnError::Fault),
            Some(Wire::Plain(_)) => Ok(ConnFacts::default()),
            None => Err(ConnError::Closed),
        }
    }
    fn close(&self, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.sockets.remove(owner, conn)?;
        Ok(())
    }
}
impl DeclaredConns for DirectoryIo {
    fn open_request(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        // This raw adapter uses this copy's timeout only for connect_timeout; the
        // original stream/request deadline remains with the actual dispatcher.
        let mut dial = desc.clone();
        if dial_timeout_ms != 0 {
            dial.timeout_ms = if desc.timeout_ms == 0 {
                dial_timeout_ms
            } else {
                dial_timeout_ms.min(desc.timeout_ms)
            };
        }
        self.open_with_security(owner, need, &dial, require_secure)
    }
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        let answer = if spec.direction != DIRECTION_OUTBOUND
            || spec.transport != "tcp"
            || (!spec.target_from.is_empty() && target.is_none())
            || (!spec.trust_from.is_empty() && trust.is_none())
        {
            Err(ConnError::Refused)
        } else {
            Ok(())
        };
        // A declaration stores operator input; settings-only validation must still reach
        // the real LDAP door. Validate/parse trust before an actual socket is opened.
        let anchors = trust.or(self.anchors.as_deref()).map(str::to_owned);
        self.needs.lock().unwrap().insert(
            (owner, need),
            Need {
                answer,
                target: target.map(str::to_owned),
                class: spec.egress_class,
                anchors,
            },
        );
        if answer.is_ok() {
            self.sockets.declare(owner, need);
        }
        answer
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.needs
            .lock()
            .unwrap()
            .get(&(owner, need))
            .map(|n| n.answer)
    }
    fn serves_scheme(&self, scheme: &str) -> bool {
        scheme == "tcp"
    }
    fn upgrade_secure(
        &self,
        owner: InstanceId,
        conn: ConnId,
        name: Option<&str>,
        trust: Option<&str>,
        verify_off: bool,
        _: Ticket,
    ) -> Result<(), ConnError> {
        if verify_off || trust.is_some() {
            return Err(ConnError::Refused);
        }
        let (_, socket) = self.sockets.get(owner, conn)?;
        let mut socket = socket.lock().unwrap();
        let Some(Wire::Plain(mut tcp)) = socket.wire.take() else {
            return Err(ConnError::Refused);
        };
        tcp.set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(io_error)?;
        let server_name =
            rustls::pki_types::ServerName::try_from(name.unwrap_or(&socket.server).to_owned())
                .map_err(|_| ConnError::Refused)?;
        let offered_sni = match &server_name {
            rustls::pki_types::ServerName::DnsName(dns) => Some(dns.as_ref().to_owned()),
            _ => None,
        };
        let mut tls = rustls::ClientConnection::new(socket.tls.clone(), server_name)
            .map_err(|_| ConnError::Refused)?;
        while tls.is_handshaking() {
            tls.complete_io(&mut tcp).map_err(|_| ConnError::Refused)?;
        }
        let leaf = tls
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or(ConnError::Refused)?;
        let fingerprint = Sha256::digest(leaf.as_ref())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let facts = ConnFacts {
            sni: offered_sni,
            alpn: tls
                .alpn_protocol()
                .map(|alpn| String::from_utf8_lossy(alpn).into_owned()),
            peer_cert: Some(CertFacts {
                // DN rendering is not provided by this raw I/O adapter. The fingerprint
                // is from the actual peer leaf, observed after chain/name verification.
                subject: String::new(),
                issuer: String::new(),
                fingerprint,
            }),
            peer_key_pin: busbar_core_connector::tls::client::peer_key_pin(leaf.as_ref()),
            ..ConnFacts::default()
        };
        tcp.set_read_timeout(Some(Duration::from_millis(2)))
            .map_err(io_error)?;
        socket.wire = Some(Wire::Secure(Box::new(rustls::StreamOwned::new(tls, tcp))));
        socket.facts = Some(facts);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::abi::host::conn::connector::{
        EGRESS_DEFAULT, EGRESS_OPERATOR_INFRASTRUCTURE,
    };
    use busbar_contract::abi::mechanism::rendering::ReadBlob;
    const OWNER: InstanceId = InstanceId(7);
    fn declare(c: &dyn DeclaredConns, id: u32, class: u32) {
        c.declare(
            OWNER,
            NeedId(id),
            &ReadNeed {
                direction: DIRECTION_OUTBOUND,
                egress_class: class,
                transport: "tcp".into(),
                auth: String::new(),
                target_from: String::new(),
                trust_from: String::new(),
                details: ReadBlob {
                    fmt: 0,
                    flags: 0,
                    bytes: Vec::new(),
                },
                timeout_ms: 0,
                keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
                keep_response_headers: Vec::new(),
                deny_response_headers: Vec::new(),
            },
            None,
            None,
        )
        .unwrap();
    }
    fn upgraded_echo(trust: Option<&str>) -> Result<Vec<u8>, ConnError> {
        let echo = TcpListener::bind("127.0.0.1:0").unwrap();
        let backend = echo.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            let (mut s, _) = echo.accept().unwrap();
            let mut bytes = [0; 5];
            if s.read_exact(&mut bytes).is_ok() {
                let _ = s.write_all(&bytes);
            }
        });
        let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reservation.local_addr().unwrap().to_string();
        drop(reservation);
        ldap_tls::start(&address, |_| true, &backend);
        let c = host(Arc::new(|_, _| {}), trust);
        declare(c.as_ref(), 0, EGRESS_OPERATOR_INFRASTRUCTURE);
        let id = c.open(
            OWNER,
            NeedId(0),
            &OpenDesc {
                target: &address,
                timeout_ms: 5000,
                ..OpenDesc::default()
            },
        )?;
        assert!(
            c.facts(OWNER, id)?.peer_cert.is_none(),
            "plain TCP has no TLS peer"
        );
        c.upgrade_secure(OWNER, id, Some("localhost"), None, false, 0)?;
        let facts = c.facts(OWNER, id)?;
        assert!(
            facts
                .peer_cert
                .as_ref()
                .is_some_and(|cert| !cert.fingerprint.is_empty()),
            "actual verified TLS must report its observed peer certificate"
        );
        let mut at = 0;
        while at < 5 {
            at += c.write(OWNER, id, &b"hello"[at..], false, false)?;
        }
        let until = std::time::Instant::now() + Duration::from_secs(10);
        let mut answer = Vec::new();
        let mut buf = [0; 5];
        while answer.len() < 5 {
            match c.read(OWNER, id, 0, &mut buf) {
                Ok(piece) if piece.kind == PieceKind::Body => {
                    answer.extend_from_slice(&buf[..piece.len])
                }
                Err(ConnError::Pending) if std::time::Instant::now() < until => {}
                other => panic!("TLS echo failed: {other:?}"),
            }
        }
        c.close(OWNER, id)?;
        Ok(answer)
    }
    #[test]
    fn the_hosts_tls_upgrade_verifies_against_the_suites_test_anchors() {
        assert_eq!(upgraded_echo(Some(anchors())), Ok(b"hello".to_vec()));
    }
    #[test]
    fn red_with_the_anchors_withheld_the_hosts_tls_upgrade_is_refused() {
        let answer = upgraded_echo(None);
        assert!(answer.is_err(), "upgraded over an untrusted CA: {answer:?}");
    }
    #[test]
    fn the_conformance_host_guard_refuses_a_private_destination() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let c = guarded_host(Arc::new(|_, _| {}), Some(anchors()));
        for (id, class, target) in [
            (0, EGRESS_DEFAULT, "10.0.0.1:443"),
            (1, EGRESS_DEFAULT, address.as_str()),
            (2, EGRESS_OPERATOR_INFRASTRUCTURE, "169.254.169.254:80"),
        ] {
            declare(c.as_ref(), id, class);
            assert_eq!(
                c.open(
                    OWNER,
                    NeedId(id),
                    &OpenDesc {
                        target,
                        timeout_ms: 2000,
                        ..OpenDesc::default()
                    }
                )
                .map(|_| ()),
                Err(ConnError::Refused)
            );
        }
        assert!(
            listener.accept().is_err(),
            "refused destination was dialled"
        );
        declare(c.as_ref(), 3, EGRESS_OPERATOR_INFRASTRUCTURE);
        let id = c
            .open(
                OWNER,
                NeedId(3),
                &OpenDesc {
                    target: &address,
                    timeout_ms: 2000,
                    ..OpenDesc::default()
                },
            )
            .expect("production operator-infrastructure class allows loopback");
        assert!(
            listener.accept().is_ok(),
            "admitted dial reached the real listener"
        );
        c.close(OWNER, id).unwrap();
    }
}
