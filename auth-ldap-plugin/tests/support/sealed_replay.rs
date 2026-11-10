// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The real LDAP door and loader completion store over a scripted raw carrier. The
//! carrier controls partial writes and wakes; it never implements service replay.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::{bind, close, load, open, Leg};
use busbar_contract::abi::auth::LOGIN_IDENTITY;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, ConnWake, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc,
    Piece, PieceKind, Ticket,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::{CertFacts, ConnFacts};
use busbar_plugin_loader::dispatch::{ConnTable, DispatchConfig, Dispatcher};

struct State {
    ticket: Ticket,
    written: Vec<u8>,
    replies: VecDeque<Vec<u8>>,
    writes: usize,
    pended: bool,
    secured: bool,
    facts: usize,
    closes: usize,
    /// The dial bound of every ESTABLISH the host was asked for, in milliseconds.
    dials: Vec<u64>,
}

pub(super) struct Carrier {
    streams: ConnSlab<()>,
    wake: ConnWake,
    partial: bool,
    pend: bool,
    state: Mutex<State>,
}

impl Carrier {
    pub(super) fn new(wake: ConnWake, partial: bool, pend: bool) -> Self {
        Self {
            streams: ConnSlab::default(),
            wake,
            partial,
            pend,
            state: Mutex::new(State {
                ticket: 0,
                written: Vec::new(),

                replies: [
                    vec![0x30, 12, 2, 1, 1, 0x61, 7, 10, 1, 0, 4, 0, 4, 0],
                    vec![0x30, 12, 2, 1, 2, 0x65, 7, 10, 1, 0, 4, 0, 4, 0],
                ]
                .into(),
                writes: 0,
                pended: false,
                secured: false,
                facts: 0,
                closes: 0,
                dials: Vec::new(),
            }),
        }
    }
}

impl Conns for Carrier {
    fn open(&self, owner: InstanceId, need: NeedId, _: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        self.streams.insert(owner, need, ())
    }

    fn write(
        &self,
        caller: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        self.streams.get(caller, conn)?;
        let mut state = self.state.lock().unwrap();
        state.writes += 1;
        if self.partial && state.writes == 1 {
            let n = 3.min(bytes.len());
            state.written.extend_from_slice(&bytes[..n]);
            return Ok(n);
        }
        if self.pend && !state.pended {
            state.pended = true;
            let ticket = state.ticket;
            assert_ne!(ticket, 0, "the real ESTABLISH registered the ticket");
            drop(state);

            (self.wake)(caller, ticket);
            return Err(ConnError::Pending);
        }
        state.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn read(
        &self,
        caller: InstanceId,
        conn: ConnId,
        _: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.streams.get(caller, conn)?;
        let reply = self.state.lock().unwrap().replies.pop_front().unwrap();
        assert!(reply.len() <= buf.len());
        buf[..reply.len()].copy_from_slice(&reply);
        Ok(Piece {
            kind: PieceKind::Body,
            stream: StreamId(0),
            len: reply.len(),
            end: true,
            status: None,
            status_code: None,
            status_namespace: None,
            retry_after_secs: None,
            fault: None,
            reason: None,
            declared_len: None,
        })
    }

    fn wait(&self, caller: InstanceId, set: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        for conn in set {
            self.streams.get(caller, *conn)?;
        }
        Err(ConnError::Pending)
    }

    fn facts(&self, caller: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.streams.get(caller, conn)?;
        let mut state = self.state.lock().unwrap();
        state.facts += 1;
        Ok(ConnFacts {
            peer_cert: state.secured.then(|| CertFacts {
                subject: "scripted directory".into(),
                issuer: "scripted CA".into(),
                fingerprint: "scripted-secure-connection".into(),
            }),
            ..ConnFacts::default()
        })
    }

    fn close(&self, caller: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.streams.remove(caller, conn)?;
        self.state.lock().unwrap().closes += 1;
        Ok(())
    }
}

impl DeclaredConns for Carrier {
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.state.lock().unwrap().dials.push(dial_timeout_ms);
        // Immediate test I/O accepts a separate dial budget without claiming TLS.
        self.open_with_security(caller, need, desc, require_secure)
    }
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        self.streams.declare(owner, need);
        Ok(())
    }

    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.streams.check_need(owner, need).ok().map(|()| Ok(()))
    }

    fn forget(&self, owner: InstanceId) {
        self.streams.forget(owner);
    }

    fn landed(&self, caller: InstanceId, conn: ConnId, ticket: Ticket) -> Result<(), ConnError> {
        self.streams.get(caller, conn)?;
        self.state.lock().unwrap().ticket = ticket;
        Ok(())
    }

    fn upgrade_secure(
        &self,
        caller: InstanceId,
        conn: ConnId,
        _: Option<&str>,
        _: Option<&str>,
        _: bool,
        ticket: Ticket,
    ) -> Result<(), ConnError> {
        self.streams.get(caller, conn)?;
        let mut state = self.state.lock().unwrap();
        state.ticket = ticket;
        state.secured = true;
        Ok(())
    }

    fn serves_scheme(&self, scheme: &str) -> bool {
        scheme == "tcp"
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    assert!(value.len() < 128);
    [&[tag, value.len() as u8][..], value].concat()
}

/// Independent short-form BER: the expected bind, group search and unbind.
fn expected_wire() -> Vec<u8> {
    let dn = b"uid=alice,dc=x";
    let bind = tlv(
        0x30,
        &[
            vec![2, 1, 1],
            tlv(
                0x60,
                &[vec![2, 1, 3], tlv(4, dn), tlv(0x80, b"pw")].concat(),
            ),
        ]
        .concat(),
    );
    let search = tlv(
        0x30,
        &[
            vec![2, 1, 2],
            tlv(
                0x63,
                &[
                    tlv(4, dn),
                    vec![10, 1, 0, 10, 1, 0, 2, 1, 0, 2, 1, 0, 1, 1, 0],
                    tlv(0x87, b"objectClass"),
                    tlv(0x30, &tlv(4, b"memberOf")),
                ]
                .concat(),
            ),
        ]
        .concat(),
    );
    [bind, search, vec![0x30, 5, 2, 1, 3, 0x42, 0]].concat()
}

#[test]
fn sealed_bind_resumes_the_last_service_through_the_real_completion_store() {
    for leg in [Leg::Linked, Leg::Dropped] {
        for (secure, partial, pend) in [
            (false, false, false),
            (true, false, false),
            (false, true, true),
            (true, false, true),
            (true, true, true),
        ] {
            let d = Arc::new(Dispatcher::with_services(
                DispatchConfig::default(),
                Arc::new(super::ClockOnly),
                busbar_contract::services::test_caller_binding(),
            ));
            let carrier = Arc::new(Carrier::new(d.conn_waker(), partial, pend));
            let settings = serde_json::json!({
                "url": if secure { "ldaps://localhost:636" } else { "ldap://localhost:389" },
                "bind_dn_template": "uid={username},dc=x",
                "base_dn": "dc=x",
                "timeout_secs": 1,
            })
            .to_string();
            let binding = busbar_plugin_loader::dispatch::Bind {
                conns: ConnTable::Host(
                    busbar_contract::conn::admissions::AdmissionAuthority::issue(
                        &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
                        carrier.clone(),
                        Default::default(),
                    ),
                ),
                ..bind(&d, "ldap-sealed-replay")
            };
            let plugin = load(leg, binding);
            assert_eq!(
                open(&plugin, settings.as_bytes()).outcome,
                super::Outcome::Ready
            );
            let answer = super::login(&plugin, &d, "alice", "pw");
            assert_eq!(
                answer,
                format!("Ready verdict={LOGIN_IDENTITY}"),
                "{leg:?} secure={secure} partial={partial} pend={pend}"
            );
            let state = carrier.state.lock().unwrap();
            assert_eq!(
                state.written,
                expected_wire(),
                "every byte sent exactly once"
            );
            assert_eq!(state.pended, pend);
            assert_eq!(state.facts, usize::from(secure), "one secure FACTS check");
            assert_eq!(state.closes, 1, "the login released its stream");
            assert_eq!(
                state.dials,
                [1000],
                "the one dial is bounded by timeout_secs, not the host's default"
            );
            drop(state);
            assert_eq!(close(&plugin).outcome, super::Outcome::Ready);
        }
    }
}
