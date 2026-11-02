// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The real LDAP door and loader completion store over a scripted raw carrier. The
//! carrier controls partial writes and wakes; it never implements service replay.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::auth::LOGIN_IDENTITY;
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnError, ConnId, ConnWake, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
    PieceKind, Ticket,
};
use busbar_contract::ids::StreamId;
use busbar_contract::transport::{CertFacts, ConnFacts};
use busbar_plugin_loader::dispatch::{ConnTable, DispatchConfig, Dispatcher};
use busbar_test_kit::conformance::{self, Leg, Subject};

struct State {
    ticket: Ticket,
    written: Vec<u8>,
    replies: VecDeque<Vec<u8>>,
    writes: usize,
    pended: bool,
    secured: bool,
    facts: usize,
    closes: usize,
}

struct Carrier {
    wake: ConnWake,
    partial: bool,
    pend: bool,
    state: Mutex<State>,
}

impl Carrier {
    fn new(wake: ConnWake, partial: bool, pend: bool) -> Self {
        Self {
            wake,
            partial,
            pend,
            state: Mutex::new(State {
                ticket: 0,
                written: Vec::new(),
                // BindResponse success, then SearchResultDone success (no groups).
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
            }),
        }
    }
}

impl Conns for Carrier {
    fn open(&self, _: InstanceId, _: NeedId, _: &OpenDesc<'_>) -> Result<ConnId, ConnError> {
        Ok(ConnId(1))
    }

    fn write(
        &self,
        caller: InstanceId,
        _: ConnId,
        bytes: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
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
            // Wake during the crossing too: the real dispatcher preserves that wake
            // when the door subsequently parks its conversation and answers PENDING.
            (self.wake)(caller, ticket);
            return Err(ConnError::Pending);
        }
        state.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn read(
        &self,
        _: InstanceId,
        _: ConnId,
        _: Ticket,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
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

    fn wait(&self, _: InstanceId, _: &[ConnId], _: Ticket) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }

    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
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

    fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
        self.state.lock().unwrap().closes += 1;
        Ok(())
    }
}

impl DeclaredConns for Carrier {
    fn declare(
        &self,
        _: InstanceId,
        _: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        Ok(())
    }

    fn declared(&self, _: InstanceId, _: NeedId) -> Option<Result<(), ConnError>> {
        Some(Ok(()))
    }

    fn landed(&self, _: InstanceId, _: ConnId, ticket: Ticket) -> Result<(), ConnError> {
        self.state.lock().unwrap().ticket = ticket;
        Ok(())
    }

    fn upgrade_secure(
        &self,
        _: InstanceId,
        _: ConnId,
        _: Option<&str>,
        _: Option<&str>,
        _: bool,
        ticket: Ticket,
    ) -> Result<(), ConnError> {
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
            ));
            let carrier = Arc::new(Carrier::new(d.conn_waker(), partial, pend));
            let settings = serde_json::json!({
                "url": if secure { "ldaps://localhost:636" } else { "ldap://localhost:389" },
                "bind_dn_template": "uid={username},dc=x",
                "base_dn": "dc=x",
                "timeout_secs": 1,
            })
            .to_string();
            let subject = Subject::of_macro(super::MACRO_DOOR, "busbar_auth_ldap_plugin", "{}");
            let binding = busbar_plugin_loader::dispatch::Bind {
                conns: ConnTable::Host(carrier.clone()),
                ..conformance::bind(&d, "ldap-sealed-replay")
            };
            let plugin = conformance::load::<busbar_plugin_loader::dispatch::kinds::auth::Auth>(
                &subject, leg, binding,
            )
            .unwrap();
            assert_eq!(
                conformance::open(&plugin, settings.as_bytes()).outcome,
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
            drop(state);
            assert_eq!(conformance::close(&plugin).outcome, super::Outcome::Ready);
        }
    }
}
