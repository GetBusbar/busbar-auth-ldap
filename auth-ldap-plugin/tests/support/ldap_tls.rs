// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TLS termination in front of the live OpenLDAP directory. The real LDAP plugin
//! still sends every bind and search; this relay only carries its bytes.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::OnceLock;
use std::time::Duration;

use busbar_core_connector::test_support::{private_ca, ServerTls, TestCa};

fn ca() -> &'static TestCa {
    static CA: OnceLock<TestCa> = OnceLock::new();
    CA.get_or_init(private_ca)
}

pub fn anchors() -> &'static str {
    &ca().ca_pem
}

pub fn start(
    at: &str,
    preamble: fn(&mut TcpStream) -> bool,
    upstream: &str,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind(at).expect("bind the LDAP TLS relay");
    let address = listener
        .local_addr()
        .expect("the bound LDAP TLS relay address");
    let tls = ServerTls::new(&[ca().leaf_der.clone()], &ca().key_der, None, &[])
        .expect("the LDAP relay has a TLS identity");
    let upstream = upstream.to_owned();
    std::thread::spawn(move || {
        for tcp in listener.incoming() {
            // A client that resets before its accept (a timed-out dial) costs only its own
            // connection: the relay is shared by every test in the binary, so it keeps serving.
            let Ok(tcp) = tcp else {
                continue;
            };
            let tls = tls.clone();
            let upstream = upstream.clone();
            std::thread::spawn(move || relay(tcp, &tls, preamble, &upstream));
        }
    });
    address
}

fn relay(
    mut tcp: TcpStream,
    tls: &ServerTls,
    preamble: fn(&mut TcpStream) -> bool,
    upstream: &str,
) {
    if !preamble(&mut tcp) {
        return;
    }
    let ctl = tcp.try_clone().expect("clone the LDAP relay socket");
    let Ok(mut secured) = tls.accept_std(tcp) else {
        return;
    };
    if !secured.handshake_ok() {
        return;
    }
    let mut directory = TcpStream::connect(upstream).expect("connect the live LDAP directory");
    let tick = Some(Duration::from_millis(2));
    ctl.set_read_timeout(tick).unwrap();
    directory.set_read_timeout(tick).unwrap();
    let idle = |e: &std::io::Error| {
        matches!(
            e.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        )
    };
    let mut bytes = [0_u8; 16 * 1024];
    loop {
        match secured.read(&mut bytes) {
            Ok(0) => return,
            Ok(n) => {
                if directory.write_all(&bytes[..n]).is_err() {
                    return;
                }
            }
            Err(e) if idle(&e) => {}
            Err(_) => return,
        }
        match directory.read(&mut bytes) {
            Ok(0) => {
                secured.close();
                return;
            }
            Ok(n) => {
                if secured
                    .write_all(&bytes[..n])
                    .and_then(|()| secured.flush())
                    .is_err()
                {
                    return;
                }
            }
            Err(e) if idle(&e) => {}
            Err(_) => return,
        }
    }
}
