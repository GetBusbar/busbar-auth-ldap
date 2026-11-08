// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! An `ldaps://` BIND the chip refuses (the host reports the stream not secure) closes the stream
//! exactly once: the chip's own close, never a second release of the same handle.

use busbar_contract::abi::auth::{
    slot as auth_slot, CompleteLoginIn, IdentifyOut, NamedValue, Ops, LOGIN_OUTAGE,
};
use busbar_contract::abi::host::conn::connector::{
    ConnectorSlots, FactsIn, IoIn, StreamFacts, StreamIn,
};
use busbar_contract::abi::host::service::{ClockNowIn, ClockReading, HostSlots, ServiceOut};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, Outcome, RawOutcome, BLOB_JSON, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as life_slot, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::sdk::test_support::zeroed;
use std::cell::RefCell;
use std::ffi::c_void;
use std::mem::size_of;

const STREAM: u64 = 71;

thread_local! {
    static CLOSES: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
    static WRITTEN: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

fn ready(out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: every callback below is handed a writable ServiceOut by the SDK.
    unsafe { (*out).outcome = RawOutcome::of(Outcome::Ready) };
    RawOutcome::of(Outcome::Ready)
}

unsafe extern "C" fn clock(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed only at CLOCK_NOW; the SDK lends the typed input and its reading.
    unsafe {
        (*input.cast::<ClockNowIn>()).reading.write(ClockReading {
            size: size_of::<ClockReading>() as u32,
            _reserved: 0,
            wall_ns: 0,
            mono_ns: 0,
        });
    }
    ready(out)
}

unsafe extern "C" fn establish(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends a writable ServiceOut to ESTABLISH.
    unsafe { (*out).value = STREAM };
    ready(out)
}

unsafe extern "C" fn secured(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    ready(out)
}

/// The host's FACTS for the stream: answered, and NOT secure.
unsafe extern "C" fn facts(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed at FACTS; the SDK lends FactsIn whose `facts` points at its slot.
    unsafe {
        let slot = &mut *(*input.cast::<FactsIn>()).facts;
        *slot = StreamFacts {
            size: size_of::<StreamFacts>() as u32,
            secure: 0,
            ..*slot
        };
    }
    ready(out)
}

/// Every byte offered to the stream, recorded (none may be: the BIND carries the password).
unsafe extern "C" fn write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed at WRITE; the SDK lends IoIn, whose buffer is readable for its length.
    unsafe {
        let io = &*input.cast::<IoIn>();
        WRITTEN.with(|w| {
            w.borrow_mut()
                .extend_from_slice(std::slice::from_raw_parts(io.buf, io.len))
        });
        (*out).len = io.len as u64;
    }
    ready(out)
}

unsafe extern "C" fn close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed only at CLOSE; the SDK lends StreamIn.
    let stream = unsafe { (*input.cast::<StreamIn>()).stream };
    CLOSES.with(|closes| closes.borrow_mut().push(stream));
    ready(out)
}

#[test]
fn a_bind_refused_for_an_insecure_stream_closes_it_once() {
    CLOSES.with(|closes| closes.borrow_mut().clear());
    WRITTEN.with(|w| w.borrow_mut().clear());
    let services = HostSlots {
        size: size_of::<HostSlots>() as u32,
        slots: busbar_contract::abi::host::service::SERVICES,
        clock_now: Some(clock),
        ..zeroed()
    };
    let conns = ConnectorSlots {
        size: size_of::<ConnectorSlots>() as u32,
        slots: busbar_contract::abi::host::conn::connector::SERVICES,
        establish: Some(establish),
        upgrade_secure: Some(secured),
        facts: Some(facts),
        write: Some(write),
        close: Some(close),
        ..zeroed()
    };
    let host = HostTables {
        size: size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx::NONE,
        wake: None,
        conns: &conns,
        services: &services,
        io: std::ptr::null(),
    };
    // SAFETY: the actual macro-generated static LDAP door, whose ops is the auth table.
    let parts = unsafe { Door::read_parts(busbar_auth_ldap::door()) };
    let ops = unsafe { &*parts.ops.cast::<Ops>() };
    let settings = br#"{"url":"ldaps://ad.corp.example","bind_dn_template":"uid={username},dc=x","base_dn":"dc=x"}"#;
    let open = OpenIn {
        head: InHead {
            size: size_of::<OpenIn>() as u32,
            op: life_slot::OPEN,
            ..zeroed()
        },
        host: &host,
        settings: Blob {
            fmt: BLOB_JSON,
            ..Blob::of(settings)
        },
        generation: 1,
        ..zeroed()
    };
    let mut opened = OpenOut {
        head: OutHead {
            size: size_of::<OpenOut>() as u32,
            ..zeroed()
        },
        ..zeroed()
    };
    // SAFETY: matching live typed OPEN frames and host tables; no instance exists yet.
    let outcome = unsafe {
        ops.head.open.unwrap()(
            std::ptr::null_mut(),
            (&open as *const OpenIn).cast(),
            (&mut opened as *mut OpenOut).cast(),
        )
    }
    .outcome();
    assert_eq!(outcome, Outcome::Ready);
    let submitted = [
        NamedValue {
            name: AbiStr::of("username"),
            value: Blob::of(b"alice").with_flags(BLOB_SECRET),
        },
        NamedValue {
            name: AbiStr::of("password"),
            value: Blob::of(b"pw").with_flags(BLOB_SECRET),
        },
    ];
    let input = CompleteLoginIn {
        head: InHead {
            size: size_of::<CompleteLoginIn>() as u32,
            op: auth_slot::COMPLETE_LOGIN,
            ticket: Ticket {
                slot: 2,
                generation: 1,
            },
            ..zeroed()
        },
        submitted: submitted.as_ptr(),
        submitted_len: submitted.len(),
        ..zeroed()
    };
    let mut answer = IdentifyOut {
        head: OutHead {
            size: size_of::<IdentifyOut>() as u32,
            ..zeroed()
        },
        ..zeroed()
    };
    // SAFETY: the real opened instance and matching live COMPLETE_LOGIN input/output.
    let login = unsafe {
        ops.complete_login.unwrap()(
            opened.instance,
            (&input as *const CompleteLoginIn).cast(),
            (&mut answer as *mut IdentifyOut).cast(),
        )
    }
    .outcome();
    let close_in = InHead {
        size: size_of::<InHead>() as u32,
        op: life_slot::CLOSE,
        ..zeroed()
    };
    let mut closed = OutHead {
        size: size_of::<OutHead>() as u32,
        ..zeroed()
    };
    // SAFETY: no concurrent call remains; CLOSE consumes the instance created by OPEN.
    let close_outcome = unsafe {
        ops.head.close.unwrap()(
            opened.instance,
            (&close_in as *const InHead).cast(),
            (&mut closed as *mut OutHead).cast(),
        )
    }
    .outcome();
    assert_eq!(close_outcome, Outcome::Ready);
    assert_eq!(login, Outcome::Ready);
    assert_eq!(
        answer.verdict, LOGIN_OUTAGE,
        "an insecure ldaps:// stream is an outage"
    );
    assert!(
        WRITTEN.with(|w| w.borrow().is_empty()),
        "no byte of the BIND reached the insecure stream"
    );
    assert_eq!(
        CLOSES.with(|closes| closes.borrow().clone()),
        [STREAM],
        "the stream the chip refused to bind on is closed once"
    );
}
