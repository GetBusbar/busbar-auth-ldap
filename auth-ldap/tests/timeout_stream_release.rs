// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The actual LDAP door releases a pending stream synchronously when its LDAP budget expires.

use busbar_contract::abi::auth::{
    slot as auth_slot, CompleteLoginIn, IdentifyOut, NamedValue, Ops, LOGIN_OUTAGE,
};
use busbar_contract::abi::host::conn::connector::{ConnectorSlots, IoIn, StreamIn};
use busbar_contract::abi::host::service::{ClockNowIn, ClockReading, HostSlots, ServiceOut};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, InHead, OutHead, Outcome, RawOutcome, BLOB_JSON, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot as life_slot, OpenIn, OpenOut};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables, Ticket};
use busbar_contract::abi::sdk::test_support::zeroed;
use std::cell::{Cell, RefCell};
use std::ffi::c_void;
use std::mem::size_of;

thread_local! {
    static CLOSE_FAILS: Cell<bool> = const { Cell::new(false) };
    static NOW: Cell<u64> = const { Cell::new(0) };
    static CLOSES: RefCell<Vec<(u64, Ticket)>> = const { RefCell::new(Vec::new()) };
    static READS: Cell<u32> = const { Cell::new(0) };
}

unsafe extern "C" fn clock(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed only at CLOCK_NOW; the SDK lends the typed input, reading and output.
    unsafe {
        let input = &*input.cast::<ClockNowIn>();
        input.reading.write(ClockReading {
            size: size_of::<ClockReading>() as u32,
            _reserved: 0,
            wall_ns: 0,
            mono_ns: NOW.with(Cell::get),
        });
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

unsafe extern "C" fn establish(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: the SDK lends a writable ServiceOut to the installed ESTABLISH callback.
    unsafe {
        (*out).value = 71;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

unsafe extern "C" fn write(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed at WRITE; the SDK lends its IoIn and output for the callback.
    unsafe {
        (*out).len = (*input.cast::<IoIn>()).len as u64;
        (*out).outcome = RawOutcome::of(Outcome::Ready);
    }
    RawOutcome::of(Outcome::Ready)
}

unsafe extern "C" fn read(_: HostCtx, _: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    READS.with(|reads| reads.set(reads.get() + 1));
    // SAFETY: the SDK lends a writable output to READ.
    unsafe {
        (*out).outcome = RawOutcome::of(Outcome::Pending);
    }
    RawOutcome::of(Outcome::Pending)
}

unsafe extern "C" fn close(_: HostCtx, input: *const c_void, out: *mut ServiceOut) -> RawOutcome {
    // SAFETY: installed only at CLOSE; the SDK lends StreamIn and writable output.
    let input = unsafe { &*input.cast::<StreamIn>() };
    CLOSES.with(|closes| {
        closes
            .borrow_mut()
            .push((input.stream, input.head.handle.ticket))
    });
    let outcome = if input.head.handle.ticket == Ticket::NONE && !CLOSE_FAILS.with(Cell::get) {
        Outcome::Ready
    } else {
        Outcome::Failed
    };
    // SAFETY: the SDK lends the output throughout this callback.
    unsafe {
        (*out).outcome = RawOutcome::of(outcome);
        if CLOSE_FAILS.with(Cell::get) {
            (*out).error = AbiStr::of("close refused");
        }
    }
    RawOutcome::of(outcome)
}

fn timed_out_pending_read_release(close_fails: bool) -> String {
    CLOSE_FAILS.with(|fails| fails.set(close_fails));
    NOW.with(|now| now.set(0));
    READS.with(|reads| reads.set(0));
    CLOSES.with(|closes| closes.borrow_mut().clear());
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
        write: Some(write),
        read: Some(read),
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
    // SAFETY: this is the actual macro-generated static LDAP door, whose ops is the auth table.
    let parts = unsafe { Door::read_parts(busbar_auth_ldap::door::door()) };
    let ops = unsafe { &*parts.ops.cast::<Ops>() };
    let settings = br#"{"url":"ldap://127.0.0.1","bind_dn_template":"uid={username},dc=x","base_dn":"dc=x","timeout_secs":1}"#;
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
    assert!(!opened.instance.is_null());
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
    let mut input = CompleteLoginIn {
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
    let mut first = IdentifyOut {
        head: OutHead {
            size: size_of::<IdentifyOut>() as u32,
            ..zeroed()
        },
        ..zeroed()
    };
    // SAFETY: the real opened instance and matching live COMPLETE_LOGIN input/output.
    let first_outcome = unsafe {
        ops.complete_login.unwrap()(
            opened.instance,
            (&input as *const CompleteLoginIn).cast(),
            (&mut first as *mut IdentifyOut).cast(),
        )
    }
    .outcome();
    NOW.with(|now| now.set(1_000_000_000));
    // Continue the pending login rather than starting a new operation on its ticket.
    input.head.flags = busbar_contract::abi::mechanism::call::FLAG_RESUME;
    let mut timed_out = IdentifyOut {
        head: OutHead {
            size: size_of::<IdentifyOut>() as u32,
            ..zeroed()
        },
        ..zeroed()
    };
    // SAFETY: same live instance, same ticket and submitted storage; prior call has returned.
    let timeout_outcome = unsafe {
        ops.complete_login.unwrap()(
            opened.instance,
            (&input as *const CompleteLoginIn).cast(),
            (&mut timed_out as *mut IdentifyOut).cast(),
        )
    }
    .outcome();
    // Read the actual door reply's captured logs before CLOSE retires the instance.
    let envelope = timed_out.head.envelope;
    let mut logs = String::new();
    for n in 0..envelope.diags_len {
        // SAFETY: the synchronous reply owns this envelope until the next door call.
        let diag = unsafe { &*envelope.diags.add(n) };
        if diag.id_idx == busbar_contract::abi::mechanism::call::DIAG_LOG {
            // SAFETY: the diagnostic's stated text remains live with this reply.
            let bytes = unsafe { std::slice::from_raw_parts(diag.text.ptr, diag.text.len) };
            logs.push_str(std::str::from_utf8(bytes).expect("diagnostic is UTF-8"));
            logs.push('\n');
        }
    }
    let close = InHead {
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
            (&close as *const InHead).cast(),
            (&mut closed as *mut OutHead).cast(),
        )
    }
    .outcome();
    assert_eq!(close_outcome, Outcome::Ready);
    assert_eq!(first_outcome, Outcome::Pending);
    assert_eq!(timeout_outcome, Outcome::Ready);
    assert_eq!(timed_out.verdict, LOGIN_OUTAGE);
    assert_eq!(
        READS.with(Cell::get),
        1,
        "timeout never reissues the abandoned read"
    );
    assert_eq!(
        CLOSES.with(|closes| closes.borrow().clone()),
        [(71, Ticket::NONE)],
        "one synchronous stream release, independent of the pending service handle"
    );
    logs
}

#[test]
fn a_timed_out_pending_read_releases_the_stream_without_replaying_its_handle() {
    timed_out_pending_read_release(false);
}

#[test]
fn a_failed_close_is_logged_not_swallowed() {
    let text = timed_out_pending_read_release(true);
    assert!(text.contains("close-failed"), "{text}");
    assert!(text.contains("close refused"), "{text}");
}
