// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the LDAP module on the auth kind's table (`busbar_contract::abi::auth`, v3). LDAP is a
//! login method, so this is its own `plugin_door!` over `abi::auth::Ops` (the SDK's
//! `auth_verify_door!` refuses the login ops):
//!
//! * the lifecycle is the SDK's (`lifecycle: life(Ldap)`): `validate`/`open` parse the settings
//!   blob with [`LdapModule::from_settings_with`] (its refusal texts), `refresh` swaps the module whole
//!   (a refusal keeps the running one);
//! * `verify` is not served: LDAP judges no bearer credential on the data plane, so the tail
//!   states the login family alone (`CAP_LOGIN`, as busbar-auth-github's) and `verify` answers
//!   REFUSED, never called;
//! * `begin_login` answers the credential form (`username` text, `password` password), `'static`;
//! * `complete_login` BINDs the submitted credential over the host connector's stream on the ONE
//!   declared need ([`NEEDS`]) and writes the principal into the host's identity buffer:
//!   `LOGIN_IDENTITY`, `LOGIN_BAD_CREDENTIAL`, or `LOGIN_OUTAGE` when the directory could not
//!   answer. While a stream service pends it answers PENDING, its [`Conversation`] parked on the
//!   ticket, and resumes on the wake (THE REPLAY RULE, `abi::sdk::conn`): the connector is made
//!   from the handle of the service that pended, so no completed service runs twice. A short
//!   buffer keeps the reached identity for the ticket's one re-call, so the retry never binds again;
//! * the outbound ops are not served (the tail states no `CAP_OUTBOUND`) and answer REFUSED;
//! * a login with no host clock answers `LOGIN_OUTAGE` ([`LdapModule::login_over`]): every
//!   directory operation is bounded on that clock, and none runs untimed.
//!
//! No call blocks: the Statement states no `MARK_BLOCKS` (no plugin opens a socket, dials, binds or does
//! TLS; the plugin ABI: Ready or Pending(wake)).

use std::collections::HashMap;
use std::ffi::c_void;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::auth::{
    AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, IdentifyOut,
    LoginField, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, VerifyIn,
    BEGIN_FORM, CANCEL_ABANDONED, CAP_LOGIN, FORM_PASSWORD, FORM_TEXT, LOGIN_BAD_CREDENTIAL,
    LOGIN_KIND_CREDENTIAL, LOGIN_OUTAGE,
};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_OPERATOR_INFRASTRUCTURE, KEEP_NAMED,
};
use busbar_contract::abi::host::service::ClockReading;
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::door::{Rewrite, Statement};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::auth_door::with_tail;
use busbar_contract::abi::sdk::auth_kit::login_identity;
use busbar_contract::abi::sdk::conn::{Answer, Connector, Host};
use busbar_contract::abi::sdk::cred::{Cred, SealedWrite};
use busbar_contract::abi::sdk::door::{abi_str, alias, statement, AbiIn, AbiOut, Slot};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::auth::Principal;
use zeroize::Zeroizing;

use crate::conversation::{Conversation, Wire};
use crate::{LdapModule, Login, PASSWORD, USERNAME};

/// The plugin's registry name.
pub const NAME: &str = "busbar-auth-ldap";
/// The name an operator's `module:` gives it.
pub const ALIAS: &str = "ldap";

/// The most logins one instance holds in flight.
const MAX_INFLIGHT: u32 = 64;

/// The other name config may call it by.
const REWRITES: &[Rewrite] = &[alias(ALIAS)];

/// The auth tail: the credential login alone. LDAP judges no bearer credential on the data plane,
/// so it states no inbound family (`verify` is never called) and no fact about verify answers.
const TAIL: AuthTail = {
    let mut t = AuthTail::EMPTY;
    t.caps = CAP_LOGIN;
    t.login_kind = LOGIN_KIND_CREDENTIAL;
    t
};

/// The need every login's stream is established on.
pub const NEED: u32 = 0;
/// The need a login dials on when the operator names a private CA (`ca_cert_pem`).
pub const NEED_ANCHORED: u32 = 1;

/// One need: outbound, a raw byte stream over the host's `tcp` carrier (the plugin frames LDAP
/// itself), under the `operator-infrastructure` egress class (directories: private, loopback and
/// plaintext allowed; pinned; cloud metadata hosts refused), trusting `trust_from`. The plugin
/// names the target per login (`host:port`, read off the `url` setting), so no `target_from`. The
/// timeout is the module's own, per operation (`timeout_secs`).
const fn stream(trust_from: AbiStr) -> Need {
    let mut n = Need::EMPTY;
    n.direction = DIRECTION_OUTBOUND;
    n.egress_class = EGRESS_OPERATOR_INFRASTRUCTURE;
    n.transport = abi_str("tcp");
    n.trust_from = trust_from;
    n.timeout_ms = 0;
    // A raw stream has no response head: the named (empty) list.
    n.keep_mode = KEEP_NAMED;
    n
}

/// The two needs, one dialled per instance ([`LdapModule::need`]): [`NEED`] on the connector's own
/// trust (the public roots), and [`NEED_ANCHORED`], whose connections the connector secures with
/// the operator's private CA (`ca_cert_pem`) on top of the public roots, for `ldaps://` and
/// STARTTLS alike. A need whose `trust_from` resolves to nothing is refused at its declaration, so
/// one need cannot serve both: an instance with no `ca_cert_pem` dials the public need.
pub const NEEDS: &[Need] = &[
    stream(AbiStr::ABSENT),
    stream(abi_str("settings.ca_cert_pem")),
];

/// The settings keys whose values are secret references, resolved in this order into
/// `OpenIn.secrets` (a literal value refuses boot).
pub const SECRET_REFS: &[AbiStr] = &[abi_str("bind_service_password")];

/// This plugin's Statement.
pub const STATEMENT: Statement = with_tail(
    statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT)
        .with_rewrites(REWRITES)
        .with_needs(NEEDS)
        .with_secret_refs(SECRET_REFS),
    &TAIL,
);

/// The credential form `begin_login` answers: `'static`, so it holds no lease.
const FORM: &[LoginField] = &[
    LoginField {
        name: abi_str(USERNAME.0),
        label: abi_str(USERNAME.1),
        kind: FORM_TEXT,
        required: 1,
    },
    LoginField {
        name: abi_str(PASSWORD.0),
        label: abi_str(PASSWORD.1),
        kind: FORM_PASSWORD,
        required: 1,
    },
];

/// The most short answers kept for their re-call at once.
const REACHED_MAX: usize = 1024;

/// The identities short answers reached, by ticket `(slot, generation)`, each stamped with the
/// order it was kept in.
#[derive(Default)]
struct Reached {
    map: HashMap<(u32, u32), (u64, Principal)>,
    next: u64,
}

/// One instance: the module (swapped whole on `refresh`), and the identity a short answer reached,
/// by ticket, for its one re-call.
pub struct Ldap {
    module: RwLock<Arc<LdapModule>>,
    reached: Mutex<Reached>,
}

/// Keep `p` for `key`'s re-call, at most `max` at once: at the cap the OLDEST entry goes, never
/// the rest (an in-flight short answer awaiting its re-call must survive).
fn keep_reached(reached: &mut Reached, max: usize, key: (u32, u32), p: Principal) {
    if reached.map.len() >= max && !reached.map.contains_key(&key) {
        let oldest = reached
            .map
            .iter()
            .min_by_key(|(_, (at, _))| *at)
            .map(|(k, _)| *k);
        if let Some(oldest) = oldest {
            reached.map.remove(&oldest);
        }
    }
    reached.next += 1;
    reached.map.insert(key, (reached.next, p));
}

/// The identity a short answer kept for `key`'s re-call, taken. Nothing else is left behind for
/// that ticket SLOT: an op on the slot under another generation proves the earlier op is over. A
/// call on no ticket (generation `0`, never minted) proves nothing and drops nothing.
fn take_reached(reached: &mut Reached, key: (u32, u32)) -> Option<Principal> {
    if key.1 != 0 {
        reached
            .map
            .retain(|&(slot, generation), _| slot != key.0 || generation == key.1);
    }
    reached.map.remove(&key).map(|(_, p)| p)
}

impl Ldap {
    fn module(&self) -> Arc<LdapModule> {
        self.module
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl Life for Ldap {
    const CANCEL: u32 = CANCEL_ABANDONED;

    /// The settings-only checks: `validate` is handed no secrets, so a secret-referenced service
    /// password's presence is `open`'s to check ([`LdapModule::validate_settings`]).
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        LdapModule::validate_settings(settings).map_err(Refusal::failed)
    }

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        let module = LdapModule::from_settings_with(settings, secrets).map_err(Refusal::failed)?;
        Ok(Self {
            module: RwLock::new(Arc::new(module)),
            reached: Mutex::default(),
        })
    }

    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let module = LdapModule::from_settings_with(settings, secrets).map_err(Refusal::failed)?;
        *self.module.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(module);
        Ok(Refreshed::default())
    }
}

/// `begin_login`: the credential form.
pub struct BeginLogin;

impl Slot for BeginLogin {
    type In = BeginLoginIn;
    type Out = BeginLoginOut;
    fn call(_: *mut c_void, _: &BeginLoginIn, out: &mut BeginLoginOut) -> Outcome {
        out.shape = BEGIN_FORM;
        out.form = FORM.as_ptr();
        out.form_len = FORM.len();
        Outcome::Ready
    }
}

/// The submitted form fields `(name, value)`, lent for the call.
fn submitted<'a>(input: Lent<'a, CompleteLoginIn>) -> Vec<(&'a [u8], &'a [u8])> {
    input
        .submitted()
        .iter()
        .map(|f| (f.name().bytes(), f.value().bytes()))
        .collect()
}

/// The submitted value of the field `name`, when it is text.
fn field<'a>(fields: &[(&[u8], &'a [u8])], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(n, _)| *n == name.as_bytes())
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
}

/// A login's run as `drive` begins it from the submitted `fields`: the module it began with, the
/// username, and the password captured by the chip ([`Cred`], wiped on drop).
fn begin(module: Arc<LdapModule>, fields: &[(&[u8], &[u8])], release: Option<Release>) -> Run {
    Run {
        module,
        username: field(fields, USERNAME.0).map(str::to_owned),
        password: field(fields, PASSWORD.0)
            .map(|p| Cred::captured(Zeroizing::new(p.as_bytes().to_vec()))),
        conv: Conversation::new(),
        stream: None,
        at: 0,
        release,
    }
}

/// Why a submission the form's fields cannot be read from is refused, when a field was submitted
/// but is not text.
fn unreadable(fields: &[(&[u8], &[u8])]) -> Option<&'static str> {
    let not_text = |name: &str| {
        fields
            .iter()
            .any(|(n, v)| *n == name.as_bytes() && std::str::from_utf8(v).is_err())
    };
    if not_text(USERNAME.0) {
        Some("the username field is not UTF-8")
    } else if not_text(PASSWORD.0) {
        Some("the password field is not UTF-8")
    } else {
        None
    }
}

/// The host clock's reading, or why there is none.
fn clock_ns(answer: Answer<ClockReading>) -> Result<u64, String> {
    match answer {
        Poll::Ready(Ok(r)) => Ok(r.mono_ns),
        Poll::Ready(Err(e)) => Err(format!("the host clock failed: {e}")),
        Poll::Pending => Err("the host clock pended (it must never pend)".to_string()),
    }
}

/// One login in flight, parked on its ticket across its PENDING answers: the module it began with
/// (a `refresh` meanwhile does not change it), the submitted credential (the password held by the
/// chip, `Cred`), the conversation, the stream once established, and the handle of the first
/// connector service not yet completed.
struct Run {
    module: Arc<LdapModule>,
    username: Option<String>,
    password: Option<Cred>,
    conv: Conversation,
    stream: Option<u64>,
    at: u32,
    /// What closes `stream` when no entry of the op will ([`Release`]).
    release: Option<Release>,
}

/// WHAT CLOSES A LOGIN'S STREAM WITH NO ENTRY OF ITS OP RUNNING: the host reclaims a connection
/// only on its CLOSE.
pub(crate) struct Release(Box<dyn Fn(u64) + Send + Sync>);

impl Release {
    /// A release that runs `close` on the stream.
    pub(crate) fn new(close: impl Fn(u64) + Send + Sync + 'static) -> Self {
        Self(Box::new(close))
    }

    /// The release through `host`'s connector on no ticket, as the SDK closes a parked exchange
    /// it gives up (a close never pends); what it answers is not read.
    fn through(host: Host) -> Self {
        Self::new(move |stream| {
            let _ = host.connector(Ticket::NONE).close(stream);
        })
    }
}

/// A parked login given up before it closed its stream (its op cancelled, a fresh op on its
/// ticket, the instance closed: the SDK drops what was parked), or one whose finish-path close
/// pended, releases the stream here. A stream the op's own close closed is `None` by now.
impl Drop for Run {
    fn drop(&mut self) {
        if let (Some(stream), Some(release)) = (self.stream.take(), self.release.as_ref()) {
            (release.0)(stream);
        }
    }
}

/// The finish path's close of `run`'s stream, as the op's own connector answered it: answered,
/// the stream is closed; PENDING, it stays for [`Release`] when the run drops (the op is over, so
/// no wake will re-drive it).
fn closed(run: &mut Run, answer: Poll<Result<(), String>>) {
    if answer.is_ready() {
        run.stream = None;
    }
}

/// The host connector's stream as the conversation's [`Wire`], for one entry of the op: its
/// services count from the handle of the one that pended last (`Host::connector_from`), so the
/// replay re-issues exactly that one and the host answers its result.
struct HostWire<'h> {
    conn: Option<Connector<'h>>,
    /// The host and the op's ticket, for the clock read between messages ([`Wire::now_ns`]).
    clock: Option<(&'h Host, Ticket)>,
    need: u32,
    stream: Option<u64>,
    at: u32,
}

impl HostWire<'_> {
    /// Make one service through `f`: a pending one leaves `at` on its own handle.
    fn serve<T>(
        &mut self,
        f: impl FnOnce(&mut Connector<'_>, u64) -> Answer<T>,
    ) -> Poll<Result<T, String>> {
        let Some(c) = self.conn.as_mut() else {
            return Poll::Ready(Err("the instance was handed no host tables".to_string()));
        };
        let before = c.issued();
        match f(c, self.stream.unwrap_or(0)) {
            Poll::Pending => {
                self.at = before;
                Poll::Pending
            }
            Poll::Ready(r) => {
                self.at = c.issued();
                Poll::Ready(r.map_err(|e| e.to_string()))
            }
        }
    }
}

impl Wire for HostWire<'_> {
    fn establish(&mut self, target: &str) -> Poll<Result<(), String>> {
        let need = self.need;
        let opened = self.serve(|c, _| c.establish(need, Some(target), ""));
        opened.map(|r| {
            r.map(|stream| {
                self.stream = Some(stream);
            })
        })
    }

    fn secure(&mut self) -> Poll<Result<(), String>> {
        self.serve(|c, s| c.upgrade_secure(s, None, None))
    }

    fn write(&mut self, bytes: &[u8]) -> Poll<Result<usize, String>> {
        self.serve(|c, s| c.write(s, bytes))
    }

    fn read(&mut self, buf: &mut [u8]) -> Poll<Result<usize, String>> {
        self.serve(|c, s| c.read(s, buf))
    }

    fn write_sealed(&mut self, w: &mut SealedWrite) -> Poll<Result<(), String>> {
        self.serve(|c, s| w.poll(c, s))
    }

    fn now_ns(&mut self) -> Option<u64> {
        let (host, ticket) = self.clock?;
        // Read quietly: a failing clock was said once, at the entry's start ([`now`]).
        clock_ns(host.connector(ticket).clock_now()).ok()
    }
}

/// The host's monotonic clock, when it offers one; a clock that fails says why, at warn (the
/// login then refuses to run untimed: [`LdapModule::login_over`]).
fn now(host: Option<&Host>, ticket: Ticket) -> Option<u64> {
    match clock_ns(host?.connector(ticket).clock_now()) {
        Ok(ns) => Some(ns),
        Err(reason) => {
            tracing::warn!(module = "ldap", %reason, "ldap login: no host clock reading");
            None
        }
    }
}

/// Run (or resume) the login on this call's ticket: PENDING while a stream service pends (the
/// run parked, the op's timer set to the operation's deadline), else what it came to, the stream
/// closed.
fn drive(
    h: &Held<Ldap>,
    instance: &Instance<'_, Held<Ldap>>,
    input: Lent<'_, CompleteLoginIn>,
    out: &mut Out<'_, IdentifyOut>,
) -> Poll<Login> {
    let ticket = instance.ticket();
    let mut run = match instance.resume::<Run>() {
        Some(run) => *run,
        None => {
            let fields = submitted(input);
            // A field submitted but not text is refused in its own words (the same verdict as a
            // field not submitted), before the wire.
            if let Some(reason) = unreadable(&fields) {
                tracing::info!(module = "ldap", "ldap login refused: {reason}");
                return Poll::Ready(Login::BadCredential);
            }
            begin(
                h.life().module(),
                &fields,
                h.host().map(|host| Release::through(*host)),
            )
        }
    };
    let host = h.host();
    let now = now(host, ticket);
    let mut wire = HostWire {
        conn: host.map(|host| host.connector_from(ticket, run.at)),
        clock: host.map(|host| (host, ticket)),
        need: run.module.need(),
        stream: run.stream,
        at: run.at,
    };
    let answer = run.module.login_over(
        &mut run.conv,
        &mut wire,
        run.username.as_deref(),
        run.password.as_ref(),
        now,
    );
    match answer {
        Poll::Pending => {
            run.stream = wire.stream;
            run.at = wire.at;
            if let Some(deadline) = run.conv.deadline_ns() {
                out.wake_at(deadline);
            }
            instance.park(run);
            Poll::Pending
        }
        Poll::Ready(login) => {
            run.stream = wire.stream;
            if run.conv.opened() {
                let answer = wire.serve(|c, s| c.close(s));
                closed(&mut run, answer);
            }
            Poll::Ready(login)
        }
    }
}

/// `complete_login`: BIND the submitted credential over the host's stream (see
/// [`LdapModule::login_over`]); PENDING while the stream pends.
pub struct CompleteLogin;

impl SafeSlot for CompleteLogin {
    type In = CompleteLoginIn;
    type Out = IdentifyOut;
    type State = Held<Ldap>;
    fn call(
        instance: Instance<'_, Held<Ldap>>,
        input: Lent<'_, CompleteLoginIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Fault;
        };
        let ldap = h.life();
        let ticket = instance.ticket();
        let key = (ticket.slot, ticket.generation);
        let kept = take_reached(
            &mut ldap.reached.lock().unwrap_or_else(PoisonError::into_inner),
            key,
        );
        let login = match kept {
            Some(p) => Login::Identity(p),
            None => match drive(h, &instance, input, &mut out) {
                Poll::Ready(login) => login,
                Poll::Pending => return Outcome::Pending,
            },
        };
        match login {
            Login::BadCredential => {
                out.set(|o| &o.verdict, LOGIN_BAD_CREDENTIAL);
                Outcome::Ready
            }
            Login::Outage => {
                out.set(|o| &o.verdict, LOGIN_OUTAGE);
                Outcome::Ready
            }
            Login::Identity(p) => {
                let answer = login_identity(&p, input.out_buf(), &mut out);
                // `0` is never a minted generation: a ticket-less call gets no re-call.
                if answer == Outcome::Failed && ticket.generation != 0 {
                    keep_reached(
                        &mut ldap.reached.lock().unwrap_or_else(PoisonError::into_inner),
                        REACHED_MAX,
                        key,
                        p,
                    );
                }
                answer
            }
        }
    }
}

/// An auth op this plugin does not serve (the tail states neither `CAP_INBOUND` nor
/// `CAP_OUTBOUND`): REFUSED, never called.
pub struct NotServed<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> Slot for NotServed<I, O> {
    type In = I;
    type Out = O;
    fn call(_: *mut c_void, _: &I, _: &mut O) -> Outcome {
        Outcome::Refused
    }
}

mod table {
    use super::{
        BeginLogin, CompleteLogin, FieldsIn, FieldsOut, IdentifyOut, Ldap, NotServed,
        OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, Safe, VerifyIn,
    };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::auth::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Ldap),
        kind_ops: {
            verify: NotServed<VerifyIn, IdentifyOut>,
            begin_login: BeginLogin,
            complete_login: Safe<CompleteLogin>,
            open_outbound: NotServed<OpenOutboundIn, OpenOutboundOut>,
            outbound_ready: NotServed<OutboundReadyIn, OutboundReadyOut>,
            fields: NotServed<FieldsIn, FieldsOut>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::{door, MACRO_DOOR};

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
