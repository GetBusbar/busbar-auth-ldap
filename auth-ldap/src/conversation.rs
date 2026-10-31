// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One login's conversation with the directory, resumable: the codec's bytes ([`crate::codec`])
//! over a byte stream someone else owns ([`Wire`]: in the plugin, the host connector's raw stream
//! on the declared need; the plugin opens no socket, dials, binds or does TLS).
//!
//! A wire service may answer PENDING. The module's bind/search logic ([`crate::LdapModule`]) then
//! stops, the op answers PENDING, and on the wake the logic runs again from the top. The
//! [`Conversation`] makes that replay cheap and exact: every directory operation that completed
//! answers its kept result without touching the wire, and the one in progress resumes where it
//! stopped (the request half sent, the reply half read). Nothing is ever sent twice.
//!
//! The connection: `ldap://` is a plain stream; `ldaps://` asks the connector for connection
//! security before the first byte; `ldap://` with `start_tls` sends the StartTLS extended request
//! in the clear, reads its answer, then asks the connector to secure the stream
//! (`upgrade_secure`, the connector's ONE generic mid-stream service).

use std::fmt;
use std::task::Poll;

use busbar_contract::abi::sdk::cred::{Cred, SealedWrite};

use crate::ber;
use crate::codec::{self, Message, Reply};
use crate::{DirEntry, Io, LdapBackend, SearchScope};

/// THE BYTE STREAM a conversation runs over. Every call answers [`Poll::Pending`] when it cannot
/// finish yet (the caller answers PENDING and is called again on its wake, making the same call
/// with the same buffer), or its result; an error is the stream's own text.
pub trait Wire {
    /// Open the stream to `target` (`host:port`).
    fn establish(&mut self, target: &str) -> Poll<Result<(), String>>;
    /// Secure the open stream (TLS, owned by whoever owns the stream).
    fn secure(&mut self) -> Poll<Result<(), String>>;
    /// Write `bytes`: how many were taken.
    fn write(&mut self, bytes: &[u8]) -> Poll<Result<usize, String>>;
    /// Read into `buf`: how many bytes arrived; `0` = the far end closed.
    fn read(&mut self, buf: &mut [u8]) -> Poll<Result<usize, String>>;
    /// Write the chip's whole message `w` (a BIND, its password sealed): `Ready(Ok(()))` once all
    /// of it is taken.
    fn write_sealed(&mut self, w: &mut SealedWrite) -> Poll<Result<(), String>>;
    /// The stream owner's monotonic clock now, when it offers one: read between the messages of
    /// one entry of the op, so a directory that answers Ready without end meets its deadline.
    fn now_ns(&mut self) -> Option<u64> {
        None
    }
}

/// How the connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// None: plaintext `ldap://`.
    Plain,
    /// `ldaps://`: secured from the first byte.
    Implicit,
    /// `ldap://` upgraded by the StartTLS extended operation.
    StartTls,
}

/// Where the directory is: the stream's target and how it is secured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// `host:port` (`[v6]:port` for an IPv6 literal).
    pub target: String,
    /// The host alone.
    pub host: String,
    /// How the stream is secured.
    pub security: Security,
}

impl Endpoint {
    /// Read an `ldap://` or `ldaps://` URL (the port defaults to 389 and 636; userinfo, a path
    /// and a query are ignored). A URL that names no host is refused.
    ///
    /// # Errors
    /// Another scheme, no host, or a bad port.
    pub fn parse(url: &str, start_tls: bool) -> Result<Self, String> {
        let url = url.trim();
        let (scheme, rest) = url
            .split_once("://")
            .ok_or_else(|| "url parse error: relative URL without a base".to_string())?;
        let (implicit, default_port) = if scheme.eq_ignore_ascii_case("ldap") {
            (false, 389)
        } else if scheme.eq_ignore_ascii_case("ldaps") {
            (true, 636)
        } else {
            return Err(format!("unknown LDAP URL scheme: {scheme}"));
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
        let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
            let (h, after) = v6
                .split_once(']')
                .ok_or_else(|| "url parse error: invalid IPv6 address".to_string())?;
            (h, after.strip_prefix(':'))
        } else {
            match hostport.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (hostport, None),
            }
        };
        if host.is_empty() {
            return Err("the URL names no host".to_string());
        }
        let port = match port {
            None | Some("") => default_port,
            Some(p) => p
                .parse::<u16>()
                .map_err(|_| "url parse error: invalid port number".to_string())?,
        };
        let target = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let security = match (implicit, start_tls) {
            (true, _) => Security::Implicit,
            (false, true) => Security::StartTls,
            (false, false) => Security::Plain,
        };
        Ok(Self {
            target,
            host: host.to_string(),
            security,
        })
    }
}

/// A directory operation that completed: what it answered.
#[derive(Debug, Clone)]
enum Kept {
    Connected,
    Bound(u32),
    Found(Vec<DirEntry>),
    /// A search the directory answered with a non-zero result: its code and text.
    Refused(u32, String),
    Unbound,
}

/// Where the operation in progress stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Opening the stream.
    Establish,
    /// Sending the StartTLS request.
    SendStartTls,
    /// Reading its answer.
    ReadStartTls,
    /// Securing the stream.
    Secure,
    /// Sending the request.
    Send,
    /// Reading the reply.
    Read,
}

/// The operation in progress: its stage, its request bytes and how many went, its message id,
/// and the entries a search has read so far. A BIND's request is the chip's sealed message, which
/// the plugin never reads; every other request's bytes are public.
struct Doing {
    stage: Stage,
    out: Vec<u8>,
    sealed: Option<SealedWrite>,
    sent: usize,
    id: i32,
    entries: Vec<DirEntry>,
    /// How many messages this operation has read ([`MAX_MESSAGES`]).
    received: u32,
    /// How many search references this operation skipped.
    references: u32,
    /// How many bytes this operation's messages took ([`OP_BYTES_CAP`]).
    read_bytes: usize,
    /// What remains of this operation's decode budget ([`codec::DECODE_BUDGET`]).
    budget: usize,
}

// By hand: a `SealedWrite` has no `Debug`; only its length shows.
impl fmt::Debug for Doing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Doing")
            .field("stage", &self.stage)
            .field("out_len", &self.out.len())
            .field("sealed_len", &self.sealed.as_ref().map(SealedWrite::len))
            .field("sent", &self.sent)
            .field("id", &self.id)
            .field("entries", &self.entries)
            .field("received", &self.received)
            .field("references", &self.references)
            .field("read_bytes", &self.read_bytes)
            .field("budget", &self.budget)
            .finish()
    }
}

/// What an operation that passed its deadline answers, after its operation's prefix (`bind: `, ...):
/// The words for an operation timeout (as ldap3's `LdapError::Timeout`, whose `Elapsed` reads
/// "deadline has elapsed").
pub const TIMEOUT: &str = "timeout: deadline has elapsed";

/// How many entries of one search are kept: the module reads the first entry and needs to know
/// only whether a second exists. Later entries are read and dropped.
const MAX_ENTRIES_KEPT: usize = 2;

/// The most messages one operation reads. Its deadline is checked between entries of the op, so a
/// directory that answers Ready forever (entries, or messages for another id) is cut off here. A
/// group read answers one entry and a user search is refused past two; 1024 is far above any.
const MAX_MESSAGES: u32 = 1024;

/// The most bytes one operation reads from the directory in all, however many messages carry them:
/// 16 MiB (one message alone may hold as much: [`ber::INBOUND_CAP`]).
const OP_BYTES_CAP: usize = 16 * 1024 * 1024;

/// How much one read asks for.
const READ_CHUNK: usize = 16 * 1024;

/// ONE LOGIN'S CONVERSATION, kept across its op's PENDING answers (parked on the op's ticket): the
/// results of the operations that completed, the one in progress, the bytes read and not yet
/// consumed, and the read buffer (a pending read fills it, so it stays put).
#[derive(Debug)]
pub struct Conversation {
    kept: Vec<Kept>,
    doing: Option<Doing>,
    inbound: Vec<u8>,
    buf: Box<[u8]>,
    next_id: i32,
    opened: bool,
    deadline_ns: Option<u64>,
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new()
    }
}

impl Conversation {
    /// A conversation that has not begun.
    #[must_use]
    pub fn new() -> Self {
        Self {
            kept: Vec::new(),
            doing: None,
            inbound: Vec::new(),
            buf: vec![0; READ_CHUNK].into_boxed_slice(),
            next_id: 0,
            opened: false,
            deadline_ns: None,
        }
    }

    /// Whether the stream was opened (and so is the caller's to close).
    #[must_use]
    pub const fn opened(&self) -> bool {
        self.opened
    }

    /// The instant (the caller's monotonic clock) the operation in progress gives up, once set.
    #[must_use]
    pub const fn deadline_ns(&self) -> Option<u64> {
        self.deadline_ns
    }

    fn next_id(&mut self) -> i32 {
        self.next_id = if self.next_id == i32::MAX {
            1
        } else {
            self.next_id + 1
        };
        self.next_id
    }
}

/// The module's [`LdapBackend`] over a [`Wire`], for one entry of the op: operations the
/// conversation kept answer at once; the one in progress drives the wire.
pub(crate) struct Over<'a, W: Wire> {
    conv: &'a mut Conversation,
    wire: &'a mut W,
    endpoint: Result<Endpoint, String>,
    op: usize,
    now_ns: Option<u64>,
    timeout_secs: u64,
}

impl<'a, W: Wire> Over<'a, W> {
    /// The backend for one entry: `url`/`start_tls` name the directory; `now_ns` is the caller's
    /// clock (`None` = none) and each operation may wait `timeout_secs` from its own start.
    pub(crate) fn new(
        conv: &'a mut Conversation,
        wire: &'a mut W,
        url: &str,
        start_tls: bool,
        now_ns: Option<u64>,
        timeout_secs: u64,
    ) -> Self {
        Self {
            conv,
            wire,
            endpoint: Endpoint::parse(url, start_tls),
            op: 0,
            now_ns,
            timeout_secs,
        }
    }

    /// The kept answer of the next operation, or `None` when it is the one to run.
    fn kept(&mut self) -> Option<Kept> {
        let k = self.conv.kept.get(self.op).cloned();
        self.op += 1;
        k
    }

    fn keep(&mut self, k: Kept) {
        self.conv.kept.push(k);
        self.conv.doing = None;
    }

    /// End the operation in progress with `e`.
    fn fail<T>(&mut self, e: impl Into<String>) -> Result<T, Io> {
        self.conv.doing = None;
        Err(Io::Failed(e.into()))
    }

    /// The operation in progress, begun as `start` when none is.
    fn doing(&mut self, start: impl FnOnce(&mut Conversation) -> Doing) -> Result<(), Io> {
        let wait = self.timeout_secs.saturating_mul(1_000_000_000);
        if self.conv.doing.is_none() {
            let d = start(&mut *self.conv);
            self.conv.doing = Some(d);
            self.conv.deadline_ns = self.now_ns.map(|n| n.saturating_add(wait));
        } else if let Some(now) = self.now_ns {
            // An operation begun on an entry with no clock is timed from the first entry with one.
            let deadline = *self
                .conv
                .deadline_ns
                .get_or_insert_with(|| now.saturating_add(wait));
            if now >= deadline {
                return self.fail(TIMEOUT);
            }
        }
        Ok(())
    }

    fn stage(&self) -> Stage {
        self.conv.doing.as_ref().map_or(Stage::Send, |d| d.stage)
    }

    fn set_stage(&mut self, s: Stage) {
        if let Some(d) = self.conv.doing.as_mut() {
            d.stage = s;
        }
    }

    /// Send what is left of the request.
    fn send(&mut self) -> Result<(), Io> {
        loop {
            let Some(d) = self.conv.doing.as_mut() else {
                return Ok(());
            };
            if let Some(w) = d.sealed.as_mut() {
                return match self.wire.write_sealed(w) {
                    Poll::Pending => Err(Io::Pending),
                    Poll::Ready(Err(e)) => self.fail(e),
                    Poll::Ready(Ok(())) => Ok(()),
                };
            }
            if d.sent >= d.out.len() {
                return Ok(());
            }
            let n = match self.wire.write(&d.out[d.sent..]) {
                Poll::Pending => return Err(Io::Pending),
                Poll::Ready(Err(e)) => return self.fail(e),
                Poll::Ready(Ok(0)) => return self.fail("the directory took no bytes"),
                Poll::Ready(Ok(n)) => n,
            };
            if let Some(d) = self.conv.doing.as_mut() {
                d.sent += n;
            }
        }
    }

    /// Whether the operation in progress is past its deadline, on the stream owner's clock now
    /// ([`Wire::now_ns`]) or, with none, the clock this entry began on.
    fn expired(&mut self) -> bool {
        let Some(deadline) = self.conv.deadline_ns else {
            return false;
        };
        self.wire
            .now_ns()
            .or(self.now_ns)
            .is_some_and(|now| now >= deadline)
    }

    /// The next whole message off the stream. The deadline is checked before every read and every
    /// message, so a directory that answers Ready without end still meets it; one operation reads
    /// at most [`OP_BYTES_CAP`] and decodes within its budget.
    fn receive(&mut self) -> Result<Message, Io> {
        loop {
            if self.expired() {
                return self.fail(TIMEOUT);
            }
            match ber::frame(&self.conv.inbound) {
                Err(e) => return self.fail(e.to_string()),
                Ok(Some(n)) => {
                    let over = self.conv.doing.as_mut().is_some_and(|d| {
                        d.read_bytes = d.read_bytes.saturating_add(n);
                        d.read_bytes > OP_BYTES_CAP
                    });
                    if over {
                        return self.fail(format!(
                            "the directory sent more than {} MiB for one operation",
                            OP_BYTES_CAP / (1024 * 1024)
                        ));
                    }
                    let mut budget = self
                        .conv
                        .doing
                        .as_ref()
                        .map_or(codec::DECODE_BUDGET, |d| d.budget);
                    let msg = codec::decode_within(&self.conv.inbound[..n], &mut budget);
                    if let Some(d) = self.conv.doing.as_mut() {
                        d.budget = budget;
                    }
                    self.conv.inbound.drain(..n);
                    return match msg {
                        Ok(m) => Ok(m),
                        Err(e) => self.fail(e.to_string()),
                    };
                }
                Ok(None) => {}
            }
            match self.wire.read(&mut self.conv.buf) {
                Poll::Pending => return Err(Io::Pending),
                Poll::Ready(Err(e)) => return self.fail(e),
                Poll::Ready(Ok(0)) => return self.fail("the directory closed the connection"),
                Poll::Ready(Ok(n)) => {
                    let n = n.min(self.conv.buf.len());
                    let (inbound, buf) = (&mut self.conv.inbound, &self.conv.buf);
                    inbound.extend_from_slice(&buf[..n]);
                }
            }
        }
    }

    /// The next message for the operation in progress: an unsolicited notice (id 0) ends it, a
    /// message for another id is skipped.
    fn reply(&mut self) -> Result<Reply, Io> {
        let want = self.conv.doing.as_ref().map_or(0, |d| d.id);
        loop {
            let m = self.receive()?;
            let read = self.conv.doing.as_mut().map_or(0, |d| {
                d.received += 1;
                d.received
            });
            if read > MAX_MESSAGES {
                return self.fail(format!(
                    "the directory sent more than {MAX_MESSAGES} messages for one operation"
                ));
            }
            if m.id == want {
                return Ok(m.reply);
            }
            if m.id == 0 {
                let text = match m.reply {
                    Reply::Extended(r, _) => r.to_string(),
                    _ => "an unsolicited notification".to_string(),
                };
                return self.fail(format!("the directory ended the session: {text}"));
            }
        }
    }

    /// Begin a request operation carrying `bytes` (built with its message id).
    fn request(&mut self, build: impl FnOnce(i32) -> Result<Vec<u8>, String>) -> Result<(), Io> {
        let mut refused = None;
        self.doing(|c| {
            let id = c.next_id();
            let out = build(id).unwrap_or_else(|e| {
                refused = Some(e);
                Vec::new()
            });
            Doing {
                stage: Stage::Send,
                out,
                sealed: None,
                sent: 0,
                id,
                entries: Vec::new(),
                received: 0,
                references: 0,
                read_bytes: 0,
                budget: codec::DECODE_BUDGET,
            }
        })?;
        match refused {
            Some(e) => self.fail(e),
            None => Ok(()),
        }
    }
}

fn wired<T>(p: Poll<Result<T, String>>) -> Result<T, Option<String>> {
    match p {
        Poll::Pending => Err(None),
        Poll::Ready(Ok(v)) => Ok(v),
        Poll::Ready(Err(e)) => Err(Some(e)),
    }
}

impl<W: Wire> LdapBackend for Over<'_, W> {
    fn connect(&mut self) -> Result<(), Io> {
        if self.kept().is_some() {
            return Ok(());
        }
        let endpoint = match &self.endpoint {
            Ok(e) => e.clone(),
            Err(e) => return Err(Io::Failed(e.clone())),
        };
        self.doing(|_| Doing {
            stage: Stage::Establish,
            out: Vec::new(),
            sealed: None,
            sent: 0,
            id: 0,
            entries: Vec::new(),
            received: 0,
            references: 0,
            read_bytes: 0,
            budget: codec::DECODE_BUDGET,
        })?;
        loop {
            match self.stage() {
                Stage::Establish => match wired(self.wire.establish(&endpoint.target)) {
                    Err(None) => return Err(Io::Pending),
                    Err(Some(e)) => return self.fail(e),
                    Ok(()) => {
                        self.conv.opened = true;
                        match endpoint.security {
                            Security::Plain => break,
                            Security::Implicit => self.set_stage(Stage::Secure),
                            Security::StartTls => {
                                let id = self.conv.next_id();
                                if let Some(d) = self.conv.doing.as_mut() {
                                    d.id = id;
                                    d.out = codec::start_tls(id);
                                    d.stage = Stage::SendStartTls;
                                }
                            }
                        }
                    }
                },
                Stage::SendStartTls => {
                    self.send()?;
                    self.set_stage(Stage::ReadStartTls);
                }
                Stage::ReadStartTls => match self.reply()? {
                    // Bytes read before the upgrade are never honoured after it (RFC 4513 s3.1.1).
                    Reply::Extended(r, _) if r.rc == 0 => {
                        if !self.conv.inbound.is_empty() {
                            return self.fail(
                                "the directory sent data after the StartTLS response, before TLS",
                            );
                        }
                        self.set_stage(Stage::Secure);
                    }
                    Reply::Extended(r, _) => return self.fail(r.to_string()),
                    _ => return self.fail("malformed reply: not an extended response"),
                },
                Stage::Secure => match wired(self.wire.secure()) {
                    Err(None) => return Err(Io::Pending),
                    Err(Some(e)) => return self.fail(e),
                    Ok(()) => break,
                },
                // A connect never sends or reads a request of its own: a stage it never sets.
                Stage::Send | Stage::Read => {
                    return self.fail("internal: a connect in a request stage");
                }
            }
        }
        self.keep(Kept::Connected);
        Ok(())
    }

    fn simple_bind(&mut self, dn: &str, password: &Cred) -> Result<u32, Io> {
        if let Some(Kept::Bound(rc)) = self.kept() {
            return Ok(rc);
        }
        self.doing(|c| {
            let id = c.next_id();
            Doing {
                stage: Stage::Send,
                out: Vec::new(),
                sealed: Some(SealedWrite::message(password.ldap_simple_bind(id, dn))),
                sent: 0,
                id,
                entries: Vec::new(),
                received: 0,
                references: 0,
                read_bytes: 0,
                budget: codec::DECODE_BUDGET,
            }
        })?;
        if self.stage() == Stage::Send {
            self.send()?;
            self.set_stage(Stage::Read);
        }
        match self.reply()? {
            Reply::Bind(r) => {
                self.keep(Kept::Bound(r.rc));
                Ok(r.rc)
            }
            _ => self.fail("malformed reply: not a bind response"),
        }
    }

    fn search(
        &mut self,
        base: &str,
        scope: SearchScope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<DirEntry>, Io> {
        match self.kept() {
            Some(Kept::Found(entries)) => return Ok(entries),
            Some(Kept::Refused(rc, text)) => return Err(Io::Refused { rc, text }),
            _ => {}
        }
        let scope = match scope {
            SearchScope::Base => codec::SCOPE_BASE,
            SearchScope::Subtree => codec::SCOPE_SUBTREE,
        };
        // The request is built once, when the operation begins (a replay resumes it): a filter that
        // does not parse fails then, before any byte is sent.
        self.request(|id| codec::search(id, base, scope, filter, attrs).map_err(str::to_string))?;
        if self.stage() == Stage::Send {
            self.send()?;
            self.set_stage(Stage::Read);
        }
        loop {
            match self.reply()? {
                Reply::Entry(e) => {
                    if let Some(d) = self.conv.doing.as_mut() {
                        if d.entries.len() < MAX_ENTRIES_KEPT {
                            d.entries.push(e);
                        }
                    }
                }
                Reply::Done(r) if r.rc == 0 => {
                    let entries = self
                        .conv
                        .doing
                        .as_mut()
                        .map(|d| std::mem::take(&mut d.entries))
                        .unwrap_or_default();
                    self.keep(Kept::Found(entries.clone()));
                    return Ok(entries);
                }
                // The search's own answer: kept, so a replay answers it again without a resend.
                Reply::Done(r) => {
                    let text = r.to_string();
                    self.keep(Kept::Refused(r.rc, text.clone()));
                    return Err(Io::Refused { rc: r.rc, text });
                }
                // A SearchResultReference is a referral this client does not chase, and RFC 4511
                // §4.5.3 lets such a client ignore it: never read as an entry, it is counted and
                // skipped, and the search is decided on its entries and its SearchResultDone.
                // (Active Directory answers every domain-root subtree search with references to
                // its ForestDnsZones, DomainDnsZones and Configuration partitions.)
                Reply::Reference => {
                    let skipped = self.conv.doing.as_mut().map_or(0, |d| {
                        d.references += 1;
                        d.references
                    });
                    tracing::debug!(
                        module = "ldap",
                        skipped,
                        "ldap search reference skipped (referrals are not chased)"
                    );
                }
                _ => return self.fail("malformed reply: not a search result"),
            }
        }
    }

    fn unbind(&mut self) -> Result<(), Io> {
        if self.kept().is_some() {
            return Ok(());
        }
        self.request(|id| Ok(codec::unbind(id)))?;
        self.send()?;
        self.keep(Kept::Unbound);
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests/conversation_tests.rs"]
mod tests;
