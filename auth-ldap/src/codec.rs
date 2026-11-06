// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The LDAP codec (RFC 4511), sans-IO: the requests the module sends as bytes, and the replies it
//! reads back from bytes, as pure functions. What crosses the host's stream is exactly these
//! bytes; nothing here opens a socket or does TLS.
//!
//! Requests carry the encoding ldap3 writes: a SEARCH (never dereferencing aliases, no size or time
//! limit, types and values), an UNBIND, and the StartTLS extended request. The simple BIND, which
//! carries a password, is the chip's sealed message (`Cred::ldap_simple_bind`), never built here. Replies decode fail-closed ([`crate::ber`]): a malformed message,
//! an overrunning nested length or a message past the 16 MiB cap is an error, never a panic.

use std::collections::HashMap;

use crate::ber::{self, BerError, Tlv};
use crate::filter;

/// The StartTLS extended operation's name (RFC 4511 §4.14.1).
pub const START_TLS_OID: &str = "1.3.6.1.4.1.1466.20037";

const BIND_RESPONSE: u8 = 0x61;
const UNBIND_REQUEST: u8 = 0x42;
const SEARCH_REQUEST: u8 = 0x63;
const SEARCH_RESULT_ENTRY: u8 = 0x64;
const SEARCH_RESULT_DONE: u8 = 0x65;
const SEARCH_RESULT_REFERENCE: u8 = 0x73;
const EXTENDED_REQUEST: u8 = 0x77;
const EXTENDED_RESPONSE: u8 = 0x78;
/// ExtendedRequest's `requestName` [0] (RFC 4511 §4.12).
const REQUEST_NAME: u8 = 0x80;

/// The most values one attribute keeps: one past the group cap, so the module still sees (and
/// logs) a truncation; the rest are skipped, never turned into strings.
pub const MAX_VALUES_KEPT: usize = crate::MAX_GROUP_VALUES + 1;

/// What one operation's replies may decode into memory (DNs, attribute names, values): 4 MiB. A
/// 16 MiB message of tiny values would otherwise become millions of strings.
pub const DECODE_BUDGET: usize = 4 * 1024 * 1024;

/// What each decoded string is charged on top of its bytes: its allocation's bookkeeping.
const PER_STRING: usize = 32;

/// The most warn lines about an attribute's values (`not-utf8-values`, `over-cap`) one operation
/// logs. A real reply carries only the attributes asked for; a hostile one naming a fresh attribute
/// per value would otherwise be one log line per attribute. Past it the values are still dropped
/// (the decode and the login go on as before), unlogged.
pub const MAX_VALUE_WARNS: u32 = 64;

/// Whether one more warn line about an attribute's values may be logged, counting it in `warned`
/// (this operation's lines so far, [`MAX_VALUE_WARNS`] at most).
fn may_warn(warned: &mut u32) -> bool {
    if *warned < MAX_VALUE_WARNS {
        *warned += 1;
        true
    } else {
        false
    }
}

/// Charge `n` decoded bytes (one string) to `budget`.
fn charge(budget: &mut usize, n: usize) -> Result<(), BerError> {
    *budget = budget
        .checked_sub(n.saturating_add(PER_STRING))
        .ok_or(BerError::OverBudget)?;
    Ok(())
}

/// SEARCH scope `baseObject`.
pub const SCOPE_BASE: i64 = 0;
/// SEARCH scope `wholeSubtree`.
pub const SCOPE_SUBTREE: i64 = 2;

/// One LDAPMessage around `op`.
fn message(id: i32, op: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(op.len() + 6);
    ber::int(&mut content, ber::INTEGER, i64::from(id));
    content.extend_from_slice(op);
    ber::element(ber::SEQUENCE, &content)
}

/// A SEARCH under `base` at `scope` (`SCOPE_*`) for `filter`, asking for `attrs`.
///
/// # Errors
/// The filter does not parse: [`filter::PARSE_ERROR`].
pub fn search(
    id: i32,
    base: &str,
    scope: i64,
    filter: &str,
    attrs: &[&str],
) -> Result<Vec<u8>, &'static str> {
    let filter = filter::encode(filter)?;
    let mut op = Vec::new();
    ber::tlv(&mut op, ber::OCTET_STRING, base.as_bytes());
    ber::int(&mut op, ber::ENUMERATED, scope);

    ber::int(&mut op, ber::ENUMERATED, 0);
    ber::int(&mut op, ber::INTEGER, 0);
    ber::int(&mut op, ber::INTEGER, 0);
    ber::boolean(&mut op, ber::BOOLEAN, false);
    op.extend_from_slice(&filter);
    let mut list = Vec::new();
    for a in attrs {
        ber::tlv(&mut list, ber::OCTET_STRING, a.as_bytes());
    }
    ber::tlv(&mut op, ber::SEQUENCE, &list);
    Ok(message(id, &ber::element(SEARCH_REQUEST, &op)))
}

/// An UNBIND.
#[must_use]
pub fn unbind(id: i32) -> Vec<u8> {
    message(id, &ber::element(UNBIND_REQUEST, &[]))
}

/// The StartTLS extended request.
#[must_use]
pub fn start_tls(id: i32) -> Vec<u8> {
    message(
        id,
        &ber::element(
            EXTENDED_REQUEST,
            &ber::element(REQUEST_NAME, START_TLS_OID.as_bytes()),
        ),
    )
}

/// An LDAPResult: the code, the matched DN and the diagnostic text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LdapResult {
    /// The result code (0 = success, 49 = invalidCredentials).
    pub rc: u32,
    /// The matched DN.
    pub matched: String,
    /// The diagnostic message.
    pub text: String,
}

impl LdapResult {
    /// Recognize AD's account-lockout subcode without returning directory-controlled text.
    /// A replacement character may represent invalid UTF-8 decoded lossily; fail closed on it.
    /// AD terminates its diagnostic with a NUL, which is the one control character allowed.
    pub(crate) fn ad_account_locked(&self) -> bool {
        const PREFIX: &str = "80090308: LdapErr:";
        let text = self.text.strip_suffix('\0').unwrap_or(&self.text);
        if self.rc != crate::LDAP_INVALID_CREDENTIALS
            || text.chars().any(|c| c.is_control() || c == '\u{fffd}')
        {
            return false;
        }
        let text = text.trim();
        if !text
            .get(..PREFIX.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(PREFIX))
        {
            return false;
        }
        let mut fields = text.split(',').skip(1).map(str::trim);
        let context =
            fields.any(|field| field.eq_ignore_ascii_case("comment: AcceptSecurityContext error"));
        if !context {
            return false;
        }
        // Only an entire data field matches, never 7750, x775 or text containing "data 775".
        // Conflicting/duplicate data fields are not a trustworthy diagnostic classification.
        let mut data = text.split(',').skip(1).map(str::trim).filter(|field| {
            field
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data "))
        });
        data.next()
            .is_some_and(|field| field.eq_ignore_ascii_case("data 775"))
            && data.next().is_none()
    }
}

/// RFC 4511's name for a result code, as it is spelled in error text.
#[must_use]
pub const fn rc_name(rc: u32) -> &'static str {
    match rc {
        0 => "success",
        1 => "operationsError",
        2 => "protocolError",
        3 => "timeLimitExceeded",
        4 => "sizeLimitExceeded",
        5 => "compareFalse",
        6 => "compareTrue",
        7 => "authMethodNotSupported",
        8 => "strongerAuthRequired",
        10 => "referral",
        11 => "adminLimitExceeded",
        12 => "unavailableCriticalExtension",
        13 => "confidentialityRequired",
        14 => "saslBindInProgress",
        16 => "noSuchAttribute",
        17 => "undefinedAttributeType",
        18 => "inappropriateMatching",
        19 => "constraintViolation",
        20 => "attributeOrValueExists",
        21 => "invalidAttributeSyntax",
        32 => "noSuchObject",
        33 => "aliasProblem",
        34 => "invalidDNSyntax",
        36 => "aliasDereferencingProblem",
        48 => "inappropriateAuthentication",
        49 => "invalidCredentials",
        50 => "insufficientAccessRights",
        51 => "busy",
        52 => "unavailable",
        53 => "unwillingToPerform",
        54 => "loopDetect",
        64 => "namingViolation",
        65 => "objectClassViolation",
        66 => "notAllowedOnNonLeaf",
        67 => "notAllowedOnRDN",
        68 => "entryAlreadyExists",
        69 => "objectClassModsProhibited",
        71 => "affectsMultipleDSAs",
        80 => "other",
        88 => "abandoned",
        122 => "assertionFailed",
        _ => "unknown",
    }
}

/// The most characters of the directory's own text (a matched DN, a diagnostic) a result shows.
const SHOWN_TEXT: usize = 128;

/// The directory's text `t` as a result shows it: its first [`SHOWN_TEXT`] characters (then `...`),
/// escaped (`\n`, `\u{1b}`, ...) so no newline or control character reaches a log line raw.
pub(crate) fn shown(t: &str) -> String {
    let mut out: String = t
        .chars()
        .take(SHOWN_TEXT)
        .flat_map(char::escape_debug)
        .collect();
    if t.chars().nth(SHOWN_TEXT).is_some() {
        out.push_str("...");
    }
    out
}

impl std::fmt::Display for LdapResult {
    /// The words for an operation that did not succeed (as `LdapError::LdapResult` words it), the
    /// directory's matched DN and diagnostic escaped and capped ([`shown`]): they are far-end text.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LDAP operation result: rc={} ({}), dn: \"{}\", text: \"{}\"",
            self.rc,
            rc_name(self.rc),
            shown(&self.matched),
            shown(&self.text)
        )
    }
}

/// A directory entry as a search answers it: its DN and its text-valued attributes. A value that is
/// not UTF-8 is left out of its attribute's values (and logged).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Entry {
    /// The entry's DN.
    pub dn: String,
    /// Its attributes, by the server's spelling of their names.
    pub attrs: HashMap<String, Vec<String>>,
}

/// What one reply message carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A BindResponse.
    Bind(LdapResult),
    /// A SearchResultEntry.
    Entry(Entry),
    /// A SearchResultReference (a referral the module does not follow).
    Reference,
    /// A SearchResultDone.
    Done(LdapResult),
    /// An ExtendedResponse: its result (StartTLS and a Notice of Disconnection are judged on it
    /// alone; the responseName is not read).
    Extended(LdapResult),
    /// Any other protocol op, by its tag.
    Other(u8),
}

/// One reply message: its message id and what it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The messageID (0 = an unsolicited notification).
    pub id: i32,
    /// The protocol op.
    pub reply: Reply,
}

fn text(bytes: &[u8], what: &'static str) -> Result<String, BerError> {
    String::from_utf8(bytes.to_vec()).map_err(|_| BerError::Malformed(what))
}

fn lossy_text(bytes: &[u8], budget: &mut usize) -> Result<String, BerError> {
    let mut remaining = bytes;
    let mut len = 0;
    loop {
        match std::str::from_utf8(remaining) {
            Ok(valid) => {
                len += valid.len();
                break;
            }
            Err(error) => {
                len += error.valid_up_to() + '\u{fffd}'.len_utf8();
                match error.error_len() {
                    Some(n) => remaining = &remaining[error.valid_up_to() + n..],
                    None => break,
                }
            }
        }
    }
    charge(budget, len)?;
    Ok(String::from_utf8_lossy(bytes).into_owned())
}

/// An LDAPResult's three leading components; what follows them (a referral, an
/// ExtendedResponse's name) is not read.
fn ldap_result(content: &[u8], budget: &mut usize) -> Result<LdapResult, BerError> {
    let (code, rest) = ber::expect(content, ber::ENUMERATED, "a result without its code")?;
    let rc = u32::try_from(ber::int_value(code)?)
        .map_err(|_| BerError::Malformed("a result code out of range"))?;
    let (matched, rest) = ber::expect(rest, ber::OCTET_STRING, "a result without its matched DN")?;
    let (diag, _) = ber::expect(rest, ber::OCTET_STRING, "a result without its diagnostic")?;
    let matched = lossy_text(matched, budget)?;
    let diag = lossy_text(diag, budget)?;
    Ok(LdapResult {
        rc,
        matched,
        text: diag,
    })
}

/// An entry, decoded within `budget` ([`DECODE_BUDGET`]): every string it keeps is charged as it
/// is made, and an attribute keeps at most [`MAX_VALUES_KEPT`] values, so what a hostile reply
/// costs is bounded WHILE it decodes. `warned` counts the operation's value warn lines
/// ([`MAX_VALUE_WARNS`]).
fn entry(content: &[u8], budget: &mut usize, warned: &mut u32) -> Result<Entry, BerError> {
    let (dn, rest) = ber::expect(content, ber::OCTET_STRING, "an entry without its DN")?;
    charge(budget, dn.len())?;
    let dn = text(dn, "an entry DN that is not UTF-8")?;
    let (mut list, _) = ber::expect(rest, ber::SEQUENCE, "an entry without its attributes")?;
    let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
    while !list.is_empty() {
        let (Tlv { tag, content }, next) = ber::read(list)?;
        list = next;
        if tag != ber::SEQUENCE {
            return Err(BerError::Malformed("an attribute that is not a SEQUENCE"));
        }
        let (name, rest) =
            ber::expect(content, ber::OCTET_STRING, "an attribute without its type")?;
        charge(budget, name.len())?;
        let name = text(name, "an attribute type that is not UTF-8")?;
        let (mut vals, _) = ber::expect(rest, ber::SET, "an attribute without its values")?;
        let values = attrs.entry(name.clone()).or_default();
        let mut dropped = 0_usize;
        let mut skipped = 0_usize;
        while !vals.is_empty() {
            let (v, next) = ber::read(vals)?;
            vals = next;
            if v.tag != ber::OCTET_STRING {
                return Err(BerError::Malformed("a value that is not an OCTET STRING"));
            }
            match std::str::from_utf8(v.content) {
                Ok(s) if values.len() < MAX_VALUES_KEPT => {
                    charge(budget, s.len())?;
                    values.push(s.to_owned());
                }
                // Past the cap a value is only counted (warned once per attribute below, at most
                // MAX_VALUE_WARNS lines per operation); the
                // module still sees `MAX_VALUES_KEPT` and applies its own cap.
                Ok(_) => skipped += 1,
                Err(_) => dropped += 1,
            }
        }
        if dropped > 0 && may_warn(warned) {
            tracing::warn!(
                module = "ldap",
                reason = "not-utf8-values",
                attribute = %shown(&name),
                dropped,
                kept = values.len(),
                "ldap attribute values that are not UTF-8 were dropped"
            );
        }
        if skipped > 0 && may_warn(warned) {
            tracing::warn!(
                module = "ldap",
                reason = "over-cap",
                attribute = %shown(&name),
                kept = values.len(),
                skipped,
                "ldap attribute values past the per-attribute cap were skipped"
            );
        }
    }
    Ok(Entry { dn, attrs })
}

/// Decode one whole message (exactly the bytes [`ber::frame`] measured), charging what it decodes
/// to `budget`: what remains of one operation's [`DECODE_BUDGET`]. `warned` is how many value warn
/// lines the operation has logged so far ([`MAX_VALUE_WARNS`]).
///
/// # Errors
/// [`BerError::Malformed`] for anything that is not an LDAPMessage, [`BerError::Overrun`] for a
/// nested length past its parent, [`BerError::OverBudget`] once the budget is spent.
pub fn decode_within(
    bytes: &[u8],
    budget: &mut usize,
    warned: &mut u32,
) -> Result<Message, BerError> {
    let (content, rest) = ber::expect(bytes, ber::SEQUENCE, "a message that is not a SEQUENCE")?;
    if !rest.is_empty() {
        return Err(BerError::Malformed("bytes after the message"));
    }
    let (id, rest) = ber::expect(content, ber::INTEGER, "a message without its id")?;
    let id = i32::try_from(ber::int_value(id)?)
        .map_err(|_| BerError::Malformed("a message id out of range"))?;
    if id < 0 {
        return Err(BerError::Malformed("a negative message id"));
    }

    let (op, _) = ber::read(rest)?;
    let reply = match op.tag {
        BIND_RESPONSE => Reply::Bind(ldap_result(op.content, budget)?),
        SEARCH_RESULT_ENTRY => Reply::Entry(entry(op.content, budget, warned)?),
        SEARCH_RESULT_REFERENCE => Reply::Reference,
        SEARCH_RESULT_DONE => Reply::Done(ldap_result(op.content, budget)?),
        EXTENDED_RESPONSE => Reply::Extended(ldap_result(op.content, budget)?),
        other => Reply::Other(other),
    };
    Ok(Message { id, reply })
}

#[cfg(test)]
#[path = "tests/codec_tests.rs"]
mod tests;
