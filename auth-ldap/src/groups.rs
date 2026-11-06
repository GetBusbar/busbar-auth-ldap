// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure helpers for the LDAP module: turning group DNs into role strings, and defending the two
//! places a username crosses into an LDAP wire syntax (a DN template, a search filter). These carry
//! no I/O, so they are fully unit-tested (the bind itself is tested over a scripted stream in
//! `tests/conversation_tests.rs`, and live in the plugin's e2e).
//!
//! ## Group DN → role normalization
//!
//! LDAP/AD groups are DNs: `CN=engineers,OU=Groups,DC=corp,DC=example`. A [`crate::Principal`]'s `roles`
//! (wire `Identity.groups`) is a `Vec<String>` and `auth.role_bindings.<provider>` keys policy on those
//! strings — so a DN "works" as a role verbatim. But it is a HOSTILE binding key: it has commas and
//! `=` (awkward YAML keys), it is case-insensitive in LDAP but case-SENSITIVE as a `role_bindings`
//! map key, and its OU path is deployment-specific. The engine offers no DN normalization, so the
//! module must decide the shape. [`RoleFrom`] lets the operator pick CN-only (the sane default) vs
//! full DN. The normalization decision sits with the plugin because the ABI has nowhere else to put
//! it; an engine-side DN-normalizing role mapper would be an additive improvement.

use std::collections::HashSet;

use crate::RoleFrom;

/// Map the raw group-membership DN values off the directory to [`crate::Principal`] role strings,
/// honoring [`RoleFrom`], de-duplicated and order-preserving.
pub fn roles_from_group_dns(group_dns: &[String], mode: RoleFrom) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(group_dns.len());

    let mut seen: HashSet<String> = HashSet::with_capacity(group_dns.len());
    let mut omitted = 0_usize;
    for dn in group_dns {
        let role = match mode {
            RoleFrom::Cn => match first_cn(dn) {
                Some(cn) if !cn.is_empty() => cn,
                // A memberOf value with no usable CN (no CN RDN, or an empty one) falls back to
                // the whole trimmed value so membership is never silently dropped.
                _ => dn.trim().to_string(),
            },
            RoleFrom::Dn => dn.trim().to_lowercase(),
        };
        if role.is_empty() {
            omitted += 1;
        } else if seen.insert(role.clone()) {
            out.push(role);
        }
    }
    if omitted > 0 {
        tracing::warn!(
            module = "ldap",
            reason = "empty-group-role",
            omitted,
            "ldap group values map to an empty role and were omitted"
        );
    }
    out
}

/// Extract the value of the first `CN=` attribute of a DN, unescaping its RFC 4514 escapes (every
/// `\c` single-character escape and `\XX` hex pair). Case-insensitive on the `CN` attribute name (LDAP is). A
/// multi-valued RDN (`CN=a+UID=b`) is split at its unescaped `+`, and an RDN with no `=` is
/// skipped. Returns `None` if there is no CN component, or if its hex escapes do not decode as
/// UTF-8 (the caller then uses the whole value).
pub(crate) fn first_cn(dn: &str) -> Option<String> {
    for rdn in split_unescaped(dn, b',') {
        for ava in split_unescaped(rdn, b'+') {
            let Some((attr, val)) = ava.split_once('=') else {
                continue;
            };
            if attr.trim().eq_ignore_ascii_case("cn") {
                return unescape_rdn_value(trim_unescaped(val));
            }
        }
    }
    None
}

/// Trim `v` of leading whitespace and of trailing whitespace that is not escaped (RFC 4514: a
/// space after an odd run of backslashes is `\ `, part of the value).
fn trim_unescaped(v: &str) -> &str {
    let mut v = v.trim_start();
    while let Some(head) = v.strip_suffix(char::is_whitespace) {
        let backslashes = head.bytes().rev().take_while(|&b| b == b'\\').count();
        if backslashes % 2 == 1 {
            break;
        }
        v = head;
    }
    v
}

/// Split a DN at every unescaped `sep` (`,` between RDNs, `+` between the attribute-value
/// assertions of a multi-valued RDN), keeping each `\x` escape whole for the value unescaper. (A
/// minimal RFC 4514 split — enough for real AD/OpenLDAP memberOf values.) The parts borrow `dn`:
/// a directory value is split without an allocation per part. A trailing empty part is dropped.
fn split_unescaped(dn: &str, sep: u8) -> impl Iterator<Item = &str> {
    let bytes = dn.as_bytes();
    let (mut start, mut at, mut done) = (0, 0, false);
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        while at < bytes.len() {
            match bytes[at] {
                // The escaped byte is never a separator: `sep` is ASCII, and a multi-byte
                // character's later bytes are all non-ASCII.
                b'\\' => at += 2,
                b if b == sep => {
                    let part = &dn[start..at];
                    at += 1;
                    start = at;
                    return Some(part);
                }
                _ => at += 1,
            }
        }
        done = true;
        (start < dn.len()).then(|| &dn[start..])
    })
}

/// Unescape the DN-value escapes that survive [`split_unescaped`], per RFC 4514:
///   - the single-char escape `\c` (e.g. `\,` `\=` `\+` `\\` `\"`) yields the literal char `c`, and
///   - the hex-pair escape `\XX` yields the raw byte `0xXX`.
///
/// Consecutive `\XX` bytes are buffered and decoded together as UTF-8, so a multi-byte character
/// encoded as several hex escapes (e.g. `\C3\A9` → `é`) round-trips correctly.
fn unescape_rdn_value(v: &str) -> Option<String> {
    let bytes = v.as_bytes();
    let mut out = String::with_capacity(v.len());

    let mut pending: Vec<u8> = Vec::new();
    macro_rules! flush {
        () => {
            if !pending.is_empty() {
                out.push_str(std::str::from_utf8(&pending).ok()?);
                pending.clear();
            }
        };
    }
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16));
            if let (Some(hi), Some(lo)) = (hi, lo) {
                pending.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }

            flush!();
            if let Some(ch) = v[i + 1..].chars().next() {
                out.push(ch);
                i += 1 + ch.len_utf8();
            } else {
                i += 1;
            }
            continue;
        }

        flush!();
        if let Some(ch) = v[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            i += 1;
        }
    }
    flush!();
    Some(out)
}

/// Validate a username destined for a BIND-DN TEMPLATE. A DN component cannot safely contain the DN
/// special characters, and a username with them is either a typo or an injection attempt (e.g.
/// `admin,dc=corp,dc=example` trying to rewrite the DN). Reject rather than escape here: a login
/// username legitimately has none of these. Returns the username unchanged on success.
pub fn validate_username(username: &str) -> Result<&str, String> {
    if username.is_empty() {
        return Err("empty username".to_string());
    }

    const FORBIDDEN: &[char] = &[',', '+', '"', '\\', '<', '>', ';', '='];
    if username
        .chars()
        .any(|c| FORBIDDEN.contains(&c) || c.is_control())
    {
        return Err("username contains characters not allowed in a bind DN".to_string());
    }

    if username.starts_with(' ') || username.ends_with(' ') || username.starts_with('#') {
        return Err(
            "username starts or ends with a space, or starts with `#`, which a bind DN value \
             cannot"
                .to_string(),
        );
    }
    Ok(username)
}

/// Escape a username for inclusion in an LDAP SEARCH FILTER (RFC4515). Used on the search-then-bind
/// path where the username goes into a filter like `(sAMAccountName={username})`. Unlike the DN path
/// we escape (not reject), because a search value can legitimately be broader — but `*()\NUL` must be
/// neutralized so a username can't inject filter syntax.
pub fn escape_filter(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(c),
        }
    }
    out
}
