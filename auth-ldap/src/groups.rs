// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure helpers for the LDAP module: turning group DNs into role strings, and defending the two

use std::collections::HashSet;

use crate::RoleFrom;

/// Map the raw group-membership DN values off the directory to [`crate::Principal`] role strings,
pub fn roles_from_group_dns(group_dns: &[String], mode: RoleFrom) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(group_dns.len());

    let mut seen: HashSet<String> = HashSet::with_capacity(group_dns.len());
    for dn in group_dns {
        let role = match mode {
            RoleFrom::Cn => match first_cn(dn) {
                Some(cn) => cn,

                None => dn.trim().to_string(),
            },
            RoleFrom::Dn => dn.trim().to_lowercase(),
        };
        if role.is_empty() {
            tracing::warn!(
                module = "ldap",
                reason = "empty-group-role",
                "ldap group value maps to an empty role and was omitted"
            );
        } else if seen.insert(role.clone()) {
            out.push(role);
        }
    }
    out
}

/// Extract the value of the first `CN=` attribute of a DN, unescaping the handful of DN escapes we
pub(crate) fn first_cn(dn: &str) -> Option<String> {
    for rdn in split_unescaped(dn, ',') {
        for ava in split_unescaped(&rdn, '+') {
            let Some((attr, val)) = ava.split_once('=') else {
                continue;
            };
            if attr.trim().eq_ignore_ascii_case("cn") {
                return unescape_rdn_value(trim_rdn_value(val));
            }
        }
    }
    None
}

/// Split a DN at every unescaped `sep` (`,` between RDNs, `+` between the attribute-value
fn split_unescaped(dn: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut chars = dn.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                cur.push('\\');
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
            }
            c if c == sep => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        parts.push(cur);
    }
    parts
}

fn trim_rdn_value(value: &str) -> &str {
    let mut value = value.trim_start();
    while value.ends_with(' ') {
        let before = &value[..value.len() - 1];
        let slashes = before.bytes().rev().take_while(|&b| b == b'\\').count();
        if slashes % 2 == 1 {
            break;
        }
        value = before;
    }
    value
}

/// Unescape the DN-value escapes that survive [`split_unescaped`], per RFC 4514:
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
pub fn validate_username(username: &str) -> Result<&str, String> {
    if username.is_empty() {
        return Err("empty username".to_string());
    }

    const FORBIDDEN: &[char] = &[',', '+', '"', '\\', '<', '>', ';', '=', '\0', '\n', '\r'];
    if username
        .chars()
        .any(|c| FORBIDDEN.contains(&c) || c.is_control())
    {
        return Err("username contains characters not allowed in a bind DN".to_string());
    }

    if username.starts_with(' ') || username.ends_with(' ') || username.starts_with('#') {
        return Err("username contains characters not allowed in a bind DN".to_string());
    }
    Ok(username)
}

/// Escape a username for inclusion in an LDAP SEARCH FILTER (RFC4515). Used on the search-then-bind
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
