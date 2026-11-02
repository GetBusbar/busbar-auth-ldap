// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The LDAP codec: requests byte for byte as 1.5.5's client wrote them (hand-assembled here, not

use std::collections::HashMap;

use super::{
    decode, search, start_tls, unbind, Entry, LdapResult, Message, Reply, SCOPE_BASE, SCOPE_SUBTREE,
};
use crate::ber::{self, BerError};

/// `tag len content`, short form only (every hand-built message here is under 128 bytes).
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    assert!(content.len() < 128);
    [&[tag, content.len() as u8][..], content].concat()
}

#[test]
fn an_anonymous_bind_is_the_textbook_bytes() {
    assert_eq!(
        bind(1, "", "")[..],
        [0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00]
    );
}

#[test]
fn a_simple_bind_carries_version_3_the_dn_and_the_password() {
    let op = [
        tlv(0x02, &[3]),
        tlv(0x04, b"cn=a,dc=x"),
        tlv(0x80, b"s3cret"),
    ]
    .concat();
    let want = tlv(0x30, &[tlv(0x02, &[2]), tlv(0x60, &op)].concat());
    assert_eq!(bind(2, "cn=a,dc=x", "s3cret")[..], want[..]);
}

#[test]
fn unbind_and_start_tls_are_their_textbook_bytes() {
    assert_eq!(unbind(3), [0x30, 0x05, 0x02, 0x01, 0x03, 0x42, 0x00]);
    let ext = tlv(0x77, &tlv(0x80, b"1.3.6.1.4.1.1466.20037"));
    assert_eq!(start_tls(1), tlv(0x30, &[tlv(0x02, &[1]), ext].concat()));
}

/// The group read exactly as 1.5.5 sent it: base scope, never deref, no limits, types and values,
#[test]
fn the_group_read_is_1_5_5s_search() {
    let op = [
        tlv(0x04, b"uid=alice,dc=x"),
        tlv(0x0a, &[0]),
        tlv(0x0a, &[0]),
        tlv(0x02, &[0]),
        tlv(0x02, &[0]),
        tlv(0x01, &[0]),
        tlv(0x87, b"objectClass"),
        tlv(0x30, &tlv(0x04, b"memberOf")),
    ]
    .concat();
    let want = tlv(0x30, &[tlv(0x02, &[4]), tlv(0x63, &op)].concat());
    assert_eq!(
        search(
            4,
            "uid=alice,dc=x",
            SCOPE_BASE,
            "(objectClass=*)",
            &["memberOf"]
        ),
        Ok(want)
    );
    let sub = search(5, "dc=x", SCOPE_SUBTREE, "(uid=a)", &["dn"]).expect("encodes");
    assert!(
        sub.windows(3).any(|w| w == [0x0a, 0x01, 0x02]),
        "subtree scope"
    );
}

#[test]
fn a_filter_1_5_5_could_not_parse_is_its_words() {
    assert_eq!(
        search(1, "dc=x", SCOPE_SUBTREE, "(uid=a", &["dn"]),
        Err("filter parse error")
    );
}

fn result(rc: u8, matched: &[u8], text: &[u8]) -> Vec<u8> {
    [tlv(0x0a, &[rc]), tlv(0x04, matched), tlv(0x04, text)].concat()
}

fn msg(id: u8, op: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tlv(0x02, &[id]), op.to_vec()].concat())
}

#[test]
fn a_bind_response_decodes() {
    let m = msg(1, &tlv(0x61, &result(49, b"", b"bad")));
    assert_eq!(ber::frame(&m), Ok(Some(m.len())));
    assert_eq!(
        decode(&m),
        Ok(Message {
            id: 1,
            reply: Reply::Bind(LdapResult {
                rc: 49,
                matched: String::new(),
                text: "bad".into()
            })
        })
    );

    let with_controls = msg(
        1,
        &[
            tlv(0x61, &result(0, b"", b"")),
            tlv(0xa0, &tlv(0x30, &tlv(0x04, b"1.2"))),
        ]
        .concat(),
    );
    assert!(
        matches!(decode(&with_controls), Ok(Message { id: 1, reply: Reply::Bind(r) }) if r.rc == 0)
    );
}

#[test]
fn a_search_entry_keeps_its_text_values_and_warns_of_the_rest() {
    fn attr(name: &[u8], vals: &[&[u8]]) -> Vec<u8> {
        let vals: Vec<u8> = vals.iter().flat_map(|v| tlv(0x04, v)).collect();
        tlv(0x30, &[tlv(0x04, name), tlv(0x31, &vals)].concat())
    }
    let attrs = [
        attr(b"memberOf", &[b"cn=a,dc=x", b"cn=b,dc=x"]),
        attr(b"jpegPhoto", &[b"\xff\xd8"]),
        attr(b"mixed", &[b"text", b"\xff"]),
        attr(b"empty", &[]),
    ]
    .concat();
    let m = msg(
        2,
        &tlv(
            0x64,
            &[tlv(0x04, b"uid=alice,dc=x"), tlv(0x30, &attrs)].concat(),
        ),
    );
    let want: HashMap<String, Vec<String>> = [
        (
            "memberOf".to_string(),
            vec!["cn=a,dc=x".to_string(), "cn=b,dc=x".to_string()],
        ),
        ("jpegPhoto".to_string(), Vec::new()),
        ("mixed".to_string(), vec!["text".to_string()]),
        ("empty".to_string(), Vec::new()),
    ]
    .into_iter()
    .collect();
    let cap = crate::diagnostics::Diagnostics::default();
    let got = tracing::subscriber::with_default(cap.subscriber(), || decode(&m));
    assert_eq!(
        got,
        Ok(Message {
            id: 2,
            reply: Reply::Entry(Entry {
                dn: "uid=alice,dc=x".into(),
                attrs: want
            })
        })
    );
    assert_eq!(cap.count("not UTF-8"), 2, "{:?}", cap.messages());
    assert!(cap.contains("attribute=mixed"), "{:?}", cap.messages());
    assert!(cap.contains("dropped=1"), "{:?}", cap.messages());
    assert!(!cap.contains("attribute=memberOf"), "{:?}", cap.messages());
}

/// A failed search reads in 1.5.5's words (`LdapError::LdapResult`'s Display).
#[test]
fn a_search_done_decodes_and_reads_in_1_5_5s_words() {
    let m = msg(3, &tlv(0x65, &result(32, b"dc=x", b"no such entry")));
    let Ok(Message {
        id: 3,
        reply: Reply::Done(r),
    }) = decode(&m)
    else {
        panic!("a done");
    };
    assert_eq!(
        r.to_string(),
        "LDAP operation result: rc=32 (noSuchObject), dn: \"dc=x\", text: \"no such entry\""
    );
    let reference = msg(3, &tlv(0x73, &tlv(0x04, b"ldap://elsewhere/")));
    assert_eq!(decode(&reference).map(|m| m.reply), Ok(Reply::Reference));
}

#[test]
fn an_extended_response_decodes_with_its_name() {
    let m = msg(
        1,
        &tlv(
            0x78,
            &[result(0, b"", b""), tlv(0x8a, b"1.3.6.1.4.1.1466.20037")].concat(),
        ),
    );
    assert_eq!(
        decode(&m).map(|m| m.reply),
        Ok(Reply::Extended(
            LdapResult::default(),
            Some("1.3.6.1.4.1.1466.20037".into())
        ))
    );

    let notice = msg(
        0,
        &tlv(
            0x78,
            &[
                result(52, b"", b"bye"),
                tlv(0x8a, b"1.3.6.1.4.1.1466.20036"),
            ]
            .concat(),
        ),
    );
    assert!(
        matches!(decode(&notice), Ok(Message { id: 0, reply: Reply::Extended(r, _) }) if r.rc == 52)
    );
}

#[test]
fn a_malformed_reply_is_an_error_never_a_panic() {
    for bad in [
        tlv(0x04, b"x"),
        tlv(0x30, &tlv(0x61, &result(0, b"", b""))),
        msg(1, &tlv(0x61, &tlv(0x04, b""))),
        msg(
            1,
            &tlv(
                0x61,
                &[tlv(0x0a, &[0xff]), tlv(0x04, b""), tlv(0x04, b"")].concat(),
            ),
        ),
        msg(
            2,
            &tlv(0x64, &[tlv(0x04, b"\xff"), tlv(0x30, &[])].concat()),
        ),
        msg(2, &tlv(0x64, &tlv(0x04, b"dn"))),
        msg(
            2,
            &tlv(
                0x64,
                &[
                    tlv(0x04, b"dn"),
                    tlv(
                        0x30,
                        &tlv(
                            0x30,
                            &[tlv(0x04, b"a"), tlv(0x31, &tlv(0x02, &[1]))].concat(),
                        ),
                    ),
                ]
                .concat(),
            ),
        ),
        [msg(1, &tlv(0x61, &result(0, b"", b""))), vec![0x00]].concat(),
    ] {
        assert!(decode(&bad).is_err(), "{bad:02x?}");
    }

    let m = msg(
        2,
        &tlv(
            0x64,
            &[
                tlv(0x04, b"uid=alice,dc=x"),
                tlv(
                    0x30,
                    &tlv(
                        0x30,
                        &[tlv(0x04, b"memberOf"), tlv(0x31, &tlv(0x04, b"cn=a"))].concat(),
                    ),
                ),
            ]
            .concat(),
        ),
    );
    for n in 0..m.len() {
        assert!(
            decode(&m[..n]).is_err(),
            "a truncated message is no message"
        );
    }
    for at in 0..m.len() {
        for b in [0x00, 0x01, 0x7f, 0x80, 0x82, 0xff] {
            let mut c = m.clone();
            c[at] = b;
            let _ = ber::frame(&c);
            let _ = decode(&c);
        }
    }
}

#[test]
fn an_overrunning_nested_length_fails_fast() {
    let inner = [tlv(0x04, b"dn"), vec![0x30, 0x7f, 0x30, 0x00]].concat();
    let m = msg(2, &tlv(0x64, &inner));
    assert_eq!(
        ber::frame(&m),
        Ok(Some(m.len())),
        "the message itself is whole"
    );
    assert_eq!(decode(&m), Err(BerError::Overrun));
}

#[test]
fn a_reply_past_the_cap_is_refused_from_its_header() {
    let len = (ber::INBOUND_CAP as u32).to_be_bytes();
    let head = [&[0x30, 0x84][..], &len[..]].concat();
    assert!(matches!(ber::frame(&head), Err(BerError::TooLarge(_))));
}

/// The chip's BIND message (`Cred::ldap_simple_bind`), as the wire carries it: the bytes above are
fn bind(id: i32, dn: &str, password: &str) -> Vec<u8> {
    let mut w = busbar_contract::abi::sdk::cred::SealedWrite::message(
        crate::tests::cred(password).ldap_simple_bind(id, dn),
    );
    let mut bytes = Vec::new();
    let sent: std::task::Poll<Result<(), ()>> =
        busbar_contract::abi::sdk::test_support::chip::drive_sealed(&mut w, |b| {
            bytes.extend_from_slice(b);
            std::task::Poll::Ready(Ok(b.len()))
        });
    assert!(sent.is_ready(), "the BIND is written whole");
    bytes
}

/// An entry of `n` values of `value` under `memberOf`, long-form lengths allowed.
fn big_entry(id: i32, n: usize, value: &[u8]) -> Vec<u8> {
    let mut vals = Vec::new();
    for _ in 0..n {
        ber::tlv(&mut vals, ber::OCTET_STRING, value);
    }
    let mut a = Vec::new();
    ber::tlv(&mut a, ber::OCTET_STRING, b"memberOf");
    ber::tlv(&mut a, ber::SET, &vals);
    let mut op = Vec::new();
    ber::tlv(&mut op, ber::OCTET_STRING, b"uid=alice,dc=x");
    ber::tlv(&mut op, ber::SEQUENCE, &ber::element(ber::SEQUENCE, &a));
    let mut content = Vec::new();
    ber::int(&mut content, ber::INTEGER, i64::from(id));
    content.extend_from_slice(&ber::element(0x64, &op));
    ber::element(ber::SEQUENCE, &content)
}

#[test]
fn an_attributes_values_are_capped_while_decoding() {
    let m = big_entry(2, 100_000, b"x");
    let Ok(Message {
        reply: Reply::Entry(e),
        ..
    }) = decode(&m)
    else {
        panic!("an entry");
    };
    assert_eq!(e.attrs["memberOf"].len(), crate::MAX_GROUP_VALUES + 1);
}

#[test]
fn decoded_values_past_the_budget_are_an_error() {
    let m = big_entry(2, 5, &vec![b'a'; 1024 * 1024]);
    assert!(m.len() < ber::INBOUND_CAP);
    let got = decode(&m);
    assert!(
        matches!(&got, Err(e) if e.to_string().contains("4 MiB")),
        "{:?}",
        got.map(|m| m.id)
    );
}

#[test]
fn a_results_far_end_text_is_escaped_and_capped() {
    let r = LdapResult {
        rc: 32,
        matched: "m".repeat(10_000),
        text: "forged\nlevel=ERROR injected\r\u{1b}[31m".repeat(50),
    };
    let shown = r.to_string();
    assert!(!shown.contains('\n') && !shown.contains('\r'), "{shown}");
    assert!(!shown.contains('\u{1b}'), "{shown}");
    assert!(
        shown.contains("\\n"),
        "the newline is shown escaped: {shown}"
    );
    assert!(
        shown.chars().count() < 2 * 128 * 4 + 80,
        "capped: {}",
        shown.len()
    );
    assert!(!shown.contains(&"m".repeat(129)), "the DN is capped");

    let short = LdapResult {
        rc: 32,
        matched: "dc=x".into(),
        text: "no such entry".into(),
    };
    assert_eq!(
        short.to_string(),
        "LDAP operation result: rc=32 (noSuchObject), dn: \"dc=x\", text: \"no such entry\""
    );
}

#[test]
fn directory_result_strings_and_response_names_share_the_decode_budget() {
    let bind = msg(1, &tlv(0x61, &result(0, b"dn", b"diagnostic")));
    let mut budget = 2 * super::PER_STRING + 2 + 10;
    assert!(super::decode_within(&bind, &mut budget).is_ok());
    assert_eq!(budget, 0);
    let mut short = 2 * super::PER_STRING + 2 + 9;
    assert_eq!(
        super::decode_within(&bind, &mut short),
        Err(BerError::OverBudget)
    );

    let extended = msg(
        1,
        &tlv(0x78, &[result(0, b"", b""), tlv(0x8a, b"name")].concat()),
    );
    let mut short = 3 * super::PER_STRING + 3;
    assert_eq!(
        super::decode_within(&extended, &mut short),
        Err(BerError::OverBudget)
    );

    let lossy = msg(1, &tlv(0x61, &result(0, b"\xff", b"")));
    let mut budget = 2 * super::PER_STRING + 3;
    assert!(super::decode_within(&lossy, &mut budget).is_ok());
    assert_eq!(budget, 0);
}

#[test]
fn repeated_attribute_descriptions_preserve_all_values() {
    let attr = |value: &[u8]| {
        tlv(
            0x30,
            &[tlv(0x04, b"memberOf"), tlv(0x31, &tlv(0x04, value))].concat(),
        )
    };
    let attrs = [attr(b"CN=a"), attr(b"CN=b")].concat();
    let message = msg(
        1,
        &tlv(0x64, &[tlv(0x04, b"uid=a"), tlv(0x30, &attrs)].concat()),
    );
    let Reply::Entry(entry) = decode(&message).unwrap().reply else {
        panic!("entry")
    };
    assert_eq!(entry.attrs["memberOf"], ["CN=a", "CN=b"]);
}

#[test]
fn a_directory_attribute_cannot_inject_a_warning_line() {
    let name = b"memberOf\n\x1b[31m";
    let attr = tlv(
        0x30,
        &[tlv(0x04, name), tlv(0x31, &tlv(0x04, b"\xff"))].concat(),
    );
    let message = msg(
        1,
        &tlv(0x64, &[tlv(0x04, b"uid=a"), tlv(0x30, &attr)].concat()),
    );
    let cap = crate::diagnostics::Diagnostics::default();
    tracing::subscriber::with_default(cap.subscriber(), || decode(&message)).unwrap();
    assert!(cap.contains("\\n"), "{:?}", cap.messages());
    assert!(!cap
        .messages()
        .iter()
        .any(|line| line.contains('\n') || line.contains('\u{1b}')));
}

#[test]
fn a_user_search_entry_with_no_requested_attributes_decodes() {
    let message = msg(
        1,
        &tlv(0x64, &[tlv(0x04, b"cn=a"), tlv(0x30, &[])].concat()),
    );
    let Reply::Entry(entry) = decode(&message).unwrap().reply else {
        panic!("entry")
    };
    assert_eq!(entry.dn, "cn=a");
    assert!(entry.attrs.is_empty());
}

#[test]
fn definite_nonminimal_ber_lengths_still_decode() {
    let message = [
        vec![0x30, 0x84, 0, 0, 0, 14],
        vec![
            0x02, 0x81, 1, 1, 0x61, 0x81, 7, 0x0a, 1, 0, 0x04, 0, 0x04, 0,
        ],
    ]
    .concat();
    assert_eq!(ber::frame(&message), Ok(Some(message.len())));
    assert!(matches!(
        decode(&message),
        Ok(Message {
            id: 1,
            reply: Reply::Bind(LdapResult { rc: 0, .. })
        })
    ));
}

#[test]
fn a_negative_message_id_is_malformed() {
    let message = msg(0xff, &tlv(0x61, &result(0, b"", b"")));
    assert!(matches!(decode(&message), Err(BerError::Malformed(_))));
}

/// A SearchResultEntry that repeats an attribute description keeps the values of BOTH
/// PartialAttributes (a later one must not overwrite the earlier one's roles).
#[test]
fn a_repeated_attribute_description_keeps_every_value() {
    fn attr(name: &[u8], vals: &[&[u8]]) -> Vec<u8> {
        let vals: Vec<u8> = vals.iter().flat_map(|v| tlv(0x04, v)).collect();
        tlv(0x30, &[tlv(0x04, name), tlv(0x31, &vals)].concat())
    }
    let attrs = [
        attr(b"memberOf", &[b"cn=admins,dc=x"]),
        attr(b"memberOf", &[b"cn=users,dc=x"]),
    ]
    .concat();
    let m = msg(
        2,
        &tlv(
            0x64,
            &[tlv(0x04, b"uid=alice,dc=x"), tlv(0x30, &attrs)].concat(),
        ),
    );
    let Ok(Message {
        reply: Reply::Entry(e),
        ..
    }) = decode(&m)
    else {
        panic!("an entry");
    };
    assert_eq!(
        e.attrs["memberOf"],
        vec!["cn=admins,dc=x".to_string(), "cn=users,dc=x".to_string()]
    );
}

/// An attribute name the directory supplies is far-end text: a hostile name with a newline and an
/// ESC never reaches the log line raw, in the not-UTF-8 warn or the over-cap warn.
#[test]
fn a_hostile_attribute_name_is_escaped_in_the_logged_warnings() {
    let name = b"evil\n<forged line>\x1b[2J";
    let vals = [tlv(0x04, b"\xff"), tlv(0x04, b"ok")].concat();
    let attrs = tlv(0x30, &[tlv(0x04, name), tlv(0x31, &vals)].concat());
    let m = msg(
        2,
        &tlv(
            0x64,
            &[tlv(0x04, b"uid=alice,dc=x"), tlv(0x30, &attrs)].concat(),
        ),
    );
    let text = crate::tests::logged_text(|| {
        assert!(decode(&m).is_ok());
    });
    assert!(text.contains("not-utf8-values"), "{text:?}");
    assert!(
        !text.contains('\u{1b}') && !text.contains("evil\n"),
        "the attribute name reached the log raw: {text:?}"
    );
    assert!(text.contains("evil\\n"), "{text:?}");
}

/// Values past the per-attribute cap are counted and the loss is logged once per attribute, with
/// the real number skipped.
#[test]
fn values_past_the_cap_are_counted_and_warned() {
    let n = crate::MAX_GROUP_VALUES + 100;
    let m = big_entry(2, n, b"x");
    let cap = crate::diagnostics::Diagnostics::default();
    let got = tracing::subscriber::with_default(cap.subscriber(), || decode(&m));
    assert!(got.is_ok());
    assert!(cap.contains("over-cap"), "{:?}", cap.messages());
    assert!(cap.contains("attribute=memberOf"), "{:?}", cap.messages());
    assert!(cap.contains("skipped=99"), "{:?}", cap.messages());
}
