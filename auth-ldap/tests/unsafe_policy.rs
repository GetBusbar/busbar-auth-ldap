// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S CODE POLICY, read off the crate's own sources (THE DESIGN §2): an auth plugin is
//! `#![forbid(unsafe_code)]` ("Plane, hook, auth (inbound and outbound) and secret plugins are
//! `#![forbid(unsafe_code)]`"), and it holds no process-global or per-thread state of its own ("A
//! plugin holds no process-global state: what it keeps is per-instance"; the one approved per-thread
//! slot is the door macro's log capture, expanded from busbar-contract, never written here).

use std::path::{Path, PathBuf};

/// Every production source under `root`: `root/**.rs` outside a `tests` directory.
fn sources_under(root: &Path) -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).expect("src is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).expect("a source is readable");
                out.push((path, text));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, &mut out);
    assert!(!out.is_empty(), "{} has sources", root.display());
    out
}

/// Every production source of the crate: `src/**.rs` outside `src/tests`.
fn sources() -> Vec<(PathBuf, String)> {
    sources_under(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"))
}

/// Every source of the shipped cdylib crate, `auth-ldap-plugin/src`.
fn plugin_sources() -> Vec<(PathBuf, String)> {
    sources_under(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../auth-ldap-plugin/src"))
}

/// The code of a source, its `//` comments dropped (prose may name what the code must not do). A
/// `//` inside a string literal (`"ldap://"`) is code, not a comment: the line is read on past it.
fn code(text: &str) -> String {
    text.lines()
        .map(|line| {
            let bytes = line.as_bytes();
            let mut in_str = false;
            let mut k = 0;
            while k < bytes.len() {
                match bytes[k] {
                    b'\\' if in_str => k += 1,
                    b'"' => in_str = !in_str,
                    b'/' if !in_str && bytes.get(k + 1) == Some(&b'/') => return &line[..k],
                    _ => {}
                }
                k += 1;
            }
            line
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Whether `code` declares a `static` item, in any visibility or after an attribute on the same
/// line: the keyword as a whole word, not a `'static` lifetime.
fn declares_a_static(code: &str) -> Option<&str> {
    code.lines().find(|line| {
        line.match_indices("static").any(|(at, _)| {
            let before = line[..at].chars().next_back();
            let after = line[at + "static".len()..].chars().next();
            !before.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '\'')
                && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    })
}

/// The detector catches every form of a static, and never a lifetime or a string's `//`.
#[test]
fn the_policy_scan_sees_every_static_form() {
    for line in [
        "static X: u8 = 0;",
        "pub static X: u8 = 0;",
        "pub(crate) static X: u8 = 0;",
        "pub(super) static X: u8 = 0;",
        "pub(in crate::door) static X: u8 = 0;",
        "#[allow(dead_code)] static X: u8 = 0;",
        "static mut X: u8 = 0;",
        "let url = \"ldap://\"; static X: u8 = 0;",
    ] {
        assert!(declares_a_static(&code(line)).is_some(), "missed: {line}");
    }
    for line in [
        "const S: &'static str = \"x\";",
        "fn f<T: 'static>() {}",
        "let s = 1; // static X: u8 = 0;",
        "let statically = 1;",
    ] {
        assert!(declares_a_static(&code(line)).is_none(), "flagged: {line}");
    }
}

#[test]
fn the_crate_forbids_unsafe_code() {
    let lib = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"))
        .expect("src/lib.rs");
    assert!(
        lib.lines().any(|l| l.trim() == "#![forbid(unsafe_code)]"),
        "src/lib.rs must be `#![forbid(unsafe_code)]` (THE DESIGN §2), not `deny` with an allow-list"
    );
    for (path, text) in sources() {
        let code = code(&text);
        for banned in [
            "allow(unsafe_code)",
            "unsafe {",
            "unsafe fn",
            "unsafe impl",
            "unsafe extern",
        ] {
            assert!(
                !code.contains(banned),
                "{} holds `{banned}`: an auth plugin's crate holds no unsafe code",
                path.display()
            );
        }
    }
}

#[test]
fn the_crate_holds_no_per_thread_or_process_global_state() {
    for (path, text) in sources() {
        let code = code(&text);
        assert!(
            !code.contains("thread_local!"),
            "{} declares a `thread_local!`: a plugin's state is per instance (THE DESIGN §2)",
            path.display()
        );
        if let Some(line) = declares_a_static(&code) {
            panic!(
                "{} declares a static (`{}`): a plugin's state is per instance (THE DESIGN §2)",
                path.display(),
                line.trim()
            );
        }
    }
}

/// The shipped cdylib crate (`auth-ldap-plugin`) is `deny(unsafe_code)` for the export macro's one
/// reviewed exemption, and a `deny` can be lifted locally: it is held here to exactly that. Its one
/// `allow(unsafe_code)` sits on `mod exported`, which holds only `export_door!`; no other `unsafe`,
/// no static and no per-thread state exists in it.
#[test]
fn the_plugin_crate_holds_only_the_export_exemption() {
    for (path, text) in plugin_sources() {
        let code = code(&text);
        assert!(
            code.lines().any(|l| l.trim() == "#![deny(unsafe_code)]") || !path.ends_with("lib.rs"),
            "{} must be `#![deny(unsafe_code)]`",
            path.display()
        );
        let allows = code.matches("allow(unsafe_code)").count();
        assert!(
            allows <= 1,
            "{}: {allows} unsafe exemptions",
            path.display()
        );
        if allows == 1 {
            let at = code.find("allow(unsafe_code)").unwrap_or(0);
            let after: String = code[at..].split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                after.starts_with(
                    "allow(unsafe_code)] mod exported { busbar_contract::export_door!(busbar_auth_ldap::door::door); }"
                ),
                "{}: the one exemption is `mod exported`, holding only `export_door!`: {after}",
                path.display()
            );
        }
        for banned in [
            "unsafe {",
            "unsafe fn",
            "unsafe impl",
            "unsafe extern",
            "thread_local!",
        ] {
            assert!(
                !code.contains(banned),
                "{} holds `{banned}`",
                path.display()
            );
        }
        assert!(
            declares_a_static(&code).is_none(),
            "{} declares a static",
            path.display()
        );
    }
}
