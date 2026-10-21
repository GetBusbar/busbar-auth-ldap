// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin-SIDE live end-to-end for the AD/LDAP login plugin — the mirror of `auth-oidc-plugin`'s
//! `tests/e2e.rs`, testing THIS plugin's OWN token-exchange direction (the GET credential-FORM flow:
//! chooser → form → POST creds → the plugin BINDs over the host connector's stream → key).
//!
//! LDAP is a `Credential` method: there is no held-token/redirect path, so the faithful test is a REAL
//! busbar boot driving the real form POST, with the plugin binding against a READY-MADE OpenLDAP
//! container (never a hand-rolled directory), provided by CI as a service container and addressed via
//! `BUSBAR_TEST_LDAP_URL` (mirrors the store plugins' `BUSBAR_TEST_POSTGRES_URL`). The container
//! auto-creates the base suffix + admin from its own env; this test seeds the test user/group over
//! LDAP itself (`ldap3`, a dev-only client; the plugin speaks its own sans-IO codec) — the CI-service equivalent of feeding
//! busbar/scripts/fixtures/auth-ldap/seed.ldif, kept in-test so the plugin's CI is self-contained.
//!
//! GATING: `BUSBAR_TEST_LDAP_URL` unset ⇒ SKIP loudly (local, no docker) — never a silent pass.
//! Under CI (`CI` set) the plugin-ci `service: openldap` arm sets it and the tests RUN; an unset URL
//! under CI FAILS, so a broken service arm cannot turn the only real-directory gate vacuous.

#[path = "../../auth-ldap/src/tests/live_seed.rs"]
mod live_seed;

use live_seed::{live_ldap_url, seed_directory, ALICE_PW};
use std::io::Write as _;

/// The busbar checkout the live e2e builds the REAL `busbar` and `busbar-plugin-pack` binaries from:
/// `BUSBAR_CHECKOUT`, a checkout of GetBusbar/busbar at `.busbar-ref` field 1 (this repo's CI `e2e` job
/// checks it out and sets the variable). This repo builds against busbar by git rev, not a sibling
/// path, so the binaries' source is named explicitly. Unset ⇒ the live leg cannot run, and says so.
fn busbar_root() -> std::path::PathBuf {
    let dir = std::env::var_os("BUSBAR_CHECKOUT").expect(
        "BUSBAR_CHECKOUT is unset: the live e2e builds the real busbar binaries from a checkout of \
         GetBusbar/busbar at .busbar-ref (ci.yml `e2e` sets it)",
    );
    std::path::PathBuf::from(dir)
        .canonicalize()
        .expect("BUSBAR_CHECKOUT names an existing busbar checkout")
}

fn build_real_binaries() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = busbar_root();
    // Two invocations: in busbar 1.6.0 `busbar-plugin-pack` is a feature-gated bin of the
    // `busbar-plugin-loader` package (`--features pack`), not a package of its own, and building it
    // separately keeps the `pack` feature out of the `busbar` build.
    for args in [
        &["build", "--release", "-p", "busbar", "--bin", "busbar"][..],
        &[
            "build",
            "--release",
            "-p",
            "busbar-plugin-loader",
            "--features",
            "pack",
            "--bin",
            "busbar-plugin-pack",
        ][..],
    ] {
        let status = std::process::Command::new("cargo")
            .args(args)
            .current_dir(&root)
            // The binaries are read back from `<sibling>/target/release` below, so the build must
            // land there: an inherited CARGO_TARGET_DIR (set for the outer `cargo test`) would
            // redirect it into the plugin's own target dir.
            .env_remove("CARGO_TARGET_DIR")
            .env("BUSBAR_RELEASE_PUBKEY", E2E_RELEASE_PUBKEY)
            .status()
            .expect("run cargo build for busbar / busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    (
        root.join("target/release/busbar"),
        root.join("target/release/busbar-plugin-pack"),
    )
}

/// THE TEST-ONLY FIRST-PARTY KEYPAIR (ed25519, `busbar-plugin-pack keygen`), never the release key.
/// busbar grants the `operator-infrastructure` egress class this module's `tcp` need declares to a
/// FIRST-PARTY plugin only (`busbar_plugin_loader::sign::egress_grant`): the busbar built here
/// embeds the public half (`BUSBAR_RELEASE_PUBKEY`, compile time, as busbar's signing gate builds
/// it) and the tarball is signed with the private half, so the plugin under test is first-party.
/// Fixed, so the cached busbar build is reused across runs (the same pair busbar-store-postgres's
/// e2e uses).
const E2E_RELEASE_PUBKEY: &str = "9209607c315f66473c8cca8bf9a7b8031115d01bb47341613cebf57f0e4f271c";
const E2E_RELEASE_PRIVKEY: &str =
    "290f2453f236650ab21b85a95d49b9dab088518e829e4d524b01e441636ab327";

fn plugin_path() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = busbar_plugin_loader::plugin_library_filename("busbar_auth_ldap_plugin");
        let uplifted = profile_dir.join(&name);
        let raw = profile_dir.join("deps").join(&name);
        [uplifted, raw]
            .into_iter()
            .filter_map(|p| {
                std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .map(|mtime| (p, mtime))
            })
            .max_by_key(|(_, mtime)| *mtime)
            .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!("busbar_auth_ldap_plugin cdylib not built under CI (run `cargo test --workspace`)");
    }
    candidate
}

fn pack_ldap(
    pack_bin: &std::path::Path,
    version: &str,
    so: &std::path::Path,
    out: &std::path::Path,
) {
    let status = std::process::Command::new(pack_bin)
        .args([
            "pack",
            "--lib",
            so.to_str().unwrap(),
            "--name",
            "busbar-auth-ldap",
            "--alias",
            "ldap",
            "--kind",
            "auth",
            "--version",
            version,
            "--publisher",
            "busbar",
            "--description",
            "ldap plugin-side e2e",
            "--license",
            "Apache-2.0",
            "--out",
            out.to_str().unwrap(),
        ])
        .env("BUSBAR_SIGN_KEY", E2E_RELEASE_PRIVKEY)
        .status()
        .expect("run busbar-plugin-pack");
    assert!(status.success(), "packing the ldap plugin must succeed");
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn cookie_state(cookie_value: &str) -> String {
    use base64::Engine as _;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cookie_value)
        .expect("cookie is base64url");
    let v: serde_json::Value = serde_json::from_slice(&bytes).expect("cookie is JSON");
    v["state"]
        .as_str()
        .expect("cookie carries state")
        .to_string()
}

fn issued_key_from_html(html: &str) -> Option<String> {
    let marker = "id=\"key\">";
    let start = html.find(marker)? + marker.len();
    let rest = &html[start..];
    let end = rest.find('<')?;
    Some(rest[..end].to_string())
}

fn login_cookie(resp: &reqwest::blocking::Response) -> String {
    resp.headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|h| h.to_str().ok())
        .find_map(|c| {
            c.strip_prefix("busbar_login=")
                .map(|r| r.split(';').next().unwrap_or("").to_string())
        })
        .expect("begin sets the busbar_login cookie")
}

fn wait_for_health(
    client: &reqwest::blocking::Client,
    url: &str,
    child: &mut std::process::Child,
    log: &std::path::Path,
) {
    for _ in 0..150 {
        if let Ok(Some(status)) = child.try_wait() {
            let said = std::fs::read_to_string(log).unwrap_or_default();
            panic!("busbar exited early during health poll: {status}\n{said}");
        }
        if client
            .get(url)
            .send()
            .is_ok_and(|r| r.status().is_success())
        {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("busbar did not become healthy at {url}");
}

/// THE plugin-side proof: a REAL busbar boot drives the ldap credential-form flow; the plugin BINDs
/// alice against OpenLDAP, reads her group DN (→ role `admins` → group eng-team), a key is minted, and
/// it authenticates on the data plane. A WRONG password is REJECTED 401 — the real bind gates.
#[test]
fn ldap_form_flow_binds_mints_key_and_gates_wrong_password() {
    let Some(url) = live_ldap_url() else {
        return;
    };
    let Some(so_path) = plugin_path() else {
        eprintln!("skip: busbar_auth_ldap_plugin cdylib not built");
        return;
    };
    seed_directory(&url);
    let (busbar_bin, pack_bin) = build_real_binaries();

    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let work = std::env::temp_dir().join(format!(
        "busbar-ldap-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins_dir = work.join("plugins");
    std::fs::create_dir_all(&plugins_dir).unwrap();
    pack_ldap(
        &pack_bin,
        // The version the plugin states in its Statement (the logic crate's, which this crate
        // shares): busbar-plugin-pack refuses any other. A fresh deployment holds no high-water mark
        // for the name, so no first-party floor applies.
        env!("CARGO_PKG_VERSION"),
        &so_path,
        &plugins_dir.join("busbar-auth-ldap.tar.gz"),
    );

    let data_port = free_port();
    let signing_key = work.join("signing.key");
    {
        let out = std::process::Command::new(&busbar_bin)
            .arg("--generate-signing-key")
            .output()
            .expect("generate signing key");
        assert!(out.status.success());
        std::fs::File::create(&signing_key)
            .unwrap()
            .write_all(&out.stdout)
            .unwrap();
    }

    let providers = work.join("providers.yaml");
    std::fs::write(
        &providers,
        "mock:\n  protocol: anthropic\n  base_url: \"http://127.0.0.1:9\"\n",
    )
    .unwrap();

    let config = work.join("config.yaml");
    std::fs::write(
        &config,
        format!(
            "listen: \"127.0.0.1:{data_port}\"\n\
             public_url: \"https://gate.busbar.e2e\"\n\
             store:\n  module: memory\n\
             identity-providers:\n  admin-tokens: {{ module: admin-tokens, token: {{ env: BUSBAR_ADMIN_TOKEN }} }}\n\
             \x20 ldap:\n    module: ldap\n    browser_login: {{}}\n\
             \x20   settings:\n      url: \"{url}\"\n\
             \x20     bind_dn_template: \"uid={{username}},ou=people,dc=example,dc=org\"\n\
             \x20     base_dn: \"dc=example,dc=org\"\n      group_attr: \"seeAlso\"\n      role_from: cn\n\
             auth:\n  key_ttl: \"7d\"\n  signing_key: {{ file: \"{signing}\" }}\n  chain:\n    - keys\n\
             \x20 admin_auth: [admin-tokens]\n\
             \x20 role_bindings:\n    ldap:\n      admins:\n        group: eng-team\n\
             plugins:\n  enabled: true\n  dir: {plugins}\n  trust:\n    allow_unsigned: true\n\
             groups:\n  eng-team:\n    limits:\n      - {{ requests: 1000000, per: day }}\n\
             \x20   child_default:\n      limits:\n        - {{ budget: 5000, per: month }}\n        - {{ requests: 1000, per: day }}\n\
             providers:\n  mock:\n    api_key: {{ env: MOCK_KEY }}\n\
             models:\n  test-model:\n    provider: mock\n",
            signing = signing_key.display(),
            plugins = plugins_dir.display(),
        ),
    )
    .unwrap();

    let stderr_log = work.join("busbar.stderr");
    let mut child = std::process::Command::new(&busbar_bin)
        .env("BUSBAR_CONFIG", &config)
        .env("BUSBAR_PROVIDERS", &providers)
        .env("MOCK_KEY", "unused")
        .env("BUSBAR_ADMIN_TOKEN", "e2e-admin-token")
        .env("BUSBAR_STATE_FILE", "")
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(&stderr_log).expect("busbar's stderr log"))
        .spawn()
        .expect("spawn busbar with identity-providers.ldap");
    let base = format!("http://127.0.0.1:{data_port}");
    wait_for_health(&client, &format!("{base}/healthz"), &mut child, &stderr_log);

    // begin: GET ?method=ldap → 200 credential form + cookie.
    let begin = client
        .get(format!("{base}/auth/token?method=ldap"))
        .send()
        .expect("GET begin");
    assert!(
        begin.status().is_success(),
        "ldap begin renders a form (200), got {}",
        begin.status()
    );
    let cookie_value = login_cookie(&begin);
    let state = cookie_state(&cookie_value);

    // POST creds (correct password) → the plugin binds + reads groups → key page.
    let ok_page = client
        .post(format!("{base}/auth/token"))
        .header(
            reqwest::header::COOKIE,
            format!("busbar_login={cookie_value}"),
        )
        .form(&[
            ("__state", state.as_str()),
            ("username", "alice"),
            ("password", ALICE_PW),
        ])
        .send()
        .expect("POST creds");
    assert!(
        ok_page.status().is_success(),
        "correct creds should mint a key, got {}",
        ok_page.status()
    );
    let page = ok_page.text().unwrap();
    assert!(
        page.contains("ldap:uid=alice"),
        "identity ldap:uid=alice must appear: {page}"
    );
    // The key page names the per-user group only. It exists because role 'admins' bound to
    // eng-team: with no bound role busbar answers 403 "No access yet" and the success check above
    // fails. The role itself is asserted directly in
    // `ldap_module_binds_live_in_both_modes_and_maps_the_group`.
    assert!(
        page.contains("user:ldap:uid=alice"),
        "group user:ldap:uid=alice must appear (role 'admins' must have bound)"
    );
    let api_key = issued_key_from_html(&page).expect("the key page carries the issued api_key");

    let chat = client
        .post(format!("{base}/v1/chat/completions"))
        .bearer_auth(&api_key)
        .json(
            &serde_json::json!({"model":"test-model","messages":[{"role":"user","content":"hi"}]}),
        )
        .send()
        .expect("chat with the issued key");
    assert_ne!(
        chat.status().as_u16(),
        401,
        "the self-scoped ldap key must authenticate"
    );

    // WRONG password must be rejected 401 — proving the REAL bind gates. Fresh begin → fresh cookie.
    let begin2 = client
        .get(format!("{base}/auth/token?method=ldap"))
        .send()
        .expect("GET begin 2");
    let cookie2 = login_cookie(&begin2);
    let state2 = cookie_state(&cookie2);
    let bad = client
        .post(format!("{base}/auth/token"))
        .header(reqwest::header::COOKIE, format!("busbar_login={cookie2}"))
        .form(&[
            ("__state", state2.as_str()),
            ("username", "alice"),
            ("password", "wrong-password"),
        ])
        .send()
        .expect("POST wrong creds");
    assert_eq!(
        bad.status().as_u16(),
        401,
        "a wrong password must be rejected 401 (bind gates)"
    );

    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&work);
}
