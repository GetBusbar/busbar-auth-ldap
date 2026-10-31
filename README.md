<!-- fleet:header:begin (rendered by `busbar-release plugin heal` from GetBusbar/busbar-release template/ and busbar's plugins.yaml; edit it there) -->
# busbar-auth-ldap

The AD/LDAP auth module as a droppable busbar plugin: a cdylib exporting the auth C ABI. Drop it in the plugins folder, define it once under identity-providers.<name> (module: ldap, settings: url, bind_dn_template, base_dn, group_attr) and reference that name from auth.chain.

| kind | alias | crate | busbar | license |
|---|---|---|---|---|
| `auth` | `ldap` | `busbar-auth-ldap-plugin` | 1.6.0 (pinned in `.busbar-ref`) | Apache-2.0 |

[![ci](https://github.com/GetBusbar/busbar-auth-ldap/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/GetBusbar/busbar-auth-ldap/actions/workflows/ci.yml)
<!-- fleet:header:end -->

## What it is for

<!-- SPDX-License-Identifier: Apache-2.0 -->

[![Coverage](https://codecov.io/gh/GetBusbar/busbar-auth-ldap/branch/dev/graph/badge.svg)](https://codecov.io/gh/GetBusbar/busbar-auth-ldap)

The first-party, signed `kind: auth` plugin for
[busbar](https://getbusbar.com) that authenticates a username and
password against an AD/LDAP directory: a real LDAP/LDAPS **BIND** as the
credential check, a group read off the bound user, and a group-DN → role
mapping that hands busbar a `Principal` it can bind to virtual keys and
roles.

It is a `cdylib` exporting one busbar 1.6.0 plugin door
(`busbar_plugin_door`, a `plugin_door!` over the auth kind's table,
`abi::auth` v3, from
[`busbar-contract`](https://github.com/GetBusbar/busbar/tree/main/crates/busbar-contract)),
loaded in-process by busbar — `dlopen`'d, not spawned as a separate
process — or linked into a busbar build as a compiled-in row through the
same door, on the auth kind's table (`abi::auth` v3). Its declares file
(`auth-ldap/declares.json`) states only its network need (`tcp`).

It is a **separate plugin from `busbar-auth-oidc`**, and takes a
different shape: OIDC is a redirect flow where the core executes the
token-exchange HTTP hop, while LDAP is a direct credential flow where the
plugin speaks the directory's wire protocol itself, as a sans-IO codec
over a byte stream the host connector owns. The plugin opens no socket
and does no TLS.

### The login flow

1. A user types a username and password on busbar's hosted login page.
   The door's Statement declares a credential login kind, so the method
   chooser renders a form rather than a redirect button, without having
   to call `begin_login` first.
2. `begin_login` answers the form, declaring two fields — `username`
   (text) and `password` (password) — which the core renders and POSTs
   back to `/auth/token`.
3. `complete_login` reads those values back out of the submitted fields,
   keyed by the field names the plugin declared; the password rides a
   secret blob and is exposed only for the bind.
4. The plugin asks the host connector for a stream on its one declared
   need (outbound, a raw `tcp` stream, egress class
   `operator-infrastructure`), secured by the connector for `ldaps://` or
   after the StartTLS extended operation for `start_tls`, and BINDs with
   the user's DN and password over it. That bind *is* the credential
   check — no token, no redirect. While the stream pends, `complete_login`
   answers PENDING and resumes on the wake; nothing is sent twice.
5. On a successful bind it reads the user's group memberships
   (`memberOf` by default) and answers the identity, subject
   `ldap:<the user entry's DN>` and groups set from the mapped
   group names. The DN is the one the directory returns for the bound
   entry (falling back to the DN bound as when the group read returns no
   entry), lowercased with every run of spaces collapsed to one, so two
   spellings of one login (`John  Smith`, `john smith`) are one principal. A wrong credential answers a bad-credential verdict; a
   directory that cannot answer (connect, TLS, timeout) answers an
   outage. Every directory operation is bounded by `timeout_secs` on the
   host's clock; a login the host lends no clock answers an outage
   ("no host clock: refusing an untimed directory call") rather than
   bind with no deadline.

Because LDAP is a login method rather than a data-plane bearer verifier,
its tail states the login family alone (`CAP_LOGIN`, as
`busbar-auth-github`'s): the host never calls `verify`, which answers
REFUSED.

There is no `client_secret`: a credential method is not a confidential
OAuth client, so `LdapConfig` has no such field and
`deny_unknown_fields` rejects one if it is configured.

### Design

This repo is a same-repo, 2-crate Cargo workspace, mirroring `auth-oidc`:
`auth-ldap/` (the `busbar-auth-ldap` library — the real LDAP BIND,
group-read and role-mapping logic, and its door, `door::door`) and
`auth-ldap-plugin/` (the `busbar-auth-ldap-plugin` cdylib, which only
exports that door with `export_door!`). A custom build links the
library crate and registers `door::door` as a compiled-in row.

LDAP work is done by the plugin's own sans-IO codec (`ber.rs`,
`filter.rs`, `codec.rs`: the requests 1.5.5's `ldap3` client wrote, byte
for byte, and the replies read fail-closed; the BIND, which carries a
password, is the SDK chip's sealed message, held to the same bytes), driven over the host's stream
by `conversation.rs`. No call blocks, so the Statement states no `blocks`
mark, and the plugin carries no LDAP client, socket or TLS crate.

Two directory shapes are supported:

- **Direct bind** — `bind_dn_template` turns the username into a DN
  (`uid={username},ou=people,dc=corp,dc=example`) and the plugin binds as
  that DN, then reads the groups off that same entry. The template must
  expand to a DN: one with no `=` (an AD UPN such as
  `{username}@corp.example`) is refused at boot.
- **Search-then-bind** — set `user_search_filter` (e.g.
  `(sAMAccountName={username})`, or
  `(userPrincipalName={username}@corp.example)` for AD UPN logins, where
  users type the bare name as they did with 1.5.5's UPN template) and the
  plugin first binds as `bind_service_dn`, locates the user entry, then
  re-binds as the DN it found. This is the mode for Active Directory.

A crafted username cannot inject DN components or filter syntax: on the
DN template path a username carrying a DN special character (`,` `=` `+`
`<` `>` `;` `\` `"`, or a control character) is rejected, and on the
search filter path the username is RFC 4515-escaped.

## Config

Configured like any other busbar auth method — an entry under
`identity-providers:` referenced by name from `auth.chain`:

```yaml
identity-providers:
  corp-ldap:                 # the NAME is the instance; `module:` is the plugin behind it
    module: ldap
    settings:
      url: "ldaps://ad.corp.example:636"
      bind_dn_template: "cn={username},cn=users,dc=corp,dc=example"
      base_dn: "dc=corp,dc=example"
      user_search_filter: "(userPrincipalName={username}@corp.example)"
      bind_service_dn: "cn=busbar-svc,cn=users,dc=corp,dc=example"
      bind_service_password: { env: LDAP_BIND_PASSWORD }   # a secret reference, never a literal
      role_from: cn

auth:
  chain: [keys, corp-ldap]   # built-ins (`keys`, `admin-tokens`) are referenced bare
```

Group-to-role mapping is keyed by that same provider name:

```yaml
auth:
  role_bindings:
    corp-ldap:
      engineers: { group: engineering }
```

| Setting | Required | Default | Notes |
|---|---|---|---|
| `url` | yes | — | `ldaps://host:636` (implicit TLS), or `ldap://host:389` for plaintext/STARTTLS. |
| `bind_dn_template` | yes | — | Turns a username into the bind DN. Must contain `{username}`; validated at boot. In direct-bind mode it must expand to a DN (contain `=`). |
| `base_dn` | yes | — | Search base for the search-then-bind user lookup. May be empty for a directory that serves a search from base `""` (the AD Global Catalog, OpenLDAP with `olcDefaultSearchBase`). (The group read is a base read of the bound user's own entry.) |
| `group_attr` | no | `memberOf` | The attribute on the user entry listing group memberships. Each value is a group DN. Must not be empty. |
| `role_from` | no | `cn` | How a group DN becomes a role string: `cn` takes the value of the first `CN=` RDN in the directory's own case (a value with no `CN=` RDN is used whole, trimmed); `dn` uses the full DN, trimmed and lowercased. `role_bindings` keys must match that spelling exactly. |
| `user_search_filter` | no | — | Enables search-then-bind. Must contain `{username}` and parse as an RFC 4515 filter nested at most 32 levels deep (checked at boot); requires `bind_service_dn`. |
| `bind_service_dn` | no | — | Service-account DN used for the search-then-bind lookup. |
| `bind_service_password` | no | — | Service-account password, a secret reference. Held by the SDK chip; see [Limitations](#limitations). |
| `ca_cert_pem` | no | — | PEM of a private CA (an AD enterprise CA) the directory's certificate chains to. Trusted on top of the public roots for `ldaps://` and STARTTLS. A value that holds no certificate is refused at boot. |
| `start_tls` | no | `false` | Use STARTTLS over an `ldap://` connection instead of implicit LDAPS. |
| `allow_insecure_transport` | no | `false` | Override the plaintext-transport guard. See below. |
| `timeout_secs` | no | `10` | Connect and operation timeout, in seconds. Must be at least 1. |

Unknown config fields are rejected (`deny_unknown_fields`) — a typo'd or
stray key fails loudly at boot instead of being silently ignored.

Every settings refusal, at `validate` and at boot alike, is one line per
problem in the contract's instance-relative form, which busbar prints
under the instance (`identity-providers.corp-ldap.settings.timeout_secs:
must be at least 1`). No line quotes a value. A `url` that is empty or
that names no host is refused here rather than failing every login. A
missing or non-UTF-8 resolved service password reads
``secrets: `bind_service_password` is not set`` / `is not UTF-8`.

A plaintext `ldap://` URL pointing at a **non-loopback** host with no
STARTTLS is rejected at config time: it would put the service-account
password and every end-user password on the wire in the clear.
`allow_insecure_transport: true` knowingly overrides that guard for a
trusted, isolated segment. It is a no-op for `ldaps://`, for STARTTLS,
and for a loopback host.

### Limitations

- **A private CA rides its own need.** The Statement declares two `tcp`
  needs: one on the connector's own trust, and one whose `trust_from` is
  `settings.ca_cert_pem`, which the connector adds to the public roots for
  that need's connections. An instance with `ca_cert_pem` dials the
  second; one without dials the first. At busbar 1.6.0-dev.2 the
  connector refuses a need whose `trust_from` names an unset setting, so
  an instance without `ca_cert_pem` has its anchored need refused at
  declaration, and busbar records that refusal (`need.1`) in its audit
  log at each open and reload. Nothing else is affected.
- **The service-account password is a secret reference.** The Statement
  names `bind_service_password` in its `secret_refs`, so the kernel
  resolves it into `OpenIn.secrets`. It must be a reference (for example
  `bind_service_password: { env: LDAP_BIND_PASSWORD }`): from busbar
  1.6.0 a literal there (accepted by 1.5.5) refuses boot, naming
  `settings.bind_service_password` and never the value. The plugin holds it, and
  the submitted end-user password, as the SDK chip's credential
  (`abi::sdk::cred::Cred`: no getter, no `Debug`, no `Display`, wiped on
  drop). Every BIND is the chip's sealed message
  (`Cred::ldap_simple_bind`), written to the host's stream without the
  plugin reading it; for an `ldaps://` URL or `start_tls` it goes out
  only on a stream the host connector reports secured. Because the password is resolved
  only at `open`, `validate` runs the settings-only checks: a
  search-then-bind config with no literal password validates, and `open`
  refuses it if no password resolves (an explicit empty literal is
  refused by both). A settings value of the wrong type is refused without
  quoting it (it may be a secret in the wrong key); a missing or unknown
  key is named.
- **Fail-closed differences from 1.5.5 (owner-signed, 2026-09-28).** A
  malformed reply is an outage and a URL that names no host is refused at boot, instead of a
  panic; a nested BER length that overruns its parent fails at once
  instead of waiting for bytes that never come; an inbound message past
  16 MiB is refused from its header.
- **A directory outage answers its own verdict** (`LOGIN_OUTAGE`,
  distinct from a bad credential), and the plugin logs the operational
  detail (never the credential) at `warn`. A user-bind result code is an
  outage only when it names a server or session condition that fails
  every user alike (1, 2, 3, 7, 8, 10, 11, 12, 13, 14, 51 busy,
  52 unavailable, 54, 71, 80), or the transport failed. Result 49
  (invalidCredentials) is a bad credential, logged at `info`; every other
  non-zero code (48, 50, 53 unwillingToPerform, 32, 19, an unnamed code,
  ...) is the same bad credential as a wrong password (busbar 1.5.5
  answered every failed user bind, outages included, as a bad
  credential), logged once at `info` with the directory's real result
  code and name (never the password, never the DN). Every other refusal
  (a missing field, an empty password, no search match, an ambiguous
  search, an empty DN, a username the DN template refuses) is logged once
  at `info` with its reason. A group read that answers no entry for the
  bound user, or answers result 32 (noSuchObject) or 50
  (insufficientAccessRights) — an ACL hiding the user's own entry — logs a
  `warn` naming the code: the login stands, with no roles. Any other
  failed group read is an outage. One operation reads at most 1024 directory messages; past that it
  is an outage.
- **Group DNs are normalized by the plugin, not the engine.** LDAP and
  AD groups are DNs (`CN=engineers,OU=Groups,DC=corp,DC=example`), which
  make hostile `role_bindings` keys: commas and `=` are awkward in YAML,
  LDAP compares case-insensitively while the map does not, and the OU
  path is deployment-specific. `role_from` picks the shape;
  `cn` is the default for that reason.
- **Group collection is capped** at 4096 values per user entry, so a
  hostile or misconfigured directory cannot drive unbounded memory use.
  The plugin logs when it truncates.
- **Only text values are read.** A directory value that is not UTF-8 is
  dropped on its own (the attribute keeps its other values) with a `warn`
  naming the attribute and how many values went; a user entry that
  carries no group attribute at all logs in with no roles and a `warn`.
- **Ranged retrieval is not paged.** Active Directory returns a
  multi-valued attribute past its `MaxValRange` (1500 by default) as a
  ranged description (`memberOf;range=0-1499`). The group attribute is
  matched on its type, ignoring options, so those values are mapped to
  roles, and the plugin logs a `warn` that the list is truncated: a user
  in more groups than the range gets fewer roles, never more. The rest of
  the range (`;range=1500-*`) is not requested.

## Build

Needs a Rust toolchain ([rustup](https://rustup.rs)); `rust-toolchain.toml` pins
the version CI uses. busbar is a pinned git dependency (see
[Dependencies](#dependencies) below).

```sh
cargo build --release      # cdylib: target/release/libbusbar_auth_ldap_plugin.{so,dylib}
cargo test                 # unit tests + the end-to-end loader test
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Dependencies

`busbar-auth-ldap` (`auth-ldap/`) is a same-repo crate; `auth-ldap-plugin`
depends on it as a normal workspace path dependency (`../auth-ldap`).

The one [busbar](https://github.com/GetBusbar/busbar) crate either crate
names is `busbar-contract` — the plugin contract, whose `abi::sdk` module
carries the export macros. `busbar-plugin-loader` is a dev-dependency only,
for the linked + dropped-in conformance test and the end-to-end test. Both
are **git dependencies pinned to one busbar commit**: the `rev` in every
`Cargo.toml` is field 1 of `.busbar-ref`, and CI's `pin` job refuses a
manifest that disagrees. No sibling checkout of busbar is needed to build
or test; the live end-to-end test (`tests/e2e.rs`) builds the real `busbar`
binary from a checkout named by `BUSBAR_CHECKOUT` (CI's `e2e` job provides
one at `.busbar-ref`).

### Pack and sign

Once built, the cdylib is packed and signed like any other busbar plugin
— see
[`docs/plugins.md`](https://github.com/GetBusbar/busbar/blob/main/docs/plugins.md#signing-and-packaging)
in busbar for the full reference. In short:

```sh
BUSBAR_SIGN_KEY=<signing key> busbar-plugin-pack pack \
    --lib target/release/libbusbar_auth_ldap_plugin.so \
    --name busbar-auth-ldap-plugin --alias ldap --kind auth \
    --version 0.1.0 --publisher busbar \
    --license Apache-2.0 \
    --out busbar-auth-ldap-plugin-0.1.0-x86_64-linux.tar.gz
```

For local development without a signing key, `busbar-plugin-pack pack
--allow-unsigned` produces a tarball busbar loads only under
`plugins.trust.allow_unsigned: true`. Drop the resulting tarball into
busbar's configured `plugins.dir`.

## Tests

`cargo test` runs the library crate's unit tests (`auth-ldap/src/tests.rs`)
and the plugin crate's. Coverage includes config parsing and
`deny_unknown_fields` (including `client_secret` being rejected),
bind-DN templating and LDAP-injection rejection, RFC 4515 filter
escaping, group-DN → role mapping (CN and DN forms, dedup, escaped
commas), and the login guards for a missing or empty field. The door
(`auth-ldap/src/door.rs`) is driven through busbar's real loader, linked
and dropped in, by `auth-ldap-plugin/tests/conformance.rs`: `verify`
refused (an undeclared op), the `begin_login` form, the `complete_login` verdicts, and the
lifecycle's refusal texts.

The live-bind happy path is integration-only: `auth-ldap-plugin/tests/e2e.rs`
packs the real cdylib with the `busbar-plugin-pack` binary, drives a
spawned busbar binary over real HTTP, and seeds a real OpenLDAP instance
over plaintext LDAP with a dev-only `ldap3` client. A second live test
drives the library module's codec (over the test's own stream) straight
against that directory in both
direct-bind and search-then-bind mode and checks the mapped role. A third
puts the test kit's TLS front, whose CA no public store holds, in front of
that directory as an `ldaps://` endpoint: busbar with `ca_cert_pem`
naming that CA mints a key over it, and without it does not. Point
`BUSBAR_TEST_LDAP_URL` at that directory to run them; with the variable
unset they skip loudly, and under CI (`CI` set) they fail instead.

## License

Licensed **Apache-2.0** ([LICENSE](LICENSE)). Contributions welcome.
Security issues go through private disclosure, not public issues.
