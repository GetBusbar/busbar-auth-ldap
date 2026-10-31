// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **AD/LDAP auth module** for busbar.
//!
//! LDAP is a DIRECT CREDENTIAL flow: the module speaks the directory's own wire protocol, as a
//! sans-IO codec over a byte stream the HOST owns (no plugin opens a socket, dials, binds or does
//! TLS; a directory wire protocol is plugin logic over the generic connection table):
//!
//! 1. A dev types username + password on the hosted login page.
//! 2. The core calls the door's `complete_login` ([`door`]) with those credentials.
//! 3. The module asks the host connector for a stream on its declared need, secured by the
//!    connector for `ldaps://` or after the StartTLS extended operation, and performs a **BIND**
//!    with the user's DN + password over it ([`codec`], [`conversation`]).
//! 4. On a successful bind it reads the user's group memberships (the `group_attr`
//!    attribute, `memberOf` by default) and answers a [`Principal`] whose `roles` are the group names, mapped to policy downstream by
//!    the operator's `auth.role_bindings.<provider name>`.
//!
//! Every stream service may answer PENDING; `complete_login` then answers PENDING and resumes on
//! the wake, and the [`conversation::Conversation`] it parks replays what completed without
//! sending it twice.
//!
//! ## The LDAP credential method, on the auth kind's door (abi::auth v3)
//!
//! - The Statement's tail declares `LOGIN_KIND_CREDENTIAL`, so the chooser renders a form (not a
//!   redirect button) WITHOUT any side-effecting `begin_login` call.
//! - `begin_login` answers the declarative form (`username` text + `password` password).
//! - `complete_login` reads the submitted values back by the field `name` it declared, BINDs over
//!   the host's stream, reads groups ([`LdapModule::login_over`]), and answers the identity.
//! - `verify` is not served: LDAP judges no bearer credential on the data plane, so the tail states
//!   the login family alone (`CAP_LOGIN`) and the host never calls it.
//! - LDAP is a `Credential` method, so it has NO confidential-client `client_secret` — `LdapConfig`
//!   structurally has no such field and `deny_unknown_fields` rejects one if configured.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use busbar_contract::abi::sdk::cred::{self, Cred};
use busbar_contract::auth::Principal;
use core::fmt;
use serde::Deserialize;
use std::task::Poll;
use zeroize::Zeroizing;

pub mod ber;
pub mod codec;
pub mod conversation;
pub mod door;
pub mod filter;
pub mod groups;

use conversation::{Conversation, Over, Wire};

#[cfg(test)]
mod tests;

/// The maximum number of `memberOf` group values read off a user entry. A hostile or misconfigured
/// directory could list an unbounded number of groups; collection is capped here to bound memory.
/// 4096 is far above any real-world group membership; the module logs when it truncates.
const MAX_GROUP_VALUES: usize = 4096;

/// `url` with any userinfo cut to `***`, safe for a refusal, a log line or `Debug`. The authority ends where the dialer ends it (`/`, `?` or `#`) and its
/// userinfo is everything up to its LAST `@`, as [`conversation::Endpoint::parse`] reads it. A URL
/// with no userinfo is unchanged.
pub(crate) fn shown_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (Some(scheme), rest),
        None => (None, url),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let Some(at) = rest[..end].rfind('@') else {
        return url.to_string();
    };
    match scheme {
        Some(scheme) => format!("{scheme}://***{}", &rest[at..]),
        None => format!("***{}", &rest[at..]),
    }
}

/// How a group DN read from the directory becomes a [`Principal`] role string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RoleFrom {
    /// Use the first `CN=` RDN value of the group DN (e.g. `CN=engineers,OU=...` → `engineers`).
    /// The natural, human-facing form to key `role_bindings` on.
    #[default]
    Cn,
    /// Use the full, lowercased group DN verbatim as the role string (exact but noisy to bind on).
    Dn,
}

/// Open-time configuration for the LDAP module — the module's OPAQUE
/// `identity-providers.<name>.settings`,
/// deserialized from the JSON the engine passes to `open`. Every LDAP-specific knob (URL, DN
/// templates, TLS/CA, group attribute) fits here as opaque module settings: the engine never needs
/// to understand any of these fields. Its `Debug` prints the URL with any userinfo cut
/// ([`shown_url`]) and the service password redacted.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapConfig {
    /// The directory URL: `ldaps://ad.corp.example:636` (LDAPS) or `ldap://ad.corp.example:389`
    /// (plaintext, or STARTTLS when `start_tls` is set).
    pub url: String,

    /// Template that turns a username into the BIND DN. `{username}` is substituted with the
    /// (validated) username. It must be a DN (contain `=`); `LdapModule::new` refuses any other
    /// template in direct-bind mode. Example: `uid={username},ou=people,dc=corp,dc=example`. An
    /// Active Directory UPN login (`{username}@corp.example`) goes through `user_search_filter`.
    ///
    /// Mutually informative with `user_search_filter`: if a search filter is set, the module does
    /// search-then-bind (bind as `bind_service_dn`, find the user, bind as the found DN) instead.
    pub bind_dn_template: String,

    /// The search base for the group read (and for search-then-bind user lookup). e.g.
    /// `dc=corp,dc=example`.
    pub base_dn: String,

    /// The attribute on the user entry that lists group memberships. Default `memberOf` (AD and most
    /// directories). Each value is a group DN.
    #[serde(default = "default_group_attr")]
    pub group_attr: String,

    /// How a group DN becomes a role string. Default [`RoleFrom::Cn`].
    #[serde(default)]
    pub role_from: RoleFrom,

    /// Optional search-then-bind: an LDAP filter to locate the user entry BEFORE binding, e.g.
    /// `(sAMAccountName={username})`. When set, `bind_service_dn`/`bind_service_password` are used to
    /// bind for the search. When absent, the module binds directly with `bind_dn_template`.
    #[serde(default)]
    pub user_search_filter: Option<String>,

    /// Service-account DN for search-then-bind (only used when `user_search_filter` is set).
    #[serde(default)]
    pub bind_service_dn: Option<String>,

    /// Service-account password. The Statement names this key in its `secret_refs`, so busbar
    /// resolves the reference and hands it to `open` as `OpenIn.secrets[0]`
    /// ([`LdapModule::from_settings_with`]); a literal in the settings blob refuses `validate` and
    /// boot. Held by the chip ([`Cred`]): no getter, no `Debug`; it reaches the wire only inside the
    /// chip's BIND message.
    #[serde(default)]
    pub bind_service_password: Option<Cred>,

    /// PEM CA bundle to trust for LDAPS/STARTTLS (a private AD CA), on top of the public roots:
    /// the module then dials on the anchored need, whose `trust_from` hands it to the host
    /// connector ([`door::NEEDS`]). A value that holds no certificate is refused at boot.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,

    /// Use STARTTLS over an `ldap://` connection instead of implicit LDAPS.
    #[serde(default)]
    pub start_tls: bool,

    /// Escape hatch for the plaintext-transport guard. By default a plaintext `ldap://` URL to a
    /// NON-loopback host with no STARTTLS is REJECTED at config time, because it would send the
    /// service-account AND every end-user password across the network in cleartext. Set this to
    /// `true` to knowingly override that guard (e.g. a trusted, isolated network segment). It does
    /// nothing for `ldaps://`, for STARTTLS, or for a loopback host — those are already secure/local.
    #[serde(default)]
    pub allow_insecure_transport: bool,

    /// How long each directory operation (the connect, each bind, each search) may wait, in
    /// seconds (the host bounds each stream service by its own). Default 10.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_group_attr() -> String {
    "memberOf".to_string()
}
/// The longest `timeout_secs` may be, in seconds.
const MAX_TIMEOUT_SECS: u64 = 120;

fn default_timeout_secs() -> u64 {
    10
}

impl fmt::Debug for LdapConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapConfig")
            .field("url", &shown_url(&self.url))
            .field("bind_dn_template", &self.bind_dn_template)
            .field("base_dn", &self.base_dn)
            .field("group_attr", &self.group_attr)
            .field("role_from", &self.role_from)
            .field("user_search_filter", &self.user_search_filter)
            .field("bind_service_dn", &self.bind_service_dn)
            .field(
                "bind_service_password",
                &self.bind_service_password.as_ref().map(|_| "[REDACTED]"),
            )
            .field("ca_cert_pem", &self.ca_cert_pem.is_some())
            .field("start_tls", &self.start_tls)
            .field("allow_insecure_transport", &self.allow_insecure_transport)
            .field("timeout_secs", &self.timeout_secs)
            .finish()
    }
}

/// The LDAP auth module: a login-only method (it authenticates a form POST, it does not verify
/// opaque bearer tokens on the data plane); the work is [`LdapModule::login_over`].
pub struct LdapModule {
    cfg: LdapConfig,
}

impl LdapModule {
    /// Build the module from parsed config: every settings check ([`check_settings`]) so a
    /// misconfiguration fails at boot, not on the first login, then the search-then-bind service
    /// password rule; logs (info) an empty search base and (warn) an opted-out plaintext transport.
    pub fn new(cfg: LdapConfig) -> Result<Self, String> {
        check_settings(&cfg)?;
        // A service DN with NO password would perform `simple_bind(dn, "")`, an UNAUTHENTICATED
        // bind on most directories, so search-then-bind requires one. The password is normally a
        // secret reference the kernel resolves at `open`, so this rule is `open`'s (here), never
        // `validate`'s ([`check_settings`]): `validate` is handed no secrets.
        if cfg.user_search_filter.is_some() && cfg.bind_service_password.is_none() {
            return Err("secrets: `bind_service_password` is not set".to_string());
        }
        // The opt-out is honoured, but never SILENTLY. An operator who copies a lab config into
        // production otherwise sends every end-user password in cleartext for the life of the
        // deployment with nothing anywhere saying so — the setting is a one-line boolean and the
        // consequence is invisible.
        //
        // This is a `tracing` call; the SDK forwards this plugin's dispatcher into the host log
        // sink, so it reaches the operator's logs.
        // An empty search base is a valid one (the AD Global Catalog, OpenLDAP's
        // `olcDefaultSearchBase` serve a search from the root DSE), so it is accepted, but said.
        if cfg.user_search_filter.is_some() && cfg.base_dn.trim().is_empty() {
            tracing::info!(
                module = "ldap",
                "base_dn is empty: the search-then-bind user search runs from the root DSE \
                 (base \"\")"
            );
        }
        if is_insecure_transport(&cfg.url, cfg.start_tls) {
            tracing::warn!(
                module = "ldap",
                url = %shown_url(&cfg.url),
                "allow_insecure_transport is set: binds run over plaintext ldap:// to a \
                 non-loopback host, so the service-account AND every end-user password cross the \
                 network in cleartext"
            );
        }
        Ok(Self { cfg })
    }

    /// Expand `bind_dn_template` with a validated username. Returns `Err` if the username contains
    /// characters that would break out of a DN component (LDAP injection defense).
    pub(crate) fn bind_dn_for(&self, username: &str) -> Result<String, String> {
        let safe = groups::validate_username(username)?;
        Ok(self.cfg.bind_dn_template.replace("{username}", safe))
    }

    /// The declared need this module's logins dial on: the anchored one when the operator names a
    /// private CA (`ca_cert_pem`), else the public one.
    #[must_use]
    pub fn need(&self) -> u32 {
        if self.cfg.ca_cert_pem.is_some() {
            door::NEED_ANCHORED
        } else {
            door::NEED
        }
    }

    /// `password` as a BIND carries it: an `ldaps://` URL, or STARTTLS, lets it go out only on a
    /// connection the host connector reports secured ([`Cred::secure_required`]).
    fn guarded(&self, password: &Cred) -> Cred {
        let password = password.clone().secure_for(&self.cfg.url);
        if self.cfg.start_tls {
            password.require_secure()
        } else {
            password
        }
    }
}

/// The SETTINGS-ONLY checks: every refusal a settings blob earns on its own, with no secret in
/// hand, one instance-relative line each (`settings.<key>: <reason>`, joined by `\n`; no line
/// quotes a value). `validate` runs exactly these ([`LdapModule::validate_settings`]); `open` runs
/// them and then the rules that need the resolved secrets ([`LdapModule::new`]).
fn check_settings(cfg: &LdapConfig) -> Result<(), String> {
    let mut lines: Vec<String> = Vec::new();
    let mut refuse = |key: &str, why: &str| lines.push(format!("settings.{key}: {why}"));
    if cfg.url.trim().is_empty() {
        refuse("url", "must not be empty");
    } else if let Err(e) = conversation::Endpoint::parse(&cfg.url, cfg.start_tls) {
        refuse(
            "url",
            &format!("is not an ldap:// or ldaps:// URL the dialer can read: {e}"),
        );
    }
    // A CA bundle that holds no certificate would leave the anchored need refused by the connector
    // and every login an outage: refuse it here, by name.
    if cfg
        .ca_cert_pem
        .as_deref()
        .is_some_and(|pem| !holds_a_certificate(pem))
    {
        refuse(
            "ca_cert_pem",
            "holds no PEM certificate (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----)",
        );
    }
    if !cfg.bind_dn_template.contains("{username}") {
        refuse(
            "bind_dn_template",
            "must contain the `{username}` placeholder",
        );
    } else if cfg.user_search_filter.is_none() && !cfg.bind_dn_template.contains('=') {
        // In direct-bind mode the expanded template is also the Base DN of the group read, so it
        // must be a DN. A template with no `=` (an AD UPN such as `{username}@corp.example`) can
        // never become one (`validate_username` refuses `=`). AD UPN logins search, then bind.
        refuse(
            "bind_dn_template",
            "is not a DN: in direct-bind mode the expanded template is the entry the groups are \
             read from, so it must be a DN such as `uid={username},ou=people,dc=corp,dc=example`; \
             for an AD UPN login set user_search_filter (e.g. \
             `(userPrincipalName={username}@corp.example)`) with bind_service_dn and \
             bind_service_password",
        );
    }
    // A zero timeout expires every connect and operation at once, so every login would fail.
    if cfg.timeout_secs == 0 {
        refuse("timeout_secs", "must be at least 1");
    } else if cfg.timeout_secs > MAX_TIMEOUT_SECS {
        // Each operation of a login waits up to this long, and a login runs several: unbounded,
        // a hung directory pins every in-flight login slot for as long as it is set to.
        refuse("timeout_secs", "must be at most 120");
    }
    // A blank group attribute is requested and read back as nothing: every login, no roles.
    if cfg.group_attr.trim().is_empty() {
        refuse("group_attr", "must not be empty");
    }
    if let Some(f) = &cfg.user_search_filter {
        if !f.contains("{username}") {
            refuse(
                "user_search_filter",
                "must contain the `{username}` placeholder",
            );
        } else if filter::encode(&f.replace("{username}", &groups::escape_filter("username")))
            .is_err()
        {
            // A template that does not parse would fail every login as an outage: refuse it
            // here, as it is applied (a sample username, escaped, in its place).
            refuse(
                "user_search_filter",
                &format!(
                    "is not an RFC 4515 search filter (or nests deeper than {} levels)",
                    filter::MAX_DEPTH
                ),
            );
        }
        if cfg
            .bind_service_dn
            .as_deref()
            .is_none_or(|d| d.trim().is_empty())
        {
            refuse(
                "bind_service_dn",
                "is required with user_search_filter (search-then-bind binds as it first)",
            );
        }
        // A present-but-EMPTY service password would perform `simple_bind(dn, "")`, an
        // UNAUTHENTICATED bind on most directories. An ABSENT one is `open`'s to refuse
        // ([`LdapModule::new`]): it is normally a secret reference, resolved only there.
        if cfg
            .bind_service_password
            .as_ref()
            .is_some_and(Cred::is_empty)
        {
            refuse(
                "bind_service_password",
                "must not be empty (an empty password becomes an unauthenticated bind for \
                 search-then-bind)",
            );
        }
    }
    // Fail CLOSED on a plaintext transport that would expose credentials on the network: a
    // `ldap://` URL with no STARTTLS, to a non-loopback host, sends the service-account AND every
    // end-user password in cleartext, unless the operator explicitly opts out.
    if is_insecure_transport(&cfg.url, cfg.start_tls) && !cfg.allow_insecure_transport {
        refuse(
            "url",
            "plaintext ldap:// to a non-loopback host with no STARTTLS sends the service and \
             end-user credentials in cleartext; use an ldaps:// URL, set start_tls = true, or (to \
             knowingly override) set allow_insecure_transport = true",
        );
    }
    if lines.is_empty() {
        Ok(())
    } else {
        Err(lines.join("\n"))
    }
}

/// Whether `pem` holds at least one certificate: every `CERTIFICATE` block's body is base64 of a
/// DER SEQUENCE, and there is one. The connector parses it in full when it declares the need.
fn holds_a_certificate(pem: &str) -> bool {
    use base64::Engine as _;
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut rest = pem;
    let mut found = false;
    while let Some(at) = rest.find(BEGIN) {
        let after = &rest[at + BEGIN.len()..];
        let Some(end) = after.find(END) else {
            return false;
        };
        let body: String = after[..end].split_whitespace().collect();
        match base64::engine::general_purpose::STANDARD.decode(body) {
            Ok(der) if der.first() == Some(&0x30) => found = true,
            _ => return false,
        }
        rest = &after[end + END.len()..];
    }
    found
}

/// Would binding over this URL send credentials in CLEARTEXT on the network? True only for a
/// plaintext `ldap://` scheme (not `ldaps://`), with STARTTLS off, to a NON-loopback host. `ldaps://`
/// is implicit TLS; STARTTLS upgrades the `ldap://` socket; a loopback host never leaves the box.
fn is_insecure_transport(url: &str, start_tls: bool) -> bool {
    let url = url.trim();
    // Implicit LDAPS is already encrypted. Compare on BYTES (not `url[..8]`, which panics if a
    // multi-byte UTF-8 char straddles byte index 8) — the scheme is ASCII, so a byte compare is exact.
    if url.len() >= 8 && url.as_bytes()[..8].eq_ignore_ascii_case(b"ldaps://") {
        return false;
    }
    // STARTTLS upgrades the plaintext socket to TLS before any bind.
    if start_tls {
        return false;
    }
    // Anything else here is a plaintext `ldap://` connection: only safe to a loopback host, which
    // never puts the credential on the wire. The host is the one the dialer dials: ONE split of the
    // URL ([`conversation::Endpoint::parse`]), so the guard and the dial cannot drift. A URL the
    // dialer cannot read is refused by name anyway, and reads as insecure here.
    !conversation::Endpoint::parse(url, false).is_ok_and(|e| is_loopback_host(&e.host))
}

/// Is this host a loopback address that never leaves the machine? Matches the canonical trio only —
/// `127.0.0.1`, `::1`, `localhost` — case-insensitively.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

/// The login form's username field: its `name` and label, as `begin_login` declares it (both doors).
pub(crate) const USERNAME: (&str, &str) = ("username", "Username");
/// The login form's password field: its `name` and label.
pub(crate) const PASSWORD: (&str, &str) = ("password", "Password");

/// What one credential submission came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Login {
    /// The directory bound the user: who.
    Identity(Principal),
    /// No usable credential, or the directory refused it.
    BadCredential,
    /// The directory could not answer (connect, TLS, timeout, no host clock, or a user-bind result
    /// code naming a server/session condition: [`is_outage`]). Logged here, never the credential.
    Outage,
}

impl LdapModule {
    /// `validate`'s check of a settings blob: everything the blob earns on its own, with no secret
    /// in hand. A search-then-bind service password is normally a secret reference the kernel
    /// resolves only at `open`, so its PRESENCE is `open`'s rule ([`LdapModule::new`]), not this
    /// one's; an explicit empty literal is still refused here.
    pub fn validate_settings(settings: &[u8]) -> Result<(), String> {
        let cfg = parse_settings(settings)?;
        refuse_a_literal_secret(&cfg)?;
        check_settings(&cfg)
    }

    /// The module from a settings blob, with the secrets the kernel resolved for the Statement's
    /// `secret_refs` (`bind_service_password`): a non-empty first secret is the service-account
    /// password (a literal in the settings refuses).
    pub fn from_settings_with(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, String> {
        let mut cfg = parse_settings(settings)?;
        refuse_a_literal_secret(&cfg)?;
        if let Some(secret) = secrets.first().filter(|s| !s.is_empty()) {
            if std::str::from_utf8(secret).is_err() {
                return Err("secrets: `bind_service_password` is not UTF-8".to_string());
            }
            cfg.bind_service_password = Some(Cred::captured(Zeroizing::new(secret.to_vec())));
        }
        Self::new(cfg)
    }

    /// One credential submission over `wire`, resumable: the `username` and `password` the form
    /// declared, absent when not submitted. An absent field or an empty password never reaches the
    /// wire (an empty password is an anonymous bind that "succeeds" on many directories).
    ///
    /// [`Poll::Pending`] = a wire service pends: call again on the wake with the same `conv` (what
    /// completed answers from it; nothing is sent twice). `now_ns` is the caller's monotonic clock
    /// (`None` = none): each operation (the connect, each bind, each search) gives up `timeout_secs`
    /// after it begins.
    pub fn login_over<W: Wire>(
        &self,
        conv: &mut Conversation,
        wire: &mut W,
        username: Option<&str>,
        password: Option<&Cred>,
        now_ns: Option<u64>,
    ) -> Poll<Login> {
        let (Some(username), Some(password)) = (username, password) else {
            tracing::info!(
                module = "ldap",
                "ldap login refused: the username or password field was not submitted"
            );
            return Poll::Ready(Login::BadCredential);
        };
        if password.is_empty() {
            tracing::info!(
                module = "ldap",
                "ldap login refused: empty password (an anonymous bind is never attempted)"
            );
            return Poll::Ready(Login::BadCredential);
        }
        // Every directory operation is bounded by `timeout_secs` on the host's clock. With no
        // clock there is no deadline, and a directory that takes the connection and never answers
        // would hold the login forever: refuse rather than run untimed.
        if now_ns.is_none() {
            tracing::warn!(
                module = "ldap",
                "no host clock: refusing an untimed directory call"
            );
            return Poll::Ready(Login::Outage);
        }
        let mut over = Over::new(
            conv,
            wire,
            &self.cfg.url,
            self.cfg.start_tls,
            now_ns,
            self.cfg.timeout_secs,
        );
        match self.bind_and_identify(&mut over, username, password) {
            Ok(principal) => Poll::Ready(Login::Identity(principal)),
            Err(BindError::Pending) => Poll::Pending,
            Err(BindError::InvalidCredentials) => Poll::Ready(Login::BadCredential),
            Err(BindError::Rejected { rc }) => {
                tracing::info!(
                    module = "ldap",
                    rc,
                    result = codec::rc_name(rc),
                    "ldap user bind refused by the directory (not invalidCredentials); \
                     answered as a bad credential"
                );
                Poll::Ready(Login::BadCredential)
            }
            Err(BindError::Directory(e)) => {
                tracing::warn!(module = "ldap", error = %e, "ldap bind/search failed (not a credential rejection)");
                Poll::Ready(Login::Outage)
            }
        }
    }
}

/// The service password is a secret REFERENCE, never a literal (auth standard S1): busbar resolves
/// it and lifts the key out of the settings into `OpenIn.secrets` before `validate` and `open`, so a
/// `bind_service_password` still IN the settings blob is a literal. It refuses, naming the key and
/// never the value.
fn refuse_a_literal_secret(cfg: &LdapConfig) -> Result<(), String> {
    if cfg.bind_service_password.is_some() {
        return Err(
            "settings.bind_service_password: must be a secret reference (for example \
             `{ env: LDAP_BIND_PASSWORD }`), never a literal"
                .to_string(),
        );
    }
    Ok(())
}

/// The settings blob as an [`LdapConfig`], parsed by the chip ([`cred::settings`]): the service
/// password is sealed as it is read and the parse tree wiped. A refusal is one instance-relative
/// line naming the key and the type, never a value.
fn parse_settings(settings: &[u8]) -> Result<LdapConfig, String> {
    if settings.trim_ascii().is_empty() {
        return Err(
            "settings: required (url, bind_dn_template, base_dn); none provided".to_string(),
        );
    }
    cred::settings(settings).map_err(|e: cred::SettingsError| {
        let text = e.to_string();
        let why = text.strip_prefix("settings: ").unwrap_or(&text);
        match e.path() {
            "" => format!("settings: {why}"),
            path => format!("settings.{path}: {why}"),
        }
    })
}

/// An attribute description's TYPE: what precedes its first `;option` (RFC 4512 §2.5).
fn attribute_type(description: &str) -> &str {
    description.split(';').next().unwrap_or(description)
}

/// The `range=<low>-<high>` option of an attribute description, when it is a PARTIAL range (its
/// high bound is not `*`): the directory returned only some of the attribute's values.
fn partial_range(description: &str) -> Option<&str> {
    description.split(';').skip(1).find(|option| {
        option.len() > 6
            && option.as_bytes()[..6].eq_ignore_ascii_case(b"range=")
            && option.rsplit_once('-').is_some_and(|(_, high)| high != "*")
    })
}

/// The attribute list that asks for no attributes (RFC 4511 §4.5.1.8): the user search needs only
/// the entry's DN, which every SearchResultEntry carries.
const NO_ATTRIBUTES: &str = "1.1";

/// LDAP result code 49, invalidCredentials (RFC 4511 §4.1.9).
const LDAP_INVALID_CREDENTIALS: u32 = 49;
/// LDAP result code 32, noSuchObject (RFC 4511 §4.1.9).
const LDAP_NO_SUCH_OBJECT: u32 = 32;
/// LDAP result code 50, insufficientAccessRights (RFC 4511 §4.1.9).
const LDAP_INSUFFICIENT_ACCESS: u32 = 50;

/// Is a (non-49) user-bind result code a SERVER or SESSION condition, one
/// that fails the bind for every user alike (an outage), rather than a refusal of this one bind?
/// An explicit list (RFC 4511 §4.1.9 names); every code not on it (48 inappropriateAuthentication,
/// 50 insufficientAccessRights, 53 unwillingToPerform, 32 noSuchObject, 19 constraintViolation,
/// 34 invalidDNSyntax, a code RFC 4511 does not name, ...) refuses the credential.
pub(crate) const fn is_outage(rc: u32) -> bool {
    matches!(
        rc,
        1 // operationsError
            | 2 // protocolError
            | 3 // timeLimitExceeded
            | 7 // authMethodNotSupported
            | 8 // strongerAuthRequired
            | 10 // referral
            | 11 // adminLimitExceeded
            | 12 // unavailableCriticalExtension
            | 13 // confidentialityRequired
            | 14 // saslBindInProgress
            | 51 // busy
            | 52 // unavailable
            | 54 // loopDetect
            | 71 // affectsMultipleDSAs
            | 80 // other
    )
}

/// Why a bind attempt did not yield an identity.
#[derive(Debug)]
enum BindError {
    /// The directory rejected the username/password (LDAP result 49 or a failed search).
    InvalidCredentials,
    /// The user bind answered a non-zero result code other than 49 that is not a server/session
    /// condition ([`is_outage`]): the credential is refused, and the code is logged.
    Rejected {
        /// The bind's LDAP result code.
        rc: u32,
    },
    /// An operational failure talking to the directory (connect/TLS/timeout/protocol) — NOT a
    /// statement about the credential's validity.
    Directory(String),
    /// A stream service pends: the op answers PENDING and runs again on its wake.
    Pending,
}

/// A directory operation that did not answer: it pends, or it failed (with its text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Io {
    /// A stream service pends.
    Pending,
    /// An operational failure, with its text.
    Failed(String),
    /// A search the directory answered with a non-zero SearchResultDone: its result code, and the
    /// failure's text.
    Refused {
        /// The SearchResultDone's result code.
        rc: u32,
        /// The failure's text.
        text: String,
    },
}

impl From<String> for Io {
    fn from(e: String) -> Self {
        Self::Failed(e)
    }
}

/// `<ctx>: <text>` for a failed operation; a pending one stays pending.
fn at(ctx: &str) -> impl FnOnce(Io) -> BindError + '_ {
    move |e| match e {
        Io::Pending => BindError::Pending,
        Io::Failed(e) | Io::Refused { text: e, .. } => BindError::Directory(format!("{ctx}: {e}")),
    }
}

/// Scope of an [`LdapBackend::search`] — the two the module uses.
#[derive(Clone, Copy)]
pub(crate) enum SearchScope {
    /// The entry named by `base` itself (used for the group read).
    Base,
    /// The whole subtree under `base` (used for the search-then-bind user lookup).
    Subtree,
}

/// A directory entry reduced to what the module reads: its DN and requested attributes.
pub(crate) use codec::Entry as DirEntry;

/// The minimal LDAP operations `LdapModule::bind_and_identify` needs, abstracted behind a trait
/// so the post-connect bind logic (result-code handling, ambiguity, group cap, roles, principal id)
/// is UNIT-TESTABLE against a fake in-memory directory. The production impl
/// ([`conversation::Over`]) speaks the codec over the host's stream; tests drive a fake.
pub(crate) trait LdapBackend {
    /// Open (and secure) the connection to the directory.
    fn connect(&mut self) -> Result<(), Io> {
        Ok(())
    }

    /// Bind with the given DN + password. `Ok(rc)` is the LDAP result code (0 = success, e.g. 49 =
    /// invalidCredentials); `Err` is an operational/transport failure (connect/TLS/timeout), NOT a
    /// statement about the credential's validity, or a pending stream.
    fn simple_bind(&mut self, dn: &str, password: &Cred) -> Result<u32, Io>;

    /// Run a search and return the matched entries. `Err` is an operational failure (which includes a
    /// non-success result code), or a pending stream.
    fn search(
        &mut self,
        base: &str,
        scope: SearchScope,
        filter: &str,
        attrs: &[&str],
    ) -> Result<Vec<DirEntry>, Io>;

    /// Best-effort unbind: a failure is ignored, only a pending stream is answered.
    fn unbind(&mut self) -> Result<(), Io>;
}

/// Build the STABLE principal id from the user entry's DN: the DN the directory RETURNED for the
/// bound entry (the group read's objectName) when it returned one, else the DN bound as. The
/// submitted username is user-controlled in its CASING (`Alice`/`alice`), its spacing
/// (`John  Smith`/`John Smith`) and form (`DOMAIN\alice`); using it raw would mint DIFFERENT
/// identities — and duplicate self-serve keys and budgets — for the SAME entry. The DN is normalised
/// for case-ignore matching (RFC 4518 §2): case folded and every run of spaces collapsed to one, so
/// there is exactly one canonical `ldap:<dn>` per directory identity, in both direct-template and
/// search-then-bind modes. Lowercasing is Unicode-aware (`to_lowercase`, not
/// `to_ascii_lowercase`) — `validate_username` allows non-ASCII names, so an ASCII-only fold would
/// mint two distinct principals for two casings of a non-ASCII username. (RFC 4518's NFKC step
/// needs a Unicode normalisation table this crate does not carry; the directory's own spelling of
/// the DN is preferred for that reason.)
fn principal_id(user_dn: &str) -> String {
    let mut id = String::with_capacity(user_dn.len() + 5);
    id.push_str("ldap:");
    let mut space = false;
    for c in user_dn.trim().to_lowercase().chars() {
        if c == ' ' {
            if !space {
                id.push(' ');
            }
            space = true;
        } else {
            id.push(c);
            space = false;
        }
    }
    id
}

impl LdapModule {
    /// Connect to the directory, BIND with the credentials, read the user's groups, and build a
    /// [`Principal`]. The connect comes first, so a username the DN template refuses is refused
    /// after it.
    /// Generic over [`LdapBackend`] so the reject paths are unit-testable: a non-zero user-bind result
    /// code, an empty or AMBIGUOUS (>1 match) search, and an over-long group list are all refused or
    /// capped here.
    fn bind_and_identify<B: LdapBackend>(
        &self,
        ldap: &mut B,
        username: &str,
        password: &Cred,
    ) -> Result<Principal, BindError> {
        ldap.connect()
            .map_err(at(&format!("connect {}", shown_url(&self.cfg.url))))?;
        // Resolve the DN to bind as: either search-then-bind, or the direct template.
        let user_dn = if let Some(filter_tpl) = &self.cfg.user_search_filter {
            // The direct-template path runs the username through `validate_username` (which rejects
            // an empty username); the search path must guard it too — an empty username has no
            // identity to resolve. Fail as invalid credentials, never reach the socket.
            if username.is_empty() {
                tracing::info!(module = "ldap", "ldap login refused: empty username");
                return Err(BindError::InvalidCredentials);
            }
            // Search-then-bind: bind as the service account, find the user entry, take its DN.
            // `new()` guarantees both bind_service_dn and bind_service_password are present here.
            let svc_dn = self.cfg.bind_service_dn.as_deref().unwrap_or("");
            let svc_pw = self
                .cfg
                .bind_service_password
                .as_ref()
                .map_or_else(Cred::empty, |pw| self.guarded(pw));
            let rc = ldap
                .simple_bind(svc_dn, &svc_pw)
                .map_err(at("service bind"))?;
            if rc != 0 {
                return Err(BindError::Directory(format!(
                    "service bind rejected (rc={rc})"
                )));
            }
            let filter = filter_tpl.replace("{username}", groups::escape_filter(username).as_str());
            let entries = ldap
                .search(
                    &self.cfg.base_dn,
                    SearchScope::Subtree,
                    &filter,
                    &[NO_ATTRIBUTES],
                )
                .map_err(at("user search"))?;
            // Ambiguous: more than one entry matched. Fail CLOSED rather than silently binding the
            // first — we cannot establish a single, unambiguous identity for the credential.
            if entries.len() > 1 {
                tracing::info!(
                    module = "ldap",
                    matches = entries.len(),
                    "ldap login refused: user_search_filter matched multiple entries (ambiguous)"
                );
                return Err(BindError::InvalidCredentials);
            }
            let Some(entry) = entries.into_iter().next() else {
                tracing::info!(
                    module = "ldap",
                    "ldap login refused: no search match for the username"
                );
                return Err(BindError::InvalidCredentials);
            };
            // Guard an empty resolved DN before binding: `simple_bind("", password)` is an anonymous
            // bind on many directories and would "succeed" without authenticating anyone.
            if entry.dn.is_empty() {
                tracing::info!(
                    module = "ldap",
                    "ldap login refused: the search matched an entry with an empty DN"
                );
                return Err(BindError::InvalidCredentials);
            }
            entry.dn
        } else {
            self.bind_dn_for(username).map_err(|reason| {
                // `validate_username`'s reasons name no part of the username.
                tracing::info!(module = "ldap", %reason, "ldap login refused: the DN template refused the username");
                BindError::InvalidCredentials
            })?
        };

        // The credential check: BIND as the user with the presented password. Result code 49
        // (invalidCredentials) is a credential rejection. For any other code: one naming a
        // server/session condition that fails every user alike (51 busy, 52 unavailable, ...:
        // [`is_outage`]) is a directory-side failure, an outage logged by `login_over`; every other
        // non-zero code (48, 50, 53, ...) refuses this credential, the same bad credential as a
        // wrong password, its real result logged at info by `login_over` (never the password or
        // the DN).
        let rc = ldap
            .simple_bind(&user_dn, &self.guarded(password))
            .map_err(at("bind"))?;
        if rc == LDAP_INVALID_CREDENTIALS {
            tracing::info!(
                module = "ldap",
                rc,
                result = codec::rc_name(rc),
                "ldap login refused: the directory rejected the credential"
            );
            return Err(BindError::InvalidCredentials);
        }
        if rc != 0 && is_outage(rc) {
            return Err(BindError::Directory(format!(
                "user bind rejected (rc={rc} {})",
                codec::rc_name(rc)
            )));
        }
        if rc != 0 {
            return Err(BindError::Rejected { rc });
        }

        // Read the group-membership attribute off the (now bound) user entry. The directory
        // already bound this user, so a read refused as 32 noSuchObject or 50
        // insufficientAccessRights (an ACL hiding the user's own entry from them) is the same as
        // a read that returns no entry: the login stands with no roles, never silently. Every
        // other failure is an outage.
        let mut refused = false;
        let entries = match ldap.search(
            &user_dn,
            SearchScope::Base,
            "(objectClass=*)",
            &[self.cfg.group_attr.as_str()],
        ) {
            Err(Io::Refused { rc, .. })
                if rc == LDAP_NO_SUCH_OBJECT || rc == LDAP_INSUFFICIENT_ACCESS =>
            {
                tracing::warn!(
                    module = "ldap",
                    rc,
                    result = codec::rc_name(rc),
                    group_attr = %self.cfg.group_attr,
                    "ldap group read refused for the bound user (an ACL may hide the entry); \
                     the login carries no roles"
                );
                refused = true;
                Vec::new()
            }
            read => read.map_err(at("group read"))?,
        };

        let mut group_dns: Vec<String> = Vec::new();
        // The principal is the entry's DN as the directory returns it (its objectName), falling
        // back to the DN bound as when the read answered no entry ([`principal_id`]).
        let mut entry_dn: Option<String> = None;
        if entries.is_empty() && !refused {
            // The bound user's own entry read back as nothing: an ACL hides it from the user, so
            // the groups were never read. The login stands with no roles, never silently.
            tracing::warn!(
                module = "ldap",
                group_attr = %self.cfg.group_attr,
                "ldap group read returned no entry for the bound user (an ACL may hide it); \
                 the login carries no roles"
            );
        }
        if let Some(entry) = entries.into_iter().next() {
            if !entry.dn.trim().is_empty() {
                entry_dn = Some(entry.dn.clone());
            }
            // LDAP attribute descriptions are case-insensitive (RFC 4512 §2.5) and the entry is keyed
            // by the server's spelling, so `group_attr: memberof` must find the server's `memberOf`.
            // The description is matched on its attribute TYPE, ignoring options: Active Directory
            // answers an attribute past its MaxValRange as `memberOf;range=0-1499`.
            let want = attribute_type(&self.cfg.group_attr);
            let vals = entry
                .attrs
                .iter()
                .find(|(k, _)| attribute_type(k).eq_ignore_ascii_case(want));
            if let Some((description, _)) = vals {
                if let Some(range) = partial_range(description) {
                    // Fail-safe: the values returned are read (fewer roles than the user holds);
                    // paging the rest (`;range=1500-*`) is not done.
                    tracing::warn!(
                        module = "ldap",
                        attribute = %description,
                        range = %range,
                        "ldap group attribute truncated by the directory's MaxValRange; only the \
                         returned values are mapped to roles"
                    );
                }
            }
            if vals.is_none() {
                // A misnamed `group_attr` would otherwise be a silent no-roles login for every
                // user (a directory omits an attribute with no values, so a user in no group also
                // lands here).
                tracing::warn!(
                    module = "ldap",
                    group_attr = %self.cfg.group_attr,
                    "ldap group attribute is absent from the bound user's entry; the login \
                     carries no roles"
                );
            }
            if let Some((_, vals)) = vals {
                // Cap the number of group values collected so a hostile/huge memberOf cannot exhaust
                // memory (see MAX_GROUP_VALUES). Log when truncating so an operator can spot it.
                if vals.len() > MAX_GROUP_VALUES {
                    tracing::warn!(
                        module = "ldap",
                        count = vals.len(),
                        cap = MAX_GROUP_VALUES,
                        "memberOf exceeded cap; truncating group values"
                    );
                }
                group_dns.extend(vals.iter().take(MAX_GROUP_VALUES).cloned());
            }
        }

        if ldap.unbind() == Err(Io::Pending) {
            return Err(BindError::Pending);
        }

        let roles = groups::roles_from_group_dns(&group_dns, self.cfg.role_from);
        let mut principal =
            Principal::from_id(principal_id(entry_dn.as_deref().unwrap_or(&user_dn)));
        principal.roles = roles;
        Ok(principal)
    }
}
