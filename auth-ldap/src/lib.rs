// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **AD/LDAP auth module** for busbar.
//!
//! LDAP is a DIRECT CREDENTIAL flow: the module speaks the directory's own wire protocol, as a
//! sans-IO codec over a byte stream the HOST owns (BUSBAR-1.6.0.md THE DESIGN §5: "No plugin opens
//! a socket, dials, binds or does TLS"; the host connector: "a database or directory wire protocol
//! is plugin logic over the generic connection table"; R5/Q82):
//!
//! 1. A dev types username + password on the hosted login page.
//! 2. The core calls the door's `complete_login` ([`door`]) with those credentials.
//! 3. The module asks the host connector for a stream on its declared need, secured by the
//!    connector for `ldaps://` or after the StartTLS extended operation, and performs a **BIND**
//!    with the user's DN + password over it ([`codec`], [`conversation`]).
//! 4. On a successful bind it reads the user's group memberships (the `group_attr`
//!    attribute, `memberOf` by default) and answers a [`Principal`] whose `roles` are the group names, mapped to policy downstream by
//!    the operator's `auth.role_bindings.ldap`.
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

// The test build keeps `deny` only for door_tests' reader of the Statement's 'static strings.
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(test, deny(unsafe_code))]

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

/// A secret string that NEVER reveals itself through `Debug`/`Display`.
///
/// The end-user password rides `Redacted` across the wire, but the service-account bind password
/// lives on the `#[derive(Debug)]` [`LdapConfig`], where a bare `String` could leak into a log line,
/// a `tracing` field, or a panic/`{:?}` dump. This wrapper makes the redaction STRUCTURAL.
/// It deserializes from a plain JSON string (moved, not copied, into its buffer), the buffer is
/// wiped on drop ([`Zeroizing`]), and the plaintext is reachable only through the explicit
/// [`SecretString::expose`] audit point. It is never serialized.
#[derive(Clone, Deserialize)]
#[serde(from = "String")]
pub struct SecretString(Zeroizing<String>);

impl From<String> for SecretString {
    fn from(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
}

impl zeroize::ZeroizeOnDrop for SecretString {}

impl SecretString {
    /// Borrow the underlying secret. AUDIT POINT — the one place the plaintext escapes redaction.
    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

/// `url` with any userinfo cut to `***`, safe for a refusal, a log line or `Debug`
/// (CREDENTIAL-LOCKDOWN H5). The authority ends where the dialer ends it (`/`, `?` or `#`) and its
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

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
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

/// Open-time configuration for the LDAP module — the module's OPAQUE `auth.methods.ldap` settings,
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

    /// Service-account password. The Statement names this key in its `secret_refs`, so the kernel
    /// resolves it into `OpenIn.secrets[0]`, which wins over this value
    /// ([`LdapModule::from_settings_with`]); a 1.5.5 literal here is still accepted.
    #[serde(default)]
    pub bind_service_password: Option<SecretString>,

    /// PEM CA bundle to trust for LDAPS/STARTTLS (private AD CA). The need states no
    /// `trust_from`, and as in 1.5.5 [`LdapModule::new`] refuses a config that sets it at boot
    /// (fail-closed) rather than silently ignoring it, so the connector's default roots are the
    /// ones trusted.
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
    /// seconds, as 1.5.5 applied it (the host bounds each stream service by its own). Default 10.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_group_attr() -> String {
    "memberOf".to_string()
}
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
            .field("bind_service_password", &self.bind_service_password)
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
    /// Build the module from parsed config. Validates the DN template references `{username}` so a
    /// misconfiguration fails at boot, not on the first login.
    pub fn new(cfg: LdapConfig) -> Result<Self, String> {
        check_settings(&cfg)?;
        // A service DN with NO password would perform `simple_bind(dn, "")`, an UNAUTHENTICATED
        // bind on most directories, so search-then-bind requires one. The password is normally a
        // secret reference the kernel resolves at `open`, so this rule is `open`'s (here), never
        // `validate`'s ([`check_settings`]): `validate` is handed no secrets.
        if cfg.user_search_filter.is_some() && cfg.bind_service_password.is_none() {
            return Err(
                "ldap user_search_filter requires bind_service_password for search-then-bind \
                 (a missing password becomes an unauthenticated bind)"
                    .to_string(),
            );
        }
        // The opt-out is honoured, but never SILENTLY. An operator who copies a lab config into
        // production otherwise sends every end-user password in cleartext for the life of the
        // deployment with nothing anywhere saying so — the setting is a one-line boolean and the
        // consequence is invisible.
        //
        // This is a `tracing` call, which used to go nowhere from inside a cdylib (its own
        // dispatcher, unjoined to the host's). The SDK now forwards this plugin's dispatcher into
        // the host log sink, so it genuinely reaches the operator's logs.
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
}

/// The SETTINGS-ONLY checks: every refusal a settings blob earns on its own, with no secret in
/// hand. `validate` runs exactly these ([`LdapModule::validate_settings`]); `open` runs them and
/// then the rules that need the resolved secrets ([`LdapModule::new`]).
fn check_settings(cfg: &LdapConfig) -> Result<(), String> {
    // Fail CLOSED on an unsupported CA bundle: `ca_cert_pem` is documented as "a CA bundle to
    // trust" but the custom-CA TLS path is not wired. Accepting-and-ignoring it would silently
    // fall back to the system trust roots while the operator believes their private CA is in use.
    if cfg.ca_cert_pem.is_some() {
        return Err(
            "ldap ca_cert_pem is not yet supported; omit it or use a system-trusted cert"
                .to_string(),
        );
    }
    if !cfg.bind_dn_template.contains("{username}") {
        return Err("ldap bind_dn_template must contain the `{username}` placeholder".to_string());
    }
    // In direct-bind mode the expanded template is also the Base DN of the group read, so it
    // must be a DN. A template with no `=` (an AD UPN such as `{username}@corp.example`) can
    // never become one (`validate_username` refuses `=`), so every login would bind and then
    // fail the group read. AD UPN logins go through search-then-bind instead.
    if cfg.user_search_filter.is_none() && !cfg.bind_dn_template.contains('=') {
        return Err(format!(
            "ldap bind_dn_template {:?} is not a DN: in direct-bind mode the expanded template \
             is the entry the groups are read from, so it must be a DN such as \
             `uid={{username}},ou=people,dc=corp,dc=example`; for an AD UPN login set \
             user_search_filter (e.g. `(userPrincipalName={{username}}@corp.example)`) with \
             bind_service_dn and bind_service_password",
            cfg.bind_dn_template
        ));
    }
    // A zero timeout expires every connect and operation at once, so every login would fail.
    if cfg.timeout_secs == 0 {
        return Err("ldap timeout_secs must be at least 1".to_string());
    }
    // A blank group attribute is requested and read back as nothing, so every login would
    // silently bind no roles.
    if cfg.group_attr.trim().is_empty() {
        return Err("ldap group_attr must not be empty".to_string());
    }
    if let Some(f) = &cfg.user_search_filter {
        if !f.contains("{username}") {
            return Err(
                "ldap user_search_filter must contain the `{username}` placeholder".to_string(),
            );
        }
        if cfg.bind_service_dn.is_none() {
            return Err(
                "ldap user_search_filter requires bind_service_dn for search-then-bind".to_string(),
            );
        }
        // A present-but-EMPTY service password would perform `simple_bind(dn, "")`, an
        // UNAUTHENTICATED bind on most directories. An ABSENT one is `open`'s to refuse
        // ([`LdapModule::new`]): it is normally a secret reference, resolved only there.
        if cfg
            .bind_service_password
            .as_ref()
            .is_some_and(|pw| pw.expose().is_empty())
        {
            return Err(
                "ldap bind_service_password must not be empty (an empty password becomes \
                 an unauthenticated bind for search-then-bind)"
                    .to_string(),
            );
        }
    }
    // Fail CLOSED on a plaintext transport that would expose credentials on the network: a
    // `ldap://` URL (not `ldaps://`) with no STARTTLS, to a non-loopback host, sends the
    // service-account AND every end-user password in cleartext. Reject unless the operator
    // explicitly opts out. `ldaps://`, STARTTLS, or a loopback host are already secure/local.
    if is_insecure_transport(&cfg.url, cfg.start_tls) && !cfg.allow_insecure_transport {
        // The URL is quoted with any userinfo cut: the words are 1.5.5's otherwise (H5).
        return Err(format!(
            "ldap url {:?} uses plaintext ldap:// to a non-loopback host with no STARTTLS, \
             which sends the service and end-user credentials in cleartext; use an ldaps:// \
             URL, set start_tls = true, or (to knowingly override) set \
             allow_insecure_transport = true",
            shown_url(&cfg.url)
        ));
    }
    Ok(())
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
    // Anything else here is a plaintext `ldap://` (or scheme-less) connection: only safe to a
    // loopback host, which never puts the credential on the wire.
    !is_loopback_host(host_of(url))
}

/// Extract the host from an `ldap://host:port` / `ldaps://host:port` URL, tolerating an `[::1]`
/// bracketed IPv6 literal and an absent scheme. Returns the raw host with no port or path.
fn host_of(url: &str) -> &str {
    let after = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    // The authority ends at the first '/', '?' or '#', as the dialer's `Endpoint::parse` ends it:
    // a different split lets `ldap://evil.example?x@127.0.0.1` read as loopback here.
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    // Strip any userinfo: everything up to and including the LAST '@'. WITHOUT this, a URL like
    // `ldap://127.0.0.1:389@evil.com` reads as loopback here while the dial actually lands on `evil.com`
    // in cleartext — a fail-OPEN bypass of the plaintext guard.
    let hostport = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if let Some(rest) = hostport.strip_prefix('[') {
        // Bracketed IPv6 literal: the host is everything up to the closing bracket.
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    // Otherwise the host ends at the first ':' (port).
    hostport.split(':').next().unwrap_or("")
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
        check_settings(&parse_settings(settings)?)
    }

    /// [`LdapModule::from_settings`], with the secrets the kernel resolved for the Statement's
    /// `secret_refs` (`bind_service_password`): a non-empty first secret is the service-account
    /// password, over any literal in the settings.
    pub fn from_settings_with(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, String> {
        let mut cfg = parse_settings(settings)?;
        if let Some(secret) = secrets.first().filter(|s| !s.is_empty()) {
            let secret = std::str::from_utf8(secret)
                .map_err(|_| "ldap bind_service_password secret is not UTF-8".to_string())?;
            cfg.bind_service_password = Some(SecretString(Zeroizing::new(secret.to_owned())));
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
    /// after it begins, as 1.5.5 timed them.
    pub fn login_over<W: Wire>(
        &self,
        conv: &mut Conversation,
        wire: &mut W,
        username: Option<&str>,
        password: Option<&str>,
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
                tracing::warn!(
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

/// The settings blob as an [`LdapConfig`]: an empty blob is refused, and a decode failure is
/// explained without the decoder's own text where that text could quote a value ([`json_err`]).
fn parse_settings(settings: &[u8]) -> Result<LdapConfig, String> {
    if settings.trim_ascii().is_empty() {
        return Err(
            "ldap plugin requires config (url, bind_dn_template, base_dn); none provided"
                .to_string(),
        );
    }
    serde_json::from_slice(settings).map_err(json_err("invalid ldap plugin config"))
}

/// The `map_err` for the settings decode, whose INPUT may carry a secret (a service password, or
/// one pasted into the wrong key). `serde_json::Error`'s own `Display` is withheld: a data error
/// quotes the offending value (`invalid type: string "<the value>"`), and this text reaches
/// `--validate` output and logs. What survives is WHAT failed, the CLASS of failure and WHERE. The
/// decoder texts kept verbatim are the ones that name a KEY, never a value: a missing field
/// (spelled from the type's own schema) and an unknown field (busbar-auth-oauth's `json_err`).
fn json_err(what: &'static str) -> impl FnOnce(serde_json::Error) -> String {
    move |e: serde_json::Error| {
        let text = e.to_string();
        if e.is_data()
            && (text.starts_with("missing field `") || text.starts_with("unknown field `"))
        {
            return format!("{what}: {text}");
        }
        let class = match e.classify() {
            serde_json::error::Category::Io => "the input could not be read",
            serde_json::error::Category::Syntax => "it is not well-formed JSON",
            serde_json::error::Category::Data => "a field is missing or has the wrong type",
            serde_json::error::Category::Eof => "it ends before the JSON does",
        };
        let (line, column) = (e.line(), e.column());
        format!("{what}: {class} (line {line}, column {column}; the decoder's text is withheld)")
    }
}

/// LDAP result code 49, invalidCredentials (RFC 4511 §4.1.9).
const LDAP_INVALID_CREDENTIALS: u32 = 49;

/// OWNER RULING (non-49 user bind): is a user-bind result code a SERVER or SESSION condition, one
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
}

impl From<String> for Io {
    fn from(e: String) -> Self {
        Self::Failed(e)
    }
}

/// `<ctx>: <text>` for a failed operation (1.5.5's prefixes); a pending one stays pending.
fn at(ctx: &str) -> impl FnOnce(Io) -> BindError + '_ {
    move |e| match e {
        Io::Pending => BindError::Pending,
        Io::Failed(e) => BindError::Directory(format!("{ctx}: {e}")),
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

/// The minimal LDAP operations [`LdapModule::bind_and_identify_on`] needs, abstracted behind a trait
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
    fn simple_bind(&mut self, dn: &str, password: &str) -> Result<u32, Io>;

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

/// Build the STABLE principal id from the resolved bind DN. The submitted username is user-controlled
/// in its CASING (`Alice`/`alice`) and form (`DOMAIN\alice`); using it raw would mint DIFFERENT
/// identities — and duplicate self-serve keys — for the SAME person. LDAP DNs are case-insensitive,
/// so we key identity on the resolved DN lowercased: exactly one canonical `ldap:<dn>` per directory
/// identity, in both direct-template and search-then-bind modes. Lowercasing is Unicode-aware
/// (`to_lowercase`, not `to_ascii_lowercase`) — `validate_username` allows non-ASCII names, so an
/// ASCII-only fold would mint two distinct principals for two casings of a non-ASCII username.
fn principal_id(user_dn: &str) -> String {
    format!("ldap:{}", user_dn.to_lowercase())
}

impl LdapModule {
    /// Connect to the directory, BIND with the credentials, read the user's groups, and build a
    /// [`Principal`]. The connect comes first, as in 1.5.5 (whose client connected when it was
    /// built), so a username the DN template refuses is refused after it (the order is kept).
    /// Generic over [`LdapBackend`] so the reject paths are unit-testable: a non-zero user-bind result
    /// code, an empty or AMBIGUOUS (>1 match) search, and an over-long group list are all refused or
    /// capped here.
    fn bind_and_identify<B: LdapBackend>(
        &self,
        ldap: &mut B,
        username: &str,
        password: &str,
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
                .map(SecretString::expose)
                .unwrap_or("");
            let rc = ldap
                .simple_bind(svc_dn, svc_pw)
                .map_err(at("service bind"))?;
            if rc != 0 {
                return Err(BindError::Directory(format!(
                    "service bind rejected (rc={rc})"
                )));
            }
            let filter = filter_tpl.replace("{username}", groups::escape_filter(username).as_str());
            let entries = ldap
                .search(&self.cfg.base_dn, SearchScope::Subtree, &filter, &["dn"])
                .map_err(at("user search"))?;
            // Ambiguous: more than one entry matched. Fail CLOSED rather than silently binding the
            // first — we cannot establish a single, unambiguous identity for the credential.
            if entries.len() > 1 {
                tracing::warn!(
                    module = "ldap",
                    matches = entries.len(),
                    "ldap user_search_filter matched multiple entries; rejecting as ambiguous"
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
        // (invalidCredentials) is a credential rejection. OWNER RULING (non-49): a code naming a
        // server/session condition that fails every user alike (51 busy, 52 unavailable, ...:
        // [`is_outage`]) is a directory-side failure, an outage logged by `login_over`; every other
        // non-zero code (48, 50, 53, ...) refuses this credential, the same bad credential as a
        // wrong password, its real result logged at warn by `login_over` (never the password or
        // the DN).
        let rc = ldap.simple_bind(&user_dn, password).map_err(at("bind"))?;
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

        // Read the group-membership attribute off the (now bound) user entry.
        let entries = ldap
            .search(
                &user_dn,
                SearchScope::Base,
                "(objectClass=*)",
                &[self.cfg.group_attr.as_str()],
            )
            .map_err(at("group read"))?;

        let mut group_dns: Vec<String> = Vec::new();
        if let Some(entry) = entries.into_iter().next() {
            // LDAP attribute descriptions are case-insensitive (RFC 4512 §2.5) and the entry is keyed
            // by the server's spelling, so `group_attr: memberof` must find the server's `memberOf`.
            let vals = entry
                .attrs
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&self.cfg.group_attr))
                .map(|(_, v)| v);
            if let Some(vals) = vals {
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
        let mut principal = Principal::from_id(principal_id(&user_dn));
        principal.roles = roles;
        Ok(principal)
    }
}
