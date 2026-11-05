// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One-off conversion of released 1.5.5 LDAP settings. Runtime parsing remains strict.

use busbar_contract::abi::sdk::migrate::{Migrate, MigrateNeed, Migrated};
use busbar_contract::SecretRef;
use serde_json::Value;

/// The LDAP-owned migration entry, called with no live instance or directory connection.
pub(crate) struct LdapMigration;

impl Migrate for LdapMigration {
    fn migrate(settings: Value, from: &str) -> Migrated {
        let mut migrated = Migrated::unchanged(settings);
        // Only the released baseline whose settings grammar was verified here. Neither current
        // config validation nor an unknown source version gets a compatibility parser.
        if !matches!(from, "1.5.5" | "v1.5.5") {
            return migrated;
        }
        let Some(settings) = migrated.settings.as_object_mut() else {
            migrated.report.push(
                "TODO settings: supply an LDAP settings object; no conversion was made".into(),
            );
            return migrated;
        };

        if let Some(value) = settings.get_mut("user_search_filter") {
            match value {
                Value::Null => {}
                Value::String(template) => {
                    let sample = template.replace(
                        "{username}",
                        &crate::groups::escape_filter(crate::SAMPLE_USERNAME),
                    );
                    if !template.contains("{username}") {
                        migrated.report.push(FILTER_TODO.into());
                    } else if crate::filter::encode(&sample).is_ok() {
                        // Already current syntax: retain spelling and make reruns a no-op.
                    } else if !template.starts_with('(')
                        && crate::filter::encode(&format!("({sample})")).is_ok()
                    {
                        // A bare item was the old parser's only alternative to a parenthesised
                        // filter. The strict parser validates the equivalent wrapped item, with
                        // the hostile sample ensuring the placeholder is an assertion value.
                        *template = format!("({template})");
                        migrated.report.push(
                            "settings.user_search_filter: added outer parentheses to the released \
                             bare-item syntax; the runtime requires RFC 4515 filters"
                                .into(),
                        );
                    } else {
                        migrated.report.push(FILTER_TODO.into());
                    }
                }
                _ => migrated.report.push(FILTER_TODO.into()),
            }
        }

        if let Some(password) = settings.get("bind_service_password") {
            match password {
                Value::Null => {}
                // In the released LDAP settings this scalar was the password itself, including
                // the string "none". Never reinterpret its content as a reference or template.
                Value::String(password) => {
                    // The host owns secure file creation and replaces this field with a file
                    // reference before printing/writing the migrated config. The need carries
                    // only its path: the original bytes remain in exactly one settings value.
                    migrated.needs.push(MigrateNeed::ExternalizeSecret {
                        path: vec!["bind_service_password".into()],
                    });
                    migrated.report.push(
                        "settings.bind_service_password: requested secure file externalization of \
                         the released literal password; the host replaces it with a file reference"
                            .into(),
                    );
                    if password.is_empty() || password.chars().any(char::is_control) {
                        migrated.report.push(
                            "TODO settings.bind_service_password: current LDAP authentication \
                             requires a non-empty password without control characters; update the \
                             directory credential and its secret file before boot"
                                .into(),
                        );
                    }
                }
                Value::Object(_)
                    if serde_json::from_value::<SecretRef>(password.clone()).is_ok() =>
                {
                    // Preserve existing reference spelling and opaque provider settings.
                }
                _ => migrated.report.push(
                    "TODO settings.bind_service_password: supply a supported secret reference; \
                     the unrecognized value was left unchanged"
                        .into(),
                ),
            }
        }
        migrated
    }
}

const FILTER_TODO: &str =
    "TODO settings.user_search_filter: supply a parenthesised RFC 4515 filter \
    with {username} in an assertion value; the unrecognized template was left unchanged";

#[cfg(test)]
#[path = "tests/migrate_tests.rs"]
mod tests;
