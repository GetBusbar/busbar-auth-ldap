// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Buffer the standard tracing formatter for LDAP's privacy and warn-once assertions.

use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(crate) struct Diagnostics {
    bytes: Arc<Mutex<Vec<u8>>>,
    level: tracing::Level,
}

impl Default for Diagnostics {
    fn default() -> Self {
        Self {
            bytes: Arc::default(),
            level: tracing::Level::WARN,
        }
    }
}

impl std::io::Write for Diagnostics {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Diagnostics {
    pub(crate) fn capturing_debug() -> Self {
        Self {
            level: tracing::Level::DEBUG,
            ..Self::default()
        }
    }
    pub(crate) fn subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        let writer = self.clone();
        tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_target(false)
            .with_max_level(self.level)
            .with_writer(move || writer.clone())
            .finish()
    }
    pub(crate) fn messages(&self) -> Vec<String> {
        String::from_utf8(self.bytes.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
    pub(crate) fn contains(&self, text: &str) -> bool {
        self.messages().iter().any(|s| s.contains(text))
    }
    pub(crate) fn count(&self, text: &str) -> usize {
        self.messages().iter().filter(|s| s.contains(text)).count()
    }
}
