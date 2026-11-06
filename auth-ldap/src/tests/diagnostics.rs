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
        arm();
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

/// Arm a log capture against tracing's callsite-interest cache. A callsite first reached on a test
/// thread with no subscriber is registered as `never` by the no-op global default, and a capture
/// installed on another thread while that registration is in flight can miss the rebuild: its
/// event is then never dispatched, and the capture reads empty. Once per binary this installs a
/// global default that answers every callsite `sometimes` (so no registration caches `never`) and
/// enables nothing; every capture then rebuilds the cache.
pub(crate) fn arm() {
    static ARMED: std::sync::Once = std::sync::Once::new();
    ARMED.call_once(|| {
        tracing::subscriber::set_global_default(Sometimes)
            .expect("no other global tracing default in the unit tests");
    });
    tracing::callsite::rebuild_interest_cache();
}

/// The unit tests' global default: every callsite stays `sometimes`, and no event is enabled.
struct Sometimes;

impl tracing::Subscriber for Sometimes {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}
