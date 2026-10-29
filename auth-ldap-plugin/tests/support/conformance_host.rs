// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//
// RENDERED by `busbar-release plugin heal busbar-auth-ldap` from GetBusbar/busbar-release
// template/conformance-host/kit-stream.rs, because this repo's declares file states network needs
// (`needs`: `tcp`); a hand edit is overwritten by the next sync.

//! THE SUITE'S HOST, IN THIS PLUGIN'S OWN TEST: busbar's test kit's stream form
//! (`busbar_test_kit::conformance_host!`): the test kit's stream table, upgraded with the
//! connector's own client TLS. No transport plugin is linked. It gives `FAR_END`, `host` (the
//! suite's `host:`), `anchors` (its `tls:`), `far_end`, `tls_front`, and the host's own proof as
//! this file's tests.

busbar_test_kit::conformance_host! { far_end: "localhost:41859" }
