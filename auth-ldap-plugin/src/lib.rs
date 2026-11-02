// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **AD/LDAP auth module as a droppable busbar plugin**: the logic crate re-exported whole, and

#![deny(unsafe_code)]
#![deny(missing_docs)]

pub use busbar_auth_ldap::*;

/// The exported door, behind `dropped-in` (the cdylib build only): the macro's `#[no_mangle]` symbol is

#[cfg(feature = "dropped-in")]
#[allow(unsafe_code)]
mod exported {
    busbar_contract::export_door!(busbar_auth_ldap::door::door);
}
