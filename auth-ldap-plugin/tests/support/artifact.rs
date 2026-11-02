// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub fn plugin_path() -> std::path::PathBuf {
    let path = if let Some(path) = std::env::var_os("BUSBAR_PLUGIN_CDYLIB") {
        let path = std::path::PathBuf::from(path);
        assert!(path.is_absolute(), "BUSBAR_PLUGIN_CDYLIB must be absolute");
        path
    } else {
        let exe = std::env::current_exe().expect("current test executable");
        let profile = exe
            .parent()
            .and_then(std::path::Path::parent)
            .expect("test executable lives under its profile/deps directory");
        profile.join(busbar_plugin_loader::plugin_library_filename(
            "busbar_auth_ldap_plugin",
        ))
    };
    let built = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .unwrap_or_else(|e| {
            panic!(
                "fresh actual LDAP cdylib required at {}: {e}",
                path.display()
            )
        });
    fn newest_source(path: &std::path::Path) -> std::time::SystemTime {
        let metadata = std::fs::metadata(path).expect("LDAP source exists");
        if metadata.is_dir() {
            std::fs::read_dir(path)
                .expect("read LDAP source directory")
                .map(|entry| newest_source(&entry.expect("source entry").path()))
                .max()
                .unwrap_or(std::time::UNIX_EPOCH)
        } else {
            metadata.modified().expect("source modification time")
        }
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    for source in [
        "Cargo.toml",
        "auth-ldap/Cargo.toml",
        "auth-ldap-plugin/Cargo.toml",
        "auth-ldap/src",
        "auth-ldap-plugin/src",
    ] {
        assert!(built >= newest_source(&root.join(source)),
            "LDAP cdylib {} predates {source}; build the actual current plugin with --features dropped-in", path.display());
    }
    path
}
