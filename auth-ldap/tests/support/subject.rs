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

// Nested builds inherit the coordinator's bounded CARGO_BUILD_JOBS budget.
pub fn build_real_binaries() -> (std::path::PathBuf, std::path::PathBuf) {
    let root = busbar_root();
    let target = std::path::PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect(
        "CARGO_TARGET_DIR must name the coordinator-assigned target for the actual binary build",
    ));
    assert!(
        target.is_absolute() && target.is_dir(),
        "CARGO_TARGET_DIR must name the existing absolute assigned target"
    );

    let metadata = std::process::Command::new("cargo")
        .args([
            "+1.98.0",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
        ])
        .arg(root.join("Cargo.toml"))
        .current_dir(&root)
        .output()
        .expect("read actual busbar checkout Cargo metadata");
    assert!(
        metadata.status.success(),
        "actual checkout metadata must resolve with its lock: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&metadata.stdout).expect("actual checkout Cargo metadata is JSON");
    let mut owners = Vec::new();
    for package in metadata["packages"].as_array().expect("metadata packages") {
        for binary in package["targets"].as_array().expect("package targets") {
            if binary["name"].as_str() == Some("busbar-plugin-pack")
                && binary["kind"]
                    .as_array()
                    .expect("target kinds")
                    .iter()
                    .any(|kind| kind.as_str() == Some("bin"))
            {
                let features = binary
                    .get("required-features")
                    .map_or_else(Vec::new, |features| {
                        features
                            .as_array()
                            .expect("required target features")
                            .iter()
                            .map(|feature| feature.as_str().expect("feature name").to_owned())
                            .collect::<Vec<_>>()
                    });
                owners.push((
                    package["name"]
                        .as_str()
                        .expect("owning package name")
                        .to_owned(),
                    features,
                ));
            }
        }
    }
    assert_eq!(
        owners.len(),
        1,
        "actual checkout must have one busbar-plugin-pack binary owner: {owners:?}"
    );
    let (pack_owner, pack_features) = owners.pop().unwrap();
    let pack_features = pack_features.join(",");
    let mut pack_args = vec![
        "+1.98.0",
        "build",
        "--locked",
        "--release",
        "-p",
        pack_owner.as_str(),
        "--bin",
        "busbar-plugin-pack",
    ];
    if !pack_features.is_empty() {
        pack_args.extend(["--features", pack_features.as_str()]);
    }
    for args in [
        &[
            "+1.98.0",
            "build",
            "--locked",
            "--release",
            "--manifest-path",
            "dist/default/Cargo.toml",
            "--bin",
            "busbar",
        ][..],
        pack_args.as_slice(),
    ] {
        let status = std::process::Command::new("cargo")
            .args(args)
            .current_dir(&root)
            .env("BUSBAR_RELEASE_PUBKEY", E2E_RELEASE_PUBKEY)
            .status()
            .expect("run cargo build for busbar / busbar-plugin-pack");
        assert!(
            status.success(),
            "building the real busbar + busbar-plugin-pack binaries must succeed ({args:?})"
        );
    }
    (
        target.join("release/busbar"),
        target.join("release/busbar-plugin-pack"),
    )
}

const E2E_RELEASE_PUBKEY: &str = "9209607c315f66473c8cca8bf9a7b8031115d01bb47341613cebf57f0e4f271c";
