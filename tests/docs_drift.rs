use std::{fs, process::Command};

use openkms::Config;
use tempfile::TempDir;

const CARGO_TOML: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README.md");
const CI_YML: &str = include_str!("../.github/workflows/ci.yml");
const EXAMPLE_CONFIG: &str = include_str!("../examples/config.toml");

fn repo_path(path: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn write_secret(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, "secret\n").expect("write secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod secret");
    }
    path
}

#[test]
fn release_metadata_matches_readme() {
    assert!(CARGO_TOML.contains("version = \"0.1.0-rc.1\""));
    assert!(CARGO_TOML.contains("license = \"Apache-2.0\""));
    assert!(CARGO_TOML.contains("Cosmos and Solana"));
    assert!(README.contains("`0.1.0-rc.1`"));
    assert!(README.contains("Licensed under Apache-2.0"));
    assert!(!README.contains("License\n\nTBD"));
}

#[test]
fn example_config_deserializes_and_validates_with_real_secret_paths() {
    let tmp = TempDir::new().expect("tempdir");
    let mut cfg: Config = toml::from_str(EXAMPLE_CONFIG).expect("example config parses");
    cfg.server.signer_token_file = write_secret(tmp.path(), "signer.token");
    cfg.server.admin_token_file = write_secret(tmp.path(), "admin.token");
    cfg.hsm.password_file = write_secret(tmp.path(), "hsm-password");
    cfg.audit.hmac_key_file = Some(write_secret(tmp.path(), "audit-hmac.key"));
    cfg.validate().expect("example config validates");
}

#[test]
fn ci_paths_cover_behavior_affecting_files() {
    for pattern in [
        ".cargo/**",
        ".github/workflows/**",
        "src/**",
        "tests/**",
        "examples/**",
        "scripts/**",
        "docs/**",
        "deploy/**",
        "openapi/**",
        "website/**",
        "README.md",
        "LICENSE",
    ] {
        assert!(
            CI_YML.contains(pattern),
            "missing CI path filter: {pattern}"
        );
    }
}

#[test]
fn documented_source_files_exist() {
    for path in [
        "examples/config.toml",
        "docs/remote-e2e.md",
        "docs/broadcast-e2e.md",
        "deploy/README.md",
        "openapi/openkms.v1.json",
        "website/src/content/docs/overview.md",
        "website/src/content/docs/guides/quick-start.md",
        "website/src/content/docs/concepts/security-model.md",
        "website/src/content/docs/guides/configuration.md",
        "website/src/content/docs/guides/policy-authoring.md",
        "website/src/content/docs/reference/http-api.md",
        "website/src/content/docs/reference/architecture.md",
        "scripts/e2e_defaults.sh",
        ".github/workflows/remote-e2e.yml",
        ".github/workflows/broadcast-e2e.yml",
    ] {
        assert!(repo_path(path).exists(), "missing documented path: {path}");
        assert!(README.contains(path), "README should point at {path}");
    }
}

#[test]
fn shell_wrapper_help_stays_available() {
    for script in [
        "scripts/generate_remote_e2e_request.sh",
        "scripts/generate_e2e_request.sh",
        "scripts/run_remote_e2e_job.sh",
        "scripts/run_broadcast_e2e.sh",
    ] {
        let out = Command::new("bash")
            .arg(repo_path(script))
            .arg("--help")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("run script --help");
        assert!(
            out.status.success(),
            "{script} --help failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
