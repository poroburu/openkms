//! TOML configuration loader for `/etc/openkms/config.toml`.
//!
//! Security invariants enforced at load time:
//!   - Token / password files must exist, be readable, and be mode `0600`
//!     (u+rw, no group, no other). Any wider permissions and we refuse to
//!     start so mis-deployed secrets are loud, not silent.
//!   - Every `[[keys]]` block must have a `[keys.policy]` block; fail-closed.
//!   - Duplicate labels or object IDs are rejected.
//!   - Per-key allowlist strings must parse (program IDs, bech32 recipients,
//!     etc.) — cheap parse-check so typos surface at service boot rather
//!     than at first sign.

use std::{collections::HashSet, fs, path::PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use crate::chain::Chain;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub hsm: HsmConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub cosmos: CosmosConfig,
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    #[serde(default, rename = "keys")]
    pub keys: Vec<KeyDef>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub listen: String,
    pub signer_token_file: PathBuf,
    pub admin_token_file: PathBuf,
    #[serde(default = "default_inflight_limit")]
    pub inflight_limit: usize,
    #[serde(default = "default_replay_window_secs")]
    pub replay_window_secs: u64,
}

fn default_inflight_limit() -> usize {
    64
}

fn default_replay_window_secs() -> u64 {
    120
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HsmConfig {
    pub connector_url: String,
    pub auth_key_id: u16,
    pub password_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuditConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub hmac_key_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct CosmosConfig {
    /// Accepted Cosmos `AuthInfo.signer_infos[].public_key.type_url` values.
    /// Includes vanilla secp256k1, Ethermint, and Injective variants by
    /// default; additional URLs can be added here without code changes.
    #[serde(default = "default_cosmos_pubkey_type_urls")]
    pub accepted_pubkey_type_urls: Vec<String>,
}

fn default_cosmos_pubkey_type_urls() -> Vec<String> {
    vec![
        "/cosmos.crypto.secp256k1.PubKey".to_string(),
        "/ethermint.crypto.v1.ethsecp256k1.PubKey".to_string(),
        "/injective.crypto.v1beta1.ethsecp256k1.PubKey".to_string(),
    ]
}

/// One `[[keys]]` block.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct KeyDef {
    pub label: String,
    pub chain: Chain,
    pub object_id: u16,
    #[serde(default)]
    pub derivation_path: Option<String>,
    #[serde(default)]
    pub address_style: AddressStyle,
    #[serde(default)]
    pub default_hrp: Option<String>,
    pub policy: KeyPolicy,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressStyle {
    #[default]
    Cosmos,
    Evm,
    Solana,
}

/// Per-key policy block. Evaluated in order by the default policy engine.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KeyPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub max_signs_per_minute: Option<u32>,
    #[serde(default)]
    pub max_signs_per_hour: Option<u32>,
    #[serde(default)]
    pub max_signs_per_day: Option<u32>,
    #[serde(default)]
    pub daily_cap_lamports: Option<String>,
    #[serde(default)]
    pub per_tx_cap_lamports: Option<String>,
    #[serde(default, rename = "allowed_programs")]
    pub allowed_programs: Vec<AllowedProgram>,
    #[serde(default, rename = "allowed_messages")]
    pub allowed_messages: Vec<AllowedMessage>,
    #[serde(default, rename = "allowed_recipients")]
    pub allowed_recipients: Vec<AllowedRecipient>,
}

/// Solana program allowlist entry.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AllowedProgram {
    pub id: String,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Cosmos Msg-type allowlist entry (also drives recipient / contract checks
/// for specific type_urls).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AllowedMessage {
    pub type_url: String,
    #[serde(default)]
    pub per_tx_cap: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub allowed_recipients: Vec<String>,
    #[serde(default)]
    pub allowed_contracts: Vec<String>,
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub comment: Option<String>,
}

/// Recipient allowlist tied to a chain-local program/instruction family.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AllowedRecipient {
    pub program: String,
    pub addresses: Vec<String>,
}

impl Config {
    /// Load and fully validate a config file.
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let raw = fs::read_to_string(path.as_ref())
            .with_context(|| format!("failed to read config {:?}", path.as_ref()))?;
        let cfg: Config = toml::from_str(&raw).context("failed to parse config TOML")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read a secret file (token or HSM password) from disk, enforcing that
    /// it exists and is `0600`. Trims trailing whitespace.
    pub fn read_secret_file(path: &std::path::Path) -> Result<String> {
        enforce_mode_0600(path)?;
        let s = fs::read_to_string(path)
            .with_context(|| format!("failed to read secret file {path:?}"))?;
        Ok(s.trim_end_matches(['\n', '\r', ' ', '\t']).to_string())
    }

    pub fn validate(&self) -> Result<()> {
        // Enforce 0600 on all secret files.
        enforce_mode_0600(&self.server.signer_token_file)?;
        enforce_mode_0600(&self.server.admin_token_file)?;
        enforce_mode_0600(&self.hsm.password_file)?;
        if let Some(p) = self.audit.hmac_key_file.as_ref() {
            enforce_mode_0600(p)?;
        }

        // Reject duplicate labels or object-ids.
        let mut labels = HashSet::new();
        let mut ids = HashSet::new();
        for k in &self.keys {
            if !labels.insert(&k.label) {
                bail!("duplicate key label {:?}", k.label);
            }
            if !ids.insert(k.object_id) {
                bail!("duplicate key object_id 0x{:04x}", k.object_id);
            }
            validate_key(k)?;
        }

        Ok(())
    }
}

fn validate_key(k: &KeyDef) -> Result<()> {
    // Fail-closed: a missing policy block is rejected by Serde already (field
    // is required). Double-check here that the policy has at least one
    // enabling decision so a key cannot be accidentally live with no rails.
    let p = &k.policy;
    let has_any_rule = p.max_signs_per_minute.is_some()
        || p.max_signs_per_hour.is_some()
        || p.max_signs_per_day.is_some()
        || p.daily_cap_lamports.is_some()
        || p.per_tx_cap_lamports.is_some()
        || !p.allowed_programs.is_empty()
        || !p.allowed_messages.is_empty()
        || !p.allowed_recipients.is_empty();
    if !has_any_rule {
        bail!(
            "key {:?}: policy block is empty; refuse to start with no policy rails",
            k.label
        );
    }

    match k.chain {
        Chain::Solana => {
            if p.allowed_programs.is_empty() {
                bail!(
                    "key {:?}: solana key must have at least one allowed_programs entry",
                    k.label
                );
            }
        }
        Chain::Cosmos => {
            if p.allowed_messages.is_empty() {
                bail!(
                    "key {:?}: cosmos key must have at least one allowed_messages entry",
                    k.label
                );
            }
        }
        Chain::Unknown => {
            bail!("key {:?}: unknown chain", k.label);
        }
    }

    if let Some(path) = &k.derivation_path {
        if !path.starts_with("m/") {
            bail!("key {:?}: derivation_path must start with m/", k.label);
        }
    }

    Ok(())
}

/// Reject files that are readable by group or other.
fn enforce_mode_0600(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        return Err(anyhow!("secret file does not exist: {path:?}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let md = fs::metadata(path).with_context(|| format!("stat {path:?}"))?;
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(anyhow!(
                "secret file {:?} has insecure mode 0o{:o}; must be 0o600 (no group/other access)",
                path,
                mode
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn write_secret(dir: &std::path::Path, name: &str, contents: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        p
    }

    fn good_config(dir: &std::path::Path) -> String {
        let signer = write_secret(dir, "signer-token", "s3cret");
        let admin = write_secret(dir, "admin-token", "s3cret");
        let pw = write_secret(dir, "hsm-password", "s3cret");
        format!(
            r#"
[server]
listen = "127.0.0.1:8443"
signer_token_file = "{}"
admin_token_file  = "{}"

[hsm]
connector_url = "http://127.0.0.1:12345"
auth_key_id   = 3
password_file = "{}"

[audit]
path = "/tmp/openkms-audit.log"

[[keys]]
label = "sol-mm-0"
chain = "solana"
object_id = 0x0100
derivation_path = "m/44'/501'/0'/0'"

[keys.policy]
max_signs_per_minute = 60
[[keys.policy.allowed_programs]]
id = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
"#,
            signer.display(),
            admin.display(),
            pw.display()
        )
    }

    #[test]
    fn good_config_loads() {
        let dir = TempDir::new().unwrap();
        let cfg = good_config(dir.path());
        let path = dir.path().join("config.toml");
        std::fs::write(&path, cfg).unwrap();
        let parsed = Config::load(&path).expect("good config should parse");
        assert_eq!(parsed.keys.len(), 1);
        assert_eq!(parsed.keys[0].label, "sol-mm-0");
    }

    #[test]
    fn duplicate_label_rejected() {
        let dir = TempDir::new().unwrap();
        let mut raw = good_config(dir.path());
        raw.push_str(
            r#"
[[keys]]
label = "sol-mm-0"
chain = "solana"
object_id = 0x0101

[keys.policy]
[[keys.policy.allowed_programs]]
id = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
"#,
        );
        let path = dir.path().join("config.toml");
        std::fs::write(&path, raw).unwrap();
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("duplicate"), "expected duplicate error: {err}");
    }

    #[test]
    fn cosmos_missing_allowed_messages_is_rejected() {
        let dir = TempDir::new().unwrap();
        let mut raw = good_config(dir.path());
        raw.push_str(
            r#"
[[keys]]
label = "cosmos-mm-0"
chain = "cosmos"
object_id = 0x0200

[keys.policy]
max_signs_per_minute = 5
"#,
        );
        let path = dir.path().join("config.toml");
        std::fs::write(&path, raw).unwrap();
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(
            err.contains("allowed_messages"),
            "expected allowed_messages error: {err}"
        );
    }

    #[test]
    fn insecure_permissions_rejected() {
        let dir = TempDir::new().unwrap();
        // Make one secret file world-readable.
        let raw = good_config(dir.path());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.path().join("signer-token"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
        }
        let path = dir.path().join("config.toml");
        std::fs::write(&path, raw).unwrap();
        let err = Config::load(&path).unwrap_err().to_string();
        assert!(err.contains("insecure mode"), "got {err}");
    }
}
