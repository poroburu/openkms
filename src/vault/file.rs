//! File-based vault driver — **dev / CI only**.
//!
//! Loads raw signing material from a JSON file on disk. Never use in production.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use k256::ecdsa::{SigningKey as K256SigningKey, signature::Signer as K256Signer};
use serde::Deserialize;
use zeroize::Zeroizing;

use super::{EcdsaCurve, KeyId, SigningVault};
use crate::config::enforce_mode_0600;
use crate::vault::yubihsm::compress_secp256k1;

#[derive(Clone)]
enum FileKeyMaterial {
    Ed25519(SigningKey),
    Secp256k1(K256SigningKey),
}

struct FileVault {
    name: String,
    keys: HashMap<String, FileKeyMaterial>,
}

#[derive(Debug, Deserialize)]
struct FileKeyEntry {
    name: String,
    algorithm: String,
    secret_hex: String,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    path: PathBuf,
}

pub fn register(m: &mut HashMap<&'static str, super::BuildFn>) {
    m.insert("file", build);
}

fn build(name: &str, table: &toml::Value) -> Result<Arc<dyn SigningVault>> {
    let conf: FileConfig = table.clone().try_into().context("invalid file vault config")?;
    enforce_mode_0600(&conf.path)?;
    let raw = std::fs::read_to_string(&conf.path)
        .with_context(|| format!("failed to read keys file {:?}", conf.path))?;
    let entries: Vec<FileKeyEntry> =
        serde_json::from_str(&raw).context("failed to parse keys.json")?;

    let mut keys = HashMap::new();
    for entry in entries {
        if keys.contains_key(&entry.name) {
            bail!("duplicate key name {:?} in {:?}", entry.name, conf.path);
        }
        let secret = parse_secret_hex(&entry.secret_hex)?;
        let material = match entry.algorithm.as_str() {
            "ed25519" => FileKeyMaterial::Ed25519(SigningKey::from_bytes(&secret)),
            "secp256k1" => {
                let sk = K256SigningKey::from_slice(secret.as_ref())
                    .map_err(|e| anyhow!("invalid secp256k1 secret for {:?}: {e}", entry.name))?;
                FileKeyMaterial::Secp256k1(sk)
            }
            other => bail!(
                "key {:?}: unsupported algorithm {other:?} (expected ed25519 or secp256k1)",
                entry.name
            ),
        };
        keys.insert(entry.name, material);
    }

    Ok(Arc::new(FileVault {
        name: name.to_string(),
        keys,
    }))
}

fn parse_secret_hex(hex_str: &str) -> Result<Zeroizing<[u8; 32]>> {
    let t = hex_str.trim();
    if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("secret_hex must be 64 hex characters (32 bytes)");
    }
    let raw = hex::decode(t).context("invalid secret_hex")?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&raw);
    Ok(out)
}

impl FileVault {
    fn key(&self, key_id: &KeyId) -> Result<&FileKeyMaterial> {
        let label = key_id.as_file_label()?;
        self.keys
            .get(label)
            .ok_or_else(|| anyhow!("file vault: unknown key {label:?}"))
    }
}

#[async_trait]
impl SigningVault for FileVault {
    fn name(&self) -> &str {
        &self.name
    }

    fn driver(&self) -> &'static str {
        "file"
    }

    async fn ready(&self) -> bool {
        true
    }

    async fn ed25519_pubkey(&self, key_id: &KeyId) -> Result<[u8; 32]> {
        match self.key(key_id)? {
            FileKeyMaterial::Ed25519(sk) => Ok(sk.verifying_key().to_bytes()),
            _ => bail!("key {:?} is not ed25519", key_id),
        }
    }

    async fn secp256k1_pubkey_uncompressed(&self, key_id: &KeyId) -> Result<[u8; 65]> {
        match self.key(key_id)? {
            FileKeyMaterial::Secp256k1(sk) => {
                use k256::elliptic_curve::sec1::ToEncodedPoint;
                let pt = sk.verifying_key().to_encoded_point(false);
                let bytes = pt.as_bytes();
                let mut out = [0u8; 65];
                out.copy_from_slice(bytes);
                Ok(out)
            }
            _ => bail!("key {:?} is not secp256k1", key_id),
        }
    }

    async fn secp256k1_pubkey_compressed(&self, key_id: &KeyId) -> Result<[u8; 33]> {
        let uncompressed = self.secp256k1_pubkey_uncompressed(key_id).await?;
        compress_secp256k1(&uncompressed)
    }

    async fn sign_ed25519(&self, key_id: &KeyId, message: &[u8]) -> Result<[u8; 64]> {
        match self.key(key_id)? {
            FileKeyMaterial::Ed25519(sk) => Ok(sk.sign(message).to_bytes()),
            _ => bail!("key {:?} is not ed25519", key_id),
        }
    }

    async fn sign_ecdsa_prehashed(
        &self,
        key_id: &KeyId,
        curve: EcdsaCurve,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>> {
        if curve != EcdsaCurve::Secp256k1 {
            bail!("file vault only supports secp256k1 ECDSA");
        }
        match self.key(key_id)? {
            FileKeyMaterial::Secp256k1(sk) => {
                use k256::ecdsa::Signature as K256Signature;
                let sig: K256Signature = sk.sign(digest);
                Ok(sig.to_der().to_bytes().to_vec())
            }
            _ => bail!("key {:?} is not secp256k1", key_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use rand_core::OsRng;
    use std::io::Write;

    fn write_secret_file(dir: &tempfile::TempDir, entries: &str) -> PathBuf {
        let p = dir.path().join("keys.json");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(entries.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        p
    }

    #[tokio::test]
    async fn file_vault_ed25519_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let sk = SigningKey::generate(&mut OsRng);
        let hex = hex::encode(sk.to_bytes());
        let path = write_secret_file(
            &dir,
            &format!(
                r#"[{{"name":"sol-dev","algorithm":"ed25519","secret_hex":"{hex}"}}]"#
            ),
        );
        let table = toml::Value::try_from(toml::map::Map::from_iter([
            ("driver".to_string(), toml::Value::String("file".to_string())),
            ("path".to_string(), toml::Value::String(path.display().to_string())),
        ]))
        .unwrap();
        let vault = build("dev", &table).unwrap();
        let key_id = KeyId::from_file_label("sol-dev");
        let pk = vault.ed25519_pubkey(&key_id).await.unwrap();
        assert_eq!(pk, sk.verifying_key().to_bytes());
        let msg = b"hello";
        let sig = vault.sign_ed25519(&key_id, msg).await.unwrap();
        sk.verifying_key()
            .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
            .unwrap();
    }

    #[tokio::test]
    async fn file_vault_secp256k1_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let sk = K256SigningKey::random(&mut OsRng);
        let hex = hex::encode(sk.to_bytes().as_slice());
        let path = write_secret_file(
            &dir,
            &format!(
                r#"[{{"name":"cosmos-dev","algorithm":"secp256k1","secret_hex":"{hex}"}}]"#
            ),
        );
        let table = toml::Value::try_from(toml::map::Map::from_iter([
            ("driver".to_string(), toml::Value::String("file".to_string())),
            ("path".to_string(), toml::Value::String(path.display().to_string())),
        ]))
        .unwrap();
        let vault = build("dev", &table).unwrap();
        let key_id = KeyId::from_file_label("cosmos-dev");
        let digest = [7u8; 32];
        let der = vault
            .sign_ecdsa_prehashed(&key_id, EcdsaCurve::Secp256k1, &digest)
            .await
            .unwrap();
        assert!(!der.is_empty());
    }
}
