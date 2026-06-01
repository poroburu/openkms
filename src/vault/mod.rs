//! Pluggable signing vault backends (signatory-inspired driver registry).
//!
//! Keys are declared in config (`[[keys]]`); each key references a named vault
//! and a driver-specific `key_id`. Runtime signing goes through [`SigningVault`].

mod aws;
mod azure;
mod cloudkms;
mod confidentialspace;
mod file;
mod hashicorp;
mod nitro;
mod yubihsm;

use std::{
    collections::HashMap,
    sync::{Arc, OnceLock},
};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use thiserror::Error;

pub use yubihsm::{
    EcdsaCurve, YubiVault, compress_secp256k1, hsm_types, ids, provisioner_auth_capabilities_setup,
};

/// Backward-compatible alias for CLI / ceremony code that still talks to YubiHSM2.
pub type Hsm = YubiVault;

/// Driver-specific key identifier passed to [`SigningVault`] methods.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyId {
    /// YubiHSM2 asymmetric object id.
    YubiObject(u16),
    /// Label in a file-based vault (`keys.json` `name` field).
    FileLabel(String),
}

impl KeyId {
    pub fn yubi_object(id: u16) -> Self {
        Self::YubiObject(id)
    }

    pub fn from_file_label(label: impl Into<String>) -> Self {
        Self::FileLabel(label.into())
    }

    pub fn yubi_object_id(&self) -> Result<u16> {
        match self {
            Self::YubiObject(id) => Ok(*id),
            other => bail!("expected YubiHSM object id, got {other:?}"),
        }
    }

    pub fn as_file_label(&self) -> Result<&str> {
        match self {
            Self::FileLabel(label) => Ok(label.as_str()),
            other => bail!("expected file vault label, got {other:?}"),
        }
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::YubiObject(id) => write!(f, "0x{id:04x}"),
            Self::FileLabel(label) => f.write_str(label),
        }
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault driver {driver} is not implemented yet")]
    NotImplemented { driver: String },
    #[error("unknown vault driver {driver}")]
    UnknownDriver { driver: String },
    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl VaultError {
    pub fn not_implemented(driver: &str) -> Self {
        Self::NotImplemented {
            driver: driver.to_string(),
        }
    }
}

type BuildFn = fn(&str, &toml::Value) -> Result<Arc<dyn SigningVault>>;

static REGISTRY: OnceLock<HashMap<&'static str, BuildFn>> = OnceLock::new();

fn registry() -> &'static HashMap<&'static str, BuildFn> {
    REGISTRY.get_or_init(|| {
        let mut m = HashMap::new();
        yubihsm::register(&mut m);
        file::register(&mut m);
        aws::register(&mut m);
        azure::register(&mut m);
        cloudkms::register(&mut m);
        hashicorp::register(&mut m);
        nitro::register(&mut m);
        confidentialspace::register(&mut m);
        m
    })
}

/// Open a vault instance from a TOML table (must include `driver`).
pub fn open_vault(name: &str, table: &toml::Value) -> Result<Arc<dyn SigningVault>> {
    let driver = table
        .get("driver")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("vault {name:?}: missing driver"))?;
    let build = registry()
        .get(driver)
        .ok_or_else(|| VaultError::UnknownDriver {
            driver: driver.to_string(),
        })?;
    build(name, table).with_context(|| format!("failed to open vault {name:?}"))
}

/// Open every vault declared in config.
pub fn open_vaults(
    vaults: &HashMap<String, toml::Value>,
) -> Result<HashMap<String, Arc<dyn SigningVault>>> {
    let mut out = HashMap::with_capacity(vaults.len());
    for (name, table) in vaults {
        out.insert(name.clone(), open_vault(name, table)?);
    }
    Ok(out)
}

/// Parse a driver-specific [`KeyId`] from config `key_id` string.
pub fn parse_key_id(driver: &str, key_id: &str) -> Result<KeyId> {
    match driver {
        "yubihsm" => Ok(KeyId::YubiObject(parse_u16_key_id(key_id)?)),
        "file" => {
            if key_id.is_empty() {
                bail!("file vault key_id must be a non-empty label");
            }
            Ok(KeyId::from_file_label(key_id))
        }
        other => bail!("cannot parse key_id for unimplemented driver {other:?}"),
    }
}

/// Parse `0x0100`, `256`, or decimal u16 strings used in config.
pub fn parse_u16_key_id(s: &str) -> Result<u16> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).with_context(|| format!("invalid hex key_id {s:?}"))
    } else {
        t.parse::<u16>()
            .with_context(|| format!("invalid decimal key_id {s:?}"))
    }
}

#[async_trait]
pub trait SigningVault: Send + Sync {
    fn name(&self) -> &str;
    fn driver(&self) -> &'static str;
    async fn ready(&self) -> bool;
    async fn ed25519_pubkey(&self, key_id: &KeyId) -> Result<[u8; 32]>;
    async fn secp256k1_pubkey_compressed(&self, key_id: &KeyId) -> Result<[u8; 33]>;
    async fn secp256k1_pubkey_uncompressed(&self, key_id: &KeyId) -> Result<[u8; 65]>;
    async fn sign_ed25519(&self, key_id: &KeyId, message: &[u8]) -> Result<[u8; 64]>;
    async fn sign_ecdsa_prehashed(
        &self,
        key_id: &KeyId,
        curve: EcdsaCurve,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn awskms_stub_not_implemented() {
        let table = toml::Value::try_from(toml::map::Map::from_iter([(
            "driver".to_string(),
            toml::Value::String("awskms".to_string()),
        )]))
        .unwrap();
        assert!(open_vault("test", &table).is_err());
    }

    #[test]
    fn parse_key_ids() {
        assert_eq!(parse_u16_key_id("0x0100").unwrap(), 0x0100);
        assert_eq!(parse_u16_key_id("256").unwrap(), 256);
        assert!(matches!(
            parse_key_id("file", "sol-dev").unwrap(),
            KeyId::FileLabel(_)
        ));
    }
}
