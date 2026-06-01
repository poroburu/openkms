//! YubiHSM2 vault driver.
//!
//! Chain-agnostic wrapper around `yubihsm::Client` implementing [`SigningVault`].

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use tokio::sync::Mutex;
use yubihsm::{
    Client, Connector, Credentials,
    asymmetric::{self, Algorithm as AsymmetricAlg, PublicKey},
    authentication,
    connector::{HttpConfig, UsbConfig},
};

use serde::Deserialize;

use super::{KeyId, SigningVault};
use crate::config::Config;
use zeroize::Zeroizing;

/// Curve selector for ECDSA signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EcdsaCurve {
    Secp256k1,
    Secp256r1,
}

impl EcdsaCurve {
    pub fn asymmetric_algorithm(self) -> AsymmetricAlg {
        match self {
            EcdsaCurve::Secp256k1 => AsymmetricAlg::EcK256,
            EcdsaCurve::Secp256r1 => AsymmetricAlg::EcP256,
        }
    }
}

/// A handle to the YubiHSM2, shared across axum handlers.
#[derive(Clone)]
pub struct YubiVault {
    inner: Arc<Mutex<Client>>,
    auth_key_id: u16,
    vault_name: String,
}

impl YubiVault {
    pub fn open_http(connector_url: &str, auth_key_id: u16, password: &[u8]) -> Result<Self> {
        let config = parse_http_config(connector_url)?;
        let connector = Connector::http(&config);
        Self::open_named(connector, auth_key_id, password, "yubihsm")
    }

    pub fn open_usb(auth_key_id: u16, password: &[u8]) -> Result<Self> {
        let connector = Connector::usb(&UsbConfig::default());
        Self::open_named(connector, auth_key_id, password, "yubihsm")
    }

    pub fn open_mock(auth_key_id: u16, password: &[u8]) -> Result<Self> {
        let connector = Connector::mockhsm();
        Self::open_named(connector, auth_key_id, password, "mockhsm")
    }

    fn open_named(
        connector: Connector,
        auth_key_id: u16,
        password: &[u8],
        name: impl Into<String>,
    ) -> Result<Self> {
        let creds = Credentials::from_password(auth_key_id, password);
        let client = Client::open(connector, creds, true)
            .map_err(|e| anyhow!("yubihsm open failed: {e}"))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(client)),
            auth_key_id,
            vault_name: name.into(),
        })
    }

    pub fn from_client(client: Client, auth_key_id: u16) -> Self {
        Self {
            inner: Arc::new(Mutex::new(client)),
            auth_key_id,
            vault_name: "yubihsm".to_string(),
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.vault_name = name.into();
        self
    }

    pub fn auth_key_id(&self) -> u16 {
        self.auth_key_id
    }

    pub fn client(&self) -> Arc<Mutex<Client>> {
        self.inner.clone()
    }

    pub async fn get_public_key(&self, key_id: u16) -> Result<PublicKey> {
        let guard = self.inner.lock().await;
        guard
            .get_public_key(key_id)
            .map_err(|e| anyhow!("get_public_key({key_id}) failed: {e}"))
    }

    pub async fn get_ed25519_pubkey(&self, key_id: u16) -> Result<[u8; 32]> {
        let pk = self.get_public_key(key_id).await?;
        if pk.algorithm != AsymmetricAlg::Ed25519 {
            return Err(anyhow!(
                "key {key_id} is not Ed25519 (algorithm = {:?})",
                pk.algorithm
            ));
        }
        let mut out = [0u8; 32];
        if pk.bytes.len() != 32 {
            return Err(anyhow!(
                "Ed25519 public key has unexpected length {}",
                pk.bytes.len()
            ));
        }
        out.copy_from_slice(&pk.bytes);
        Ok(out)
    }

    pub async fn get_secp256k1_pubkey_uncompressed(&self, key_id: u16) -> Result<[u8; 65]> {
        let pk = self.get_public_key(key_id).await?;
        if pk.algorithm != AsymmetricAlg::EcK256 {
            return Err(anyhow!(
                "key {key_id} is not secp256k1 (algorithm = {:?})",
                pk.algorithm
            ));
        }
        if pk.bytes.len() != 64 {
            return Err(anyhow!(
                "secp256k1 public key has unexpected length {}",
                pk.bytes.len()
            ));
        }
        let mut out = [0u8; 65];
        out[0] = 0x04;
        out[1..].copy_from_slice(&pk.bytes);
        Ok(out)
    }

    pub async fn get_secp256k1_pubkey_compressed(&self, key_id: u16) -> Result<[u8; 33]> {
        let uncompressed = self.get_secp256k1_pubkey_uncompressed(key_id).await?;
        compress_secp256k1(&uncompressed)
    }

    pub async fn sign_ed25519(&self, key_id: u16, message: &[u8]) -> Result<[u8; 64]> {
        let guard = self.inner.lock().await;
        let sig = guard
            .sign_ed25519(key_id, message)
            .map_err(|e| anyhow!("sign_ed25519({key_id}) failed: {e}"))?;
        let bytes = sig.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    pub async fn sign_ecdsa_prehashed(
        &self,
        key_id: u16,
        curve: EcdsaCurve,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let _ = curve;
        let guard = self.inner.lock().await;
        let der = guard
            .sign_ecdsa_prehash_raw(key_id, digest.as_slice())
            .map_err(|e| anyhow!("sign_ecdsa_prehashed({key_id}) failed: {e}"))?;
        Ok(der)
    }

    pub async fn get_pseudo_random(&self, len: usize) -> Result<Vec<u8>> {
        let guard = self.inner.lock().await;
        guard
            .get_pseudo_random(len)
            .map_err(|e| anyhow!("get_pseudo_random({len}) failed: {e}"))
    }

    pub async fn ping(&self) -> bool {
        let guard = self.inner.lock().await;
        guard.ping().is_ok()
    }
}

#[derive(Debug, Deserialize)]
struct YubiConfig {
    #[serde(default)]
    connector_url: Option<String>,
    auth_key_id: u16,
    #[serde(default)]
    password_file: Option<std::path::PathBuf>,
    #[serde(default)]
    mock: bool,
}

pub fn register(m: &mut std::collections::HashMap<&'static str, super::BuildFn>) {
    m.insert("yubihsm", build);
}

fn build(name: &str, table: &toml::Value) -> Result<Arc<dyn SigningVault>> {
    let conf: YubiConfig = table.clone().try_into().context("invalid yubihsm vault config")?;
    let password = if conf.mock {
        Zeroizing::new(b"password".to_vec())
    } else {
        let path = conf
            .password_file
            .as_ref()
            .ok_or_else(|| anyhow!("yubihsm vault: password_file is required unless mock = true"))?;
        Config::read_hsm_password_file(path)?
    };
    let vault = if conf.mock {
        YubiVault::open_mock(conf.auth_key_id, password.as_slice())?
    } else {
        let url = conf
            .connector_url
            .as_deref()
            .ok_or_else(|| anyhow!("yubihsm vault: connector_url is required unless mock = true"))?;
        YubiVault::open_http(url, conf.auth_key_id, password.as_slice())?
    }
    .with_name(name);
    Ok(Arc::new(vault))
}

#[async_trait]
impl SigningVault for YubiVault {
    fn name(&self) -> &str {
        &self.vault_name
    }

    fn driver(&self) -> &'static str {
        "yubihsm"
    }

    async fn ready(&self) -> bool {
        self.ping().await
    }

    async fn ed25519_pubkey(&self, key_id: &KeyId) -> Result<[u8; 32]> {
        self.get_ed25519_pubkey(key_id.yubi_object_id()?).await
    }

    async fn secp256k1_pubkey_compressed(&self, key_id: &KeyId) -> Result<[u8; 33]> {
        self.get_secp256k1_pubkey_compressed(key_id.yubi_object_id()?)
            .await
    }

    async fn secp256k1_pubkey_uncompressed(&self, key_id: &KeyId) -> Result<[u8; 65]> {
        self.get_secp256k1_pubkey_uncompressed(key_id.yubi_object_id()?)
            .await
    }

    async fn sign_ed25519(&self, key_id: &KeyId, message: &[u8]) -> Result<[u8; 64]> {
        self.sign_ed25519(key_id.yubi_object_id()?, message).await
    }

    async fn sign_ecdsa_prehashed(
        &self,
        key_id: &KeyId,
        curve: EcdsaCurve,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>> {
        self.sign_ecdsa_prehashed(key_id.yubi_object_id()?, curve, digest)
            .await
    }
}

fn parse_http_config(url: &str) -> Result<HttpConfig> {
    let parsed: http::Uri = url
        .parse()
        .with_context(|| format!("invalid connector URL {url:?}"))?;
    let mut config = HttpConfig::default();
    if let Some(host) = parsed.host() {
        config.addr = host.to_string();
    }
    if let Some(port) = parsed.port_u16() {
        config.port = port;
    }
    Ok(config)
}

pub fn compress_secp256k1(uncompressed: &[u8; 65]) -> Result<[u8; 33]> {
    if uncompressed[0] != 0x04 {
        return Err(anyhow!("expected uncompressed SEC1 tag 0x04"));
    }
    let mut out = [0u8; 33];
    out[0] = if uncompressed[64] & 1 == 0 {
        0x02
    } else {
        0x03
    };
    out[1..].copy_from_slice(&uncompressed[1..33]);
    Ok(out)
}

mod http {
    pub use ::http::Uri;
}

#[allow(unused_imports)]
use asymmetric as _;
#[allow(unused_imports)]
use authentication as _;

pub mod hsm_types {
    pub use yubihsm::{
        Capability, Client, Connector, Credentials, Domain,
        asymmetric::Algorithm as AsymmetricAlg,
        authentication::{Algorithm as AuthAlg, Key as AuthKey},
        object::{self, Id as ObjectId, Label as ObjectLabel, Type as ObjectType},
        wrap::{self, Algorithm as WrapAlg},
    };
}

pub mod ids {
    pub const CEREMONY_AUTH_KEY_ID: u16 = 1;
    pub const PROVISIONER_AUTH_KEY_ID: u16 = 2;
    pub const SIGNER_AUTH_KEY_ID: u16 = 3;
    pub const WRAP_KEY_ID: u16 = 4;
}

pub fn provisioner_auth_capabilities_setup() -> yubihsm::Capability {
    use yubihsm::Capability as C;
    C::GENERATE_ASYMMETRIC_KEY
        | C::PUT_ASYMMETRIC_KEY
        | C::IMPORT_WRAPPED
        | C::EXPORT_WRAPPED
        | C::DELETE_ASYMMETRIC_KEY
        | C::PUT_AUTHENTICATION_KEY
        | C::DELETE_AUTHENTICATION_KEY
        | C::PUT_WRAP_KEY
        | C::RESET_DEVICE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_hsm_ping_and_pseudo_random() {
        let hsm = YubiVault::open_mock(1, b"password").expect("open mock");
        assert!(hsm.ping().await, "mockhsm should ping");
        let r = hsm.get_pseudo_random(16).await.expect("pseudo random");
        assert_eq!(r.len(), 16);
    }

    #[test]
    fn provisioner_setup_capabilities_include_reset_and_generate() {
        let c = provisioner_auth_capabilities_setup();
        assert!(c.contains(yubihsm::Capability::RESET_DEVICE));
        assert!(c.contains(yubihsm::Capability::GENERATE_ASYMMETRIC_KEY));
    }

    #[test]
    fn curve_maps_to_algorithm() {
        assert_eq!(
            EcdsaCurve::Secp256k1.asymmetric_algorithm(),
            AsymmetricAlg::EcK256
        );
        assert_eq!(
            EcdsaCurve::Secp256r1.asymmetric_algorithm(),
            AsymmetricAlg::EcP256
        );
    }

    #[test]
    fn compress_point_parity() {
        let mut pt = [0u8; 65];
        pt[0] = 0x04;
        pt[64] = 0x02;
        let c = compress_secp256k1(&pt).unwrap();
        assert_eq!(c[0], 0x02);
        pt[64] = 0x03;
        let c = compress_secp256k1(&pt).unwrap();
        assert_eq!(c[0], 0x03);
    }
}
