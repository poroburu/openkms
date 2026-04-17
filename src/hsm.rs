//! Chain-agnostic wrapper around `yubihsm::Client`.
//!
//! Offers only the three primitives openKMS needs at runtime:
//!   - [`Hsm::get_public_key`]
//!   - [`Hsm::sign_ed25519`]
//!   - [`Hsm::sign_ecdsa_prehashed`] — curve-parameterized over secp256k1 and
//!     secp256r1 so the HSM layer is signature-scheme-complete for every
//!     blockchain YubiHSM2 can reach (see the plan's "Signature-scheme
//!     coverage across chains" section).
//!
//! The HSM client is serialized by a single `tokio::sync::Mutex`: YubiHSM2 is
//! one USB device and the Yubico connector serializes access regardless, so
//! openKMS does the serialization itself at the client level.

use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use tokio::sync::Mutex;
use yubihsm::{
    Client, Connector, Credentials,
    asymmetric::{self, Algorithm as AsymmetricAlg, PublicKey},
    authentication,
    connector::{HttpConfig, UsbConfig},
};

/// Curve selector for ECDSA signing.
///
/// secp256k1 is today's Cosmos/EVM family. secp256r1 (P-256) covers ICP, Sui /
/// Aptos alt-schemes, EIP-7212 passkey-backed smart accounts, and Starknet P-256
/// accounts — no chain implementation today, but the HSM layer is wired for it.
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
pub struct Hsm {
    inner: Arc<Mutex<Client>>,
    auth_key_id: u16,
}

impl Hsm {
    /// Build an HSM handle talking to `yubihsm-connector` at the given URL.
    ///
    /// `reconnect=true` is pinned by design (TMKMS pattern): transient USB
    /// disconnects self-heal on the next request rather than requiring the
    /// service to be restarted.
    pub fn open_http(
        connector_url: &str,
        auth_key_id: u16,
        password: &[u8],
    ) -> Result<Self> {
        let config = parse_http_config(connector_url)?;
        let connector = Connector::http(&config);
        Self::open(connector, auth_key_id, password)
    }

    /// Build an HSM handle talking to a USB-attached device directly.
    pub fn open_usb(auth_key_id: u16, password: &[u8]) -> Result<Self> {
        let connector = Connector::usb(&UsbConfig::default());
        Self::open(connector, auth_key_id, password)
    }

    /// Build an HSM handle backed by the in-process MockHsm for tests.
    pub fn open_mock(auth_key_id: u16, password: &[u8]) -> Result<Self> {
        let connector = Connector::mockhsm();
        Self::open(connector, auth_key_id, password)
    }

    fn open(connector: Connector, auth_key_id: u16, password: &[u8]) -> Result<Self> {
        let creds = Credentials::from_password(auth_key_id, password);
        let client = Client::open(connector, creds, true)
            .map_err(|e| anyhow!("yubihsm open failed: {e}"))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(client)),
            auth_key_id,
        })
    }

    /// Wrap a pre-constructed client (used after `openkms setup`-style flows
    /// that want to keep a live authenticated session around).
    pub fn from_client(client: Client, auth_key_id: u16) -> Self {
        Self {
            inner: Arc::new(Mutex::new(client)),
            auth_key_id,
        }
    }

    pub fn auth_key_id(&self) -> u16 {
        self.auth_key_id
    }

    /// Low-level borrow of the client mutex (for CLI / ceremony code that
    /// needs to invoke capabilities the runtime doesn't use — e.g. `setup`,
    /// `backup`, `restore`).
    pub fn client(&self) -> Arc<Mutex<Client>> {
        self.inner.clone()
    }

    /// Return the raw public-key bytes for an asymmetric object.
    pub async fn get_public_key(&self, key_id: u16) -> Result<PublicKey> {
        let guard = self.inner.lock().await;
        guard
            .get_public_key(key_id)
            .map_err(|e| anyhow!("get_public_key({key_id}) failed: {e}"))
    }

    /// Return the Ed25519 public key for a signing object.
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

    /// Return the secp256k1 public key as a 65-byte uncompressed SEC1 point
    /// (with leading 0x04 prepended — YubiHSM2 returns only `x || y`).
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

    /// Return the compressed secp256k1 public key (33 bytes, `02|03 || x`).
    /// Cosmos SDK public keys are this form.
    pub async fn get_secp256k1_pubkey_compressed(&self, key_id: u16) -> Result<[u8; 33]> {
        let uncompressed = self.get_secp256k1_pubkey_uncompressed(key_id).await?;
        compress_secp256k1(&uncompressed)
    }

    /// Sign arbitrary message bytes with an Ed25519 key. YubiHSM2 hashes
    /// internally per RFC 8032.
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

    /// Sign a 32-byte prehash with ECDSA over the selected curve. Returns the
    /// DER-encoded signature straight from the HSM; normalize / convert in
    /// [`crate::sig`].
    pub async fn sign_ecdsa_prehashed(
        &self,
        key_id: u16,
        curve: EcdsaCurve,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>> {
        let _ = curve; // curve is determined by the object on the HSM; kept in
                       // the signature so callers record which curve they expect.
        let guard = self.inner.lock().await;
        let der = guard
            .sign_ecdsa_prehash_raw(key_id, digest.as_slice())
            .map_err(|e| anyhow!("sign_ecdsa_prehashed({key_id}) failed: {e}"))?;
        Ok(der)
    }

    /// Pull `len` bytes of entropy from the HSM's on-chip TRNG.
    pub async fn get_pseudo_random(&self, len: usize) -> Result<Vec<u8>> {
        let guard = self.inner.lock().await;
        guard
            .get_pseudo_random(len)
            .map_err(|e| anyhow!("get_pseudo_random({len}) failed: {e}"))
    }

    /// Ping the HSM for liveness.
    pub async fn ping(&self) -> bool {
        let guard = self.inner.lock().await;
        guard.ping().is_ok()
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

/// Convert an uncompressed SEC1 secp256k1 point (65 bytes, `04 || x || y`) to
/// its 33-byte compressed form (`02 || x` if y even, `03 || x` if y odd).
pub fn compress_secp256k1(uncompressed: &[u8; 65]) -> Result<[u8; 33]> {
    if uncompressed[0] != 0x04 {
        return Err(anyhow!("expected uncompressed SEC1 tag 0x04"));
    }
    let mut out = [0u8; 33];
    out[0] = if uncompressed[64] & 1 == 0 { 0x02 } else { 0x03 };
    out[1..].copy_from_slice(&uncompressed[1..33]);
    Ok(out)
}

// Small shim so we can parse a URL without pulling a full `url` crate dep for
// this one use — HTTP is the `http` crate's `Uri` which is already in the tree
// via axum/hyper.
mod http {
    pub use ::http::Uri;
}

/// Shared `yubihsm` re-exports the rest of the crate reaches for when talking
/// directly to the HSM (CLI, ceremony, backup/restore).
pub mod hsm_types {
    pub use yubihsm::{
        Capability, Client, Connector, Credentials, Domain,
        asymmetric::Algorithm as AsymmetricAlg,
        authentication::{Algorithm as AuthAlg, Key as AuthKey},
        object::{self, Id as ObjectId, Label as ObjectLabel, Type as ObjectType},
        wrap::{self, Algorithm as WrapAlg},
    };
}

/// Conventional object-IDs used by openKMS's ceremony (mirrors TMKMS).
pub mod ids {
    pub const CEREMONY_AUTH_KEY_ID: u16 = 1;
    pub const PROVISIONER_AUTH_KEY_ID: u16 = 2;
    pub const SIGNER_AUTH_KEY_ID: u16 = 3;
    pub const WRAP_KEY_ID: u16 = 1;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_hsm_ping_and_pseudo_random() {
        let hsm = Hsm::open_mock(1, b"password").expect("open mock");
        assert!(hsm.ping().await, "mockhsm should ping");
        let r = hsm.get_pseudo_random(16).await.expect("pseudo random");
        assert_eq!(r.len(), 16);
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
        // y is even (trailing byte 0x02) -> prefix 0x02
        let mut pt = [0u8; 65];
        pt[0] = 0x04;
        pt[64] = 0x02;
        let c = compress_secp256k1(&pt).unwrap();
        assert_eq!(c[0], 0x02);

        // y is odd -> prefix 0x03
        pt[64] = 0x03;
        let c = compress_secp256k1(&pt).unwrap();
        assert_eq!(c[0], 0x03);
    }
}

// Silence unused-import warnings when optional sub-modules are not compiled.
#[allow(unused_imports)]
use asymmetric as _;
#[allow(unused_imports)]
use authentication as _;
