//! BIP-39 mnemonic handling, HKDF-based ceremony derivation, and BIP-32 /
//! SLIP-10 child-key derivation for Path B provisioning.
//!
//! Every intermediate buffer that holds secret material is wrapped in
//! `Zeroizing<...>` so it is wiped on drop.

use std::str::FromStr;

use anyhow::{Context, Result, anyhow};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// BIP-39 PBKDF2-HMAC-SHA512 seed output length (64 bytes).
pub const SEED_LEN: usize = 64;

/// AES-256 wrap-key size, also reused for auth-key password length (32 bytes).
pub const KEY_LEN: usize = 32;

/// HKDF info labels for the four ceremony-time outputs. These are the
/// domain-separation strings the plan pins for v1; changing any of them breaks
/// recovery, so bump `/v1/` -> `/v2/` on any future change.
pub mod info {
    pub const CEREMONY_AUTH: &[u8] = b"openkms/v1/auth/ceremony";
    pub const PROVISIONER_AUTH: &[u8] = b"openkms/v1/auth/provisioner";
    pub const SIGNER_AUTH: &[u8] = b"openkms/v1/auth/signer";
    pub const WRAP_KEY: &[u8] = b"openkms/v1/wrap";
    pub const AUDIT_HMAC: &[u8] = b"openkms/v1/audit/hmac";
}

/// Four deterministic outputs produced from a BIP-39 seed during
/// `openkms setup`. All fields zeroize on drop.
#[derive(Clone)]
pub struct CeremonySecrets {
    pub ceremony_password: Zeroizing<[u8; KEY_LEN]>,
    pub provisioner_password: Zeroizing<[u8; KEY_LEN]>,
    pub signer_password: Zeroizing<[u8; KEY_LEN]>,
    pub wrap_key: Zeroizing<[u8; KEY_LEN]>,
}

/// Convert a BIP-39 mnemonic + optional passphrase to a 64-byte seed.
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; SEED_LEN]>> {
    let mnemonic =
        bip39::Mnemonic::from_str(phrase).map_err(|e| anyhow!("invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed(passphrase);
    Ok(Zeroizing::new(seed))
}

/// Generate a fresh 24-word BIP-39 mnemonic from 32 bytes of entropy.
///
/// `entropy` MUST come from a cryptographically strong source. In the openKMS
/// `new-mnemonic` command, that source is the HSM's on-chip TRNG (via
/// `GetPseudoRandom`). Callers are responsible for printing the mnemonic
/// exactly once and never persisting it to disk.
pub fn mnemonic_from_entropy(entropy: &[u8; 32]) -> Result<String> {
    let m = bip39::Mnemonic::from_entropy(entropy)
        .map_err(|e| anyhow!("mnemonic from entropy failed: {e}"))?;
    Ok(m.to_string())
}

/// Derive the four ceremony secrets (3 auth passwords + 1 wrap key) from a
/// BIP-39 seed using HKDF-SHA256 with domain-separated info labels.
pub fn derive_ceremony(seed: &[u8; SEED_LEN]) -> CeremonySecrets {
    let hkdf = Hkdf::<Sha256>::new(None, seed);

    let mut ceremony = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(info::CEREMONY_AUTH, ceremony.as_mut_slice())
        .expect("32 bytes fits in HKDF-SHA256 output");

    let mut provisioner = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(info::PROVISIONER_AUTH, provisioner.as_mut_slice())
        .expect("32 bytes fits in HKDF-SHA256 output");

    let mut signer = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(info::SIGNER_AUTH, signer.as_mut_slice())
        .expect("32 bytes fits in HKDF-SHA256 output");

    let mut wrap = Zeroizing::new([0u8; KEY_LEN]);
    hkdf.expand(info::WRAP_KEY, wrap.as_mut_slice())
        .expect("32 bytes fits in HKDF-SHA256 output");

    CeremonySecrets {
        ceremony_password: ceremony,
        provisioner_password: provisioner,
        signer_password: signer,
        wrap_key: wrap,
    }
}

/// Derive a BIP32 secp256k1 child private scalar at the given path.
///
/// Suitable for Cosmos (`m/44'/118'/...'`), Ethermint (`m/44'/60'/...`), and
/// EVM (`m/44'/60'/...`). Returns the 32-byte private scalar.
pub fn derive_secp256k1(seed: &[u8; SEED_LEN], path: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let dp: bip32::DerivationPath = path
        .parse()
        .with_context(|| format!("failed to parse BIP32 path {path:?}"))?;
    let xprv = bip32::XPrv::derive_from_path(seed, &dp)
        .map_err(|e| anyhow!("secp256k1 derivation failed: {e}"))?;
    let scalar = xprv.private_key().to_bytes();
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&scalar);
    Ok(out)
}

/// Derive a SLIP-10 Ed25519 child private key at the given path.
///
/// SLIP-10 is Solana/Phantom-compatible for `m/44'/501'/N'/0'`. All child
/// indexes are treated as hardened (Ed25519 has no unhardened derivation).
pub fn derive_ed25519(seed: &[u8; SEED_LEN], path: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let indexes = parse_hardened_indexes(path)?;
    let sk = slip10_ed25519::derive_ed25519_private_key(seed, &indexes);
    Ok(Zeroizing::new(sk))
}

/// Parse a BIP-32-style path (e.g. `m/44'/501'/0'/0'`) into a vector of child
/// indexes (without the hardening flag — SLIP-10 for Ed25519 treats everything
/// as hardened).
fn parse_hardened_indexes(path: &str) -> Result<Vec<u32>> {
    let mut parts = path.split('/');
    let root = parts
        .next()
        .ok_or_else(|| anyhow!("empty derivation path"))?;
    if root != "m" {
        return Err(anyhow!("derivation path must start with 'm': got {path:?}"));
    }
    let mut out = Vec::new();
    for part in parts {
        let part = part.trim_end_matches('\'').trim_end_matches('h');
        let idx: u32 = part
            .parse()
            .with_context(|| format!("invalid index {part:?} in path {path:?}"))?;
        if idx & 0x8000_0000 != 0 {
            return Err(anyhow!(
                "index {part:?} too large (MSB reserved for hardening)"
            ));
        }
        out.push(idx);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceremony_outputs_are_distinct() {
        let seed = [0u8; SEED_LEN];
        let s = derive_ceremony(&seed);
        assert_ne!(
            s.ceremony_password.as_slice(),
            s.provisioner_password.as_slice()
        );
        assert_ne!(
            s.provisioner_password.as_slice(),
            s.signer_password.as_slice()
        );
        assert_ne!(s.signer_password.as_slice(), s.wrap_key.as_slice());
    }

    #[test]
    fn ceremony_is_deterministic() {
        let seed = [0u8; SEED_LEN];
        let a = derive_ceremony(&seed);
        let b = derive_ceremony(&seed);
        assert_eq!(
            a.ceremony_password.as_slice(),
            b.ceremony_password.as_slice()
        );
        assert_eq!(a.wrap_key.as_slice(), b.wrap_key.as_slice());
    }

    #[test]
    fn slip10_known_vector() {
        let seed_hex = "000102030405060708090a0b0c0d0e0f";
        let seed_bytes = hex::decode(seed_hex).unwrap();
        let mut seed = [0u8; SEED_LEN];
        seed[..seed_bytes.len()].copy_from_slice(&seed_bytes);

        // SLIP-10 vector for `m/0'/1'/2'` (CASE 1 from the SLIP-10 spec):
        // expected private key "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"
        let derived = slip10_ed25519::derive_ed25519_private_key(&seed_bytes, &[0, 1, 2]);
        assert_eq!(
            hex::encode(derived),
            "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"
        );
    }

    #[test]
    fn bip39_mnemonic_roundtrip() {
        let entropy = [7u8; 32];
        let phrase = mnemonic_from_entropy(&entropy).unwrap();
        let seed1 = mnemonic_to_seed(&phrase, "").unwrap();
        let seed2 = mnemonic_to_seed(&phrase, "").unwrap();
        assert_eq!(seed1.as_slice(), seed2.as_slice());
        let seed3 = mnemonic_to_seed(&phrase, "my-passphrase").unwrap();
        assert_ne!(seed1.as_slice(), seed3.as_slice());
    }

    #[test]
    fn secp256k1_derivation_is_deterministic() {
        let seed = [5u8; SEED_LEN];
        let k1 = derive_secp256k1(&seed, "m/44'/118'/0'/0/0").unwrap();
        let k2 = derive_secp256k1(&seed, "m/44'/118'/0'/0/0").unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
        let k3 = derive_secp256k1(&seed, "m/44'/118'/1'/0/0").unwrap();
        assert_ne!(k1.as_slice(), k3.as_slice());
    }

    #[test]
    fn ed25519_derivation_is_deterministic() {
        let seed = [5u8; SEED_LEN];
        let k1 = derive_ed25519(&seed, "m/44'/501'/0'/0'").unwrap();
        let k2 = derive_ed25519(&seed, "m/44'/501'/0'/0'").unwrap();
        assert_eq!(k1.as_slice(), k2.as_slice());
    }

    #[test]
    fn parse_bad_path_is_rejected() {
        assert!(parse_hardened_indexes("44'/501'").is_err());
        assert!(parse_hardened_indexes("m/44'/bad'/0'").is_err());
    }
}
