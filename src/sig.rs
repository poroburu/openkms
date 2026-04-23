//! Shared ECDSA signature post-processing.
//!
//! YubiHSM2 returns ECDSA signatures as ASN.1 DER blobs. Cosmos SDK (and EVM)
//! consumers expect a compact 64-byte `r || s` form with low-`s` normalization
//! (BIP-0062 rule 5) to prevent signature malleability.

use k256::ecdsa::Signature as K256Sig;
use k256::elliptic_curve::{consts::U32, generic_array::GenericArray};

/// A compact ECDSA signature: 32-byte `r` followed by 32-byte `s` (64 bytes total).
pub type CompactSignature = [u8; 64];

/// Errors produced by signature post-processing.
#[derive(Debug, thiserror::Error)]
pub enum SigError {
    #[error("DER signature parse failed: {0}")]
    Parse(String),
    #[error("signature bytes have unexpected length: got {0}, expected 64")]
    BadCompactLength(usize),
}

/// Parse a DER-encoded secp256k1 ECDSA signature, normalize `s` to the low half
/// of the curve order, and return the 64-byte compact form.
///
/// Used by Cosmos and (future) EVM signers. Cosmos SDK rejects high-`s`
/// signatures; Ethereum EIP-2 also requires low-`s`.
pub fn secp256k1_der_to_compact_low_s(der: &[u8]) -> Result<CompactSignature, SigError> {
    let sig = K256Sig::from_der(der).map_err(|e| SigError::Parse(e.to_string()))?;
    let normalized = sig.normalize_s().unwrap_or(sig);
    let bytes = normalized.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Split a 64-byte compact signature into its `r` and `s` 32-byte halves.
pub fn split_rs(compact: &CompactSignature) -> (GenericArray<u8, U32>, GenericArray<u8, U32>) {
    let mut r = GenericArray::<u8, U32>::default();
    let mut s = GenericArray::<u8, U32>::default();
    r.copy_from_slice(&compact[..32]);
    s.copy_from_slice(&compact[32..]);
    (r, s)
}

/// Reconstruct an ECDSA `Signature` from a compact representation.
///
/// Returns `None` if the bytes do not form a valid curve-order-bounded signature.
pub fn compact_to_k256(compact: &CompactSignature) -> Option<K256Sig> {
    K256Sig::from_slice(compact).ok()
}

/// Recovery-id trial helper placeholder for the future EVM module.
///
/// For Ethereum signing we need to know which of the two possible public keys
/// recovered from (r, s, prehash) matches the expected signer. `k256` exposes
/// `RecoveryId::trial_recovery_from_prehash`, which we'll wire up here when the
/// EVM chain module lands. The helper is intentionally present in the generic
/// `sig` module so the EVM module only has to import it.
#[cfg(feature = "evm")]
pub fn trial_recovery_id(
    _verifying_key: &k256::ecdsa::VerifyingKey,
    _prehash: &[u8; 32],
    _signature: &K256Sig,
) -> Option<k256::ecdsa::RecoveryId> {
    // Deliberately unimplemented until EVM support lands.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{SigningKey, signature::Signer};
    use rand_core::OsRng;

    #[test]
    fn der_roundtrip_produces_low_s() {
        let sk = SigningKey::random(&mut OsRng);
        let msg = b"test message";
        let der_sig: K256Sig = sk.sign(msg);
        let der = der_sig.to_der();

        let compact =
            secp256k1_der_to_compact_low_s(der.as_bytes()).expect("DER parse should succeed");

        // Low-s: s must be <= n/2.
        let sig_rebuilt = compact_to_k256(&compact).expect("rebuild");
        assert!(sig_rebuilt.normalize_s().is_none(), "s must already be low");
    }

    #[test]
    fn split_rs_yields_32_bytes() {
        let compact = [42u8; 64];
        let (r, s) = split_rs(&compact);
        assert_eq!(r.len(), 32);
        assert_eq!(s.len(), 32);
        assert_eq!(r[0], 42);
        assert_eq!(s[0], 42);
    }
}
