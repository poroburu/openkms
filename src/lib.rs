//! openKMS — YubiHSM2-backed transaction signer for Cosmos + Solana (+ EVM later).

pub mod hsm;
pub mod sig;

pub use hsm::{EcdsaCurve, Hsm};
