//! Chain-agnostic traits that every concrete chain signer (Solana, Cosmos,
//! future EVM) implements, plus the typed policy-evaluation data model.
//!
//! The server is one route per chain. Each route knows the concrete
//! [`ChainSigner`] impl it is calling, so the trait is not required to be
//! object-safe.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{config::KeyDef, hsm::Hsm};

pub mod cosmos;
pub mod solana;

/// Well-known identifier for the chain a key signs on. Used by metrics,
/// audit-log records, and the `chain` field in `[[keys]]` config blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Solana,
    Cosmos,
    #[serde(other)]
    Unknown,
}

impl Chain {
    pub fn as_str(self) -> &'static str {
        match self {
            Chain::Solana => "solana",
            Chain::Cosmos => "cosmos",
            Chain::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-request metadata that flows alongside the raw body from the server
/// into the `ChainSigner::decode` call.
#[derive(Clone, Debug)]
pub struct RequestContext {
    /// UUID propagated from the caller's `X-Request-Id` header (or minted if
    /// absent). Shows up in metrics, logs, and the audit log.
    pub request_id: String,
    /// Caller-provided chain-id (Cosmos chains supply this per-request).
    pub expected_chain_id: Option<String>,
}

/// A single outbound value movement — native token or wrapped / SPL / CW20 /
/// ERC-20. The policy engine's amount-cap and recipient-allowlist rules match
/// against these.
#[derive(Clone, Debug)]
pub struct Transfer {
    pub token: TokenRef,
    pub amount: u128,
    pub recipient: String,
    /// Free-form comment that surfaces in the human summary (e.g.
    /// `"SystemProgram::transfer"`).
    pub kind: &'static str,
}

#[derive(Clone, Debug)]
pub enum TokenRef {
    /// Native token (SOL, ATOM, OSMO, ETH, ...). String is the bech32 HRP or
    /// chain ticker, for display only.
    Native(String),
    Spl(String),
    Cw20(String),
    Erc20(String),
}

impl TokenRef {
    pub fn human(&self) -> String {
        match self {
            TokenRef::Native(x) => format!("native:{x}"),
            TokenRef::Spl(mint) => format!("spl:{mint}"),
            TokenRef::Cw20(contract) => format!("cw20:{contract}"),
            TokenRef::Erc20(address) => format!("erc20:{address}"),
        }
    }
}

/// A program / contract / EVM target the transaction invokes.
#[derive(Clone, Debug)]
pub struct ProgramRef {
    /// Chain-local program identifier: Solana program-ID string, Cosmos
    /// contract address, or `(to_address)` for EVM.
    pub id: String,
    /// Method / Msg-type URL / 4-byte selector (hex, without 0x), if known.
    pub method: Option<String>,
}

/// Typed decoded transaction ready for policy evaluation and signing.
///
/// The policy engine only reaches for the typed accessors below; it never
/// looks at chain-specific structures. This keeps the policy layer generic
/// (works for any `Intent`) while each chain signer owns its own
/// domain-specific details.
pub trait Intent {
    /// Chain-id the transaction claims (e.g. `"osmosis-1"` or the Solana
    /// cluster genesis hash). Solana returns `"solana"` since the protocol
    /// does not embed a chain-id directly in the message.
    fn chain_id(&self) -> &str;
    /// Address (or address-equivalent) of the HSM key that signs.
    fn signer_address(&self) -> &str;
    fn outgoing_transfers(&self) -> &[Transfer];
    fn invoked_programs(&self) -> &[ProgramRef];
    /// Flat list of Msg type URLs (Cosmos) or a synthetic per-program name
    /// (Solana). For Solana, each element corresponds 1:1 with an entry in
    /// `invoked_programs`.
    fn message_types(&self) -> &[String];
    /// One-line human summary for logs and the audit record.
    fn human_summary(&self) -> String;
    /// Exact bytes the HSM will sign. Replay-cache key lives off this.
    fn signing_digest(&self) -> &[u8];
}

/// Unified error type returned by chain signers.
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("decode failed: {0}")]
    Decode(String),
    #[error("validation failed: {0}")]
    Validation(String),
    #[error("hsm error: {0}")]
    Hsm(#[from] anyhow::Error),
}

pub type ChainResult<T> = std::result::Result<T, ChainError>;

/// The raw request body accepted by `/sign/<chain>` routes.
#[derive(Clone, Debug, Deserialize)]
pub struct SignRequest {
    /// Key label as configured in `/etc/openkms/config.toml`.
    pub label: String,
    /// Chain-specific payload. Solana uses `message_b64` +
    /// `address_lookup_tables`; Cosmos uses `sign_doc_b64` +
    /// `expected_chain_id`. We accept both shapes and defer decoding to the
    /// chain signer.
    #[serde(flatten)]
    pub payload: serde_json::Value,
}

/// The signing interface every chain implements.
///
/// `decode` is sync (pure parse + validate). `sign` is async because it ends
/// up holding the single HSM mutex.
#[allow(async_fn_in_trait)]
pub trait ChainSigner: Send + Sync + 'static {
    const CHAIN: Chain;
    type Intent: Intent + Send + Sync;
    type Response: Serialize + Send;

    fn decode(
        &self,
        key: &KeyDef,
        req: SignRequest,
        ctx: &RequestContext,
    ) -> ChainResult<Self::Intent>;

    fn authorize(&self, intent: &Self::Intent, key: &KeyDef) -> ChainResult<()>;

    async fn sign(
        &self,
        hsm: &Hsm,
        key: &KeyDef,
        intent: Self::Intent,
    ) -> ChainResult<Self::Response>;
}
