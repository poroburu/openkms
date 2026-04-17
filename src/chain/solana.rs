//! Solana chain signer.
//!
//! Decodes a bincoded `VersionedMessage` (legacy or v0), verifies the HSM
//! key's Ed25519 pubkey is among the required signers, extracts a typed
//! [`SolanaIntent`] the policy engine can score, and signs the raw message
//! bytes via the HSM's `sign_ed25519`.
//!
//! Caller-supplied address-lookup-table entries are accepted so the policy
//! engine can see what accounts v0 instructions reference; the signer never
//! makes outbound RPC calls.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use solana_sdk::{message::VersionedMessage, pubkey::Pubkey};

use crate::{
    chain::{Chain, ChainError, ChainResult, ChainSigner, Intent, ProgramRef, RequestContext, SignRequest, TokenRef, Transfer},
    config::KeyDef,
    hsm::Hsm,
};

/// Solana's `Message` packet limit (bytes). Reject oversized payloads up front.
const MAX_MESSAGE_BYTES: usize = 1232;

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// Decoded form of `/sign/solana` payload.
#[derive(Clone, Debug, Deserialize)]
struct SolanaRequest {
    message_b64: String,
    #[serde(default)]
    address_lookup_tables: Vec<AltEntry>,
}

/// Caller-supplied address-lookup-table entry. The caller pre-resolves the
/// ALT so the signer can see which accounts the instructions ultimately
/// reference.
#[derive(Clone, Debug, Deserialize)]
struct AltEntry {
    key: String,
    addresses: Vec<String>,
}

#[derive(Serialize)]
pub struct SolanaResponse {
    /// Base64 of the 64-byte Ed25519 signature.
    pub signature_b64: String,
}

#[derive(Debug)]
pub struct SolanaIntent {
    chain_id: String,
    signer_address: String,
    transfers: Vec<Transfer>,
    programs: Vec<ProgramRef>,
    message_types: Vec<String>,
    human_summary: String,
    signing_digest: Vec<u8>,
}

impl Intent for SolanaIntent {
    fn chain_id(&self) -> &str {
        &self.chain_id
    }
    fn signer_address(&self) -> &str {
        &self.signer_address
    }
    fn outgoing_transfers(&self) -> &[Transfer] {
        &self.transfers
    }
    fn invoked_programs(&self) -> &[ProgramRef] {
        &self.programs
    }
    fn message_types(&self) -> &[String] {
        &self.message_types
    }
    fn human_summary(&self) -> String {
        self.human_summary.clone()
    }
    fn signing_digest(&self) -> &[u8] {
        &self.signing_digest
    }
}

pub struct SolanaSigner {
    /// Pre-fetched Ed25519 public key for the key in `KeyDef`. Caching it
    /// avoids a round-trip to the HSM on every decode.
    pub pubkey: [u8; 32],
    pub address: String,
}

impl SolanaSigner {
    pub async fn from_hsm(hsm: &Hsm, key: &KeyDef) -> anyhow::Result<Self> {
        let pk = hsm.get_ed25519_pubkey(key.object_id).await?;
        let address = bs58::encode(&pk).into_string();
        Ok(Self { pubkey: pk, address })
    }

    /// Test constructor: build a signer from a known pubkey (bypasses the
    /// HSM round-trip). Used by unit tests.
    #[cfg(test)]
    fn with_pubkey(pubkey: [u8; 32]) -> Self {
        let address = bs58::encode(&pubkey).into_string();
        Self { pubkey, address }
    }

    fn decode_versioned_message(bytes: &[u8]) -> ChainResult<VersionedMessage> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(ChainError::Validation(format!(
                "message is {} bytes; exceeds solana packet limit {}",
                bytes.len(),
                MAX_MESSAGE_BYTES
            )));
        }
        bincode::deserialize::<VersionedMessage>(bytes)
            .map_err(|e| ChainError::Decode(format!("bincode: {e}")))
    }
}

impl ChainSigner for SolanaSigner {
    const CHAIN: Chain = Chain::Solana;
    type Intent = SolanaIntent;
    type Response = SolanaResponse;

    fn decode(
        &self,
        _key: &KeyDef,
        req: SignRequest,
        ctx: &RequestContext,
    ) -> ChainResult<Self::Intent> {
        let parsed: SolanaRequest = serde_json::from_value(req.payload)
            .map_err(|e| ChainError::Decode(format!("json: {e}")))?;

        let raw = B64
            .decode(parsed.message_b64.as_bytes())
            .map_err(|e| ChainError::Decode(format!("message_b64: {e}")))?;
        let msg = Self::decode_versioned_message(&raw)?;
        msg.sanitize()
            .map_err(|e| ChainError::Validation(format!("sanitize: {e}")))?;

        // Verify the HSM key is a required signer.
        let required_signers = msg.header().num_required_signatures as usize;
        let static_keys = msg.static_account_keys();
        let hsm_pk = Pubkey::from(self.pubkey);
        let is_required = static_keys
            .iter()
            .take(required_signers)
            .any(|k| k == &hsm_pk);
        if !is_required {
            return Err(ChainError::Validation(format!(
                "HSM pubkey {} is not among the first {} required signers",
                self.address, required_signers
            )));
        }

        // Resolve ALT indexes against caller-supplied tables (v0 only).
        let alt_resolved = resolve_alt_addresses(&msg, &parsed.address_lookup_tables)?;

        // Extract programs + transfers.
        let (programs, message_types, transfers) = extract_intent_payload(&msg, static_keys, &alt_resolved)?;

        let human_summary = format!(
            "solana message: {} instructions, {} outgoing transfer(s), req_id={}",
            msg.instructions().len(),
            transfers.len(),
            ctx.request_id,
        );

        let signing_digest = msg.serialize();

        Ok(SolanaIntent {
            // Solana itself doesn't embed a chain id in the message body.
            // Callers can still pass `expected_chain_id = "solana-mainnet"`
            // which gets echoed to the audit log, but there's no on-wire
            // equivalent to Cosmos SignDoc.chain_id to compare against.
            chain_id: ctx
                .expected_chain_id
                .clone()
                .unwrap_or_else(|| "solana".to_string()),
            signer_address: self.address.clone(),
            transfers,
            programs,
            message_types,
            human_summary,
            signing_digest,
        })
    }

    fn authorize(&self, _intent: &Self::Intent, _key: &KeyDef) -> ChainResult<()> {
        // The decode step already proved the HSM key is a required signer of
        // this message; nothing else is required here. Cosmos has more to do
        // at this step (chain-id, public key type_url, etc.).
        Ok(())
    }

    async fn sign(
        &self,
        hsm: &Hsm,
        key: &KeyDef,
        intent: Self::Intent,
    ) -> ChainResult<Self::Response> {
        let sig = hsm
            .sign_ed25519(key.object_id, &intent.signing_digest)
            .await
            .map_err(ChainError::Hsm)?;
        Ok(SolanaResponse {
            signature_b64: B64.encode(sig),
        })
    }
}

fn resolve_alt_addresses(
    msg: &VersionedMessage,
    tables: &[AltEntry],
) -> ChainResult<Vec<Pubkey>> {
    let Some(lookups) = msg.address_table_lookups() else {
        return Ok(Vec::new());
    };
    let mut resolved = Vec::new();
    for lookup in lookups {
        let entry = find_alt(tables, &lookup.account_key)
            .ok_or_else(|| {
                ChainError::Validation(format!(
                    "message references ALT {} but request did not include its entries",
                    lookup.account_key
                ))
            })?;
        resolve_indexes(&mut resolved, entry, &lookup.writable_indexes)?;
        resolve_indexes(&mut resolved, entry, &lookup.readonly_indexes)?;
    }
    Ok(resolved)
}

fn find_alt<'a>(tables: &'a [AltEntry], key: &Pubkey) -> Option<&'a AltEntry> {
    let needle = key.to_string();
    tables.iter().find(|t| t.key == needle)
}

fn resolve_indexes(out: &mut Vec<Pubkey>, entry: &AltEntry, indexes: &[u8]) -> ChainResult<()> {
    for idx in indexes {
        let addr = entry.addresses.get(*idx as usize).ok_or_else(|| {
            ChainError::Validation(format!(
                "ALT {} index {} out of range (len {})",
                entry.key,
                idx,
                entry.addresses.len()
            ))
        })?;
        let pk: Pubkey = addr
            .parse()
            .map_err(|e| ChainError::Validation(format!("ALT address {addr:?} parse failed: {e}")))?;
        out.push(pk);
    }
    Ok(())
}

fn extract_intent_payload(
    msg: &VersionedMessage,
    static_keys: &[Pubkey],
    _alt_resolved: &[Pubkey],
) -> ChainResult<(Vec<ProgramRef>, Vec<String>, Vec<Transfer>)> {
    // Programs cannot be loaded from ALT; they must come from static keys.
    let mut programs = Vec::new();
    let mut message_types = Vec::new();
    let mut transfers = Vec::new();

    for ix in msg.instructions() {
        let program_pk = static_keys
            .get(ix.program_id_index as usize)
            .ok_or_else(|| {
                ChainError::Validation(format!(
                    "instruction program_id_index {} out of static key range",
                    ix.program_id_index
                ))
            })?;
        let program_id = program_pk.to_string();

        // Parse system-program transfers for amount caps.
        if program_id == SYSTEM_PROGRAM_ID {
            if let Some(t) = parse_system_transfer(&ix.data, static_keys, &ix.accounts) {
                transfers.push(t);
            }
        }

        programs.push(ProgramRef {
            id: program_id.clone(),
            method: None,
        });
        message_types.push(program_id);
    }

    Ok((programs, message_types, transfers))
}

/// Parse a `SystemInstruction::Transfer { lamports }` payload. Returns None
/// for all other SystemInstruction variants, which are surfaced only as a
/// program invocation (not a transfer).
fn parse_system_transfer(
    data: &[u8],
    static_keys: &[Pubkey],
    accounts: &[u8],
) -> Option<Transfer> {
    if data.len() < 4 {
        return None;
    }
    // Discriminator 2 == Transfer { lamports }. See solana-system-interface::SystemInstruction.
    let disc = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if disc != 2 {
        return None;
    }
    if data.len() != 12 {
        return None;
    }
    let lamports = u64::from_le_bytes(data[4..12].try_into().ok()?);
    // Transfer takes [from, to] accounts.
    let to_idx = *accounts.get(1)? as usize;
    let to = static_keys.get(to_idx)?.to_string();
    Some(Transfer {
        token: TokenRef::Native("lamports".to_string()),
        amount: lamports as u128,
        recipient: to,
        kind: "SystemProgram::Transfer",
    })
}

// base58 is used for Solana addresses; pull it from solana_sdk via transitive.
// Expose via explicit re-export for clarity.
mod bs58 {
    pub fn encode(bytes: &[u8]) -> Bs58Encoder<'_> {
        Bs58Encoder(bytes)
    }

    pub struct Bs58Encoder<'a>(&'a [u8]);
    impl<'a> Bs58Encoder<'a> {
        pub fn into_string(self) -> String {
            ::bs58::encode(self.0).into_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::{
        hash::Hash,
        message::{Message as LegacyMessage, VersionedMessage},
        pubkey::Pubkey,
    };
    use solana_system_interface::instruction as system_instruction;

    fn build_legacy_transfer_message(payer: Pubkey, to: Pubkey, lamports: u64) -> Vec<u8> {
        let ix = system_instruction::transfer(&payer, &to, lamports);
        let msg = LegacyMessage::new_with_blockhash(&[ix], Some(&payer), &Hash::default());
        let vm = VersionedMessage::Legacy(msg);
        vm.serialize()
    }

    #[test]
    fn decode_legacy_transfer_and_extract_intent() {
        let payer = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let raw = build_legacy_transfer_message(payer, to, 1_000_000);

        let signer = SolanaSigner::with_pubkey(payer.to_bytes());
        let key = KeyDef {
            label: "test".into(),
            chain: Chain::Solana,
            object_id: 1,
            derivation_path: None,
            address_style: crate::config::AddressStyle::Solana,
            default_hrp: None,
            policy: Default::default(),
        };
        let req = SignRequest {
            label: "test".into(),
            payload: serde_json::json!({
                "message_b64": B64.encode(&raw)
            }),
        };
        let ctx = RequestContext {
            request_id: "r-1".into(),
            expected_chain_id: None,
        };
        let intent = signer.decode(&key, req, &ctx).expect("decode");
        assert_eq!(intent.invoked_programs().len(), 1);
        assert_eq!(
            intent.invoked_programs()[0].id,
            SYSTEM_PROGRAM_ID,
            "program should be System"
        );
        assert_eq!(intent.outgoing_transfers().len(), 1);
        assert_eq!(intent.outgoing_transfers()[0].amount, 1_000_000);
        assert_eq!(intent.outgoing_transfers()[0].recipient, to.to_string());
        assert_eq!(intent.signing_digest(), &raw[..]);
    }

    #[test]
    fn rejects_non_signer_hsm_pubkey() {
        let payer = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let raw = build_legacy_transfer_message(payer, to, 1_000);

        let signer = SolanaSigner::with_pubkey([7u8; 32]);
        let key = KeyDef {
            label: "test".into(),
            chain: Chain::Solana,
            object_id: 1,
            derivation_path: None,
            address_style: crate::config::AddressStyle::Solana,
            default_hrp: None,
            policy: Default::default(),
        };
        let req = SignRequest {
            label: "test".into(),
            payload: serde_json::json!({ "message_b64": B64.encode(&raw) }),
        };
        let ctx = RequestContext {
            request_id: "r-2".into(),
            expected_chain_id: None,
        };
        let err = signer.decode(&key, req, &ctx).unwrap_err().to_string();
        assert!(err.contains("not among the first"), "got {err}");
    }

    #[test]
    fn rejects_oversized_message() {
        let signer = SolanaSigner::with_pubkey([1u8; 32]);
        let big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        let key = KeyDef {
            label: "test".into(),
            chain: Chain::Solana,
            object_id: 1,
            derivation_path: None,
            address_style: crate::config::AddressStyle::Solana,
            default_hrp: None,
            policy: Default::default(),
        };
        let req = SignRequest {
            label: "test".into(),
            payload: serde_json::json!({ "message_b64": B64.encode(&big) }),
        };
        let ctx = RequestContext {
            request_id: "r-3".into(),
            expected_chain_id: None,
        };
        let err = signer.decode(&key, req, &ctx).unwrap_err().to_string();
        assert!(err.contains("packet limit"), "got {err}");
    }
}
