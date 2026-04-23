//! Cosmos chain signer.
//!
//! Accepts any Cosmos SDK chain — `chain_id` is supplied per request. Decodes
//! `cosmos.tx.v1beta1.SignDoc` + `AuthInfo` + `TxBody`, verifies the HSM key's
//! pubkey matches a signer (with a configurable set of accepted pubkey
//! `type_url`s for Ethermint / Injective / base Cosmos), extracts a typed
//! [`CosmosIntent`] for policy evaluation, and produces a compact, low-s
//! ECDSA signature.

use std::collections::BTreeSet;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use prost::Message;
use ripemd::Ripemd160;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    chain::{
        Chain, ChainError, ChainResult, ChainSigner, Intent, ProgramRef, RequestContext,
        SignRequest, TokenRef, Transfer,
    },
    config::{AddressStyle, KeyDef},
    hsm::{EcdsaCurve, Hsm},
    sig::secp256k1_der_to_compact_low_s,
};

use cosmrs::proto::cosmos::{
    bank::v1beta1::MsgSend as ProtoMsgSend,
    tx::v1beta1::{AuthInfo as ProtoAuthInfo, SignDoc as ProtoSignDoc, TxBody as ProtoTxBody},
};
use cosmrs::proto::cosmwasm::wasm::v1::MsgExecuteContract as ProtoMsgExecuteContract;

/// Cosmos `MsgSend` type URL. Used inline for transfer extraction.
const MSG_SEND_TYPE_URL: &str = "/cosmos.bank.v1beta1.MsgSend";
/// CosmWasm `MsgExecuteContract` type URL.
const MSG_EXECUTE_CONTRACT_TYPE_URL: &str = "/cosmwasm.wasm.v1.MsgExecuteContract";

#[derive(Clone, Debug, Deserialize)]
struct CosmosRequest {
    sign_doc_b64: String,
    expected_chain_id: String,
}

#[derive(Serialize)]
pub struct CosmosResponse {
    /// Base64 of the 64-byte compact `r||s` secp256k1 signature (low-s).
    pub signature_b64: String,
}

#[derive(Debug)]
pub struct CosmosIntent {
    chain_id: String,
    signer_address: String,
    transfers: Vec<Transfer>,
    programs: Vec<ProgramRef>,
    message_types: Vec<String>,
    human_summary: String,
    signing_digest: Vec<u8>,
    /// The exact 32-byte sha256(SignDoc) we will hand to the HSM.
    prehash: [u8; 32],
}

impl Intent for CosmosIntent {
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

pub struct CosmosSigner {
    /// HSM-backed compressed secp256k1 public key (33 bytes).
    pub compressed_pubkey: [u8; 33],
    /// Uncompressed SEC1 pubkey (65 bytes, `04 || x || y`).
    pub uncompressed_pubkey: [u8; 65],
    /// Derived default address (per `KeyDef.default_hrp` + `address_style`).
    pub default_address: String,
    /// Accepted AuthInfo pubkey type URLs — bank, Ethermint, Injective, etc.
    pub accepted_pubkey_type_urls: BTreeSet<String>,
    /// Address style — determines whether we derive via ripemd160+sha256 (base
    /// Cosmos) or keccak256 (Ethermint / EVM).
    pub address_style: AddressStyle,
}

impl CosmosSigner {
    pub async fn from_hsm(
        hsm: &Hsm,
        key: &KeyDef,
        accepted_type_urls: impl IntoIterator<Item = String>,
    ) -> anyhow::Result<Self> {
        let compressed = hsm.get_secp256k1_pubkey_compressed(key.object_id).await?;
        let uncompressed = hsm.get_secp256k1_pubkey_uncompressed(key.object_id).await?;
        let hrp = key
            .default_hrp
            .clone()
            .unwrap_or_else(|| "cosmos".to_string());
        let default_address = derive_address(&compressed, &uncompressed, key.address_style, &hrp)?;
        Ok(Self {
            compressed_pubkey: compressed,
            uncompressed_pubkey: uncompressed,
            default_address,
            accepted_pubkey_type_urls: accepted_type_urls.into_iter().collect(),
            address_style: key.address_style,
        })
    }

    /// Test constructor: build a signer from a known pubkey.
    #[cfg(test)]
    fn with_fixed(
        compressed: [u8; 33],
        uncompressed: [u8; 65],
        hrp: &str,
        style: AddressStyle,
    ) -> Self {
        let default_address = derive_address(&compressed, &uncompressed, style, hrp).unwrap();
        let mut set = BTreeSet::new();
        set.insert("/cosmos.crypto.secp256k1.PubKey".to_string());
        set.insert("/ethermint.crypto.v1.ethsecp256k1.PubKey".to_string());
        Self {
            compressed_pubkey: compressed,
            uncompressed_pubkey: uncompressed,
            default_address,
            accepted_pubkey_type_urls: set,
            address_style: style,
        }
    }
}

impl ChainSigner for CosmosSigner {
    const CHAIN: Chain = Chain::Cosmos;
    type Intent = CosmosIntent;
    type Response = CosmosResponse;

    fn decode(
        &self,
        _key: &KeyDef,
        req: SignRequest,
        ctx: &RequestContext,
    ) -> ChainResult<Self::Intent> {
        let parsed: CosmosRequest = serde_json::from_value(req.payload)
            .map_err(|e| ChainError::Decode(format!("json: {e}")))?;

        // Per-request chain_id wins over the RequestContext copy (the context
        // version just echoes whatever middleware extracted).
        if let Some(ctx_chain_id) = ctx.expected_chain_id.as_ref() {
            if ctx_chain_id != &parsed.expected_chain_id {
                return Err(ChainError::Validation(format!(
                    "context chain_id {:?} does not match body expected_chain_id {:?}",
                    ctx_chain_id, parsed.expected_chain_id
                )));
            }
        }

        let raw = B64
            .decode(parsed.sign_doc_b64.as_bytes())
            .map_err(|e| ChainError::Decode(format!("sign_doc_b64: {e}")))?;

        let sign_doc = ProtoSignDoc::decode(raw.as_slice())
            .map_err(|e| ChainError::Decode(format!("SignDoc protobuf: {e}")))?;

        if sign_doc.chain_id != parsed.expected_chain_id {
            return Err(ChainError::Validation(format!(
                "SignDoc.chain_id {:?} != expected {:?}",
                sign_doc.chain_id, parsed.expected_chain_id
            )));
        }

        // Decode AuthInfo and verify the pubkey matches our HSM object.
        let auth_info = ProtoAuthInfo::decode(sign_doc.auth_info_bytes.as_slice())
            .map_err(|e| ChainError::Decode(format!("AuthInfo protobuf: {e}")))?;
        self.verify_pubkey(&auth_info)?;

        // Decode TxBody for Msg extraction.
        let body = ProtoTxBody::decode(sign_doc.body_bytes.as_slice())
            .map_err(|e| ChainError::Decode(format!("TxBody protobuf: {e}")))?;

        let (programs, message_types, transfers) = extract_body(&body, &self.default_address);

        let human_summary = format!(
            "cosmos tx on {}: {} msg(s), {} outgoing transfer(s), req_id={}",
            sign_doc.chain_id,
            body.messages.len(),
            transfers.len(),
            ctx.request_id,
        );

        let prehash: [u8; 32] = Sha256::digest(&raw).into();

        Ok(CosmosIntent {
            chain_id: sign_doc.chain_id,
            signer_address: self.default_address.clone(),
            transfers,
            programs,
            message_types,
            human_summary,
            signing_digest: raw,
            prehash,
        })
    }

    fn authorize(&self, _intent: &Self::Intent, _key: &KeyDef) -> ChainResult<()> {
        // The decode step already checked the pubkey type URL + bytes match.
        Ok(())
    }

    async fn sign(
        &self,
        hsm: &Hsm,
        key: &KeyDef,
        intent: Self::Intent,
    ) -> ChainResult<Self::Response> {
        let der = hsm
            .sign_ecdsa_prehashed(key.object_id, EcdsaCurve::Secp256k1, &intent.prehash)
            .await
            .map_err(ChainError::Hsm)?;
        let compact = secp256k1_der_to_compact_low_s(&der)
            .map_err(|e| ChainError::Hsm(anyhow::anyhow!("DER->compact failed: {e}")))?;
        Ok(CosmosResponse {
            signature_b64: B64.encode(compact),
        })
    }
}

impl CosmosSigner {
    fn verify_pubkey(&self, auth_info: &ProtoAuthInfo) -> ChainResult<()> {
        // Find the signer info whose public key (Any) matches one of our
        // accepted type URLs and the compressed-pubkey bytes.
        let signer = auth_info
            .signer_infos
            .iter()
            .find(|s| {
                s.public_key
                    .as_ref()
                    .map(|any| self.accepted_pubkey_type_urls.contains(&any.type_url))
                    .unwrap_or(false)
            })
            .ok_or_else(|| {
                ChainError::Validation(
                    "AuthInfo has no signer with an accepted public_key type_url".into(),
                )
            })?;

        let any = signer.public_key.as_ref().expect("filtered above");

        // Every accepted pubkey type URL Cosmos has (base, Ethermint,
        // Injective) wraps a `PubKey { bytes key }` protobuf whose `key`
        // field contains the 33-byte compressed secp256k1 point. We can
        // therefore parse any of them with the same message shape.
        let inner = decode_cosmos_pubkey_bytes(&any.value)
            .map_err(|e| ChainError::Decode(format!("pubkey protobuf: {e}")))?;

        if inner != self.compressed_pubkey {
            return Err(ChainError::Validation(format!(
                "AuthInfo pubkey does not match HSM key (type_url={})",
                any.type_url
            )));
        }

        Ok(())
    }
}

/// Decode the `bytes key = 1` field of any of the three accepted pubkey
/// protobufs — they're all wire-compatible (one bytes field tagged 1).
fn decode_cosmos_pubkey_bytes(raw: &[u8]) -> Result<[u8; 33], prost::DecodeError> {
    #[derive(Clone, PartialEq, ::prost::Message)]
    struct PubKeyBytes {
        #[prost(bytes = "vec", tag = "1")]
        pub key: Vec<u8>,
    }
    let pk = PubKeyBytes::decode(raw)?;
    if pk.key.len() != 33 {
        return Err(prost::DecodeError::new(format!(
            "expected 33-byte compressed pubkey, got {} bytes",
            pk.key.len()
        )));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&pk.key);
    Ok(out)
}

fn extract_body(
    body: &ProtoTxBody,
    signer_address: &str,
) -> (Vec<ProgramRef>, Vec<String>, Vec<Transfer>) {
    let mut programs = Vec::new();
    let mut message_types = Vec::new();
    let mut transfers = Vec::new();

    for msg in &body.messages {
        let type_url = msg.type_url.clone();
        message_types.push(type_url.clone());

        let (program, msg_transfers) = match type_url.as_str() {
            MSG_SEND_TYPE_URL => match ProtoMsgSend::decode(msg.value.as_slice()) {
                Ok(send) => {
                    let mut ts = Vec::new();
                    for coin in &send.amount {
                        let amount: u128 = coin.amount.parse().unwrap_or(0);
                        ts.push(Transfer {
                            token: TokenRef::Native(coin.denom.clone()),
                            amount,
                            recipient: send.to_address.clone(),
                            kind: "cosmos.bank.MsgSend",
                        });
                    }
                    (
                        ProgramRef {
                            id: type_url.clone(),
                            method: None,
                        },
                        ts,
                    )
                }
                Err(_) => (
                    ProgramRef {
                        id: type_url.clone(),
                        method: None,
                    },
                    Vec::new(),
                ),
            },
            MSG_EXECUTE_CONTRACT_TYPE_URL => {
                match ProtoMsgExecuteContract::decode(msg.value.as_slice()) {
                    Ok(wasm) => {
                        let mut ts = Vec::new();
                        for coin in &wasm.funds {
                            let amount: u128 = coin.amount.parse().unwrap_or(0);
                            ts.push(Transfer {
                                token: TokenRef::Native(coin.denom.clone()),
                                amount,
                                recipient: wasm.contract.clone(),
                                kind: "cosmwasm.MsgExecuteContract.funds",
                            });
                        }
                        let method = parse_wasm_method(&wasm.msg);
                        (
                            ProgramRef {
                                id: wasm.contract.clone(),
                                method,
                            },
                            ts,
                        )
                    }
                    Err(_) => (
                        ProgramRef {
                            id: type_url.clone(),
                            method: None,
                        },
                        Vec::new(),
                    ),
                }
            }
            _ => (
                ProgramRef {
                    id: type_url.clone(),
                    method: None,
                },
                Vec::new(),
            ),
        };

        let _ = signer_address; // hook: future per-chain checks
        programs.push(program);
        transfers.extend(msg_transfers);
    }

    (programs, message_types, transfers)
}

/// Extract the top-level JSON key from a CosmWasm `msg` payload (e.g.
/// `{"swap": {...}}` -> `"swap"`). Returns None if the payload isn't JSON.
fn parse_wasm_method(msg: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(msg).ok()?;
    let obj = v.as_object()?;
    obj.keys().next().cloned()
}

/// Derive a bech32 address from the HSM key using the requested style.
///
/// - `AddressStyle::Cosmos`  : `bech32(hrp, ripemd160(sha256(compressed_pubkey)))`
/// - `AddressStyle::Evm`     : `bech32(hrp, keccak256(uncompressed_xy)[12..])`
/// - `AddressStyle::Solana`  : not applicable — returns an error.
pub fn derive_address(
    compressed: &[u8; 33],
    uncompressed: &[u8; 65],
    style: AddressStyle,
    hrp: &str,
) -> anyhow::Result<String> {
    let bytes: [u8; 20] = match style {
        AddressStyle::Cosmos => {
            let sha = Sha256::digest(compressed);
            let rip = Ripemd160::digest(&sha);
            let mut out = [0u8; 20];
            out.copy_from_slice(&rip);
            out
        }
        AddressStyle::Evm => {
            use sha3::Keccak256;
            let xy = &uncompressed[1..]; // strip 0x04
            let hash = Keccak256::digest(xy);
            let mut out = [0u8; 20];
            out.copy_from_slice(&hash[12..]);
            out
        }
        AddressStyle::Solana => {
            anyhow::bail!("solana style is not supported by derive_address");
        }
    };
    let hrp = bech32::Hrp::parse(hrp).map_err(|e| anyhow::anyhow!("bad hrp: {e}"))?;
    Ok(bech32::encode::<bech32::Bech32>(hrp, &bytes)
        .map_err(|e| anyhow::anyhow!("bech32 encode: {e}"))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmrs::proto::cosmos::{
        bank::v1beta1::MsgSend,
        base::v1beta1::Coin,
        tx::v1beta1::{
            AuthInfo as ProtoAuthInfoTest, SignDoc as ProtoSignDocTest, SignerInfo, TxBody,
        },
    };
    use k256::ecdsa::SigningKey;

    fn mk_key_and_pubkeys() -> (SigningKey, [u8; 33], [u8; 65]) {
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = sk.verifying_key();
        let enc = vk.to_encoded_point(false);
        let mut uncomp = [0u8; 65];
        uncomp.copy_from_slice(enc.as_bytes());
        let enc_c = vk.to_encoded_point(true);
        let mut comp = [0u8; 33];
        comp.copy_from_slice(enc_c.as_bytes());
        (sk, comp, uncomp)
    }

    fn encode_pubkey_proto(compressed: &[u8; 33], type_url: &str) -> cosmrs::Any {
        #[derive(Clone, PartialEq, ::prost::Message)]
        struct PubKeyBytes {
            #[prost(bytes = "vec", tag = "1")]
            pub key: Vec<u8>,
        }
        let mut buf = Vec::new();
        PubKeyBytes {
            key: compressed.to_vec(),
        }
        .encode(&mut buf)
        .unwrap();
        cosmrs::Any {
            type_url: type_url.to_string(),
            value: buf,
        }
    }

    fn build_sign_doc(comp_pubkey: &[u8; 33], chain_id: &str, to: &str) -> Vec<u8> {
        let body = TxBody {
            messages: vec![cosmrs::Any {
                type_url: MSG_SEND_TYPE_URL.into(),
                value: {
                    let mut b = Vec::new();
                    MsgSend {
                        from_address: "cosmos1me3cc".into(),
                        to_address: to.into(),
                        amount: vec![Coin {
                            denom: "uatom".into(),
                            amount: "12345".into(),
                        }],
                    }
                    .encode(&mut b)
                    .unwrap();
                    b
                },
            }],
            memo: "".into(),
            timeout_height: 0,
            extension_options: vec![],
            non_critical_extension_options: vec![],
        };
        let mut body_bytes = Vec::new();
        body.encode(&mut body_bytes).unwrap();

        let auth_info = ProtoAuthInfoTest {
            signer_infos: vec![SignerInfo {
                public_key: Some(encode_pubkey_proto(
                    comp_pubkey,
                    "/cosmos.crypto.secp256k1.PubKey",
                )),
                mode_info: None,
                sequence: 0,
            }],
            fee: None,
            ..Default::default()
        };
        let mut auth_info_bytes = Vec::new();
        auth_info.encode(&mut auth_info_bytes).unwrap();

        let sign_doc = ProtoSignDocTest {
            body_bytes,
            auth_info_bytes,
            chain_id: chain_id.to_string(),
            account_number: 0,
        };
        let mut doc_bytes = Vec::new();
        sign_doc.encode(&mut doc_bytes).unwrap();
        doc_bytes
    }

    #[test]
    fn decode_msg_send_and_check_chain_id() {
        let (_sk, comp, uncomp) = mk_key_and_pubkeys();
        let signer = CosmosSigner::with_fixed(comp, uncomp, "cosmos", AddressStyle::Cosmos);
        let doc = build_sign_doc(&comp, "cosmoshub-4", "cosmos1recipient");
        let req = SignRequest {
            label: "c".into(),
            payload: serde_json::json!({
                "sign_doc_b64": B64.encode(&doc),
                "expected_chain_id": "cosmoshub-4",
            }),
        };
        let key = KeyDef {
            label: "c".into(),
            chain: Chain::Cosmos,
            object_id: 1,
            derivation_path: None,
            address_style: AddressStyle::Cosmos,
            default_hrp: Some("cosmos".into()),
            policy: Default::default(),
        };
        let ctx = RequestContext {
            request_id: "r".into(),
            expected_chain_id: None,
        };
        let intent = signer.decode(&key, req, &ctx).expect("decode");
        assert_eq!(intent.chain_id(), "cosmoshub-4");
        assert_eq!(intent.message_types(), &[MSG_SEND_TYPE_URL.to_string()]);
        assert_eq!(intent.outgoing_transfers().len(), 1);
        assert_eq!(intent.outgoing_transfers()[0].amount, 12345u128);
        assert_eq!(intent.outgoing_transfers()[0].recipient, "cosmos1recipient");

        // Prehash matches sha256 of the exact sign_doc bytes the caller sent.
        assert_eq!(intent.signing_digest(), &doc[..]);
        assert_eq!(intent.prehash, <[u8; 32]>::from(Sha256::digest(&doc)));
    }

    #[test]
    fn chain_id_mismatch_is_rejected() {
        let (_sk, comp, uncomp) = mk_key_and_pubkeys();
        let signer = CosmosSigner::with_fixed(comp, uncomp, "cosmos", AddressStyle::Cosmos);
        let doc = build_sign_doc(&comp, "cosmoshub-4", "cosmos1recipient");
        let req = SignRequest {
            label: "c".into(),
            payload: serde_json::json!({
                "sign_doc_b64": B64.encode(&doc),
                "expected_chain_id": "osmosis-1",
            }),
        };
        let key = KeyDef {
            label: "c".into(),
            chain: Chain::Cosmos,
            object_id: 1,
            derivation_path: None,
            address_style: AddressStyle::Cosmos,
            default_hrp: Some("cosmos".into()),
            policy: Default::default(),
        };
        let ctx = RequestContext {
            request_id: "r".into(),
            expected_chain_id: None,
        };
        let err = signer.decode(&key, req, &ctx).unwrap_err().to_string();
        assert!(err.contains("chain_id"), "got {err}");
    }

    #[test]
    fn pubkey_mismatch_is_rejected() {
        let (_sk, comp, uncomp) = mk_key_and_pubkeys();
        let signer = CosmosSigner::with_fixed(comp, uncomp, "cosmos", AddressStyle::Cosmos);
        // Build a doc containing a different compressed pubkey:
        let wrong_sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        let wrong_comp: [u8; 33] = wrong_sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let doc = build_sign_doc(&wrong_comp, "cosmoshub-4", "cosmos1recipient");
        let req = SignRequest {
            label: "c".into(),
            payload: serde_json::json!({
                "sign_doc_b64": B64.encode(&doc),
                "expected_chain_id": "cosmoshub-4",
            }),
        };
        let key = KeyDef {
            label: "c".into(),
            chain: Chain::Cosmos,
            object_id: 1,
            derivation_path: None,
            address_style: AddressStyle::Cosmos,
            default_hrp: Some("cosmos".into()),
            policy: Default::default(),
        };
        let ctx = RequestContext {
            request_id: "r".into(),
            expected_chain_id: None,
        };
        let err = signer.decode(&key, req, &ctx).unwrap_err().to_string();
        assert!(err.contains("pubkey"), "got {err}");
    }

    #[test]
    fn cosmos_address_derivation_smoke() {
        let (_sk, comp, uncomp) = mk_key_and_pubkeys();
        let addr = derive_address(&comp, &uncomp, AddressStyle::Cosmos, "cosmos").unwrap();
        assert!(addr.starts_with("cosmos1"), "got {addr}");
        let addr = derive_address(&comp, &uncomp, AddressStyle::Cosmos, "osmo").unwrap();
        assert!(addr.starts_with("osmo1"), "got {addr}");
    }

    #[test]
    fn evm_style_address_smoke() {
        let (_sk, comp, uncomp) = mk_key_and_pubkeys();
        let addr = derive_address(&comp, &uncomp, AddressStyle::Evm, "inj").unwrap();
        assert!(addr.starts_with("inj1"), "got {addr}");
    }
}
