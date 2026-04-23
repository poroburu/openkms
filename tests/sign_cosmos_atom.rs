//! Integration test: sign a Cosmos `provider`-chain transaction (ATOM ICS
//! testnet) end-to-end through the openKMS HTTP server, then verify the
//! returned compact secp256k1 signature against the HSM-derived public key.
//!
//! Sign-only — the test never broadcasts the resulting transaction.

mod common;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use cosmrs::proto::cosmos::{
    bank::v1beta1::MsgSend,
    base::v1beta1::Coin,
    tx::v1beta1::{AuthInfo as ProtoAuthInfo, Fee, SignDoc as ProtoSignDoc, SignerInfo, TxBody},
};
use k256::ecdsa::{
    Signature as K256Sig, SigningKey, VerifyingKey, signature::hazmat::PrehashVerifier,
};
use openkms::{chain::cosmos::derive_address, config::AddressStyle, hsm::Hsm};
use prost::Message;
use sha2::{Digest, Sha256};

const SIGNER_SCALAR: [u8; 32] = [7u8; 32];
const RECIPIENT_SCALAR: [u8; 32] = [0x42u8; 32];
const SIGNER_OBJECT_ID: u16 = 0x0100;
const ATOM_DENOM: &str = "uatom";
const PROVIDER_CHAIN_ID: &str = "provider";
const COSMOS_HRP: &str = "cosmos";
const PUBKEY_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";
const MSG_SEND_TYPE_URL: &str = "/cosmos.bank.v1beta1.MsgSend";

/// Compute the (compressed, uncompressed) SEC1 form of a secp256k1 public key
/// derived from a 32-byte scalar.
fn secp_pubkeys(scalar: &[u8; 32]) -> ([u8; 33], [u8; 65]) {
    let sk = SigningKey::from_slice(scalar).expect("valid secp256k1 scalar");
    let vk = sk.verifying_key();
    let comp_point = vk.to_encoded_point(true);
    let uncomp_point = vk.to_encoded_point(false);
    let mut comp = [0u8; 33];
    let mut uncomp = [0u8; 65];
    comp.copy_from_slice(comp_point.as_bytes());
    uncomp.copy_from_slice(uncomp_point.as_bytes());
    (comp, uncomp)
}

/// Encode a Cosmos `PubKey { bytes key = 1 }` proto for any of the accepted
/// pubkey type URLs (the wire format is identical across them).
fn encode_pubkey_any(compressed: &[u8; 33], type_url: &str) -> cosmrs::Any {
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
    .expect("encode PubKey");
    cosmrs::Any {
        type_url: type_url.to_string(),
        value: buf,
    }
}

/// Build a realistic, well-formed `SignDoc` for chain_id `provider` paying
/// `amount` uatom from `from_addr` to `to_addr`. Returns the encoded bytes.
fn build_sign_doc(
    signer_compressed: &[u8; 33],
    pubkey_type_url: &str,
    chain_id: &str,
    from_addr: &str,
    to_addr: &str,
    amount_uatom: u64,
) -> Vec<u8> {
    let mut send_bytes = Vec::new();
    MsgSend {
        from_address: from_addr.to_string(),
        to_address: to_addr.to_string(),
        amount: vec![Coin {
            denom: ATOM_DENOM.to_string(),
            amount: amount_uatom.to_string(),
        }],
    }
    .encode(&mut send_bytes)
    .expect("encode MsgSend");

    let body = TxBody {
        messages: vec![cosmrs::Any {
            type_url: MSG_SEND_TYPE_URL.to_string(),
            value: send_bytes,
        }],
        memo: "openkms integration test".to_string(),
        timeout_height: 0,
        extension_options: vec![],
        non_critical_extension_options: vec![],
    };
    let mut body_bytes = Vec::new();
    body.encode(&mut body_bytes).expect("encode TxBody");

    let auth_info = ProtoAuthInfo {
        signer_infos: vec![SignerInfo {
            public_key: Some(encode_pubkey_any(signer_compressed, pubkey_type_url)),
            // `mode_info: None` is accepted by the openkms decoder; the cosmos
            // sdk would normally encode SIGN_MODE_DIRECT here. Either way the
            // bytes are part of `auth_info_bytes` and therefore the signature.
            mode_info: None,
            sequence: 0,
        }],
        fee: Some(Fee {
            amount: vec![Coin {
                denom: ATOM_DENOM.to_string(),
                amount: "2000".to_string(),
            }],
            gas_limit: 200_000,
            payer: String::new(),
            granter: String::new(),
        }),
        ..Default::default()
    };
    let mut auth_info_bytes = Vec::new();
    auth_info
        .encode(&mut auth_info_bytes)
        .expect("encode AuthInfo");

    let sign_doc = ProtoSignDoc {
        body_bytes,
        auth_info_bytes,
        chain_id: chain_id.to_string(),
        account_number: 0,
    };
    let mut out = Vec::new();
    sign_doc.encode(&mut out).expect("encode SignDoc");
    out
}

/// Verify a 64-byte compact secp256k1 signature against the given prehash.
fn verify_compact_sig(compressed_pubkey: &[u8; 33], prehash: &[u8; 32], sig_bytes: &[u8]) {
    assert_eq!(
        sig_bytes.len(),
        64,
        "compact signature must be 64 bytes, got {}",
        sig_bytes.len()
    );
    let sig = K256Sig::from_slice(sig_bytes).expect("compact signature parse");
    assert!(
        sig.normalize_s().is_none(),
        "signature is not low-s normalized"
    );
    let vk = VerifyingKey::from_sec1_bytes(compressed_pubkey).expect("verifying key");
    vk.verify_prehash(prehash, &sig)
        .expect("HSM signature verifies against the configured pubkey");
}

#[tokio::test]
async fn signs_provider_chain_msg_send_end_to_end() {
    // 1) Provision the deterministic signing key into the mock HSM.
    let dir = common::tmp_dir("cosmos-happy");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_secp256k1(&hsm, SIGNER_OBJECT_ID, "atom-test", &SIGNER_SCALAR).await;

    let (signer_comp, signer_uncomp) = secp_pubkeys(&SIGNER_SCALAR);
    let signer_addr = derive_address(
        &signer_comp,
        &signer_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .expect("derive signer address");
    let (recipient_comp, recipient_uncomp) = secp_pubkeys(&RECIPIENT_SCALAR);
    let recipient_addr = derive_address(
        &recipient_comp,
        &recipient_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .expect("derive recipient address");

    let key = common::cosmos_key_def("atom-test", SIGNER_OBJECT_ID, COSMOS_HRP);
    let cfg = common::base_config(dir.clone(), audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    // 2) Build a real SignDoc against `provider`.
    let sign_doc = build_sign_doc(
        &signer_comp,
        PUBKEY_TYPE_URL,
        PROVIDER_CHAIN_ID,
        &signer_addr,
        &recipient_addr,
        125_000,
    );
    let prehash: [u8; 32] = Sha256::digest(&sign_doc).into();

    // 3) Submit through /sign/cosmos.
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/sign/cosmos", server.base))
        .bearer_auth(&server.signer_token)
        .json(&serde_json::json!({
            "label": "atom-test",
            "sign_doc_b64": B64.encode(&sign_doc),
            "expected_chain_id": PROVIDER_CHAIN_ID,
        }))
        .send()
        .await
        .expect("POST /sign/cosmos");
    assert_eq!(resp.status(), 200, "body: {}", resp.text().await.unwrap());
    let body: serde_json::Value = client
        .post(format!("{}/sign/cosmos", server.base))
        .bearer_auth(&server.signer_token)
        .json(&serde_json::json!({
            "label": "atom-test",
            "sign_doc_b64": B64.encode(&sign_doc),
            "expected_chain_id": PROVIDER_CHAIN_ID,
        }))
        .send()
        .await
        .expect("POST /sign/cosmos again")
        .json()
        .await
        .expect("response is JSON");
    let sig_b64 = body
        .get("signature_b64")
        .and_then(|v| v.as_str())
        .expect("signature_b64 in response");
    let sig_bytes = B64.decode(sig_b64).expect("base64-decode signature");

    // 4) Verify the signature against the prehash + HSM pubkey.
    verify_compact_sig(&signer_comp, &prehash, &sig_bytes);
}

#[tokio::test]
async fn chain_id_mismatch_returns_400() {
    let dir = common::tmp_dir("cosmos-chainid");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_secp256k1(&hsm, SIGNER_OBJECT_ID, "atom-test", &SIGNER_SCALAR).await;

    let (signer_comp, signer_uncomp) = secp_pubkeys(&SIGNER_SCALAR);
    let signer_addr = derive_address(
        &signer_comp,
        &signer_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .unwrap();
    let (recipient_comp, recipient_uncomp) = secp_pubkeys(&RECIPIENT_SCALAR);
    let recipient_addr = derive_address(
        &recipient_comp,
        &recipient_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .unwrap();
    let key = common::cosmos_key_def("atom-test", SIGNER_OBJECT_ID, COSMOS_HRP);
    let cfg = common::base_config(dir, audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    let sign_doc = build_sign_doc(
        &signer_comp,
        PUBKEY_TYPE_URL,
        PROVIDER_CHAIN_ID,
        &signer_addr,
        &recipient_addr,
        1,
    );
    let resp = reqwest::Client::new()
        .post(format!("{}/sign/cosmos", server.base))
        .bearer_auth(&server.signer_token)
        .json(&serde_json::json!({
            "label": "atom-test",
            "sign_doc_b64": B64.encode(&sign_doc),
            "expected_chain_id": "cosmoshub-4",
        }))
        .send()
        .await
        .expect("POST /sign/cosmos");
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("chain_id"),
        "expected chain_id error in body, got: {body}"
    );
}

#[tokio::test]
async fn wrong_pubkey_in_authinfo_returns_400() {
    let dir = common::tmp_dir("cosmos-pubkey");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_secp256k1(&hsm, SIGNER_OBJECT_ID, "atom-test", &SIGNER_SCALAR).await;

    let (signer_comp, signer_uncomp) = secp_pubkeys(&SIGNER_SCALAR);
    let signer_addr = derive_address(
        &signer_comp,
        &signer_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .unwrap();
    let (other_comp, _) = secp_pubkeys(&[0x9au8; 32]);
    let (recipient_comp, recipient_uncomp) = secp_pubkeys(&RECIPIENT_SCALAR);
    let recipient_addr = derive_address(
        &recipient_comp,
        &recipient_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .unwrap();
    let key = common::cosmos_key_def("atom-test", SIGNER_OBJECT_ID, COSMOS_HRP);
    let cfg = common::base_config(dir, audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    // Build a SignDoc whose AuthInfo carries a *different* compressed pubkey.
    let sign_doc = build_sign_doc(
        &other_comp,
        PUBKEY_TYPE_URL,
        PROVIDER_CHAIN_ID,
        &signer_addr,
        &recipient_addr,
        1,
    );
    let resp = reqwest::Client::new()
        .post(format!("{}/sign/cosmos", server.base))
        .bearer_auth(&server.signer_token)
        .json(&serde_json::json!({
            "label": "atom-test",
            "sign_doc_b64": B64.encode(&sign_doc),
            "expected_chain_id": PROVIDER_CHAIN_ID,
        }))
        .send()
        .await
        .expect("POST /sign/cosmos");
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("pubkey"),
        "expected pubkey error in body, got: {body}"
    );
}

#[tokio::test]
async fn replay_returns_cached_signature() {
    let dir = common::tmp_dir("cosmos-replay");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_secp256k1(&hsm, SIGNER_OBJECT_ID, "atom-test", &SIGNER_SCALAR).await;

    let (signer_comp, signer_uncomp) = secp_pubkeys(&SIGNER_SCALAR);
    let signer_addr = derive_address(
        &signer_comp,
        &signer_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .unwrap();
    let (recipient_comp, recipient_uncomp) = secp_pubkeys(&RECIPIENT_SCALAR);
    let recipient_addr = derive_address(
        &recipient_comp,
        &recipient_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .unwrap();
    let key = common::cosmos_key_def("atom-test", SIGNER_OBJECT_ID, COSMOS_HRP);
    let cfg = common::base_config(dir, audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    let sign_doc = build_sign_doc(
        &signer_comp,
        PUBKEY_TYPE_URL,
        PROVIDER_CHAIN_ID,
        &signer_addr,
        &recipient_addr,
        7,
    );
    let request_body = serde_json::json!({
        "label": "atom-test",
        "sign_doc_b64": B64.encode(&sign_doc),
        "expected_chain_id": PROVIDER_CHAIN_ID,
    });
    let client = reqwest::Client::new();
    let first: serde_json::Value = client
        .post(format!("{}/sign/cosmos", server.base))
        .bearer_auth(&server.signer_token)
        .json(&request_body)
        .send()
        .await
        .expect("first POST")
        .json()
        .await
        .expect("first JSON");
    let second: serde_json::Value = client
        .post(format!("{}/sign/cosmos", server.base))
        .bearer_auth(&server.signer_token)
        .json(&request_body)
        .send()
        .await
        .expect("second POST")
        .json()
        .await
        .expect("second JSON");
    assert_eq!(
        first, second,
        "replay cache should return byte-identical body"
    );
}
