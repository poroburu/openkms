//! Integration test: sign a Solana devnet-shaped transaction end-to-end
//! through the openKMS HTTP server, then verify the returned Ed25519
//! signature against the HSM-derived public key.
//!
//! Sign-only — the test never broadcasts to the devnet RPC.

mod common;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey as Ed25519Vk};
use openkms::hsm::Hsm;
use solana_sdk::{
    hash::Hash,
    message::{Message as LegacyMessage, VersionedMessage},
    pubkey::Pubkey,
};
use solana_system_interface::instruction as system_instruction;

const SIGNER_SEED: [u8; 32] = [3u8; 32];
const SIGNER_OBJECT_ID: u16 = 0x0101;
const DEVNET_CHAIN_ID: &str = "devnet";

/// Compute the Ed25519 public-key bytes the YubiHSM2 (and mockhsm) will
/// derive when imported with `seed`. RFC-8032 keypair derivation matches
/// what `ed25519-dalek::SigningKey::from_bytes(seed).verifying_key()`
/// produces.
fn ed25519_pubkey_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let sk = ed25519_dalek::SigningKey::from_bytes(seed);
    sk.verifying_key().to_bytes()
}

/// Build a serialized legacy `VersionedMessage` containing one System Program
/// transfer instruction from `payer` to a fresh recipient.
fn build_transfer_message(payer: Pubkey, lamports: u64) -> (Pubkey, Vec<u8>) {
    let recipient = Pubkey::new_unique();
    let ix = system_instruction::transfer(&payer, &recipient, lamports);
    let msg = LegacyMessage::new_with_blockhash(&[ix], Some(&payer), &Hash::default());
    let vm = VersionedMessage::Legacy(msg);
    (recipient, vm.serialize())
}

/// Verify an Ed25519 signature against the message bytes the HSM signed.
fn verify_ed25519(pubkey: &[u8; 32], message: &[u8], sig_bytes: &[u8]) {
    assert_eq!(
        sig_bytes.len(),
        64,
        "ed25519 signature must be 64 bytes, got {}",
        sig_bytes.len()
    );
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let sig = Ed25519Sig::from_bytes(&sig_arr);
    let vk = Ed25519Vk::from_bytes(pubkey).expect("ed25519 verifying key");
    vk.verify(message, &sig)
        .expect("HSM signature verifies against the configured pubkey");
}

#[tokio::test]
async fn signs_devnet_system_transfer_end_to_end() {
    let dir = common::tmp_dir("solana-happy");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_ed25519(&hsm, SIGNER_OBJECT_ID, "sol-test", &SIGNER_SEED).await;

    let pubkey = ed25519_pubkey_from_seed(&SIGNER_SEED);
    let payer = Pubkey::from(pubkey);
    let (_recipient, raw_msg) = build_transfer_message(payer, 1_000_000);

    let key = common::solana_key_def("sol-test", SIGNER_OBJECT_ID);
    let cfg = common::base_config(dir, audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/sign/solana", server.base))
        .bearer_auth(&server.signer_token)
        .json(&serde_json::json!({
            "label": "sol-test",
            "message_b64": B64.encode(&raw_msg),
            "expected_chain_id": DEVNET_CHAIN_ID,
        }))
        .send()
        .await
        .expect("POST /sign/solana");
    assert_eq!(resp.status(), 200, "body: {}", resp.text().await.unwrap());

    let body: serde_json::Value = reqwest::Client::new()
        .post(format!("{}/sign/solana", server.base))
        .bearer_auth(&server.signer_token)
        .json(&serde_json::json!({
            "label": "sol-test",
            "message_b64": B64.encode(&raw_msg),
            "expected_chain_id": DEVNET_CHAIN_ID,
        }))
        .send()
        .await
        .expect("POST /sign/solana again")
        .json()
        .await
        .expect("response is JSON");
    let sig_b64 = body
        .get("signature_b64")
        .and_then(|v| v.as_str())
        .expect("signature_b64 in response");
    let sig_bytes = B64.decode(sig_b64).expect("base64-decode signature");
    verify_ed25519(&pubkey, &raw_msg, &sig_bytes);
}

#[tokio::test]
async fn wrong_signer_in_message_returns_400() {
    let dir = common::tmp_dir("solana-wrongsigner");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_ed25519(&hsm, SIGNER_OBJECT_ID, "sol-test", &SIGNER_SEED).await;

    // Build a transfer whose payer is *not* the HSM key.
    let other_payer = Pubkey::new_unique();
    let (_recipient, raw_msg) = build_transfer_message(other_payer, 1_000);

    let key = common::solana_key_def("sol-test", SIGNER_OBJECT_ID);
    let cfg = common::base_config(dir, audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    let resp = reqwest::Client::new()
        .post(format!("{}/sign/solana", server.base))
        .bearer_auth(&server.signer_token)
        .json(&serde_json::json!({
            "label": "sol-test",
            "message_b64": B64.encode(&raw_msg),
            "expected_chain_id": DEVNET_CHAIN_ID,
        }))
        .send()
        .await
        .expect("POST /sign/solana");
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("not among the first") || body.contains("required signers"),
        "expected 'not among the first ... required signers', got: {body}"
    );
}

#[tokio::test]
async fn oversized_message_returns_400() {
    let dir = common::tmp_dir("solana-oversized");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_ed25519(&hsm, SIGNER_OBJECT_ID, "sol-test", &SIGNER_SEED).await;

    let key = common::solana_key_def("sol-test", SIGNER_OBJECT_ID);
    let cfg = common::base_config(dir, audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    // 1233 bytes — one over Solana's packet limit.
    let oversized = vec![0u8; 1233];

    let resp = reqwest::Client::new()
        .post(format!("{}/sign/solana", server.base))
        .bearer_auth(&server.signer_token)
        .json(&serde_json::json!({
            "label": "sol-test",
            "message_b64": B64.encode(&oversized),
            "expected_chain_id": DEVNET_CHAIN_ID,
        }))
        .send()
        .await
        .expect("POST /sign/solana");
    assert_eq!(resp.status(), 400);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("packet limit"),
        "expected 'packet limit' error, got: {body}"
    );
}

#[tokio::test]
async fn replay_returns_cached_signature() {
    let dir = common::tmp_dir("solana-replay");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_ed25519(&hsm, SIGNER_OBJECT_ID, "sol-test", &SIGNER_SEED).await;

    let pubkey = ed25519_pubkey_from_seed(&SIGNER_SEED);
    let payer = Pubkey::from(pubkey);
    let (_recipient, raw_msg) = build_transfer_message(payer, 42_000);

    let key = common::solana_key_def("sol-test", SIGNER_OBJECT_ID);
    let cfg = common::base_config(dir, audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    let request_body = serde_json::json!({
        "label": "sol-test",
        "message_b64": B64.encode(&raw_msg),
        "expected_chain_id": DEVNET_CHAIN_ID,
    });
    let client = reqwest::Client::new();
    let first: serde_json::Value = client
        .post(format!("{}/sign/solana", server.base))
        .bearer_auth(&server.signer_token)
        .json(&request_body)
        .send()
        .await
        .expect("first POST")
        .json()
        .await
        .expect("first JSON");
    let second: serde_json::Value = client
        .post(format!("{}/sign/solana", server.base))
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
