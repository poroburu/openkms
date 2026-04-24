//! Live broadcast test: boot a local openKMS signer against `mockhsm`, sign a
//! real Solana devnet transfer, broadcast it over JSON-RPC, and wait for
//! confirmation.
//!
//! Ignored by default. Opt in with:
//!
//! Prefer `./scripts/run_broadcast_e2e.sh solana` (see `docs/broadcast-e2e.md`).
//! Manual equivalent:
//!
//! ```text
//! set -a && source ./.tmp/broadcast-keys/broadcast-keys.env && set +a
//! export OPENKMS_SOLANA_RPC_URL="https://api.devnet.solana.com"
//! OPENKMS_BROADCAST_TESTS=1 cargo test --test broadcast_solana_e2e -- --ignored --nocapture
//! ```
//!
//! Optional: `OPENKMS_SOLANA_CHAIN_ID` (default `devnet`) must match the cluster
//! you use with `OPENKMS_SOLANA_RPC_URL`.
//!
//! Fund the signer on the target cluster before running; the test does not
//! obtain SOL automatically. See `docs/broadcast-e2e.md`.

mod common;

use std::{str::FromStr, time::Duration};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::SigningKey;
use openkms::hsm::Hsm;
use serde_json::{Value, json};
use solana_sdk::{
    hash::Hash,
    message::{Message as LegacyMessage, VersionedMessage},
    pubkey::Pubkey,
    signature::Signature as SolanaSignature,
    transaction::VersionedTransaction,
};
use solana_system_interface::instruction as system_instruction;

const SIGNER_OBJECT_ID: u16 = 0x0201;

fn signer_pubkey_from_seed(seed: &[u8; 32]) -> Pubkey {
    let sk = SigningKey::from_bytes(seed);
    Pubkey::from(sk.verifying_key().to_bytes())
}

async fn rpc_call(rpc_url: &str, method: &str, params: Value) -> Result<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp: Value = reqwest::Client::new()
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {method}"))?
        .error_for_status()
        .with_context(|| format!("{method} returned error status"))?
        .json()
        .await
        .with_context(|| format!("decode JSON for {method}"))?;
    if let Some(err) = resp.get("error") {
        bail!("{method} RPC error: {err}");
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("{method} missing result field"))
}

async fn latest_blockhash(rpc_url: &str) -> Result<Hash> {
    let result = rpc_call(
        rpc_url,
        "getLatestBlockhash",
        json!([{ "commitment": "confirmed" }]),
    )
    .await?;
    let blockhash = result
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("getLatestBlockhash missing value.blockhash"))?;
    Hash::from_str(blockhash).context("parse latest blockhash")
}

async fn get_balance(rpc_url: &str, pubkey: &Pubkey) -> Result<u64> {
    let result = rpc_call(rpc_url, "getBalance", json!([pubkey.to_string()])).await?;
    result
        .get("value")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("getBalance missing value"))
}

async fn send_transaction(rpc_url: &str, tx_bytes: &[u8]) -> Result<String> {
    let result = rpc_call(
        rpc_url,
        "sendTransaction",
        json!([
            B64.encode(tx_bytes),
            {
                "encoding": "base64",
                "preflightCommitment": "confirmed",
                "maxRetries": 3
            }
        ]),
    )
    .await?;
    result
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("sendTransaction missing signature string"))
}

async fn wait_for_confirmation(rpc_url: &str, signature: &str, timeout: Duration) -> Result<()> {
    let started = tokio::time::Instant::now();
    loop {
        let result = rpc_call(
            rpc_url,
            "getSignatureStatuses",
            json!([[signature], { "searchTransactionHistory": true }]),
        )
        .await?;
        let status = result
            .get("value")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .cloned()
            .unwrap_or(Value::Null);
        if let Some(status_obj) = status.as_object() {
            if !status_obj.get("err").unwrap_or(&Value::Null).is_null() {
                bail!("transaction failed on chain: {}", status_obj["err"]);
            }
            let confirmed = status_obj
                .get("confirmationStatus")
                .and_then(Value::as_str)
                .is_some_and(|s| matches!(s, "confirmed" | "finalized"));
            if confirmed {
                return Ok(());
            }
        }
        if started.elapsed() > timeout {
            bail!("timed out waiting for Solana confirmation");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
#[ignore = "live broadcast test; set OPENKMS_BROADCAST_TESTS=1 to enable"]
async fn broadcasts_devnet_transfer_through_local_signer() {
    if !common::broadcast_enabled() {
        eprintln!("skipping: OPENKMS_BROADCAST_TESTS not set");
        return;
    }

    let rpc_url = common::require_env("OPENKMS_SOLANA_RPC_URL");
    let signer_seed = common::decode_b64_32("OPENKMS_SOLANA_SIGNER_SEED_B64");
    let chain_id = common::solana_sign_chain_id();
    let lamports = common::env_u64("OPENKMS_SOLANA_TRANSFER_LAMPORTS", 5_000);
    let fee_reserve = common::env_u64("OPENKMS_SOLANA_FEE_RESERVE_LAMPORTS", 50_000);
    let confirm_timeout_secs = common::env_u64("OPENKMS_SOLANA_CONFIRM_TIMEOUT_SECS", 90);

    let signer_pubkey = signer_pubkey_from_seed(&signer_seed);
    eprintln!(
        "broadcast_solana_e2e: rpc_url={rpc_url} signer={signer_pubkey} expected_chain_id={chain_id}"
    );
    let recipient = Pubkey::new_unique();
    let min_balance = lamports.saturating_add(fee_reserve);
    let balance = get_balance(&rpc_url, &signer_pubkey)
        .await
        .expect("query signer balance");
    assert!(
        balance > min_balance,
        "signer balance {balance} lamports is at or below the required {min_balance} (transfer {lamports} + fee reserve {fee_reserve}); fund {signer_pubkey} on cluster {chain_id} (see docs/broadcast-e2e.md)"
    );
    eprintln!("broadcast_solana_e2e: signer balance ok: {balance} lamports (need > {min_balance})");

    let dir = common::tmp_dir("solana-broadcast");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_ed25519(&hsm, SIGNER_OBJECT_ID, "sol-broadcast", &signer_seed).await;

    let key = common::solana_key_def("sol-broadcast", SIGNER_OBJECT_ID);
    let cfg = common::base_config(dir, audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    let blockhash = latest_blockhash(&rpc_url)
        .await
        .expect("fetch recent blockhash");
    let ix = system_instruction::transfer(&signer_pubkey, &recipient, lamports);
    let message = LegacyMessage::new_with_blockhash(&[ix], Some(&signer_pubkey), &blockhash);
    let versioned = VersionedMessage::Legacy(message);
    let raw_message = versioned.serialize();

    let sign_resp = reqwest::Client::new()
        .post(format!("{}/sign/solana", server.base))
        .bearer_auth(&server.signer_token)
        .json(&json!({
            "label": "sol-broadcast",
            "message_b64": B64.encode(&raw_message),
            "expected_chain_id": chain_id,
        }))
        .send()
        .await
        .expect("POST /sign/solana");
    let sign_resp = common::http_success_or_panic(sign_resp, "POST /sign/solana").await;
    let response: Value = sign_resp.json().await.expect("sign response JSON");

    let sig_b64 = response
        .get("signature_b64")
        .and_then(Value::as_str)
        .expect("signature_b64 in response");
    let sig_bytes = B64.decode(sig_b64).expect("decode returned signature");
    let signature = SolanaSignature::try_from(sig_bytes.as_slice()).expect("parse signature bytes");

    let tx = VersionedTransaction {
        signatures: vec![signature],
        message: versioned,
    };
    let tx_bytes = bincode::serialize(&tx).expect("serialize versioned transaction");

    let tx_sig = send_transaction(&rpc_url, &tx_bytes)
        .await
        .expect("broadcast transaction");
    assert_eq!(
        tx_sig,
        signature.to_string(),
        "RPC echoed unexpected signature"
    );

    wait_for_confirmation(&rpc_url, &tx_sig, Duration::from_secs(confirm_timeout_secs))
        .await
        .expect("confirm broadcast transaction");
}
