//! Live broadcast test: boot a local openKMS signer against `mockhsm`, sign a
//! real Cosmos SDK `MsgSend`, submit it through the chain REST API, and wait
//! for the transaction to appear on chain.
//!
//! Ignored by default. Opt in with:
//!
//! Prefer `./scripts/run_broadcast_e2e.sh cosmos` (see `docs/broadcast-e2e.md`).
//! Manual equivalent:
//!
//! ```text
//! set -a && source ./.tmp/broadcast-keys/broadcast-keys.env && set +a
//! OPENKMS_BROADCAST_TESTS=1 cargo test --test broadcast_cosmos_e2e -- --ignored --nocapture
//! ```
//!
//! With `./scripts/run_broadcast_e2e.sh cosmos`, REST/fee/chain id default from
//! chain-registry when unset (see `docs/broadcast-e2e.md`). Export
//! `OPENKMS_COSMOS_*` yourself only to override.
//!
//! If the spend denomination for `MsgSend` differs from the fee denom, set
//! `OPENKMS_COSMOS_AMOUNT_DENOM` (defaults to `OPENKMS_COSMOS_FEE_DENOM`).
//!
//! The signer address must **already exist on chain** (typically at least one
//! inbound transfer so auth state is created). An unfunded brand-new key shows
//! as HTTP 404 on `.../cosmos/auth/v1beta1/accounts/{addr}`.

mod common;

use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use cosmrs::proto::cosmos::{
    bank::v1beta1::MsgSend,
    base::v1beta1::Coin,
    crypto::secp256k1::PubKey as ProtoSecp256k1PubKey,
    tx::signing::v1beta1::SignMode,
    tx::v1beta1::{
        AuthInfo as ProtoAuthInfo, Fee, ModeInfo, SignDoc as ProtoSignDoc, SignerInfo, TxBody,
        TxRaw, mode_info, mode_info::Single,
    },
};
use k256::ecdsa::SigningKey;
use openkms::{chain::cosmos::derive_address, config::AddressStyle, hsm::Hsm};
use prost::Message;
use serde_json::{Value, json};

const SIGNER_OBJECT_ID: u16 = 0x0200;
const MSG_SEND_TYPE_URL: &str = "/cosmos.bank.v1beta1.MsgSend";
const PUBKEY_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";

struct BuildSignDocArgs<'a> {
    signer_compressed: &'a [u8; 33],
    chain_id: &'a str,
    from_addr: &'a str,
    to_addr: &'a str,
    amount: u64,
    amount_denom: &'a str,
    fee_amount: &'a str,
    fee_denom: &'a str,
    gas_limit: u64,
    account_number: u64,
    sequence: u64,
    memo: &'a str,
}

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

fn find_json_field<'a>(value: &'a Value, field: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map
            .get(field)
            .or_else(|| map.values().find_map(|child| find_json_field(child, field))),
        Value::Array(items) => items.iter().find_map(|child| find_json_field(child, field)),
        _ => None,
    }
}

fn parse_u64_field(value: &Value, field: &str) -> Result<u64> {
    let raw = find_json_field(value, field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))?;
    raw.parse()
        .with_context(|| format!("parse {field} value {raw:?} as u64"))
}

fn trim_rest_base(url: &str) -> &str {
    url.trim_end_matches('/')
}

async fn fetch_chain_id(rest_url: &str) -> Result<String> {
    let body: Value = reqwest::Client::new()
        .get(format!(
            "{}/cosmos/base/tendermint/v1beta1/node_info",
            trim_rest_base(rest_url)
        ))
        .send()
        .await
        .context("GET node_info")?
        .error_for_status()
        .context("node_info returned error status")?
        .json()
        .await
        .context("decode node_info JSON")?;
    body.get("default_node_info")
        .and_then(|v| v.get("network"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("node_info response missing default_node_info.network"))
}

async fn fetch_account_state(rest_url: &str, address: &str) -> Result<(u64, u64)> {
    let url = format!(
        "{}/cosmos/auth/v1beta1/accounts/{}",
        trim_rest_base(rest_url),
        address
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .context("GET account")?;
    let status = resp.status();
    let body_text = resp.text().await.context("read account response body")?;
    if !status.is_success() {
        let hint = if status == reqwest::StatusCode::NOT_FOUND {
            format!(
                "account {address} is not on chain yet — send it a small {hint_denom} transfer first so auth state exists (404 from LCD is normal for never-funded keys)",
                hint_denom = std::env::var("OPENKMS_COSMOS_FEE_DENOM")
                    .unwrap_or_else(|_| "fee token".into())
            )
        } else {
            format!("GET account returned HTTP {status}")
        };
        bail!("{hint}; url={url}; body={body_text}");
    }
    let body: Value = serde_json::from_str(&body_text).context("decode account JSON")?;
    Ok((
        parse_u64_field(&body, "account_number")?,
        parse_u64_field(&body, "sequence")?,
    ))
}

fn build_sign_doc(args: BuildSignDocArgs<'_>) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let BuildSignDocArgs {
        signer_compressed,
        chain_id,
        from_addr,
        to_addr,
        amount,
        amount_denom,
        fee_amount,
        fee_denom,
        gas_limit,
        account_number,
        sequence,
        memo,
    } = args;
    let mut send_bytes = Vec::new();
    MsgSend {
        from_address: from_addr.to_string(),
        to_address: to_addr.to_string(),
        amount: vec![Coin {
            denom: amount_denom.to_string(),
            amount: amount.to_string(),
        }],
    }
    .encode(&mut send_bytes)
    .expect("encode MsgSend");

    let body = TxBody {
        messages: vec![cosmrs::Any {
            type_url: MSG_SEND_TYPE_URL.to_string(),
            value: send_bytes,
        }],
        memo: memo.to_string(),
        timeout_height: 0,
        extension_options: vec![],
        non_critical_extension_options: vec![],
    };
    let mut body_bytes = Vec::new();
    body.encode(&mut body_bytes).expect("encode TxBody");

    let mut pubkey_bytes = Vec::new();
    ProtoSecp256k1PubKey {
        key: signer_compressed.to_vec(),
    }
    .encode(&mut pubkey_bytes)
    .expect("encode secp256k1 pubkey");

    let auth_info = ProtoAuthInfo {
        signer_infos: vec![SignerInfo {
            public_key: Some(cosmrs::Any {
                type_url: PUBKEY_TYPE_URL.to_string(),
                value: pubkey_bytes,
            }),
            mode_info: Some(ModeInfo {
                sum: Some(mode_info::Sum::Single(Single {
                    mode: SignMode::Direct as i32,
                })),
            }),
            sequence,
        }],
        fee: Some(Fee {
            amount: vec![Coin {
                denom: fee_denom.to_string(),
                amount: fee_amount.to_string(),
            }],
            gas_limit,
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
        body_bytes: body_bytes.clone(),
        auth_info_bytes: auth_info_bytes.clone(),
        chain_id: chain_id.to_string(),
        account_number,
    };
    let mut sign_doc_bytes = Vec::new();
    sign_doc
        .encode(&mut sign_doc_bytes)
        .expect("encode SignDoc");

    (body_bytes, auth_info_bytes, sign_doc_bytes)
}

async fn broadcast_tx(rest_url: &str, tx_bytes: &[u8]) -> Result<String> {
    let http = reqwest::Client::new()
        .post(format!(
            "{}/cosmos/tx/v1beta1/txs",
            trim_rest_base(rest_url)
        ))
        .json(&json!({
            "tx_bytes": B64.encode(tx_bytes),
            "mode": "BROADCAST_MODE_SYNC",
        }))
        .send()
        .await
        .context("POST broadcast tx")?;
    let http = common::http_success_or_panic(http, "POST /cosmos/tx/v1beta1/txs").await;
    let resp: Value = http.json().await.context("decode broadcast tx JSON")?;
    let tx_response = resp
        .get("tx_response")
        .ok_or_else(|| anyhow!("broadcast response missing tx_response"))?;
    let code = tx_response
        .get("code")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("broadcast response missing tx_response.code"))?;
    if code != 0 {
        bail!(
            "broadcast rejected with code {}: {}",
            code,
            tx_response
                .get("raw_log")
                .and_then(Value::as_str)
                .unwrap_or("<missing raw_log>")
        );
    }
    tx_response
        .get("txhash")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow!("broadcast response missing tx_response.txhash"))
}

async fn wait_for_tx(rest_url: &str, txhash: &str, timeout: Duration) -> Result<()> {
    let started = tokio::time::Instant::now();
    loop {
        let resp = reqwest::Client::new()
            .get(format!(
                "{}/cosmos/tx/v1beta1/txs/{}",
                trim_rest_base(rest_url),
                txhash
            ))
            .send()
            .await
            .context("GET tx by hash")?;
        if resp.status().is_success() {
            let body: Value = resp.json().await.context("decode tx lookup JSON")?;
            let tx_response = body
                .get("tx_response")
                .ok_or_else(|| anyhow!("tx lookup missing tx_response"))?;
            let code = tx_response
                .get("code")
                .and_then(Value::as_u64)
                .ok_or_else(|| anyhow!("tx lookup missing tx_response.code"))?;
            if code != 0 {
                bail!(
                    "transaction committed with code {}: {}",
                    code,
                    tx_response
                        .get("raw_log")
                        .and_then(Value::as_str)
                        .unwrap_or("<missing raw_log>")
                );
            }
            return Ok(());
        }
        if started.elapsed() > timeout {
            bail!("timed out waiting for Cosmos transaction {}", txhash);
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
#[ignore = "live broadcast test; set OPENKMS_BROADCAST_TESTS=1 to enable"]
async fn broadcasts_msg_send_through_local_signer() {
    if !common::broadcast_enabled() {
        eprintln!("skipping: OPENKMS_BROADCAST_TESTS not set");
        return;
    }

    let rest_url = common::require_env("OPENKMS_COSMOS_REST_URL");
    let signer_scalar = common::decode_b64_32("OPENKMS_COSMOS_SIGNER_SCALAR_B64");
    let hrp = std::env::var("OPENKMS_COSMOS_HRP").unwrap_or_else(|_| "cosmos".into());
    let fee_denom = common::require_env("OPENKMS_COSMOS_FEE_DENOM");
    let fee_amount = common::require_env("OPENKMS_COSMOS_FEE_AMOUNT");
    let amount_denom = std::env::var("OPENKMS_COSMOS_AMOUNT_DENOM").unwrap_or_else(|_| fee_denom.clone());
    let gas_limit = common::env_u64("OPENKMS_COSMOS_GAS_LIMIT", 200_000);
    let amount = common::env_u64("OPENKMS_COSMOS_TRANSFER_AMOUNT", 1);
    let confirm_timeout_secs = common::env_u64("OPENKMS_COSMOS_CONFIRM_TIMEOUT_SECS", 90);
    let chain_id = match std::env::var("OPENKMS_COSMOS_CHAIN_ID") {
        Ok(v) if !v.is_empty() => v,
        _ => fetch_chain_id(&rest_url).await.expect("discover chain_id"),
    };

    let (signer_comp, signer_uncomp) = secp_pubkeys(&signer_scalar);
    let signer_addr = derive_address(&signer_comp, &signer_uncomp, AddressStyle::Cosmos, &hrp)
        .expect("derive signer address");
    eprintln!(
        "broadcast_cosmos_e2e: rest_url={rest_url} signer={signer_addr} chain_id={chain_id} amount_denom={amount_denom}"
    );
    let recipient_scalar = [0x42u8; 32];
    let (recipient_comp, recipient_uncomp) = secp_pubkeys(&recipient_scalar);
    let recipient_addr = derive_address(
        &recipient_comp,
        &recipient_uncomp,
        AddressStyle::Cosmos,
        &hrp,
    )
    .expect("derive recipient address");
    let (account_number, sequence) = fetch_account_state(&rest_url, &signer_addr)
        .await
        .expect("query account state");

    let dir = common::tmp_dir("cosmos-broadcast");
    let audit = dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_secp256k1(&hsm, SIGNER_OBJECT_ID, "cosmos-broadcast", &signer_scalar).await;

    let key = common::cosmos_key_def("cosmos-broadcast", SIGNER_OBJECT_ID, &hrp);
    let cfg = common::base_config(dir, audit, vec![key]);
    let server = common::spawn(cfg, hsm).await;

    let memo = format!("openkms-broadcast-{}", uuid::Uuid::new_v4());
    let (body_bytes, auth_info_bytes, sign_doc) = build_sign_doc(BuildSignDocArgs {
        signer_compressed: &signer_comp,
        chain_id: &chain_id,
        from_addr: &signer_addr,
        to_addr: &recipient_addr,
        amount,
        amount_denom: &amount_denom,
        fee_amount: &fee_amount,
        fee_denom: &fee_denom,
        gas_limit,
        account_number,
        sequence,
        memo: &memo,
    });

    let sign_resp = reqwest::Client::new()
        .post(format!("{}/sign/cosmos", server.base))
        .bearer_auth(&server.signer_token)
        .json(&json!({
            "label": "cosmos-broadcast",
            "sign_doc_b64": B64.encode(&sign_doc),
            "expected_chain_id": chain_id,
        }))
        .send()
        .await
        .expect("POST /sign/cosmos");
    let sign_resp = common::http_success_or_panic(sign_resp, "POST /sign/cosmos").await;
    let response: Value = sign_resp
        .json()
        .await
        .expect("sign response JSON");
    let sig_b64 = response
        .get("signature_b64")
        .and_then(Value::as_str)
        .expect("signature_b64 in response");
    let signature = B64.decode(sig_b64).expect("decode compact signature");

    let mut tx_bytes = Vec::new();
    TxRaw {
        body_bytes,
        auth_info_bytes,
        signatures: vec![signature],
    }
    .encode(&mut tx_bytes)
    .expect("encode TxRaw");

    let txhash = broadcast_tx(&rest_url, &tx_bytes)
        .await
        .expect("broadcast Cosmos transaction");
    wait_for_tx(
        &rest_url,
        &txhash,
        Duration::from_secs(confirm_timeout_secs),
    )
    .await
    .expect("confirm Cosmos transaction");
}
