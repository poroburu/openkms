//! Regression: `scripts/run_remote_e2e_job.sh` must stay aligned with a live mock
//! HTTP signer (same path operators and `remote-e2e.yml` use).

mod common;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use cosmrs::proto::cosmos::{
    bank::v1beta1::MsgSend,
    base::v1beta1::Coin,
    tx::v1beta1::{AuthInfo as ProtoAuthInfo, Fee, SignDoc as ProtoSignDoc, SignerInfo, TxBody},
};
use k256::ecdsa::SigningKey;
use openkms::{
    chain::cosmos::derive_address,
    config::AddressStyle,
    hsm::{Hsm, hsm_types as H},
};
use prost::Message;
use solana_sdk::{
    hash::Hash,
    message::{Message as LegacyMessage, VersionedMessage},
    pubkey::Pubkey,
};
use solana_system_interface::instruction as system_instruction;
use std::process::Command;
use std::str::FromStr;
use tempfile::TempDir;

const LABEL: &str = "solana-hot-0";
const OBJECT_ID: u16 = 0x0101;

fn build_transfer_message(payer: [u8; 32], lamports: u64) -> Vec<u8> {
    let payer = Pubkey::new_from_array(payer);
    let to = Pubkey::new_unique();
    let ix = system_instruction::transfer(&payer, &to, lamports);
    let msg = LegacyMessage::new_with_blockhash(&[ix], Some(&payer), &Hash::default());
    VersionedMessage::Legacy(msg).serialize()
}

async fn provision_mock_solana_key(hsm: &Hsm, label: &str, object_id: u16) -> [u8; 32] {
    let client = hsm.client();
    let guard = client.lock().await;
    guard
        .generate_asymmetric_key(
            object_id,
            H::ObjectLabel::from_str(label).unwrap(),
            H::Domain::DOM1,
            H::Capability::SIGN_EDDSA | H::Capability::EXPORTABLE_UNDER_WRAP,
            H::AsymmetricAlg::Ed25519,
        )
        .expect("generate mock solana key");
    drop(guard);
    hsm.get_ed25519_pubkey(object_id)
        .await
        .expect("read mock pubkey")
}

async fn wait_health(base: &str) {
    let client = reqwest::Client::new();
    for _ in 0..80 {
        if client
            .get(format!("{base}/health"))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!("server at {base} did not become ready");
}

// Run only in the dedicated CI job: `cargo test --test remote_e2e_job_shell -- --ignored`
// so `cargo test --all-targets` logs stay focused on unit/integration tests.
#[tokio::test]
#[ignore = "CI job remote-e2e-job-shell (cargo test --test remote_e2e_job_shell -- --ignored)"]
async fn run_remote_e2e_job_script_solana_smoke() {
    let state_dir = TempDir::new().expect("tempdir");
    let audit = state_dir.path().join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    let payer = provision_mock_solana_key(&hsm, LABEL, OBJECT_ID).await;
    let cfg = common::base_config(
        state_dir.path().to_path_buf(),
        audit.clone(),
        vec![common::solana_key_def(LABEL, OBJECT_ID)],
    );
    let srv = common::spawn(cfg, hsm).await;
    wait_health(&srv.base).await;

    let message = build_transfer_message(payer, 1_000);
    let body = serde_json::json!({
        "label": LABEL,
        "message_b64": B64.encode(&message),
        "expected_chain_id": "devnet",
    });
    let compact = serde_json::to_string(&body).expect("serialize sign json");
    let req_b64 = B64.encode(compact.as_bytes());

    let repo = env!("CARGO_MANIFEST_DIR").to_string();
    let script = format!("{repo}/scripts/run_remote_e2e_job.sh");
    let base = srv.base.clone();
    let token = srv.signer_token.clone();
    let out = tokio::task::spawn_blocking(move || {
        Command::new("bash")
            .arg(&script)
            .arg("solana")
            .current_dir(&repo)
            .env("OPENKMS_BASE_URL", &base)
            .env("OPENKMS_SIGNER_TOKEN", &token)
            .env("OPENKMS_SIGN_REQUEST_B64", req_b64)
            .env("OPENKMS_EXPECT_KEY_LABEL", LABEL)
            .output()
            .expect("spawn run_remote_e2e_job.sh")
    })
    .await
    .expect("spawn_blocking join");

    assert!(
        out.status.success(),
        "run_remote_e2e_job.sh failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

const COSMOS_LABEL: &str = "cosmos-hub-0";
const COSMOS_OBJECT_ID: u16 = 0x0202;
const COSMOS_SIGNER_SCALAR: [u8; 32] = [7u8; 32];
const COSMOS_RECIPIENT_SCALAR: [u8; 32] = [0x42u8; 32];
const COSMOS_HRP: &str = "cosmos";
const COSMOS_CHAIN_ID: &str = "provider";
const ATOM_DENOM: &str = "uatom";
const PUBKEY_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";
const MSG_SEND_TYPE_URL: &str = "/cosmos.bank.v1beta1.MsgSend";

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

fn build_cosmos_sign_doc(
    signer_compressed: &[u8; 33],
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
        memo: "openkms remote_e2e_job_shell cosmos".to_string(),
        timeout_height: 0,
        extension_options: vec![],
        non_critical_extension_options: vec![],
    };
    let mut body_bytes = Vec::new();
    body.encode(&mut body_bytes).expect("encode TxBody");

    let auth_info = ProtoAuthInfo {
        signer_infos: vec![SignerInfo {
            public_key: Some(encode_pubkey_any(signer_compressed, PUBKEY_TYPE_URL)),
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
        chain_id: COSMOS_CHAIN_ID.to_string(),
        account_number: 0,
    };
    let mut out = Vec::new();
    sign_doc.encode(&mut out).expect("encode SignDoc");
    out
}

// Run only in the dedicated CI job: `cargo test --test remote_e2e_job_shell -- --ignored`
#[tokio::test]
#[ignore = "CI job remote-e2e-job-shell (cargo test --test remote_e2e_job_shell -- --ignored)"]
async fn run_remote_e2e_job_script_cosmos_smoke() {
    let state_dir = TempDir::new().expect("tempdir");
    let audit = state_dir.path().join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    common::provision_secp256k1(&hsm, COSMOS_OBJECT_ID, COSMOS_LABEL, &COSMOS_SIGNER_SCALAR).await;

    let (signer_comp, signer_uncomp) = secp_pubkeys(&COSMOS_SIGNER_SCALAR);
    let signer_addr = derive_address(
        &signer_comp,
        &signer_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .expect("derive signer address");
    let (recipient_comp, recipient_uncomp) = secp_pubkeys(&COSMOS_RECIPIENT_SCALAR);
    let recipient_addr = derive_address(
        &recipient_comp,
        &recipient_uncomp,
        AddressStyle::Cosmos,
        COSMOS_HRP,
    )
    .expect("derive recipient address");

    let cfg = common::base_config(
        state_dir.path().to_path_buf(),
        audit.clone(),
        vec![common::cosmos_key_def(
            COSMOS_LABEL,
            COSMOS_OBJECT_ID,
            COSMOS_HRP,
        )],
    );
    let srv = common::spawn(cfg, hsm).await;
    wait_health(&srv.base).await;

    let sign_doc = build_cosmos_sign_doc(&signer_comp, &signer_addr, &recipient_addr, 125_000);
    let body = serde_json::json!({
        "label": COSMOS_LABEL,
        "sign_doc_b64": B64.encode(&sign_doc),
        "expected_chain_id": COSMOS_CHAIN_ID,
    });
    let compact = serde_json::to_string(&body).expect("serialize sign json");
    let req_b64 = B64.encode(compact.as_bytes());

    let repo = env!("CARGO_MANIFEST_DIR").to_string();
    let script = format!("{repo}/scripts/run_remote_e2e_job.sh");
    let base = srv.base.clone();
    let token = srv.signer_token.clone();
    let out = tokio::task::spawn_blocking(move || {
        Command::new("bash")
            .arg(&script)
            .arg("cosmos")
            .current_dir(&repo)
            .env("OPENKMS_BASE_URL", &base)
            .env("OPENKMS_SIGNER_TOKEN", &token)
            .env("OPENKMS_SIGN_REQUEST_B64", req_b64)
            .env("OPENKMS_EXPECT_KEY_LABEL", COSMOS_LABEL)
            .output()
            .expect("spawn run_remote_e2e_job.sh")
    })
    .await
    .expect("spawn_blocking join");

    assert!(
        out.status.success(),
        "run_remote_e2e_job.sh cosmos failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}
