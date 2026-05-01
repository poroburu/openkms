//! Regression: `scripts/run_remote_e2e_job.sh` must stay aligned with a live mock
//! HTTP signer (same path operators and `remote-e2e.yml` use).

mod common;

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use openkms::hsm::{Hsm, hsm_types as H};
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
