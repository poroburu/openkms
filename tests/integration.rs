//! Integration tests that bring up the full `openkms` HTTP server on an
//! ephemeral TCP port backed by `yubihsm::Connector::mockhsm`.
//!
//! These tests intentionally cross a real socket with `reqwest` so they catch
//! listener, routing, auth, and serialization regressions that `Router::oneshot`
//! would miss.

use std::{path::Path, str::FromStr, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use openkms::{
    config::{
        AddressStyle, AllowedProgram, AuditConfig, Config, CosmosConfig, HsmConfig, KeyDef,
        KeyPolicy, ServerConfig,
    },
    hsm::{Hsm, hsm_types as H},
    server::{AppState, router},
};
use reqwest::Client;
use solana_sdk::{
    hash::Hash,
    message::{Message as LegacyMessage, VersionedMessage},
    pubkey::Pubkey,
};
use solana_system_interface::instruction as system_instruction;
use tempfile::TempDir;
use tokio::{net::TcpListener, task::JoinHandle, time::sleep};

const SIGNER_TOKEN: &str = "signer-token";
const ADMIN_TOKEN: &str = "admin-token";
const SOLANA_LABEL: &str = "solana-hot-0";
const SOLANA_OBJECT_ID: u16 = 0x0101;

fn base_config(state_dir: &Path, audit_path: &Path, listen: &str, keys: Vec<KeyDef>) -> Config {
    Config {
        server: ServerConfig {
            listen: listen.into(),
            signer_token_file: "/tmp/unused".into(),
            admin_token_file: "/tmp/unused".into(),
            inflight_limit: 1,
            replay_window_secs: 1,
        },
        hsm: HsmConfig {
            connector_url: "mock".into(),
            auth_key_id: 1,
            password_file: "/tmp/unused".into(),
        },
        audit: AuditConfig {
            path: audit_path.into(),
            hmac_key_file: None,
        },
        cosmos: CosmosConfig::default(),
        state_dir: Some(state_dir.into()),
        keys,
    }
}

fn solana_key(label: &str, object_id: u16) -> KeyDef {
    KeyDef {
        label: label.into(),
        chain: openkms::chain::Chain::Solana,
        object_id,
        derivation_path: None,
        address_style: AddressStyle::Solana,
        default_hrp: None,
        policy: KeyPolicy {
            enabled: true,
            allowed_programs: vec![AllowedProgram {
                id: system_program_id(),
                comment: Some("system transfer smoke test".into()),
            }],
            ..Default::default()
        },
    }
}

fn system_program_id() -> String {
    "11111111111111111111111111111111".to_string()
}

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

async fn spawn_server(
    cfg: Config,
    hsm: Hsm,
    signer_token: &str,
    admin_token: &str,
) -> (String, JoinHandle<()>) {
    let state = AppState::build(cfg, hsm, signer_token.into(), admin_token.into())
        .await
        .expect("build app state");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let app = router(state);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    let base_url = format!("http://{addr}");
    wait_until_ready(&base_url).await;
    (base_url, handle)
}

async fn wait_until_ready(base_url: &str) {
    let client = Client::new();
    for _ in 0..40 {
        if client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .map(|resp| resp.status().is_success())
            .unwrap_or(false)
        {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("server at {base_url} did not become ready");
}

#[tokio::test]
async fn serves_health_and_keys_over_real_http() {
    let state_dir = TempDir::new().expect("tempdir");
    let audit = state_dir.path().join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    let cfg = base_config(state_dir.path(), &audit, "127.0.0.1:0", vec![]);
    let (base_url, server_handle) = spawn_server(cfg, hsm, SIGNER_TOKEN, ADMIN_TOKEN).await;
    let client = Client::new();

    let health: serde_json::Value = client
        .get(format!("{base_url}/health"))
        .send()
        .await
        .expect("health request")
        .error_for_status()
        .expect("health status")
        .json()
        .await
        .expect("health body");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["hsm_up"], true);

    let keys: serde_json::Value = client
        .get(format!("{base_url}/keys"))
        .send()
        .await
        .expect("keys request")
        .error_for_status()
        .expect("keys status")
        .json()
        .await
        .expect("keys body");
    assert!(keys.is_array(), "expected /keys array, got {keys}");
    assert!(
        keys.as_array().unwrap().is_empty(),
        "expected no keys, got {keys}"
    );

    server_handle.abort();
    let _ = server_handle.await;
}

#[tokio::test]
async fn unauthenticated_sign_is_rejected_over_real_http() {
    let state_dir = TempDir::new().expect("tempdir");
    let audit = state_dir.path().join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    let cfg = base_config(state_dir.path(), &audit, "127.0.0.1:0", vec![]);
    let (base_url, server_handle) = spawn_server(cfg, hsm, SIGNER_TOKEN, ADMIN_TOKEN).await;
    let client = Client::new();

    let resp = client
        .post(format!("{base_url}/sign/solana"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("unauthenticated request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    let resp = client
        .post(format!("{base_url}/sign/cosmos"))
        .header("authorization", "Bearer nope")
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("wrong token request");
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    server_handle.abort();
    let _ = server_handle.await;
}

#[tokio::test]
async fn signs_and_honors_admin_disable_over_real_http() {
    let state_dir = TempDir::new().expect("tempdir");
    let audit = state_dir.path().join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    let payer = provision_mock_solana_key(&hsm, SOLANA_LABEL, SOLANA_OBJECT_ID).await;
    let cfg = base_config(
        state_dir.path(),
        &audit,
        "127.0.0.1:0",
        vec![solana_key(SOLANA_LABEL, SOLANA_OBJECT_ID)],
    );
    let (base_url, server_handle) = spawn_server(cfg, hsm, SIGNER_TOKEN, ADMIN_TOKEN).await;
    let client = Client::new();

    let message = build_transfer_message(payer, 1_000);
    let sign_resp: serde_json::Value = client
        .post(format!("{base_url}/sign/solana"))
        .bearer_auth(SIGNER_TOKEN)
        .json(&serde_json::json!({
            "label": SOLANA_LABEL,
            "message_b64": B64.encode(&message),
        }))
        .send()
        .await
        .expect("sign request")
        .error_for_status()
        .expect("sign status")
        .json()
        .await
        .expect("sign body");
    let sig_b64 = sign_resp["signature_b64"]
        .as_str()
        .expect("signature_b64 response field");
    let sig_bytes = B64.decode(sig_b64.as_bytes()).expect("decode signature");
    let sig = Signature::from_slice(&sig_bytes).expect("ed25519 signature");
    let verifying_key = VerifyingKey::from_bytes(&payer).expect("verifying key");
    verifying_key
        .verify(&message, &sig)
        .expect("signature verifies");

    let keys: serde_json::Value = client
        .get(format!("{base_url}/keys"))
        .send()
        .await
        .expect("keys request")
        .error_for_status()
        .expect("keys status")
        .json()
        .await
        .expect("keys body");
    assert_eq!(keys.as_array().unwrap().len(), 1);
    assert_eq!(keys[0]["label"], SOLANA_LABEL);
    assert_eq!(keys[0]["enabled"], true);

    let disable_resp: serde_json::Value = client
        .post(format!("{base_url}/admin/keys/{SOLANA_LABEL}/disable"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .expect("disable request")
        .error_for_status()
        .expect("disable status")
        .json()
        .await
        .expect("disable body");
    assert_eq!(disable_resp["enabled"], false);

    let blocked = client
        .post(format!("{base_url}/sign/solana"))
        .bearer_auth(SIGNER_TOKEN)
        .json(&serde_json::json!({
            "label": SOLANA_LABEL,
            "message_b64": B64.encode(build_transfer_message(payer, 2_000)),
        }))
        .send()
        .await
        .expect("blocked request");
    assert_eq!(blocked.status(), reqwest::StatusCode::FORBIDDEN);

    server_handle.abort();
    let _ = server_handle.await;
}

// -------------------------------------------------------------------------
// Hardware-gated tests
// -------------------------------------------------------------------------
//
// These tests talk to a physical YubiHSM2 via `yubihsm-connector` and are
// intentionally `#[ignore]`d so they never run as part of the default test
// suite. Opt in with:
//
//   OPENKMS_HARDWARE_TESTS=1 cargo test --test integration -- --ignored
//
// If `yubihsm-connector` isn't reachable at `OPENKMS_CONNECTOR` (default:
// `http://127.0.0.1:12345`) and the test was explicitly requested, the test
// fails so the caller doesn't get a false green run.

fn hardware_enabled() -> bool {
    matches!(std::env::var("OPENKMS_HARDWARE_TESTS").as_deref(), Ok("1"))
}

fn connector_url() -> String {
    std::env::var("OPENKMS_CONNECTOR").unwrap_or_else(|_| "http://127.0.0.1:12345".into())
}

#[tokio::test]
#[ignore = "hardware test; set OPENKMS_HARDWARE_TESTS=1 to enable"]
async fn hardware_ping_real_hsm() {
    if !hardware_enabled() {
        eprintln!("skipping: OPENKMS_HARDWARE_TESTS not set");
        return;
    }
    let password = std::env::var("OPENKMS_HSM_PASSWORD").unwrap_or_else(|_| "password".into());
    let auth_key_id: u16 = std::env::var("OPENKMS_AUTH_KEY_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let hsm = Hsm::open_http(&connector_url(), auth_key_id, password.as_bytes())
        .unwrap_or_else(|e| panic!("OPENKMS_HARDWARE_TESTS=1 but connector is unavailable: {e:?}"));
    assert!(hsm.ping().await, "hardware HSM should ping");
    let r = hsm.get_pseudo_random(16).await.expect("random");
    assert_eq!(r.len(), 16);
}

// Silence `unused` warnings for KeyDef/KeyPolicy which this module keeps
// in-scope as a deliberate compile-time contract for future end-to-end
// signing tests (once we plumb mockhsm key generation through the public API).
#[allow(dead_code)]
fn _static_contract(_: KeyDef, _: KeyPolicy) {}
