//! Shared fixtures for the chain-specific integration tests.
//!
//! Each test binary (`sign_cosmos_atom`, `sign_solana_devnet`) pulls helpers
//! from here via `mod common;`. Functions that aren't used by a given test
//! binary will be flagged as dead code by the linter, hence the
//! `#![allow(dead_code)]` at the top — this is the canonical pattern for
//! shared `tests/common/` modules.

#![allow(dead_code)]

use std::{net::SocketAddr, path::PathBuf, str::FromStr};

use openkms::{
    chain::Chain,
    config::{
        AddressStyle, AllowedMessage, AllowedProgram, AuditConfig, Config, CosmosConfig,
        HsmConfig, KeyDef, KeyPolicy, ServerConfig,
    },
    hsm::{Hsm, hsm_types as H},
    server::{AppState, router},
};
use tokio::net::TcpListener;

/// Handle to a spawned in-process openkms HTTP server.
pub struct ServerHandle {
    pub base: String,
    pub signer_token: String,
    pub admin_token: String,
    pub hsm: Hsm,
    join: tokio::task::JoinHandle<()>,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.join.abort();
    }
}

/// Create a fresh, unique temp directory under `$TMPDIR`. Cleaned up
/// implicitly by tests being short-lived; we don't bother removing on drop.
pub fn tmp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "openkms-it-{}-{}-{}",
        tag,
        std::process::id(),
        nanos,
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Build a [`Config`] suitable for an integration test. The `state_dir` and
/// `audit_path` should point inside a per-test temp dir.
pub fn base_config(state_dir: PathBuf, audit_path: PathBuf, keys: Vec<KeyDef>) -> Config {
    Config {
        server: ServerConfig {
            listen: "127.0.0.1:0".into(),
            signer_token_file: "/tmp/unused".into(),
            admin_token_file: "/tmp/unused".into(),
            inflight_limit: 64,
            replay_window_secs: 120,
        },
        hsm: HsmConfig {
            connector_url: "mock".into(),
            auth_key_id: 1,
            password_file: "/tmp/unused".into(),
        },
        audit: AuditConfig {
            path: audit_path,
            hmac_key_file: None,
        },
        cosmos: CosmosConfig {
            accepted_pubkey_type_urls: vec![
                "/cosmos.crypto.secp256k1.PubKey".into(),
                "/ethermint.crypto.v1.ethsecp256k1.PubKey".into(),
                "/injective.crypto.v1beta1.ethsecp256k1.PubKey".into(),
            ],
        },
        state_dir: Some(state_dir),
        keys,
    }
}

/// Import a raw 32-byte secp256k1 scalar into the mock HSM at `object_id`.
pub async fn provision_secp256k1(hsm: &Hsm, object_id: u16, label: &str, scalar: &[u8; 32]) {
    let client = hsm.client();
    let guard = client.lock().await;
    guard
        .put_asymmetric_key(
            object_id,
            H::ObjectLabel::from_str(label).unwrap(),
            H::Domain::DOM1,
            H::Capability::SIGN_ECDSA | H::Capability::EXPORTABLE_UNDER_WRAP,
            H::AsymmetricAlg::EcK256,
            scalar.to_vec(),
        )
        .expect("put_asymmetric_key (secp256k1) into mock HSM");
}

/// Import a raw 32-byte Ed25519 seed into the mock HSM at `object_id`.
pub async fn provision_ed25519(hsm: &Hsm, object_id: u16, label: &str, seed: &[u8; 32]) {
    let client = hsm.client();
    let guard = client.lock().await;
    guard
        .put_asymmetric_key(
            object_id,
            H::ObjectLabel::from_str(label).unwrap(),
            H::Domain::DOM1,
            H::Capability::SIGN_EDDSA | H::Capability::EXPORTABLE_UNDER_WRAP,
            H::AsymmetricAlg::Ed25519,
            seed.to_vec(),
        )
        .expect("put_asymmetric_key (Ed25519) into mock HSM");
}

/// Permissive Cosmos `KeyDef`: rate limits high enough not to interfere,
/// the supplied `MsgSend` per-tx cap, and a single allowlisted message type.
pub fn cosmos_key_def(label: &str, object_id: u16, hrp: &str) -> KeyDef {
    KeyDef {
        label: label.into(),
        chain: Chain::Cosmos,
        object_id,
        derivation_path: None,
        address_style: AddressStyle::Cosmos,
        default_hrp: Some(hrp.into()),
        policy: KeyPolicy {
            enabled: true,
            max_signs_per_minute: Some(600),
            max_signs_per_hour: None,
            max_signs_per_day: None,
            daily_cap_lamports: None,
            per_tx_cap_lamports: Some("1000000000000".into()),
            allowed_programs: vec![],
            allowed_messages: vec![AllowedMessage {
                type_url: "/cosmos.bank.v1beta1.MsgSend".into(),
                per_tx_cap: None,
                allowed_recipients: vec![],
                allowed_contracts: vec![],
                allowed_methods: vec![],
                comment: None,
            }],
            allowed_recipients: vec![],
        },
    }
}

/// Permissive Solana `KeyDef`: System Program allowlisted, large per-tx cap.
pub fn solana_key_def(label: &str, object_id: u16) -> KeyDef {
    KeyDef {
        label: label.into(),
        chain: Chain::Solana,
        object_id,
        derivation_path: None,
        address_style: AddressStyle::Solana,
        default_hrp: None,
        policy: KeyPolicy {
            enabled: true,
            max_signs_per_minute: Some(600),
            max_signs_per_hour: None,
            max_signs_per_day: None,
            daily_cap_lamports: None,
            per_tx_cap_lamports: Some("1000000000000".into()),
            allowed_programs: vec![AllowedProgram {
                id: "11111111111111111111111111111111".into(),
                comment: None,
            }],
            allowed_messages: vec![],
            allowed_recipients: vec![],
        },
    }
}

/// Build the `AppState`, bind an ephemeral TCP socket, and spawn axum on it.
/// Returns a [`ServerHandle`] whose `Drop` aborts the background task.
pub async fn spawn(cfg: Config, hsm: Hsm) -> ServerHandle {
    let signer_token = "signer-token-test".to_string();
    let admin_token = "admin-token-test".to_string();
    let state = AppState::build(cfg, hsm.clone(), signer_token.clone(), admin_token.clone())
        .await
        .expect("AppState::build");
    let app = router(state);

    let listener = TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");

    let join = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Tiny settle delay so the very first request doesn't race the bind.
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    ServerHandle {
        base,
        signer_token,
        admin_token,
        hsm,
        join,
    }
}
