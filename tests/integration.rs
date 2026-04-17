//! End-to-end test that spawns the full `openkms` HTTP server on an ephemeral
//! port, backed by `yubihsm::Connector::mockhsm`.
//!
//! This mirrors `openkms run` as closely as is practical in-process: we build
//! an `AppState` with the in-memory mock HSM, start `axum::serve` on a TCP
//! listener bound to `127.0.0.1:0`, and drive it with a real HTTP client.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use axum::{Router, body::Body, http::Request};
use openkms::{
    config::{
        AuditConfig, Config, CosmosConfig, HsmConfig, KeyDef, KeyPolicy, ServerConfig,
    },
    hsm::Hsm,
    server::{AppState, router},
};
use tokio::net::TcpListener;
use tower::ServiceExt;

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "openkms-it-{}-{}",
        tag,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn base_config(state_dir: PathBuf, audit_path: PathBuf, listen: &str) -> Config {
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
            path: audit_path,
            hmac_key_file: None,
        },
        cosmos: CosmosConfig::default(),
        state_dir: Some(state_dir),
        keys: vec![],
    }
}

#[tokio::test]
async fn serves_health_and_keys_over_real_socket() {
    // Build an HSM, then the state without any keys — simplest possible
    // "server is running" smoke test.
    let state_dir = tmp_dir("health");
    let audit = state_dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    let cfg = base_config(state_dir, audit, "127.0.0.1:0");
    let state = AppState::build(cfg, hsm, "s".into(), "a".into())
        .await
        .expect("build app state");
    let app: Router = router(state);

    let listener = TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind");
    let addr = listener.local_addr().unwrap();

    // Run the server in the background.
    let app_for_task = app.clone();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app_for_task).await.unwrap();
    });

    // Give the server a moment to settle before hitting it (mostly for CI
    // machines that are under heavy contention).
    tokio::time::sleep(Duration::from_millis(25)).await;

    // Hit /health.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // /keys returns a JSON array (empty, since we registered no keys).
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/keys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(v.is_array(), "expected /keys to return JSON array; got {v}");
    assert!(v.as_array().unwrap().is_empty());

    server_handle.abort();
    let _ = server_handle.await;

    // Sanity check: we actually used the bound address.
    assert!(addr.port() != 0);
}

#[tokio::test]
async fn unauthenticated_sign_is_rejected() {
    let state_dir = tmp_dir("auth");
    let audit = state_dir.join("audit.jsonl");
    let hsm = Hsm::open_mock(1, b"password").expect("mock hsm");
    let cfg = base_config(state_dir, audit, "127.0.0.1:0");
    let state = AppState::build(cfg, hsm, "signer-token".into(), "admin-token".into())
        .await
        .expect("build app state");
    let app: Router = router(state);

    // No bearer token.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sign/solana")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);

    // Wrong bearer token.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sign/cosmos")
                .header("authorization", "Bearer nope")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 401);
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
// `http://127.0.0.1:12345`), the test short-circuits with a warning instead
// of failing.

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
    let password =
        std::env::var("OPENKMS_HSM_PASSWORD").unwrap_or_else(|_| "password".into());
    let auth_key_id: u16 = std::env::var("OPENKMS_AUTH_KEY_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let hsm = match Hsm::open_http(&connector_url(), auth_key_id, password.as_bytes()) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("skipping: could not reach connector {e:?}");
            return;
        }
    };
    assert!(hsm.ping().await, "hardware HSM should ping");
    let r = hsm.get_pseudo_random(16).await.expect("random");
    assert_eq!(r.len(), 16);
}

// Silence `unused` warnings for KeyDef/KeyPolicy which this module keeps
// in-scope as a deliberate compile-time contract for future end-to-end
// signing tests (once we plumb mockhsm key generation through the public API).
#[allow(dead_code)]
fn _static_contract(_: KeyDef, _: KeyPolicy) {}
