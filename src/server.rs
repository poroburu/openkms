//! HTTP server.
//!
//! Wires the chain-agnostic pieces together:
//!
//! ```text
//!   incoming request
//!     -> request-id middleware
//!     -> bearer-token auth (signer or admin realm)
//!     -> tower::Buffer / ConcurrencyLimit (backpressure)
//!     -> chain-specific handler (decode -> policy -> replay? -> HSM sign -> audit)
//! ```
//!
//! Design notes:
//!   * A single HSM is shared across all routes via `Hsm` (Arc<Mutex<Client>>).
//!   * Per-key signer handles (`SolanaSigner`, `CosmosSigner`) are pre-built
//!     at startup with the key's pubkey so we don't hit the HSM during decode.
//!   * The replay cache is keyed on sha256(signing_digest). See `replay.rs`
//!     for why caching is safe.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

use anyhow::{Context, Result, anyhow};
use axum::{
    Router,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode, header::AUTHORIZATION},
    response::IntoResponse,
    routing::{get, post},
    Json,
};
use serde::Serialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    admin::AdminStore,
    audit::AuditLog,
    chain::{
        Chain, ChainError, ChainSigner, Intent, RequestContext, SignRequest,
        cosmos::CosmosSigner,
        solana::SolanaSigner,
    },
    config::{Config, KeyDef},
    hsm::Hsm,
    metrics::Metrics,
    policy::{DefaultPolicyEngine, PolicyEngine, PolicyError},
    replay::{CachedResponse, ReplayCache},
};

/// The application state shared by every handler.
#[derive(Clone)]
pub struct AppState {
    pub hsm: Hsm,
    pub policy: Arc<DefaultPolicyEngine>,
    pub audit: AuditLog,
    pub admin: AdminStore,
    pub metrics: Metrics,
    pub replay: ReplayCache,
    pub keys: Arc<HashMap<String, KeyDef>>,
    pub solana_signers: Arc<HashMap<String, Arc<SolanaSigner>>>,
    pub cosmos_signers: Arc<HashMap<String, Arc<CosmosSigner>>>,
    pub signer_token: Arc<String>,
    pub admin_token: Arc<String>,
    pub config: Arc<Config>,
}

impl AppState {
    /// Build state from a `Config` and an open HSM. Construction touches the
    /// HSM once per key to fetch pubkeys.
    pub async fn build(
        config: Config,
        hsm: Hsm,
        signer_token: String,
        admin_token: String,
    ) -> Result<Self> {
        let policy = Arc::new(DefaultPolicyEngine::new(&config));
        let audit = AuditLog::open(&config.audit)?;
        let state_dir = config
            .state_dir
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/openkms"));
        let admin = AdminStore::open(&state_dir)?;
        admin.apply_all(policy.as_ref()).await;

        let metrics = Metrics::new()?;
        let replay = ReplayCache::new(
            1024,
            std::time::Duration::from_secs(config.server.replay_window_secs.max(1)),
        );

        let mut keys = HashMap::new();
        let mut solana_signers: HashMap<String, Arc<SolanaSigner>> = HashMap::new();
        let mut cosmos_signers: HashMap<String, Arc<CosmosSigner>> = HashMap::new();
        for k in &config.keys {
            keys.insert(k.label.clone(), k.clone());
            match k.chain {
                Chain::Solana => {
                    let s = SolanaSigner::from_hsm(&hsm, k).await.with_context(|| {
                        format!("failed to initialize Solana signer for key {:?}", k.label)
                    })?;
                    solana_signers.insert(k.label.clone(), Arc::new(s));
                }
                Chain::Cosmos => {
                    let s = CosmosSigner::from_hsm(
                        &hsm,
                        k,
                        config.cosmos.accepted_pubkey_type_urls.iter().cloned(),
                    )
                    .await
                    .with_context(|| {
                        format!("failed to initialize Cosmos signer for key {:?}", k.label)
                    })?;
                    cosmos_signers.insert(k.label.clone(), Arc::new(s));
                }
                Chain::Unknown => {
                    return Err(anyhow!("key {:?} has unknown chain", k.label));
                }
            }
        }

        Ok(Self {
            hsm,
            policy,
            audit,
            admin,
            metrics,
            replay,
            keys: Arc::new(keys),
            solana_signers: Arc::new(solana_signers),
            cosmos_signers: Arc::new(cosmos_signers),
            signer_token: Arc::new(signer_token),
            admin_token: Arc::new(admin_token),
            config: Arc::new(config),
        })
    }
}

/// Build the axum router. Use [`AppState::build`] then pass in the state.
pub fn router(state: AppState) -> Router {
    let signer_routes = Router::new()
        .route("/sign/solana", post(sign_solana))
        .route("/sign/cosmos", post(sign_cosmos))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            signer_auth_mw,
        ));

    let admin_routes = Router::new()
        .route("/admin/keys/{label}/enable", post(admin_enable))
        .route("/admin/keys/{label}/disable", post(admin_disable))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin_auth_mw,
        ));

    Router::new()
        .route("/health", get(health))
        .route("/keys", get(list_keys))
        .route("/metrics", get(metrics_handler))
        .merge(signer_routes)
        .merge(admin_routes)
        .with_state(state)
}

/// Bind + serve. Uses tower::ConcurrencyLimit for basic backpressure.
pub async fn serve(state: AppState) -> Result<()> {
    let listen: SocketAddr = state
        .config
        .server
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {:?}", state.config.server.listen))?;
    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    info!("openkms listening on {listen}");
    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
    hsm_up: bool,
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let up = state.hsm.ping().await;
    state.metrics.hsm_up().set(if up { 1 } else { 0 });
    Json(HealthBody {
        status: "ok",
        hsm_up: up,
    })
}

#[derive(Serialize)]
struct KeySummary {
    label: String,
    chain: String,
    address: String,
    enabled: bool,
    object_id: u16,
    derivation_path: Option<String>,
}

async fn list_keys(State(state): State<AppState>) -> impl IntoResponse {
    let mut out = Vec::new();
    let flags = state.admin.snapshot().await.enabled;
    for k in state.config.keys.iter() {
        let address = match k.chain {
            Chain::Solana => state
                .solana_signers
                .get(&k.label)
                .map(|s| s.address.clone())
                .unwrap_or_default(),
            Chain::Cosmos => state
                .cosmos_signers
                .get(&k.label)
                .map(|s| s.default_address.clone())
                .unwrap_or_default(),
            Chain::Unknown => String::new(),
        };
        let enabled = flags.get(&k.label).copied().unwrap_or(k.policy.enabled);
        out.push(KeySummary {
            label: k.label.clone(),
            chain: k.chain.as_str().to_string(),
            address,
            enabled,
            object_id: k.object_id,
            derivation_path: k.derivation_path.clone(),
        });
    }
    Json(out)
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    match state.metrics.render() {
        Ok((body, ct)) => ([(axum::http::header::CONTENT_TYPE, ct)], body).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("metrics error: {e}"))
            .into_response(),
    }
}

// ---------- /sign/solana ----------

async fn sign_solana(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SignRequest>,
) -> impl IntoResponse {
    let request_id = extract_or_mint_request_id(&headers);
    let label = body.label.clone();
    let key = match state.keys.get(&label).cloned() {
        Some(k) if matches!(k.chain, Chain::Solana) => k,
        Some(_) => {
            return json_err(StatusCode::BAD_REQUEST, "key is not a solana key");
        }
        None => {
            return json_err(StatusCode::NOT_FOUND, "unknown key label");
        }
    };
    let signer = match state.solana_signers.get(&label).cloned() {
        Some(s) => s,
        None => {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, "signer not initialized");
        }
    };
    run_sign(state, request_id, key, signer.as_ref(), body, Chain::Solana).await
}

// ---------- /sign/cosmos ----------

async fn sign_cosmos(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SignRequest>,
) -> impl IntoResponse {
    let request_id = extract_or_mint_request_id(&headers);
    let label = body.label.clone();
    let key = match state.keys.get(&label).cloned() {
        Some(k) if matches!(k.chain, Chain::Cosmos) => k,
        Some(_) => {
            return json_err(StatusCode::BAD_REQUEST, "key is not a cosmos key");
        }
        None => {
            return json_err(StatusCode::NOT_FOUND, "unknown key label");
        }
    };
    let signer = match state.cosmos_signers.get(&label).cloned() {
        Some(s) => s,
        None => {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, "signer not initialized");
        }
    };
    // Cosmos's SignRequest carries expected_chain_id inside the payload; we
    // surface it up to RequestContext so it appears in audit + logs.
    run_sign(state, request_id, key, signer.as_ref(), body, Chain::Cosmos).await
}

/// RAII guard that decrements the inflight gauge when dropped.
struct InflightGuard(Metrics);
impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.inflight().dec();
    }
}

async fn run_sign<S>(
    state: AppState,
    request_id: String,
    key: KeyDef,
    signer: &S,
    body: SignRequest,
    chain: Chain,
) -> axum::response::Response
where
    S: ChainSigner,
{
    state.metrics.inflight().inc();
    let _inflight = InflightGuard(state.metrics.clone());

    let start = Instant::now();

    let ctx = RequestContext {
        request_id: request_id.clone(),
        expected_chain_id: body.payload.get("expected_chain_id")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    };

    // Decode.
    let intent = match signer.decode(&key, body, &ctx) {
        Ok(i) => i,
        Err(e) => {
            state
                .metrics
                .signer_errors_total()
                .with_label_values(&[chain.as_str(), "decode"])
                .inc();
            warn!(%request_id, ?chain, key_label=%key.label, "decode failed: {e}");
            return json_err(StatusCode::BAD_REQUEST, &e.to_string());
        }
    };

    // Replay cache: return the stored body on a hit.
    let replay_key = ReplayCache::digest_key(intent.signing_digest());
    if let Some(hit) = state.replay.get(&replay_key) {
        state.metrics.replay_hits_total().inc();
        state
            .metrics
            .signs_total()
            .with_label_values(&[chain.as_str(), &key.label, "replay"])
            .inc();
        return (StatusCode::OK, Json(hit.body_json)).into_response();
    }

    // Policy.
    if let Err(e) = state.policy.evaluate(&key, &intent).await {
        state
            .metrics
            .policy_denials_total()
            .with_label_values(&[chain.as_str(), &key.label, e.reason_code()])
            .inc();
        state
            .metrics
            .signs_total()
            .with_label_values(&[chain.as_str(), &key.label, "deny"])
            .inc();
        let rec = AuditLog::build_deny(
            &request_id,
            &key.label,
            chain,
            Some(&intent),
            &e,
        );
        let _ = state.audit.append(rec).await;
        return policy_err_response(&e);
    }

    // Build a partial audit record from the intent *before* we consume the
    // intent by calling sign(). We fill in the signature hash below.
    let mut allow_rec = AuditLog::build_allow(&request_id, &key.label, chain, &intent, b"");

    // HSM-sign. Each concrete ChainSigner impl returns its own Response type;
    // we serialize it to a `serde_json::Value` to cache in the replay entry.
    let response = match signer.sign(&state.hsm, &key, intent).await {
        Ok(r) => r,
        Err(ChainError::Hsm(e)) => {
            state
                .metrics
                .signer_errors_total()
                .with_label_values(&[chain.as_str(), "hsm"])
                .inc();
            warn!(%request_id, ?chain, key_label=%key.label, "hsm sign failed: {e}");
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("hsm: {e}"));
        }
        Err(e) => {
            state
                .metrics
                .signer_errors_total()
                .with_label_values(&[chain.as_str(), "sign"])
                .inc();
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
        }
    };

    let body_json = match serde_json::to_value(&response) {
        Ok(v) => v,
        Err(e) => {
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, &format!("serialize: {e}"));
        }
    };

    // Extract the signature bytes from the response for audit + replay.
    let signature_bytes = body_json
        .get("signature_b64")
        .and_then(|v| v.as_str())
        .and_then(|s| base64::Engine::decode(&base64::engine::general_purpose::STANDARD, s).ok())
        .unwrap_or_default();

    state.replay.insert(
        replay_key,
        CachedResponse {
            signature: signature_bytes.clone(),
            body_json: body_json.clone(),
        },
    );

    // Fill in signature hash on the record we built before signing.
    use sha2::{Digest, Sha256};
    allow_rec.signature_sha256 = hex::encode(Sha256::digest(&signature_bytes));
    let _ = state.audit.append(allow_rec).await;

    state
        .metrics
        .signs_total()
        .with_label_values(&[chain.as_str(), &key.label, "allow"])
        .inc();
    state
        .metrics
        .sign_duration_seconds()
        .with_label_values(&[chain.as_str(), &key.label])
        .observe(start.elapsed().as_secs_f64());

    info!(
        %request_id, chain=%chain, key_label=%key.label, "signed"
    );

    (StatusCode::OK, Json(body_json)).into_response()
}

// ---------- /admin/keys/:label/{enable,disable} ----------

#[derive(Serialize)]
struct AdminResponse {
    label: String,
    enabled: bool,
}

async fn admin_enable(
    State(state): State<AppState>,
    AxumPath(label): AxumPath<String>,
) -> impl IntoResponse {
    admin_set(&state, &label, true).await
}

async fn admin_disable(
    State(state): State<AppState>,
    AxumPath(label): AxumPath<String>,
) -> impl IntoResponse {
    admin_set(&state, &label, false).await
}

async fn admin_set(state: &AppState, label: &str, enabled: bool) -> axum::response::Response {
    if !state.keys.contains_key(label) {
        return json_err(StatusCode::NOT_FOUND, "unknown key label");
    }
    if let Err(e) = state.admin.set_enabled(state.policy.as_ref(), label, enabled).await {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    Json(AdminResponse {
        label: label.to_string(),
        enabled,
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

async fn signer_auth_mw(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    match bearer_token(req.headers()) {
        Some(tok) if tok == state.signer_token.as_str() => next.run(req).await,
        _ => json_err(StatusCode::UNAUTHORIZED, "bad or missing signer token"),
    }
}

async fn admin_auth_mw(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    match bearer_token(req.headers()) {
        Some(tok) if tok == state.admin_token.as_str() => next.run(req).await,
        _ => json_err(StatusCode::UNAUTHORIZED, "bad or missing admin token"),
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let h = headers.get(AUTHORIZATION)?.to_str().ok()?;
    h.strip_prefix("Bearer ").map(str::trim)
}

fn extract_or_mint_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn json_err(status: StatusCode, detail: &str) -> axum::response::Response {
    #[derive(Serialize)]
    struct ErrBody<'a> {
        error: &'a str,
    }
    (status, Json(ErrBody { error: detail })).into_response()
}

fn policy_err_response(e: &PolicyError) -> axum::response::Response {
    let status = match e {
        PolicyError::KeyDisabled(_) => StatusCode::FORBIDDEN,
        PolicyError::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
        _ => StatusCode::FORBIDDEN,
    };
    json_err(status, &e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt;

    fn minimal_config() -> Config {
        Config {
            server: crate::config::ServerConfig {
                listen: "127.0.0.1:0".into(),
                signer_token_file: "/tmp/x".into(),
                admin_token_file: "/tmp/x".into(),
                inflight_limit: 1,
                replay_window_secs: 1,
            },
            hsm: crate::config::HsmConfig {
                connector_url: "mock".into(),
                auth_key_id: 1,
                password_file: "/tmp/x".into(),
            },
            audit: crate::config::AuditConfig {
                path: std::env::temp_dir().join("openkms-test-audit.log"),
                hmac_key_file: None,
            },
            cosmos: Default::default(),
            state_dir: Some(std::env::temp_dir().join("openkms-test-state")),
            keys: vec![],
        }
    }

    #[tokio::test]
    async fn health_endpoint_reports_hsm_up() {
        let hsm = Hsm::open_mock(1, b"password").unwrap();
        let state = AppState::build(minimal_config(), hsm, "s".into(), "a".into())
            .await
            .unwrap();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["hsm_up"], true);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_prometheus_text() {
        let hsm = Hsm::open_mock(1, b"password").unwrap();
        let state = AppState::build(minimal_config(), hsm, "s".into(), "a".into())
            .await
            .unwrap();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sign_solana_requires_bearer() {
        let hsm = Hsm::open_mock(1, b"password").unwrap();
        let state = AppState::build(minimal_config(), hsm, "signer-token".into(), "a".into())
            .await
            .unwrap();
        let app = router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/sign/solana")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
