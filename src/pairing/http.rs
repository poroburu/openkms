//! HTTP handlers for pairing routes.

use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};

use crate::{
    chain::Chain,
    pairing::{PairAsset, PickStrategy, PoolKeyEntry, PoolSummary},
    server::AppState,
};

#[derive(Deserialize)]
pub struct PairRequestBody {
    pub client_id: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub chain: Option<String>,
    #[serde(default)]
    pub pick: Option<PickStrategy>,
    #[serde(default)]
    pub asset: Option<PairAsset>,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Client-generated bearer (`okms_` + 64 hex). Hashed at ingest; plaintext is not stored.
    #[serde(default)]
    pub bearer: Option<String>,
}

#[derive(Serialize)]
pub struct PairRequestResponse {
    pub request_id: String,
    pub status: &'static str,
    pub expires_at: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
pub enum BearerSource {
    Server,
    Client,
}

#[derive(Serialize)]
pub struct ApproveResponse {
    pub pairing_id: String,
    pub client_id: String,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pick: Option<PickStrategy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    pub bearer_source: BearerSource,
}

#[derive(Deserialize)]
pub struct ApproveBody {
    #[serde(default)]
    pub label: Option<String>,
}

fn key_addresses(state: &AppState) -> HashMap<String, String> {
    let mut m = HashMap::new();
    for (label, s) in state.solana_signers.iter() {
        m.insert(label.clone(), s.address.clone());
    }
    for (label, s) in state.cosmos_signers.iter() {
        m.insert(label.clone(), s.default_address.clone());
    }
    m
}

pub async fn pair_pool(State(state): State<AppState>) -> axum::response::Response {
    match state.pairing.pool_summary(&state.config, &state.admin).await {
        Ok(pool) => {
            let reveal = state.pairing.config().reveal_addresses;
            if reveal {
                let addrs = key_addresses(&state);
                match state
                    .pairing
                    .admin_pool_entries(&state.config, &state.admin, &addrs, true)
                    .await
                {
                    Ok(keys) => Json(PoolResponse { pool, keys: Some(keys) }).into_response(),
                    Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                }
            } else {
                Json(PoolResponse {
                    pool,
                    keys: None,
                })
                .into_response()
            }
        }
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

#[derive(Serialize)]
struct PoolResponse {
    #[serde(flatten)]
    pool: PoolSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<PoolKeyEntry>>,
}

pub async fn pair_request(
    State(state): State<AppState>,
    Json(body): Json<PairRequestBody>,
) -> axum::response::Response {
    let chain = body.chain.as_deref().and_then(parse_chain);
    let result = state
        .pairing
        .submit_request(
            &body.client_id,
            body.label.as_deref(),
            chain,
            body.pick,
            body.asset,
            body.display_name.as_deref(),
            body.bearer.as_deref(),
            &state.config,
            &state.admin,
        )
        .await;

    match result {
        Ok(req) => {
            state
                .audit
                .append_pair_event(
                    "pair.requested",
                    &req.client_id,
                    req.label.as_deref(),
                    req.chain.as_deref(),
                    req.pick,
                    &req.id,
                )
                .await;
            state.metrics.inc_pair_pending();
            Json(PairRequestResponse {
                request_id: req.id,
                status: "pending",
                expires_at: req.expires_at,
            })
            .into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("no allocatable") || msg.contains("too many pending") {
                state
                    .audit
                    .append_pair_event(
                        "pair.allocate_failed",
                        &body.client_id,
                        body.label.as_deref(),
                        body.chain.as_deref(),
                        body.pick,
                        "",
                    )
                    .await;
                json_err(StatusCode::CONFLICT, &msg)
            } else {
                json_err(StatusCode::BAD_REQUEST, &msg)
            }
        }
    }
}

pub async fn admin_list_pending(State(state): State<AppState>) -> axum::response::Response {
    let pending = state.pairing.list_pending().await;
    Json(pending).into_response()
}

pub async fn admin_list_pair(State(state): State<AppState>) -> axum::response::Response {
    let active = state.pairing.list_active().await;
    Json(active).into_response()
}

pub async fn admin_pair_pool(State(state): State<AppState>) -> axum::response::Response {
    let addrs = key_addresses(&state);
    match state
        .pairing
        .pool_summary(&state.config, &state.admin)
        .await
    {
        Ok(pool) => match state
            .pairing
            .admin_pool_entries(&state.config, &state.admin, &addrs, true)
            .await
        {
            Ok(keys) => Json(PoolResponse {
                pool,
                keys: Some(keys),
            })
            .into_response(),
            Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        },
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

pub async fn admin_approve_pair(
    State(state): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> axum::response::Response {
    let label_override = body.and_then(|Json(b)| b.label);
    let addrs = key_addresses(&state);
    let pending = state.pairing.list_pending().await;
    let pick = pending.iter().find(|p| p.id == id).and_then(|p| p.pick);

    match state
        .pairing
        .approve(
            &id,
            label_override.as_deref(),
            &state.config,
            &state.admin,
            &state.balance_ranker,
            &addrs,
        )
        .await
    {
        Ok((pairing, minted_token)) => {
            state.metrics.dec_pair_pending();
            state.metrics.inc_pair_active(&pairing.label);
            state
                .audit
                .append_pair_event(
                    "pair.approved",
                    &pairing.client_id,
                    Some(&pairing.label),
                    None,
                    pick,
                    &pairing.id,
                )
                .await;
            let bearer_source = if minted_token.is_some() {
                BearerSource::Server
            } else {
                BearerSource::Client
            };
            Json(ApproveResponse {
                pairing_id: pairing.id,
                client_id: pairing.client_id,
                label: pairing.label,
                pick,
                token: minted_token,
                bearer_source,
            })
            .into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("rpc") || msg.contains("not configured") {
                json_err(StatusCode::SERVICE_UNAVAILABLE, &msg)
            } else if msg.contains("not found") || msg.contains("no allocatable") {
                json_err(StatusCode::CONFLICT, &msg)
            } else {
                json_err(StatusCode::BAD_REQUEST, &msg)
            }
        }
    }
}

pub async fn admin_reject_pair(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.pairing.reject(&id).await {
        Ok(()) => {
            state.metrics.dec_pair_pending();
            state
                .audit
                .append_pair_event("pair.rejected", "", None, None, None, &id)
                .await;
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Err(e) => json_err(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

pub async fn admin_revoke_pair(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> axum::response::Response {
    match state.pairing.revoke(&id).await {
        Ok(p) => {
            state.metrics.dec_pair_active(&p.label);
            state
                .audit
                .append_pair_event(
                    "pair.revoked",
                    &p.client_id,
                    Some(&p.label),
                    None,
                    None,
                    &p.id,
                )
                .await;
            Json(serde_json::json!({ "ok": true, "label": p.label })).into_response()
        }
        Err(e) => json_err(StatusCode::NOT_FOUND, &e.to_string()),
    }
}

fn parse_chain(s: &str) -> Option<Chain> {
    match s.to_lowercase().as_str() {
        "solana" => Some(Chain::Solana),
        "cosmos" => Some(Chain::Cosmos),
        _ => None,
    }
}

fn json_err(status: StatusCode, detail: &str) -> axum::response::Response {
    #[derive(Serialize)]
    struct ErrBody<'a> {
        error: &'a str,
    }
    (status, Json(ErrBody { error: detail })).into_response()
}
