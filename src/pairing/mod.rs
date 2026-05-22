//! User-to-key pairing (OpenClaw-style): pending requests, operator approval, per-client bearer tokens.

mod balance;
pub mod http;

pub use balance::BalanceRanker;
pub use http::{
    admin_approve_pair, admin_list_pair, admin_list_pending, admin_pair_pool, admin_reject_pair,
    admin_revoke_pair, pair_pool, pair_request,
};

use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use tokio::sync::Mutex as AsyncMutex;

use anyhow::{Context, Result, anyhow, bail};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    admin::AdminStore,
    chain::Chain,
    config::{Config, KeyDef, PairingConfig},
};

/// How to pick among allocatable keys for an auto pairing request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PickStrategy {
    Most,
    Least,
    Random,
}

/// Asset used for balance ranking.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum PairAsset {
    Native,
    Spl { mint: String },
    Denom { denom: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestKind {
    Labeled,
    Auto,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingRequest {
    pub id: String,
    pub client_id: String,
    pub request_kind: RequestKind,
    pub label: Option<String>,
    pub chain: Option<String>,
    pub pick: Option<PickStrategy>,
    pub asset: Option<PairAsset>,
    pub display_name: Option<String>,
    pub requested_at: i64,
    pub expires_at: i64,
    /// SHA-256 hex of client-proposed bearer (never the plaintext).
    #[serde(default, skip_serializing)]
    pub token_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActivePairing {
    pub id: String,
    pub client_id: String,
    pub label: String,
    #[serde(skip_serializing)]
    pub token_hash: String,
    pub paired_at: i64,
    pub revoked_at: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct PairingFile {
    #[serde(default)]
    pending: Vec<PendingRequest>,
    #[serde(default)]
    paired: Vec<ActivePairing>,
}

#[derive(Clone)]
pub struct PairingStore {
    inner: Arc<PairingInner>,
}

struct AwaitingPickup {
    label: String,
    token: String,
}

/// Result of `GET /policy/{label}?request_id=…` while a pairing request is in flight.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PairPollOutcome {
    Pending { expires_at: i64 },
    Ready { token: String },
    NotFound,
    LabelMismatch,
}

struct PairingInner {
    path: PathBuf,
    pairing: PairingConfig,
    data: Mutex<PairingFile>,
    /// Bearer tokens minted on approve, delivered once via policy poll (not persisted).
    awaiting_pickup: AsyncMutex<HashMap<String, AwaitingPickup>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChainPoolStats {
    pub configured: u32,
    pub allocatable: u32,
    pub paired: u32,
    pub reserved: u32,
    pub can_allocate: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PoolSummary {
    pub chains: BTreeMap<String, ChainPoolStats>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PoolKeyEntry {
    pub label: String,
    pub chain: String,
    pub allocatable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

impl PairingStore {
    pub fn open(state_dir: &Path, pairing: PairingConfig) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("create state_dir {state_dir:?}"))?;
        let path = state_dir.join("pairing.json");
        let data = if path.exists() {
            let raw = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
            serde_json::from_str(&raw).with_context(|| format!("parse {path:?}"))?
        } else {
            PairingFile::default()
        };
        Ok(Self {
            inner: Arc::new(PairingInner {
                path,
                pairing,
                data: Mutex::new(data),
                awaiting_pickup: AsyncMutex::new(HashMap::new()),
            }),
        })
    }

    pub fn config(&self) -> &PairingConfig {
        &self.inner.pairing
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    async fn persist(&self) -> Result<()> {
        let data = self.inner.data.lock().await;
        let raw = serde_json::to_string_pretty(&*data)?;
        let tmp = self.inner.path.with_extension("json.tmp");
        std::fs::write(&tmp, &raw)?;
        std::fs::rename(&tmp, &self.inner.path)?;
        Ok(())
    }

    fn purge_expired_pending(data: &mut PairingFile, now: i64) {
        data.pending.retain(|p| p.expires_at > now);
    }

    pub fn hash_token(token: &str) -> String {
        let digest = Sha256::digest(token.as_bytes());
        hex::encode(digest)
    }

    pub fn generate_token() -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        format!("okms_{}", hex::encode(bytes))
    }

    /// Validates `okms_` + 64 lowercase hex chars (same shape as [`generate_token`]).
    pub fn validate_bearer_format(bearer: &str) -> Result<()> {
        const PREFIX: &str = "okms_";
        let rest = bearer
            .strip_prefix(PREFIX)
            .ok_or_else(|| anyhow!("bearer must start with okms_"))?;
        if rest.len() != 64 {
            bail!("bearer must be okms_ followed by 64 hex characters");
        }
        if !rest.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("bearer hex segment is invalid");
        }
        Ok(())
    }

    /// Labels with an active (non-revoked) pairing.
    pub async fn paired_labels(&self) -> Vec<String> {
        let data = self.inner.data.lock().await;
        data.paired
            .iter()
            .filter(|p| p.revoked_at.is_none())
            .map(|p| p.label.clone())
            .collect()
    }

    pub async fn lookup_token(&self, bearer: &str) -> Option<String> {
        let hash = Self::hash_token(bearer);
        let data = self.inner.data.lock().await;
        data.paired
            .iter()
            .find(|p| p.revoked_at.is_none() && p.token_hash == hash)
            .map(|p| p.label.clone())
    }

    pub async fn pool_summary(&self, config: &Config, admin: &AdminStore) -> Result<PoolSummary> {
        let paired = self.paired_labels().await;
        let flags = admin.snapshot().await;
        let effective = admin.effective_config(config).await?;
        let mut chains: BTreeMap<String, ChainPoolStats> = BTreeMap::new();
        let paired_set: std::collections::HashSet<_> = paired.iter().cloned().collect();

        for k in &effective.keys {
            let chain = k.chain.as_str().to_string();
            let entry = chains.entry(chain).or_insert_with(|| ChainPoolStats {
                configured: 0,
                allocatable: 0,
                paired: 0,
                reserved: 0,
                can_allocate: false,
            });
            entry.configured += 1;
            let enabled = flags
                .enabled
                .get(&k.label)
                .copied()
                .unwrap_or(k.policy.enabled);
            let is_paired = paired_set.contains(&k.label);
            if is_paired {
                entry.paired += 1;
            } else if Self::is_allocatable_key(k, enabled) {
                entry.allocatable += 1;
            } else {
                entry.reserved += 1;
            }
        }
        for stats in chains.values_mut() {
            stats.can_allocate = stats.allocatable > 0;
        }
        Ok(PoolSummary { chains })
    }

    fn is_allocatable_key(k: &KeyDef, enabled: bool) -> bool {
        k.allocatable && enabled
    }

    pub async fn list_pending(&self) -> Vec<PendingRequest> {
        let mut data = self.inner.data.lock().await;
        let now = Self::now_secs();
        Self::purge_expired_pending(&mut data, now);
        data.pending.clone()
    }

    pub async fn list_active(&self) -> Vec<ActivePairing> {
        let data = self.inner.data.lock().await;
        data.paired
            .iter()
            .filter(|p| p.revoked_at.is_none())
            .cloned()
            .collect()
    }

    pub async fn submit_request(
        &self,
        client_id: &str,
        label: Option<&str>,
        chain: Option<Chain>,
        pick: Option<PickStrategy>,
        asset: Option<PairAsset>,
        display_name: Option<&str>,
        bearer: Option<&str>,
        config: &Config,
        admin: &AdminStore,
    ) -> Result<PendingRequest> {
        if !self.inner.pairing.enabled {
            bail!("pairing is disabled");
        }
        let client_id = client_id.trim();
        if client_id.is_empty() {
            bail!("client_id is required");
        }

        let token_hash = match bearer {
            None => None,
            Some(b) => {
                let b = b.trim();
                if b.is_empty() {
                    bail!("bearer must not be empty");
                }
                Self::validate_bearer_format(b)?;
                Some(Self::hash_token(b))
            }
        };

        let now = Self::now_secs();
        let ttl = self.inner.pairing.pending_ttl_secs.max(60) as i64;
        let expires_at = now + ttl;

        let mut data = self.inner.data.lock().await;
        Self::purge_expired_pending(&mut data, now);

        if data.pending.len() >= self.inner.pairing.max_pending.max(1) {
            bail!("too many pending pairing requests");
        }

        let (request_kind, label_opt, chain_opt, pick_opt, asset_opt) =
            if let Some(lbl) = label {
                if config.keys.iter().all(|k| k.label != lbl) {
                    bail!("unknown key label {lbl:?}");
                }
                (RequestKind::Labeled, Some(lbl.to_string()), None, None, None)
            } else {
                let chain = chain.ok_or_else(|| anyhow!("chain is required for auto pairing"))?;
                let pick = pick.ok_or_else(|| anyhow!("pick is required for auto pairing"))?;
                match pick {
                    PickStrategy::Most | PickStrategy::Least => {
                        if asset.is_none() {
                            bail!("asset is required for pick=most|least");
                        }
                    }
                    PickStrategy::Random => {}
                }
                (
                    RequestKind::Auto,
                    None,
                    Some(chain.as_str().to_string()),
                    Some(pick),
                    asset,
                )
            };

        // Pool check for auto
        if request_kind == RequestKind::Auto {
            let _paired: Vec<String> = data
                .paired
                .iter()
                .filter(|p| p.revoked_at.is_none())
                .map(|p| p.label.clone())
                .collect();
            drop(data);
            let pool = self.pool_summary(config, admin).await?;
            let chain_str = chain_opt.as_deref().unwrap_or("");
            let stats = pool.chains.get(chain_str);
            if stats.is_none_or(|s| !s.can_allocate) {
                bail!("no allocatable keys for chain {chain_str}");
            }
            data = self.inner.data.lock().await;
        }

        // Labeled: reject if already paired
        if let Some(ref lbl) = label_opt {
            if data
                .paired
                .iter()
                .any(|p| p.revoked_at.is_none() && p.label == *lbl)
            {
                bail!("key {lbl} is already paired");
            }
        }

        let req = PendingRequest {
            id: Uuid::new_v4().to_string(),
            client_id: client_id.to_string(),
            request_kind,
            label: label_opt,
            chain: chain_opt,
            pick: pick_opt,
            asset: asset_opt,
            display_name: display_name.map(str::to_string),
            requested_at: now,
            expires_at,
            token_hash,
        };
        data.pending.push(req.clone());
        drop(data);
        self.persist().await?;
        Ok(req)
    }

    pub async fn reject(&self, request_id: &str) -> Result<()> {
        let mut data = self.inner.data.lock().await;
        let before = data.pending.len();
        data.pending.retain(|p| p.id != request_id);
        if data.pending.len() == before {
            bail!("pending request not found");
        }
        drop(data);
        self.persist().await
    }

    pub async fn approve(
        &self,
        request_id: &str,
        label_override: Option<&str>,
        config: &Config,
        admin: &AdminStore,
        ranker: &BalanceRanker,
        addresses: &HashMap<String, String>,
    ) -> Result<(ActivePairing, Option<String>)> {
        let mut data = self.inner.data.lock().await;
        let now = Self::now_secs();
        Self::purge_expired_pending(&mut data, now);

        let idx = data
            .pending
            .iter()
            .position(|p| p.id == request_id)
            .ok_or_else(|| anyhow!("pending request not found"))?;

        let pending = data.pending.remove(idx);
        drop(data);

        let label = self
            .resolve_label_for_approve(
                &pending,
                label_override,
                config,
                admin,
                ranker,
                addresses,
            )
            .await?;

        let (token_hash, minted_token) = if let Some(hash) = pending.token_hash.clone() {
            (hash, None)
        } else {
            let token = Self::generate_token();
            (Self::hash_token(&token), Some(token))
        };

        let pairing = ActivePairing {
            id: Uuid::new_v4().to_string(),
            client_id: pending.client_id.clone(),
            label: label.clone(),
            token_hash,
            paired_at: now,
            revoked_at: None,
        };

        let mut data = self.inner.data.lock().await;
        if data
            .paired
            .iter()
            .any(|p| p.revoked_at.is_none() && p.label == label)
        {
            bail!("key {label} is already paired");
        }
        data.paired.push(pairing.clone());
        drop(data);
        if let Some(token) = minted_token.clone() {
            self.inner
                .awaiting_pickup
                .lock()
                .await
                .insert(
                    request_id.to_string(),
                    AwaitingPickup {
                        label: label.clone(),
                        token,
                    },
                );
        }
        self.persist().await?;
        Ok((pairing, minted_token))
    }

    /// Poll pairing progress via `GET /policy/{label}?request_id=…` (no bearer).
    pub async fn poll_pairing_request(
        &self,
        request_id: &str,
        label: &str,
    ) -> PairPollOutcome {
        let now = Self::now_secs();
        let mut data = self.inner.data.lock().await;
        Self::purge_expired_pending(&mut data, now);
        if let Some(p) = data.pending.iter().find(|p| p.id == request_id) {
            let expected = p.label.as_deref().unwrap_or(label);
            if expected != label {
                return PairPollOutcome::LabelMismatch;
            }
            return PairPollOutcome::Pending {
                expires_at: p.expires_at,
            };
        }
        drop(data);

        let mut awaiting = self.inner.awaiting_pickup.lock().await;
        if let Some(pickup) = awaiting.remove(request_id) {
            if pickup.label != label {
                awaiting.insert(request_id.to_string(), pickup);
                return PairPollOutcome::LabelMismatch;
            }
            return PairPollOutcome::Ready {
                token: pickup.token,
            };
        }

        PairPollOutcome::NotFound
    }

    async fn resolve_label_for_approve(
        &self,
        pending: &PendingRequest,
        label_override: Option<&str>,
        config: &Config,
        admin: &AdminStore,
        ranker: &BalanceRanker,
        addresses: &HashMap<String, String>,
    ) -> Result<String> {
        if let Some(lbl) = label_override {
            if config.keys.iter().all(|k| k.label != lbl) {
                bail!("unknown key label {lbl:?}");
            }
            return Ok(lbl.to_string());
        }

        match pending.request_kind {
            RequestKind::Labeled => pending
                .label
                .clone()
                .ok_or_else(|| anyhow!("labeled request missing label")),
            RequestKind::Auto => {
                let chain_str = pending
                    .chain
                    .as_deref()
                    .ok_or_else(|| anyhow!("auto request missing chain"))?;
                let chain = Chain::from_str_lenient(chain_str)?;
                let pick = pending
                    .pick
                    .ok_or_else(|| anyhow!("auto request missing pick"))?;
                let candidates = self.allocatable_labels(config, admin, chain).await?;
                if candidates.is_empty() {
                    bail!("no allocatable keys for chain {chain_str}");
                }
                balance::select_label(
                    ranker,
                    chain,
                    pick,
                    pending.asset.as_ref(),
                    &candidates,
                    addresses,
                )
                .await
            }
        }
    }

    pub async fn allocatable_labels(
        &self,
        config: &Config,
        admin: &AdminStore,
        chain: Chain,
    ) -> Result<Vec<String>> {
        let paired = self.paired_labels().await;
        let paired_set: std::collections::HashSet<_> = paired.into_iter().collect();
        let flags = admin.snapshot().await;
        let effective = admin.effective_config(config).await?;
        let mut labels: Vec<String> = effective
            .keys
            .iter()
            .filter(|k| {
                k.chain == chain
                    && Self::is_allocatable_key(
                        k,
                        flags.enabled.get(&k.label).copied().unwrap_or(k.policy.enabled),
                    )
                    && !paired_set.contains(&k.label)
            })
            .map(|k| k.label.clone())
            .collect();
        labels.sort();
        Ok(labels)
    }

    pub async fn revoke(&self, pairing_id: &str) -> Result<ActivePairing> {
        let mut data = self.inner.data.lock().await;
        let now = Self::now_secs();
        let p = data
            .paired
            .iter_mut()
            .find(|p| p.id == pairing_id && p.revoked_at.is_none())
            .ok_or_else(|| anyhow!("active pairing not found"))?;
        p.revoked_at = Some(now);
        let out = p.clone();
        drop(data);
        self.persist().await?;
        Ok(out)
    }

    /// Test helper: insert an active pairing with a known bearer token.
    pub async fn seed_pairing(&self, client_id: &str, label: &str, token: &str) -> Result<()> {
        let pairing = ActivePairing {
            id: Uuid::new_v4().to_string(),
            client_id: client_id.to_string(),
            label: label.to_string(),
            token_hash: Self::hash_token(token),
            paired_at: Self::now_secs(),
            revoked_at: None,
        };
        let mut data = self.inner.data.lock().await;
        data.paired.push(pairing);
        drop(data);
        self.persist().await
    }

    pub async fn admin_pool_entries(
        &self,
        config: &Config,
        admin: &AdminStore,
        addresses: &HashMap<String, String>,
        reveal: bool,
    ) -> Result<Vec<PoolKeyEntry>> {
        let paired = self.paired_labels().await;
        let paired_set: std::collections::HashSet<_> = paired.into_iter().collect();
        let flags = admin.snapshot().await;
        let effective = admin.effective_config(config).await?;
        let mut out = Vec::new();
        for k in &effective.keys {
            let enabled = flags
                .enabled
                .get(&k.label)
                .copied()
                .unwrap_or(k.policy.enabled);
            let allocatable =
                Self::is_allocatable_key(k, enabled) && !paired_set.contains(&k.label);
            let addr = if reveal {
                addresses.get(&k.label).cloned()
            } else {
                None
            };
            out.push(PoolKeyEntry {
                label: k.label.clone(),
                chain: k.chain.as_str().to_string(),
                allocatable,
                address: addr,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuditConfig, CosmosConfig, HsmConfig, KeyPolicy, ServerConfig};
    use tempfile::TempDir;

    fn test_config(dir: &Path, keys: Vec<KeyDef>) -> Config {
        Config {
            server: ServerConfig {
                listen: "127.0.0.1:0".into(),
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
                path: dir.join("audit.log"),
                hmac_key_file: None,
            },
            cosmos: CosmosConfig::default(),
            state_dir: Some(dir.to_path_buf()),
            pairing: PairingConfig::default(),
            keys,
        }
    }

    fn sol_key(label: &str, allocatable: bool) -> KeyDef {
        KeyDef {
            label: label.into(),
            chain: Chain::Solana,
            object_id: 0x100,
            derivation_path: None,
            address_style: Default::default(),
            default_hrp: None,
            allocatable,
            policy: KeyPolicy {
                enabled: true,
                max_signs_per_minute: Some(60),
                allowed_programs: vec![crate::config::AllowedProgram {
                    id: "11111111111111111111111111111111".into(),
                    comment: None,
                }],
                ..Default::default()
            },
        }
    }

    #[tokio::test]
    async fn labeled_request_and_approve() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(
            dir.path(),
            vec![sol_key("sol-a", false), sol_key("sol-b", true)],
        );
        let admin = AdminStore::open(dir.path()).unwrap();
        let store = PairingStore::open(dir.path(), PairingConfig::default()).unwrap();
        let ranker = BalanceRanker::new(&PairingConfig::default());
        let addrs = HashMap::new();

        let req = store
            .submit_request(
                "client1",
                Some("sol-a"),
                None,
                None,
                None,
                None,
                None,
                &cfg,
                &admin,
            )
            .await
            .unwrap();
        assert_eq!(req.request_kind, RequestKind::Labeled);

        let (pairing, tok) = store
            .approve(&req.id, None, &cfg, &admin, &ranker, &addrs)
            .await
            .unwrap();
        assert_eq!(pairing.label, "sol-a");
        let tok = tok.expect("server-mint token");
        assert!(store.lookup_token(&tok).await.is_some());
    }

    #[tokio::test]
    async fn client_bearer_request_and_approve() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path(), vec![sol_key("sol-a", false)]);
        let admin = AdminStore::open(dir.path()).unwrap();
        let store = PairingStore::open(dir.path(), PairingConfig::default()).unwrap();
        let ranker = BalanceRanker::new(&PairingConfig::default());
        let addrs = HashMap::new();
        let client_bearer = PairingStore::generate_token();

        let req = store
            .submit_request(
                "client1",
                Some("sol-a"),
                None,
                None,
                None,
                None,
                Some(&client_bearer),
                &cfg,
                &admin,
            )
            .await
            .unwrap();
        assert!(req.token_hash.is_some());

        let (pairing, tok) = store
            .approve(&req.id, None, &cfg, &admin, &ranker, &addrs)
            .await
            .unwrap();
        assert_eq!(pairing.label, "sol-a");
        assert!(tok.is_none());
        assert!(store.lookup_token(&client_bearer).await.is_some());
    }

    #[tokio::test]
    async fn invalid_client_bearer_rejected() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path(), vec![sol_key("sol-a", false)]);
        let admin = AdminStore::open(dir.path()).unwrap();
        let store = PairingStore::open(dir.path(), PairingConfig::default()).unwrap();

        let err = store
            .submit_request(
                "client1",
                Some("sol-a"),
                None,
                None,
                None,
                None,
                Some("not-a-valid-bearer"),
                &cfg,
                &admin,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("okms_"));
    }

    #[tokio::test]
    async fn random_auto_picks_allocatable() {
        let dir = TempDir::new().unwrap();
        let cfg = test_config(dir.path(), vec![sol_key("sol-a", true), sol_key("sol-b", true)]);
        let admin = AdminStore::open(dir.path()).unwrap();
        let store = PairingStore::open(dir.path(), PairingConfig::default()).unwrap();
        let ranker = BalanceRanker::new(&PairingConfig::default());
        let addrs = HashMap::new();

        let req = store
            .submit_request(
                "c1",
                None,
                Some(Chain::Solana),
                Some(PickStrategy::Random),
                None,
                None,
                None,
                &cfg,
                &admin,
            )
            .await
            .unwrap();
        let (p, _) = store
            .approve(&req.id, None, &cfg, &admin, &ranker, &addrs)
            .await
            .unwrap();
        assert!(p.label == "sol-a" || p.label == "sol-b");
    }
}
