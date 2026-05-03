//! Admin plane: kill-switch endpoints for the signer.
//!
//! The admin plane is a small, separately-authenticated surface on the same
//! axum app. It lets an operator disable a key label immediately (e.g. when
//! an Openclaw worker is misbehaving) without restarting the service.
//!
//! Persistence: key enabled overrides and per-key policy overlays are mirrored
//! into `{state_dir}/key-flags.json`. On startup the server reads this file,
//! rebuilds effective policy from `config.toml` plus overlays, then calls
//! [`PolicyEngine::set_enabled`] so a `disable` survives a restart.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::{
    config::{Config, KeyPolicyPatch},
    policy::PolicyEngine,
};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KeyFlags {
    /// Map key label -> override flag. Missing labels follow the config.
    #[serde(default)]
    pub enabled: BTreeMap<String, bool>,
    /// Partial per-key policy overlays applied on top of `config.toml`.
    #[serde(default)]
    pub policy_overlays: BTreeMap<String, KeyPolicyPatch>,
}

/// On-disk-backed admin store. Clone is cheap (internal `Arc`).
#[derive(Clone)]
pub struct AdminStore {
    inner: Arc<AdminInner>,
}

struct AdminInner {
    path: PathBuf,
    flags: Mutex<KeyFlags>,
}

impl AdminStore {
    /// Open the admin store at `state_dir/key-flags.json`, creating the
    /// directory if absent. Missing file is fine — we start with an empty
    /// override set.
    pub fn open(state_dir: &std::path::Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("create state_dir {state_dir:?}"))?;
        let path = state_dir.join("key-flags.json");
        let flags = if path.exists() {
            let raw = std::fs::read_to_string(&path).with_context(|| format!("read {path:?}"))?;
            serde_json::from_str::<KeyFlags>(&raw).with_context(|| format!("parse {path:?}"))?
        } else {
            KeyFlags::default()
        };
        Ok(Self {
            inner: Arc::new(AdminInner {
                path,
                flags: Mutex::new(flags),
            }),
        })
    }

    /// Return a snapshot of the current flag map.
    pub async fn snapshot(&self) -> KeyFlags {
        self.inner.flags.lock().await.clone()
    }

    /// Apply persisted policy overlays to a baseline config snapshot.
    pub async fn effective_config(&self, baseline: &Config) -> Result<Config> {
        let flags = self.inner.flags.lock().await;
        effective_config_from_overlays(baseline, &flags.policy_overlays)
    }

    /// Store or update a partial policy overlay for a key label.
    pub async fn set_policy_overlay(
        &self,
        baseline: &Config,
        label: &str,
        patch: KeyPolicyPatch,
    ) -> Result<KeyPolicyPatch> {
        let mut flags = self.inner.flags.lock().await;
        let mut merged = flags
            .policy_overlays
            .get(label)
            .cloned()
            .unwrap_or_default();
        merged.merge(patch);
        validate_overlay(baseline, label, &merged)?;
        flags
            .policy_overlays
            .insert(label.to_string(), merged.clone());
        self.persist(&flags).await?;
        Ok(merged)
    }

    /// Clear any persisted policy overlay for a key label.
    pub async fn clear_policy_overlay(&self, label: &str) -> Result<bool> {
        let mut flags = self.inner.flags.lock().await;
        let removed = flags.policy_overlays.remove(label).is_some();
        self.persist(&flags).await?;
        Ok(removed)
    }

    /// Persist a new flag to disk. `engine` is updated synchronously in the
    /// same call so callers don't have to remember to poke both.
    pub async fn set_enabled(
        &self,
        engine: &dyn PolicyEngine,
        label: &str,
        enabled: bool,
    ) -> Result<()> {
        engine.set_enabled(label, enabled).await;

        let mut flags = self.inner.flags.lock().await;
        flags.enabled.insert(label.to_string(), enabled);
        self.persist(&flags).await?;
        Ok(())
    }

    /// Re-apply every stored flag to the engine. Call this at startup and
    /// after every `reload`.
    pub async fn apply_all(&self, engine: &dyn PolicyEngine) {
        let flags = self.inner.flags.lock().await;
        for (label, enabled) in flags.enabled.iter() {
            engine.set_enabled(label, *enabled).await;
        }
    }

    async fn persist(&self, flags: &KeyFlags) -> Result<()> {
        let raw = serde_json::to_vec_pretty(flags)?;
        // Atomic-ish replace via tmp + rename.
        let tmp = self.inner.path.with_extension("tmp");
        tokio::fs::write(&tmp, &raw)
            .await
            .with_context(|| format!("write tmp {tmp:?}"))?;
        tokio::fs::rename(&tmp, &self.inner.path)
            .await
            .with_context(|| format!("rename {tmp:?} -> {:?}", self.inner.path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&self.inner.path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&self.inner.path, perms)?;
        }
        Ok(())
    }

    pub fn path(&self) -> &std::path::Path {
        &self.inner.path
    }
}

fn effective_config_from_overlays(
    baseline: &Config,
    overlays: &BTreeMap<String, KeyPolicyPatch>,
) -> Result<Config> {
    let mut cfg = baseline.clone();
    for (label, overlay) in overlays {
        let key = cfg
            .keys
            .iter_mut()
            .find(|key| key.label == *label)
            .ok_or_else(|| anyhow::anyhow!("unknown key label {label:?} in policy overlay"))?;
        overlay.apply_to(&mut key.policy);
        baseline.validate_key_policy(label, &key.policy)?;
    }
    Ok(cfg)
}

fn validate_overlay(baseline: &Config, label: &str, overlay: &KeyPolicyPatch) -> Result<()> {
    let mut key = baseline
        .keys
        .iter()
        .find(|key| key.label == label)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("unknown key label {label:?}"))?;
    overlay.apply_to(&mut key.policy);
    baseline.validate_key_policy(label, &key.policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{Chain, Intent};
    use crate::config::{AllowedProgram, KeyDef, KeyPolicy};
    use async_trait::async_trait;
    use tempfile::TempDir;

    #[derive(Default)]
    struct MockEngine {
        log: Mutex<Vec<(String, bool)>>,
    }

    #[async_trait]
    impl PolicyEngine for MockEngine {
        async fn evaluate(
            &self,
            _key: &KeyDef,
            _intent: &(dyn Intent + Send + Sync),
        ) -> Result<(), crate::policy::PolicyError> {
            Ok(())
        }
        async fn reload(&self, _config: &crate::config::Config) {}
        async fn set_enabled(&self, label: &str, enabled: bool) {
            self.log.lock().await.push((label.to_string(), enabled));
        }
    }

    #[tokio::test]
    async fn persists_and_reapplies_flags() {
        let dir = TempDir::new().unwrap();
        let store = AdminStore::open(dir.path()).unwrap();
        let engine = MockEngine::default();
        store.set_enabled(&engine, "k1", false).await.unwrap();
        store.set_enabled(&engine, "k2", true).await.unwrap();

        // Reopen and re-apply.
        let store2 = AdminStore::open(dir.path()).unwrap();
        let snap = store2.snapshot().await;
        assert_eq!(snap.enabled.get("k1"), Some(&false));
        assert_eq!(snap.enabled.get("k2"), Some(&true));
        let engine2 = MockEngine::default();
        store2.apply_all(&engine2).await;
        let log = engine2.log.lock().await;
        assert!(log.contains(&("k1".to_string(), false)));
        assert!(log.contains(&("k2".to_string(), true)));
    }

    fn baseline_config() -> Config {
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
                path: "/tmp/audit.jsonl".into(),
                hmac_key_file: None,
            },
            cosmos: Default::default(),
            state_dir: None,
            keys: vec![KeyDef {
                label: "k1".into(),
                chain: Chain::Solana,
                object_id: 1,
                derivation_path: None,
                address_style: Default::default(),
                default_hrp: None,
                policy: KeyPolicy {
                    enabled: true,
                    allowed_programs: vec![AllowedProgram {
                        id: "11111111111111111111111111111111".into(),
                        comment: None,
                    }],
                    ..Default::default()
                },
            }],
        }
    }

    #[tokio::test]
    async fn policy_overlays_persist_and_apply_to_effective_config() {
        let dir = TempDir::new().unwrap();
        let baseline = baseline_config();
        let store = AdminStore::open(dir.path()).unwrap();
        store
            .set_policy_overlay(
                &baseline,
                "k1",
                KeyPolicyPatch {
                    max_signs_per_minute: Some(5),
                    per_tx_cap_lamports: Some("1000".into()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let reopened = AdminStore::open(dir.path()).unwrap();
        let effective = reopened.effective_config(&baseline).await.unwrap();
        assert_eq!(effective.keys[0].policy.max_signs_per_minute, Some(5));
        assert_eq!(
            effective.keys[0].policy.per_tx_cap_lamports.as_deref(),
            Some("1000")
        );
    }

    #[tokio::test]
    async fn invalid_policy_overlay_is_rejected() {
        let dir = TempDir::new().unwrap();
        let baseline = baseline_config();
        let store = AdminStore::open(dir.path()).unwrap();
        let err = store
            .set_policy_overlay(
                &baseline,
                "k1",
                KeyPolicyPatch {
                    allowed_programs: Some(vec![]),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("policy block is empty") || message.contains("allowed_programs"),
            "unexpected error: {message}"
        );
    }
}
