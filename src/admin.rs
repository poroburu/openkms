//! Admin plane: kill-switch endpoints for the signer.
//!
//! The admin plane is a small, separately-authenticated surface on the same
//! axum app. It lets an operator disable a key label immediately (e.g. when
//! an Openclaw worker is misbehaving) without restarting the service.
//!
//! Persistence: the current "enabled" state of every configured key is
//! mirrored into `{state_dir}/key-flags.json`. On startup the server reads
//! this file and calls [`PolicyEngine::set_enabled`] accordingly — so a
//! `disable` survives a restart.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::policy::PolicyEngine;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct KeyFlags {
    /// Map key label -> override flag. Missing labels follow the config.
    #[serde(default)]
    pub enabled: BTreeMap<String, bool>,
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
            let raw = std::fs::read_to_string(&path)
                .with_context(|| format!("read {path:?}"))?;
            serde_json::from_str::<KeyFlags>(&raw)
                .with_context(|| format!("parse {path:?}"))?
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
        tokio::fs::write(&tmp, &raw).await
            .with_context(|| format!("write tmp {tmp:?}"))?;
        tokio::fs::rename(&tmp, &self.inner.path).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::Intent;
    use crate::config::KeyDef;
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
}
