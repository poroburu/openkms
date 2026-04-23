//! Replay cache for signing requests.
//!
//! Purpose: when an Openclaw worker retries a transient failure it should not
//! spend HSM cycles re-signing the same `Intent`. We hash the exact bytes the
//! HSM would sign (the intent's `signing_digest`) and cache the response.
//!
//! Determinism note:
//!   * Ed25519 (Solana) is deterministic by construction (RFC 8032 §5.1.6):
//!     same key + same message ⇒ byte-identical signature.
//!   * ECDSA over secp256k1 is *not* deterministic in the generic case, but
//!     the YubiHSM2 implements RFC-6979 deterministic nonces. A given
//!     (key, prehash) pair therefore also produces a byte-identical
//!     signature.
//!
//! Consequence: caching the previous response and returning it on a repeat
//! request is observationally equivalent to re-signing — except we avoid the
//! HSM round-trip and we avoid bumping the per-key rate-limit bucket twice
//! for what is logically a single operation.
//!
//! The cache is bounded LRU with a wall-clock expiry; callers configure the
//! retention window (`replay_window_secs`) in the main config.

use std::{
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use sha2::{Digest, Sha256};

pub type DigestHash = [u8; 32];

/// A cached sign response, sized small because Ed25519 (64B) and secp256k1
/// compact (64B) are both short.
#[derive(Clone, Debug)]
pub struct CachedResponse {
    pub signature: Vec<u8>,
    pub body_json: serde_json::Value,
}

struct Entry {
    inserted_at: std::time::Instant,
    response: CachedResponse,
}

/// Bounded LRU with TTL. Clone is cheap (internal `Arc`).
#[derive(Clone)]
pub struct ReplayCache {
    inner: Arc<Mutex<lru::LruCache<DigestHash, Entry>>>,
    ttl: Duration,
}

impl ReplayCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).expect("capacity >= 1");
        Self {
            inner: Arc::new(Mutex::new(lru::LruCache::new(cap))),
            ttl,
        }
    }

    /// Hash the prehash / full bytes the HSM will sign.
    pub fn digest_key(prehash_or_bytes: &[u8]) -> DigestHash {
        let out = Sha256::digest(prehash_or_bytes);
        let mut k = [0u8; 32];
        k.copy_from_slice(&out);
        k
    }

    /// Look up a cached response if the entry is still within the TTL window.
    pub fn get(&self, key: &DigestHash) -> Option<CachedResponse> {
        let mut guard = self.inner.lock().expect("replay cache poisoned");
        match guard.get(key) {
            Some(entry) if entry.inserted_at.elapsed() <= self.ttl => Some(entry.response.clone()),
            Some(_) => {
                // Stale — remove so we don't keep ageing it.
                guard.pop(key);
                None
            }
            None => None,
        }
    }

    pub fn insert(&self, key: DigestHash, response: CachedResponse) {
        let mut guard = self.inner.lock().expect("replay cache poisoned");
        guard.put(
            key,
            Entry {
                inserted_at: std::time::Instant::now(),
                response,
            },
        );
    }

    /// Current cache size (for metrics / introspection).
    pub fn len(&self) -> usize {
        self.inner.lock().expect("replay cache poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inserts_and_retrieves() {
        let cache = ReplayCache::new(4, Duration::from_secs(10));
        let k = ReplayCache::digest_key(b"some-intent-bytes");
        assert!(cache.get(&k).is_none());
        cache.insert(
            k,
            CachedResponse {
                signature: vec![1, 2, 3, 4],
                body_json: serde_json::json!({"ok": true}),
            },
        );
        let hit = cache.get(&k).expect("should hit");
        assert_eq!(hit.signature, vec![1, 2, 3, 4]);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn ttl_expiry_evicts_stale_entries() {
        let cache = ReplayCache::new(4, Duration::from_millis(1));
        let k = ReplayCache::digest_key(b"x");
        cache.insert(
            k,
            CachedResponse {
                signature: vec![9],
                body_json: serde_json::json!({}),
            },
        );
        std::thread::sleep(Duration::from_millis(10));
        assert!(cache.get(&k).is_none(), "stale entry should have evicted");
    }

    #[test]
    fn lru_eviction_when_capacity_reached() {
        let cache = ReplayCache::new(2, Duration::from_secs(60));
        let k1 = ReplayCache::digest_key(b"1");
        let k2 = ReplayCache::digest_key(b"2");
        let k3 = ReplayCache::digest_key(b"3");
        cache.insert(
            k1,
            CachedResponse {
                signature: vec![1],
                body_json: serde_json::json!({}),
            },
        );
        cache.insert(
            k2,
            CachedResponse {
                signature: vec![2],
                body_json: serde_json::json!({}),
            },
        );
        // Access k1 to mark it MRU.
        let _ = cache.get(&k1);
        cache.insert(
            k3,
            CachedResponse {
                signature: vec![3],
                body_json: serde_json::json!({}),
            },
        );
        // k2 should have been evicted.
        assert!(cache.get(&k2).is_none());
        assert!(cache.get(&k1).is_some());
        assert!(cache.get(&k3).is_some());
    }
}
