//! Policy engine.
//!
//! Every `/sign/*` request runs through the engine *before* touching the HSM.
//! The engine is intentionally fail-closed: anything ambiguous produces a
//! deny. The default implementation covers the rails called out in the plan
//! (rate limits, per-tx amount caps, daily caps, program/message/recipient
//! allowlists, kill-switch). More sophisticated engines (e.g. a Wasm-hosted
//! rego policy) can slot in behind the trait.
//!
//! Hot-reload: the default engine owns a [`tokio::sync::RwLock<KeyStates>`].
//! The admin layer calls [`DefaultPolicyEngine::reload`] with a fresh
//! [`Config`] and the engine rebuilds per-key state (rate limiters reset; the
//! daily-spend counters are preserved where labels still exist).

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    num::NonZeroU32,
    sync::Arc,
};

use governor::{Quota, RateLimiter, state::InMemoryState, state::direct::NotKeyed};
use governor::clock::DefaultClock;
use tokio::sync::RwLock;

use crate::{
    chain::{Chain, Intent, TokenRef},
    config::{Config, KeyDef, KeyPolicy},
};

type DirectLimiter =
    RateLimiter<NotKeyed, InMemoryState, DefaultClock, governor::middleware::NoOpMiddleware>;

/// The trait the server layer codes against. The default engine below is what
/// the runtime ships; tests and specialty engines can swap in a different
/// implementation.
#[async_trait::async_trait]
pub trait PolicyEngine: Send + Sync + 'static {
    /// Evaluate policy for a request that has been successfully decoded into
    /// an `Intent`. Returns `Ok(())` to authorize or a `PolicyError` to deny.
    async fn evaluate(
        &self,
        key: &KeyDef,
        intent: &(dyn Intent + Send + Sync),
    ) -> Result<(), PolicyError>;

    /// Replace the engine's rules with a fresh config snapshot. The existing
    /// per-key daily-spend counters are preserved so a hot-reload does not
    /// hand the caller a free second daily allowance.
    async fn reload(&self, config: &Config);

    /// Kill-switch: toggle a key's `enabled` flag at runtime. This survives
    /// until the next `reload` from config.
    async fn set_enabled(&self, label: &str, enabled: bool);
}

/// Structured denial reasons. Used both as the human error string and, in
/// metrics, as the `reason` label for the `policy_denials_total` counter.
#[derive(Clone, Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("key {0:?} is disabled")]
    KeyDisabled(String),
    #[error("rate limited ({0})")]
    RateLimited(&'static str),
    #[error("per-tx cap exceeded: {token} amount={amount} cap={cap}")]
    PerTxCapExceeded { token: String, amount: u128, cap: u128 },
    #[error("daily cap exceeded: {token} today={spent} cap={cap}")]
    DailyCapExceeded { token: String, spent: u128, cap: u128 },
    #[error("program not allowed: {0}")]
    ProgramNotAllowed(String),
    #[error("message type not allowed: {0}")]
    MessageNotAllowed(String),
    #[error("recipient not allowed: program={program} recipient={recipient}")]
    RecipientNotAllowed {
        program: String,
        recipient: String,
    },
    #[error("no policy rules configured — fail-closed")]
    NoRules,
    #[error("internal policy error: {0}")]
    Internal(String),
}

impl PolicyError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            PolicyError::KeyDisabled(_) => "key_disabled",
            PolicyError::RateLimited(_) => "rate_limited",
            PolicyError::PerTxCapExceeded { .. } => "per_tx_cap",
            PolicyError::DailyCapExceeded { .. } => "daily_cap",
            PolicyError::ProgramNotAllowed(_) => "program_not_allowed",
            PolicyError::MessageNotAllowed(_) => "msg_not_allowed",
            PolicyError::RecipientNotAllowed { .. } => "recipient_not_allowed",
            PolicyError::NoRules => "no_rules",
            PolicyError::Internal(_) => "internal",
        }
    }
}

/// Default policy engine.
///
/// Stores one [`KeyState`] per configured key label. The HashMap is replaced
/// wholesale on hot-reload; per-key mutable state (daily-spend counters,
/// enable flag) survives so long as the key label still exists.
pub struct DefaultPolicyEngine {
    /// Map key label -> state. Behind an RwLock so reload is atomic without
    /// blocking evaluates for longer than necessary.
    states: RwLock<HashMap<String, Arc<KeyState>>>,
}

/// Mutable per-key runtime state.
struct KeyState {
    policy: KeyPolicy,
    chain: Chain,
    /// Parsed per-tx cap (`amount`).
    per_tx_cap: Option<u128>,
    /// Parsed daily cap.
    daily_cap: Option<u128>,
    /// Allowed program-IDs (Solana) as a set.
    allowed_programs: HashSet<String>,
    /// Allowed message type-URLs (Cosmos) as a set.
    allowed_messages: HashSet<String>,
    /// Combined recipient allowlist (union across all entries).
    allowed_recipients: HashSet<String>,
    /// Rate limiters per-window (optional).
    lim_minute: Option<DirectLimiter>,
    lim_hour: Option<DirectLimiter>,
    lim_day: Option<DirectLimiter>,
    /// Runtime mutable state protected by its own mutex.
    runtime: RwLock<KeyRuntime>,
}

#[derive(Default)]
struct KeyRuntime {
    /// Runtime kill-switch override (None = follow config flag).
    enabled_override: Option<bool>,
    /// Per-token cumulative spend, keyed by token's human string. We track
    /// (`day_unix`, `amount`) so we can reset at midnight UTC.
    daily_spend: BTreeMap<String, (i64, u128)>,
}

impl KeyState {
    fn is_enabled(&self, runtime: &KeyRuntime) -> bool {
        runtime.enabled_override.unwrap_or(self.policy.enabled)
    }
}

impl DefaultPolicyEngine {
    pub fn new(config: &Config) -> Self {
        let states = build_states(config, &HashMap::new());
        Self {
            states: RwLock::new(states),
        }
    }
}

#[async_trait::async_trait]
impl PolicyEngine for DefaultPolicyEngine {
    async fn evaluate(
        &self,
        key: &KeyDef,
        intent: &(dyn Intent + Send + Sync),
    ) -> Result<(), PolicyError> {
        let states = self.states.read().await;
        let state = states
            .get(&key.label)
            .cloned()
            .ok_or_else(|| PolicyError::Internal(format!("unknown key label {:?}", key.label)))?;
        // Drop the outer read-lock ASAP.
        drop(states);

        // Kill-switch.
        {
            let rt = state.runtime.read().await;
            if !state.is_enabled(&rt) {
                return Err(PolicyError::KeyDisabled(key.label.clone()));
            }
        }

        // Rate limits — evaluated in ascending window order so the smallest
        // window produces the reason string when multiple trip at once.
        for (lim, window) in [
            (&state.lim_minute, "per_minute"),
            (&state.lim_hour, "per_hour"),
            (&state.lim_day, "per_day"),
        ] {
            if let Some(lim) = lim {
                if lim.check().is_err() {
                    return Err(PolicyError::RateLimited(window));
                }
            }
        }

        // Per-tx amount cap: sum all outgoing transfers (native token).
        let native_sum: u128 = intent
            .outgoing_transfers()
            .iter()
            .filter(|t| matches!(t.token, TokenRef::Native(_)))
            .map(|t| t.amount)
            .sum();
        if let Some(cap) = state.per_tx_cap {
            if native_sum > cap {
                return Err(PolicyError::PerTxCapExceeded {
                    token: "native".into(),
                    amount: native_sum,
                    cap,
                });
            }
        }

        // Allowlists per chain.
        match state.chain {
            Chain::Solana => {
                for p in intent.invoked_programs() {
                    if !state.allowed_programs.contains(&p.id) {
                        return Err(PolicyError::ProgramNotAllowed(p.id.clone()));
                    }
                }
            }
            Chain::Cosmos => {
                for t in intent.message_types() {
                    if !state.allowed_messages.contains(t) {
                        return Err(PolicyError::MessageNotAllowed(t.clone()));
                    }
                }
            }
            Chain::Unknown => {
                return Err(PolicyError::Internal("unknown chain".into()));
            }
        }

        // Recipient allowlist (union across AllowedRecipient entries). If
        // configured, every outgoing transfer recipient must appear in the
        // union. If not configured, no recipient check runs.
        if !state.allowed_recipients.is_empty() {
            for t in intent.outgoing_transfers() {
                if !state.allowed_recipients.contains(&t.recipient) {
                    return Err(PolicyError::RecipientNotAllowed {
                        program: t.kind.to_string(),
                        recipient: t.recipient.clone(),
                    });
                }
            }
        }

        // Daily cap: update per-token spend counters for today (UTC). Any
        // transfer that would push the running total over the cap denies.
        if let Some(cap) = state.daily_cap {
            let today = unix_day_utc();
            let mut rt = state.runtime.write().await;
            // Reset counters whose day-bucket is stale.
            for (_, (day, amount)) in rt.daily_spend.iter_mut() {
                if *day != today {
                    *day = today;
                    *amount = 0;
                }
            }
            let native_label = "native".to_string();
            let entry = rt.daily_spend.entry(native_label.clone()).or_insert((today, 0));
            let projected = entry.1.saturating_add(native_sum);
            if projected > cap {
                return Err(PolicyError::DailyCapExceeded {
                    token: native_label,
                    spent: projected,
                    cap,
                });
            }
            entry.1 = projected;
        }

        Ok(())
    }

    async fn reload(&self, config: &Config) {
        let old = self.states.read().await;
        // Snapshot the runtime state we want to preserve across reload.
        let mut preserved: HashMap<String, KeyRuntime> = HashMap::new();
        for (label, state) in old.iter() {
            let rt = state.runtime.read().await;
            preserved.insert(
                label.clone(),
                KeyRuntime {
                    enabled_override: rt.enabled_override,
                    daily_spend: rt.daily_spend.clone(),
                },
            );
        }
        drop(old);

        let fresh = build_states(config, &preserved);
        let mut slot = self.states.write().await;
        *slot = fresh;
    }

    async fn set_enabled(&self, label: &str, enabled: bool) {
        let states = self.states.read().await;
        if let Some(state) = states.get(label) {
            let mut rt = state.runtime.write().await;
            rt.enabled_override = Some(enabled);
        }
    }
}

fn build_states(
    config: &Config,
    preserved: &HashMap<String, KeyRuntime>,
) -> HashMap<String, Arc<KeyState>> {
    let mut out = HashMap::with_capacity(config.keys.len());
    for k in &config.keys {
        let per_tx_cap = parse_u128(k.policy.per_tx_cap_lamports.as_deref());
        let daily_cap = parse_u128(k.policy.daily_cap_lamports.as_deref());

        let allowed_programs: HashSet<String> =
            k.policy.allowed_programs.iter().map(|p| p.id.clone()).collect();
        let allowed_messages: HashSet<String> =
            k.policy.allowed_messages.iter().map(|m| m.type_url.clone()).collect();
        let allowed_recipients: HashSet<String> = k
            .policy
            .allowed_recipients
            .iter()
            .flat_map(|r| r.addresses.iter().cloned())
            .collect();

        let lim_minute = k
            .policy
            .max_signs_per_minute
            .and_then(NonZeroU32::new)
            .map(|nz| RateLimiter::direct(Quota::per_minute(nz)));
        let lim_hour = k
            .policy
            .max_signs_per_hour
            .and_then(NonZeroU32::new)
            .map(|nz| RateLimiter::direct(Quota::per_hour(nz)));
        let lim_day = k.policy.max_signs_per_day.and_then(NonZeroU32::new).map(|nz| {
            // governor doesn't ship a `per_day` helper; 1-day = 24h.
            let quota = Quota::with_period(std::time::Duration::from_secs(86_400 / u64::from(nz.get())))
                .expect("non-zero period")
                .allow_burst(nz);
            RateLimiter::direct(quota)
        });

        let runtime = preserved
            .get(&k.label)
            .map(|rt| KeyRuntime {
                enabled_override: rt.enabled_override,
                daily_spend: rt.daily_spend.clone(),
            })
            .unwrap_or_default();

        let state = Arc::new(KeyState {
            policy: k.policy.clone(),
            chain: k.chain,
            per_tx_cap,
            daily_cap,
            allowed_programs,
            allowed_messages,
            allowed_recipients,
            lim_minute,
            lim_hour,
            lim_day,
            runtime: RwLock::new(runtime),
        });
        out.insert(k.label.clone(), state);
    }
    out
}

fn parse_u128(s: Option<&str>) -> Option<u128> {
    s.and_then(|v| v.trim().parse::<u128>().ok())
}

fn unix_day_utc() -> i64 {
    chrono::Utc::now().date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc().timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{ProgramRef, Transfer};
    use crate::config::{
        AddressStyle, AllowedMessage, AllowedProgram, AllowedRecipient, CosmosConfig,
        KeyDef as ConfigKey, KeyPolicy,
    };

    /// Hand-rolled intent that mirrors what a chain signer would produce. We
    /// construct it directly to keep tests independent of Solana/Cosmos code.
    #[derive(Debug)]
    struct TestIntent {
        chain_id: String,
        signer_address: String,
        transfers: Vec<Transfer>,
        programs: Vec<ProgramRef>,
        message_types: Vec<String>,
    }

    impl Intent for TestIntent {
        fn chain_id(&self) -> &str {
            &self.chain_id
        }
        fn signer_address(&self) -> &str {
            &self.signer_address
        }
        fn outgoing_transfers(&self) -> &[Transfer] {
            &self.transfers
        }
        fn invoked_programs(&self) -> &[ProgramRef] {
            &self.programs
        }
        fn message_types(&self) -> &[String] {
            &self.message_types
        }
        fn human_summary(&self) -> String {
            "test".into()
        }
        fn signing_digest(&self) -> &[u8] {
            &[]
        }
    }

    fn base_config(chain: Chain, policy: KeyPolicy) -> Config {
        Config {
            server: crate::config::ServerConfig {
                listen: "127.0.0.1:0".into(),
                signer_token_file: "/tmp/x".into(),
                admin_token_file: "/tmp/x".into(),
                inflight_limit: 1,
                replay_window_secs: 1,
            },
            hsm: crate::config::HsmConfig {
                connector_url: "http://x".into(),
                auth_key_id: 3,
                password_file: "/tmp/x".into(),
            },
            audit: crate::config::AuditConfig {
                path: "/tmp/a".into(),
                hmac_key_file: None,
            },
            cosmos: CosmosConfig::default(),
            state_dir: None,
            keys: vec![ConfigKey {
                label: "k1".into(),
                chain,
                object_id: 1,
                derivation_path: None,
                address_style: AddressStyle::Cosmos,
                default_hrp: None,
                policy,
            }],
        }
    }

    fn solana_intent(program_id: &str, amount: u128, recipient: &str) -> TestIntent {
        TestIntent {
            chain_id: "solana".into(),
            signer_address: "signer".into(),
            transfers: vec![Transfer {
                token: TokenRef::Native("sol".into()),
                amount,
                recipient: recipient.into(),
                kind: "SystemProgram::Transfer",
            }],
            programs: vec![ProgramRef {
                id: program_id.into(),
                method: None,
            }],
            message_types: vec!["SystemProgram::Transfer".into()],
        }
    }

    fn cosmos_intent(msg_type: &str, amount: u128, recipient: &str) -> TestIntent {
        TestIntent {
            chain_id: "cosmoshub-4".into(),
            signer_address: "signer".into(),
            transfers: vec![Transfer {
                token: TokenRef::Native("uatom".into()),
                amount,
                recipient: recipient.into(),
                kind: "cosmos.bank.MsgSend",
            }],
            programs: vec![ProgramRef {
                id: msg_type.into(),
                method: None,
            }],
            message_types: vec![msg_type.into()],
        }
    }

    #[tokio::test]
    async fn disabled_key_is_denied() {
        let policy = KeyPolicy {
            enabled: false,
            allowed_programs: vec![AllowedProgram {
                id: "P".into(),
                comment: None,
            }],
            ..Default::default()
        };
        let cfg = base_config(Chain::Solana, policy);
        let eng = DefaultPolicyEngine::new(&cfg);
        let intent = solana_intent("P", 0, "R");
        let err = eng.evaluate(&cfg.keys[0], &intent).await.unwrap_err();
        assert!(matches!(err, PolicyError::KeyDisabled(_)));
    }

    #[tokio::test]
    async fn program_not_in_allowlist_is_denied() {
        let policy = KeyPolicy {
            enabled: true,
            allowed_programs: vec![AllowedProgram {
                id: "ALLOWED".into(),
                comment: None,
            }],
            ..Default::default()
        };
        let cfg = base_config(Chain::Solana, policy);
        let eng = DefaultPolicyEngine::new(&cfg);
        let intent = solana_intent("DIFFERENT", 0, "R");
        let err = eng.evaluate(&cfg.keys[0], &intent).await.unwrap_err();
        assert!(matches!(err, PolicyError::ProgramNotAllowed(_)));
    }

    #[tokio::test]
    async fn allowed_program_passes() {
        let policy = KeyPolicy {
            enabled: true,
            allowed_programs: vec![AllowedProgram {
                id: "P".into(),
                comment: None,
            }],
            ..Default::default()
        };
        let cfg = base_config(Chain::Solana, policy);
        let eng = DefaultPolicyEngine::new(&cfg);
        let intent = solana_intent("P", 100, "R");
        eng.evaluate(&cfg.keys[0], &intent).await.unwrap();
    }

    #[tokio::test]
    async fn per_tx_cap_exceeded() {
        let policy = KeyPolicy {
            enabled: true,
            per_tx_cap_lamports: Some("500".into()),
            allowed_programs: vec![AllowedProgram {
                id: "P".into(),
                comment: None,
            }],
            ..Default::default()
        };
        let cfg = base_config(Chain::Solana, policy);
        let eng = DefaultPolicyEngine::new(&cfg);
        let intent = solana_intent("P", 1_000, "R");
        let err = eng.evaluate(&cfg.keys[0], &intent).await.unwrap_err();
        assert!(matches!(err, PolicyError::PerTxCapExceeded { .. }));
    }

    #[tokio::test]
    async fn daily_cap_accumulates_and_trips() {
        let policy = KeyPolicy {
            enabled: true,
            daily_cap_lamports: Some("150".into()),
            allowed_programs: vec![AllowedProgram {
                id: "P".into(),
                comment: None,
            }],
            ..Default::default()
        };
        let cfg = base_config(Chain::Solana, policy);
        let eng = DefaultPolicyEngine::new(&cfg);
        // 100 + 40 is fine, next 20 trips the cap.
        eng.evaluate(&cfg.keys[0], &solana_intent("P", 100, "R"))
            .await
            .unwrap();
        eng.evaluate(&cfg.keys[0], &solana_intent("P", 40, "R"))
            .await
            .unwrap();
        let err = eng
            .evaluate(&cfg.keys[0], &solana_intent("P", 20, "R"))
            .await
            .unwrap_err();
        assert!(matches!(err, PolicyError::DailyCapExceeded { .. }));
    }

    #[tokio::test]
    async fn rate_limit_per_minute() {
        let policy = KeyPolicy {
            enabled: true,
            max_signs_per_minute: Some(1),
            allowed_programs: vec![AllowedProgram {
                id: "P".into(),
                comment: None,
            }],
            ..Default::default()
        };
        let cfg = base_config(Chain::Solana, policy);
        let eng = DefaultPolicyEngine::new(&cfg);
        eng.evaluate(&cfg.keys[0], &solana_intent("P", 0, "R"))
            .await
            .unwrap();
        let err = eng
            .evaluate(&cfg.keys[0], &solana_intent("P", 0, "R"))
            .await
            .unwrap_err();
        assert!(matches!(err, PolicyError::RateLimited(_)));
    }

    #[tokio::test]
    async fn cosmos_msg_not_allowed() {
        let policy = KeyPolicy {
            enabled: true,
            allowed_messages: vec![AllowedMessage {
                type_url: "/allowed.Msg".into(),
                per_tx_cap: None,
                allowed_recipients: vec![],
                allowed_contracts: vec![],
                allowed_methods: vec![],
                comment: None,
            }],
            ..Default::default()
        };
        let cfg = base_config(Chain::Cosmos, policy);
        let eng = DefaultPolicyEngine::new(&cfg);
        let intent = cosmos_intent("/cosmos.bank.v1beta1.MsgSend", 0, "r");
        let err = eng.evaluate(&cfg.keys[0], &intent).await.unwrap_err();
        assert!(matches!(err, PolicyError::MessageNotAllowed(_)));
    }

    #[tokio::test]
    async fn recipient_allowlist_enforced() {
        let policy = KeyPolicy {
            enabled: true,
            allowed_programs: vec![AllowedProgram {
                id: "P".into(),
                comment: None,
            }],
            allowed_recipients: vec![AllowedRecipient {
                program: "transfer".into(),
                addresses: vec!["ALLOWED".into()],
            }],
            ..Default::default()
        };
        let cfg = base_config(Chain::Solana, policy);
        let eng = DefaultPolicyEngine::new(&cfg);
        let err = eng
            .evaluate(&cfg.keys[0], &solana_intent("P", 1, "WRONG"))
            .await
            .unwrap_err();
        assert!(matches!(err, PolicyError::RecipientNotAllowed { .. }));
        eng.evaluate(&cfg.keys[0], &solana_intent("P", 1, "ALLOWED"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn admin_kill_switch_and_reload_preserves_counters() {
        let policy = KeyPolicy {
            enabled: true,
            daily_cap_lamports: Some("1000".into()),
            allowed_programs: vec![AllowedProgram {
                id: "P".into(),
                comment: None,
            }],
            ..Default::default()
        };
        let cfg = base_config(Chain::Solana, policy.clone());
        let eng = DefaultPolicyEngine::new(&cfg);
        eng.evaluate(&cfg.keys[0], &solana_intent("P", 700, "R"))
            .await
            .unwrap();

        // kill switch
        eng.set_enabled("k1", false).await;
        let err = eng
            .evaluate(&cfg.keys[0], &solana_intent("P", 1, "R"))
            .await
            .unwrap_err();
        assert!(matches!(err, PolicyError::KeyDisabled(_)));

        // reload with the same label — enabled override + counter should persist
        eng.reload(&cfg).await;
        let err = eng
            .evaluate(&cfg.keys[0], &solana_intent("P", 1, "R"))
            .await
            .unwrap_err();
        assert!(matches!(err, PolicyError::KeyDisabled(_)));

        eng.set_enabled("k1", true).await;
        // already spent 700; 400 more would trip 1000
        let err = eng
            .evaluate(&cfg.keys[0], &solana_intent("P", 400, "R"))
            .await
            .unwrap_err();
        assert!(matches!(err, PolicyError::DailyCapExceeded { .. }));
    }
}
