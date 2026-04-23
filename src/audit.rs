//! Append-only JSONL audit log.
//!
//! Every sign / policy decision is written as a single newline-terminated JSON
//! record. The schema is deliberately flat so `jq` and log shippers can carve
//! fields without knowing the Rust types.
//!
//! When `hmac_key_file` is configured, each record also gets an `hmac` field
//! equal to `HMAC-SHA256(key, prev_hmac || serialized_record_without_hmac)`.
//! That lets downstream auditors detect silent truncation: you either see the
//! whole chain reproduce, or you see a break.

use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use crate::{
    chain::{Chain, Intent, ProgramRef, Transfer},
    config::AuditConfig,
    policy::PolicyError,
};

type HmacSha256 = Hmac<Sha256>;

/// Complete audit record emitted per sign attempt (allow or deny).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditRecord {
    /// RFC3339 UTC timestamp.
    pub timestamp: String,
    /// Caller-assigned request ID (mirrors `X-Request-Id`).
    pub request_id: String,
    pub key_label: String,
    pub chain: String,
    pub chain_id: String,
    pub signer_address: String,
    pub decision: Decision,
    /// `key_disabled`, `rate_limited`, ... — see [`PolicyError::reason_code`].
    /// Empty string on allow.
    pub deny_reason: String,
    pub deny_detail: String,
    pub message_types: Vec<String>,
    pub invoked_programs: Vec<ProgramView>,
    pub outgoing_transfers: Vec<TransferView>,
    pub human_summary: String,
    /// Hex-encoded SHA256 of the exact bytes the HSM signed.
    pub signing_digest_sha256: String,
    /// Hex-encoded SHA256 of the signature returned to the caller. Empty on
    /// deny or when signing is skipped.
    pub signature_sha256: String,
    /// HMAC chain value — filled in by [`AuditLog::append`] if enabled.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub hmac: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramView {
    pub id: String,
    pub method: Option<String>,
}

impl From<&ProgramRef> for ProgramView {
    fn from(p: &ProgramRef) -> Self {
        Self {
            id: p.id.clone(),
            method: p.method.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferView {
    pub token: String,
    pub amount: String,
    pub recipient: String,
    pub kind: String,
}

impl From<&Transfer> for TransferView {
    fn from(t: &Transfer) -> Self {
        Self {
            token: t.token.human(),
            amount: t.amount.to_string(),
            recipient: t.recipient.clone(),
            kind: t.kind.to_string(),
        }
    }
}

/// Append-only audit log. Clone is cheap (`Arc` inside).
#[derive(Clone)]
pub struct AuditLog {
    inner: Arc<AuditInner>,
}

struct AuditInner {
    path: PathBuf,
    writer: Mutex<BufWriter<File>>,
    hmac_key: Option<Vec<u8>>,
    /// Last-record HMAC (hex) — used as the prev value for the next record.
    last_hmac: Mutex<String>,
}

impl AuditLog {
    /// Open (creating if necessary) the audit file at `cfg.path` in append
    /// mode. The caller is expected to ensure the surrounding directory has
    /// appropriate permissions; the file itself is created `0600`.
    pub fn open(cfg: &AuditConfig) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&cfg.path)
            .with_context(|| format!("failed to open audit log {:?}", cfg.path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata()?.permissions();
            if perms.mode() & 0o777 != 0o600 {
                perms.set_mode(0o600);
                std::fs::set_permissions(&cfg.path, perms)?;
            }
        }
        let hmac_key = cfg
            .hmac_key_file
            .as_ref()
            .map(|p| {
                let raw = std::fs::read(p)
                    .with_context(|| format!("failed to read hmac key file {p:?}"))?;
                Ok::<_, anyhow::Error>(raw)
            })
            .transpose()?;
        Ok(Self {
            inner: Arc::new(AuditInner {
                path: cfg.path.clone(),
                writer: Mutex::new(BufWriter::new(file)),
                hmac_key,
                last_hmac: Mutex::new(String::new()),
            }),
        })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.inner.path
    }

    /// Build an allow record from an intent that passed policy, plus the
    /// signature that was returned.
    pub fn build_allow(
        request_id: &str,
        key_label: &str,
        chain: Chain,
        intent: &(dyn Intent + Send + Sync),
        signature_bytes: &[u8],
    ) -> AuditRecord {
        build_record(
            request_id,
            key_label,
            chain,
            intent,
            Decision::Allow,
            "",
            "",
            Some(signature_bytes),
        )
    }

    /// Build a deny record for a decoded intent + the PolicyError that
    /// rejected it. `intent` is optional so purely-decode-level failures can
    /// also be logged (in which case chain-specific fields are empty).
    pub fn build_deny(
        request_id: &str,
        key_label: &str,
        chain: Chain,
        intent: Option<&(dyn Intent + Send + Sync)>,
        err: &PolicyError,
    ) -> AuditRecord {
        let detail = err.to_string();
        match intent {
            Some(i) => build_record(
                request_id,
                key_label,
                chain,
                i,
                Decision::Deny,
                err.reason_code(),
                &detail,
                None,
            ),
            None => AuditRecord {
                timestamp: now_rfc3339(),
                request_id: request_id.to_string(),
                key_label: key_label.to_string(),
                chain: chain.as_str().to_string(),
                chain_id: String::new(),
                signer_address: String::new(),
                decision: Decision::Deny,
                deny_reason: err.reason_code().to_string(),
                deny_detail: detail,
                message_types: vec![],
                invoked_programs: vec![],
                outgoing_transfers: vec![],
                human_summary: String::new(),
                signing_digest_sha256: String::new(),
                signature_sha256: String::new(),
                hmac: String::new(),
            },
        }
    }

    /// Append a record to the log, computing an HMAC chain link if configured.
    /// The `hmac` field on the passed record is set in place and the caller
    /// can inspect it (useful for tests).
    pub async fn append(&self, mut rec: AuditRecord) -> Result<AuditRecord> {
        if let Some(key) = self.inner.hmac_key.as_ref() {
            let prev = self.inner.last_hmac.lock().await.clone();
            let serialized_no_hmac = {
                let tmp = rec.clone();
                serde_json::to_vec(&AuditRecordNoHmac::from(&tmp))?
            };
            let mut mac =
                HmacSha256::new_from_slice(key).map_err(|e| anyhow::anyhow!("hmac new: {e}"))?;
            mac.update(prev.as_bytes());
            mac.update(&serialized_no_hmac);
            let tag = mac.finalize().into_bytes();
            let hex = hex::encode(tag);
            rec.hmac = hex.clone();
            *self.inner.last_hmac.lock().await = hex;
        }

        let mut line = serde_json::to_vec(&rec)?;
        line.push(b'\n');

        let mut w = self.inner.writer.lock().await;
        w.write_all(&line)
            .with_context(|| format!("failed to write to audit log {:?}", self.inner.path))?;
        w.flush().ok();
        Ok(rec)
    }
}

fn build_record(
    request_id: &str,
    key_label: &str,
    chain: Chain,
    intent: &(dyn Intent + Send + Sync),
    decision: Decision,
    deny_reason: &str,
    deny_detail: &str,
    signature: Option<&[u8]>,
) -> AuditRecord {
    let digest_hex = hex::encode(Sha256::digest(intent.signing_digest()));
    let sig_hex = signature
        .map(|s| hex::encode(Sha256::digest(s)))
        .unwrap_or_default();
    AuditRecord {
        timestamp: now_rfc3339(),
        request_id: request_id.to_string(),
        key_label: key_label.to_string(),
        chain: chain.as_str().to_string(),
        chain_id: intent.chain_id().to_string(),
        signer_address: intent.signer_address().to_string(),
        decision,
        deny_reason: deny_reason.to_string(),
        deny_detail: deny_detail.to_string(),
        message_types: intent.message_types().to_vec(),
        invoked_programs: intent.invoked_programs().iter().map(Into::into).collect(),
        outgoing_transfers: intent.outgoing_transfers().iter().map(Into::into).collect(),
        human_summary: intent.human_summary(),
        signing_digest_sha256: digest_hex,
        signature_sha256: sig_hex,
        hmac: String::new(),
    }
}

/// Mirror of AuditRecord without the `hmac` field (used for MAC computation).
#[derive(Serialize)]
struct AuditRecordNoHmac<'a> {
    timestamp: &'a str,
    request_id: &'a str,
    key_label: &'a str,
    chain: &'a str,
    chain_id: &'a str,
    signer_address: &'a str,
    decision: Decision,
    deny_reason: &'a str,
    deny_detail: &'a str,
    message_types: &'a [String],
    invoked_programs: &'a [ProgramView],
    outgoing_transfers: &'a [TransferView],
    human_summary: &'a str,
    signing_digest_sha256: &'a str,
    signature_sha256: &'a str,
}

impl<'a> From<&'a AuditRecord> for AuditRecordNoHmac<'a> {
    fn from(r: &'a AuditRecord) -> Self {
        Self {
            timestamp: &r.timestamp,
            request_id: &r.request_id,
            key_label: &r.key_label,
            chain: &r.chain,
            chain_id: &r.chain_id,
            signer_address: &r.signer_address,
            decision: r.decision,
            deny_reason: &r.deny_reason,
            deny_detail: &r.deny_detail,
            message_types: &r.message_types,
            invoked_programs: &r.invoked_programs,
            outgoing_transfers: &r.outgoing_transfers,
            human_summary: &r.human_summary,
            signing_digest_sha256: &r.signing_digest_sha256,
            signature_sha256: &r.signature_sha256,
        }
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{Intent, ProgramRef};
    use tempfile::TempDir;

    #[derive(Debug)]
    struct MockIntent;
    impl Intent for MockIntent {
        fn chain_id(&self) -> &str {
            "cosmoshub-4"
        }
        fn signer_address(&self) -> &str {
            "cosmos1abc"
        }
        fn outgoing_transfers(&self) -> &[Transfer] {
            static T: [Transfer; 0] = [];
            &T
        }
        fn invoked_programs(&self) -> &[ProgramRef] {
            static P: [ProgramRef; 0] = [];
            &P
        }
        fn message_types(&self) -> &[String] {
            static M: [String; 0] = [];
            &M
        }
        fn human_summary(&self) -> String {
            "mock".into()
        }
        fn signing_digest(&self) -> &[u8] {
            b"hello"
        }
    }

    #[tokio::test]
    async fn appends_allow_record_jsonl() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        let cfg = AuditConfig {
            path: path.clone(),
            hmac_key_file: None,
        };
        let log = AuditLog::open(&cfg).unwrap();
        let intent = MockIntent;
        let rec = AuditLog::build_allow("r1", "k1", Chain::Cosmos, &intent, b"sig");
        let written = log.append(rec).await.unwrap();
        assert_eq!(written.decision, Decision::Allow);
        assert!(written.hmac.is_empty());

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.ends_with('\n'));
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["decision"], "allow");
        assert_eq!(parsed["chain"], "cosmos");
        assert_eq!(parsed["key_label"], "k1");
        assert!(parsed["signing_digest_sha256"].as_str().unwrap().len() == 64);
        assert!(parsed["signature_sha256"].as_str().unwrap().len() == 64);
    }

    #[tokio::test]
    async fn hmac_chain_links_records() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        let key_file = dir.path().join("key");
        std::fs::write(&key_file, b"super-secret-key").unwrap();

        let cfg = AuditConfig {
            path: path.clone(),
            hmac_key_file: Some(key_file),
        };
        let log = AuditLog::open(&cfg).unwrap();
        let intent = MockIntent;

        let r1 = log
            .append(AuditLog::build_allow(
                "r1",
                "k1",
                Chain::Cosmos,
                &intent,
                b"s1",
            ))
            .await
            .unwrap();
        let r2 = log
            .append(AuditLog::build_allow(
                "r2",
                "k1",
                Chain::Cosmos,
                &intent,
                b"s2",
            ))
            .await
            .unwrap();

        assert_eq!(r1.hmac.len(), 64);
        assert_eq!(r2.hmac.len(), 64);
        assert_ne!(r1.hmac, r2.hmac, "hmac should chain across records");

        // Record 2's MAC depends on Record 1's MAC — any tamper break detectable.
        let raw = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = raw.trim().lines().collect();
        assert_eq!(lines.len(), 2);
        let p1: AuditRecord = serde_json::from_str(lines[0]).unwrap();
        let p2: AuditRecord = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(p1.hmac, r1.hmac);
        assert_eq!(p2.hmac, r2.hmac);
    }

    #[tokio::test]
    async fn deny_record_without_intent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.log");
        let cfg = AuditConfig {
            path: path.clone(),
            hmac_key_file: None,
        };
        let log = AuditLog::open(&cfg).unwrap();
        let err = PolicyError::KeyDisabled("k1".into());
        let rec = AuditLog::build_deny("r", "k1", Chain::Solana, None, &err);
        let _ = log.append(rec).await.unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let p: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(p["decision"], "deny");
        assert_eq!(p["deny_reason"], "key_disabled");
    }
}
