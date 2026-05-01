//! Emit a JSON body for `POST /sign/solana` or `/sign/cosmos`, then print
//! `base64 -w0`-style output suitable for `OPENKMS_REMOTE_E2E_SOLANA_REQUEST_B64` or
//! `OPENKMS_REMOTE_E2E_COSMOS_REQUEST_B64` (see `docs/remote-e2e.md`).
//!
//! Run via: `./scripts/generate_remote_e2e_request.sh …` or
//! `cargo run --bin generate_remote_e2e_request -- …`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use k256::ecdsa::SigningKey as Secp256k1SigningKey;
use openkms::chain::cosmos::derive_address;
use openkms::config::AddressStyle;
use prost::Message;
use serde_json::{Value, json};
use solana_sdk::{
    hash::Hash,
    message::{Message as LegacyMessage, VersionedMessage},
    pubkey::Pubkey,
};
use solana_system_interface::instruction as system_instruction;

use cosmrs::proto::cosmos::{
    bank::v1beta1::MsgSend,
    base::v1beta1::Coin,
    crypto::secp256k1::PubKey as ProtoSecp256k1PubKey,
    tx::signing::v1beta1::SignMode,
    tx::v1beta1::{
        AuthInfo as ProtoAuthInfo, Fee, ModeInfo, SignDoc as ProtoSignDoc, SignerInfo, TxBody,
        mode_info, mode_info::Single,
    },
};

const MSG_SEND_TYPE_URL: &str = "/cosmos.bank.v1beta1.MsgSend";
const PUBKEY_TYPE_URL: &str = "/cosmos.crypto.secp256k1.PubKey";

/// Load `KEY=value` lines into the process environment only when `KEY` is not
/// already set (same idea as `act`'s default `--secret-file .secrets`).
fn merge_dotenv_file(path: &Path, missing_ok: bool) -> Result<()> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if missing_ok && e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, mut val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        val = val.trim();
        if (val.starts_with('"') && val.ends_with('"') && val.len() >= 2)
            || (val.starts_with('\'') && val.ends_with('\'') && val.len() >= 2)
        {
            val = &val[1..val.len() - 1];
        }
        if std::env::var_os(key).is_none() {
            // SAFETY: `set_var` is `unsafe` in Rust 2024; we run this only at
            // single-threaded process startup before spawning work that reads env.
            unsafe {
                std::env::set_var(key, val);
            }
        }
    }
    Ok(())
}

/// Preload dotenv files for `clap` `env = …` resolution (same `KEY=value` style
/// as act): secrets first, then vars. Existing environment variables are not
/// overwritten. Optional files are skipped when missing.
fn preload_local_dotenv() -> Result<()> {
    let cwd = std::env::current_dir().context("current_dir")?;

    if let Ok(p) = std::env::var("OPENKMS_SECRETS_FILE") {
        let path = PathBuf::from(&p);
        merge_dotenv_file(&path, false)
            .with_context(|| format!("OPENKMS_SECRETS_FILE={}", path.display()))?;
    } else {
        merge_dotenv_file(&cwd.join(".secrets"), true).context(".secrets")?;
    }

    if let Ok(p) = std::env::var("OPENKMS_VARS_FILE") {
        let path = PathBuf::from(&p);
        merge_dotenv_file(&path, false)
            .with_context(|| format!("OPENKMS_VARS_FILE={}", path.display()))?;
    } else {
        merge_dotenv_file(&cwd.join(".vars"), true).context(".vars")?;
    }

    Ok(())
}

/// If `OPENKMS_REMOTE_E2E_LABEL` is set and a chain-specific label is not, copy
/// the legacy value so older `.secrets` layouts still work with `solana` /
/// `cosmos` / `both`.
fn promote_legacy_remote_e2e_label() {
    let Ok(legacy) = std::env::var("OPENKMS_REMOTE_E2E_LABEL") else {
        return;
    };
    let legacy = legacy.trim();
    if legacy.is_empty() {
        return;
    }
    // SAFETY: single-threaded startup before other threads read env.
    if std::env::var_os("OPENKMS_REMOTE_E2E_SOLANA_LABEL").is_none() {
        unsafe {
            std::env::set_var("OPENKMS_REMOTE_E2E_SOLANA_LABEL", legacy);
        }
    }
    if std::env::var_os("OPENKMS_REMOTE_E2E_COSMOS_LABEL").is_none() {
        unsafe {
            std::env::set_var("OPENKMS_REMOTE_E2E_COSMOS_LABEL", legacy);
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "generate_remote_e2e_request",
    about = "Build remote E2E sign JSON and print base64 (for OPENKMS_REMOTE_E2E_*_REQUEST_B64 secrets)",
    after_long_help = "Environment preload: before parsing flags, loads secrets then vars (act-style KEY=value; never overwrites existing env). OPENKMS_SECRETS_FILE or ./.secrets, then OPENKMS_VARS_FILE or ./.vars (each optional file is skipped if missing).\n\nIf `OPENKMS_REMOTE_E2E_LABEL` is set but `OPENKMS_REMOTE_E2E_SOLANA_LABEL` / `OPENKMS_REMOTE_E2E_COSMOS_LABEL` are not, the legacy value is copied into those names (same label on both chains, or until you add chain-specific lines).\n\nNo chain defaults in this binary: `solana` / `cosmos` require explicit flags or env for RPC, chain id, fees, etc. Subcommand `both` reads only from env and requires: OPENKMS_REMOTE_E2E_SOLANA_LABEL, OPENKMS_SOLANA_SIGNER_SEED_B64, OPENKMS_SOLANA_RPC_URL, OPENKMS_SOLANA_CHAIN_ID, OPENKMS_SOLANA_TRANSFER_LAMPORTS, OPENKMS_REMOTE_E2E_COSMOS_LABEL, OPENKMS_COSMOS_REST_URL, OPENKMS_COSMOS_SIGNER_SCALAR_B64, OPENKMS_COSMOS_HRP, OPENKMS_COSMOS_FEE_DENOM, OPENKMS_COSMOS_FEE_AMOUNT, OPENKMS_COSMOS_GAS_LIMIT, OPENKMS_COSMOS_TRANSFER_AMOUNT, OPENKMS_COSMOS_CHAIN_ID. It prints two base64 lines on stdout (Solana, then Cosmos); stderr labels each line with the GitHub secret name (`OPENKMS_REMOTE_E2E_*_REQUEST_B64`). For the same tuning as broadcast E2E, use `scripts/generate_remote_e2e_request.sh -e` with `broadcast-keys.env` (see docs/remote-e2e.md)."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Print the JSON fixture to stderr before the base64 line.
    #[arg(long, global = true)]
    show_json: bool,

    /// Write the JSON fixture to this path (UTF-8).
    #[arg(long, global = true)]
    write_json: Option<std::path::PathBuf>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Build a Solana `/sign/solana` body (`label`, `message_b64`, `expected_chain_id`).
    Solana(SolanaArgs),
    /// Build a Cosmos `/sign/cosmos` body (`label`, `sign_doc_b64`, `expected_chain_id`).
    Cosmos(CosmosArgs),
    /// Emit two base64 lines on stdout (Solana, then Cosmos); labels go to stderr (requires every env var in `--help`).
    Both,
}

#[derive(Parser, Debug)]
struct SolanaArgs {
    /// Key label configured on the remote signer (must match `/keys`).
    #[arg(long, env = "OPENKMS_REMOTE_E2E_SOLANA_LABEL")]
    label: String,

    /// Base64 of the 32-byte Ed25519 seed (same as broadcast tests).
    #[arg(long, env = "OPENKMS_SOLANA_SIGNER_SEED_B64")]
    seed_b64: String,

    /// JSON-RPC URL for `getLatestBlockhash` (no default).
    #[arg(long, env = "OPENKMS_SOLANA_RPC_URL")]
    rpc_url: String,

    /// `expected_chain_id` in the JSON body (must match the cluster you use).
    #[arg(long, env = "OPENKMS_SOLANA_CHAIN_ID")]
    expected_chain_id: String,

    /// Lamports for a self-transfer in the VersionedMessage (no default).
    #[arg(long, env = "OPENKMS_SOLANA_TRANSFER_LAMPORTS")]
    lamports: u64,
}

#[derive(Parser, Debug)]
struct CosmosArgs {
    #[arg(long, env = "OPENKMS_REMOTE_E2E_COSMOS_LABEL")]
    label: String,

    #[arg(long, env = "OPENKMS_COSMOS_REST_URL")]
    rest_url: String,

    #[arg(long, env = "OPENKMS_COSMOS_SIGNER_SCALAR_B64")]
    scalar_b64: String,

    #[arg(long, env = "OPENKMS_COSMOS_HRP")]
    hrp: String,

    #[arg(long, env = "OPENKMS_COSMOS_FEE_DENOM")]
    fee_denom: String,

    #[arg(long, env = "OPENKMS_COSMOS_FEE_AMOUNT")]
    fee_amount: String,

    #[arg(long, env = "OPENKMS_COSMOS_GAS_LIMIT")]
    gas_limit: u64,

    #[arg(long, env = "OPENKMS_COSMOS_TRANSFER_AMOUNT")]
    transfer_amount: u64,

    #[arg(long, env = "OPENKMS_COSMOS_CHAIN_ID")]
    chain_id: String,
}

#[derive(Clone, Debug)]
struct SolanaParams {
    label: String,
    seed_b64: String,
    rpc_url: String,
    expected_chain_id: String,
    lamports: u64,
}

#[derive(Clone, Debug)]
struct CosmosParams {
    label: String,
    rest_url: String,
    scalar_b64: String,
    hrp: String,
    fee_denom: String,
    fee_amount: String,
    gas_limit: u64,
    transfer_amount: u64,
    chain_id: String,
}

impl From<&SolanaArgs> for SolanaParams {
    fn from(a: &SolanaArgs) -> Self {
        Self {
            label: a.label.clone(),
            seed_b64: a.seed_b64.clone(),
            rpc_url: a.rpc_url.clone(),
            expected_chain_id: a.expected_chain_id.clone(),
            lamports: a.lamports,
        }
    }
}

impl From<&CosmosArgs> for CosmosParams {
    fn from(a: &CosmosArgs) -> Self {
        Self {
            label: a.label.clone(),
            rest_url: a.rest_url.clone(),
            scalar_b64: a.scalar_b64.clone(),
            hrp: a.hrp.clone(),
            fee_denom: a.fee_denom.clone(),
            fee_amount: a.fee_amount.clone(),
            gas_limit: a.gas_limit,
            transfer_amount: a.transfer_amount,
            chain_id: a.chain_id.clone(),
        }
    }
}

fn env_nonempty(name: &'static str) -> Result<String> {
    let v = std::env::var(name).with_context(|| format!("missing required env: {name}"))?;
    let t = v.trim();
    if t.is_empty() {
        bail!("{name} is set but empty");
    }
    Ok(t.to_string())
}

fn env_var_nonempty(name: &str) -> bool {
    std::env::var(name)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

/// Every env var `both` reads (non-empty). Checked up front so one error lists all gaps.
const BOTH_SOLANA_ENV: &[&str] = &[
    "OPENKMS_REMOTE_E2E_SOLANA_LABEL",
    "OPENKMS_SOLANA_SIGNER_SEED_B64",
    "OPENKMS_SOLANA_RPC_URL",
    "OPENKMS_SOLANA_CHAIN_ID",
    "OPENKMS_SOLANA_TRANSFER_LAMPORTS",
];

const BOTH_COSMOS_ENV: &[&str] = &[
    "OPENKMS_REMOTE_E2E_COSMOS_LABEL",
    "OPENKMS_COSMOS_REST_URL",
    "OPENKMS_COSMOS_SIGNER_SCALAR_B64",
    "OPENKMS_COSMOS_HRP",
    "OPENKMS_COSMOS_FEE_DENOM",
    "OPENKMS_COSMOS_FEE_AMOUNT",
    "OPENKMS_COSMOS_GAS_LIMIT",
    "OPENKMS_COSMOS_TRANSFER_AMOUNT",
    "OPENKMS_COSMOS_CHAIN_ID",
];

fn validate_both_subcommand_env() -> Result<()> {
    let missing: Vec<&'static str> = BOTH_SOLANA_ENV
        .iter()
        .chain(BOTH_COSMOS_ENV.iter())
        .copied()
        .filter(|name| !env_var_nonempty(name))
        .collect();
    if !missing.is_empty() {
        bail!(
            "`both` needs these non-empty environment variables (shell or .secrets):\n  {}\n\n`OPENKMS_SOLANA_CHAIN_ID` must match `OPENKMS_SOLANA_RPC_URL` (e.g. `devnet` with `https://api.devnet.solana.com`). See docs/remote-e2e.md.",
            missing.join("\n  ")
        );
    }
    Ok(())
}

fn env_u64(name: &'static str) -> Result<u64> {
    let s = env_nonempty(name)?;
    s.parse()
        .with_context(|| format!("{name}: expected unsigned integer, got {s:?}"))
}

fn solana_params_from_env_for_both() -> Result<SolanaParams> {
    Ok(SolanaParams {
        label: env_nonempty("OPENKMS_REMOTE_E2E_SOLANA_LABEL")?,
        seed_b64: env_nonempty("OPENKMS_SOLANA_SIGNER_SEED_B64")?,
        rpc_url: env_nonempty("OPENKMS_SOLANA_RPC_URL")?,
        expected_chain_id: env_nonempty("OPENKMS_SOLANA_CHAIN_ID")?,
        lamports: env_u64("OPENKMS_SOLANA_TRANSFER_LAMPORTS")?,
    })
}

fn cosmos_params_from_env_for_both() -> Result<CosmosParams> {
    Ok(CosmosParams {
        label: env_nonempty("OPENKMS_REMOTE_E2E_COSMOS_LABEL")?,
        rest_url: env_nonempty("OPENKMS_COSMOS_REST_URL")?,
        scalar_b64: env_nonempty("OPENKMS_COSMOS_SIGNER_SCALAR_B64")?,
        hrp: env_nonempty("OPENKMS_COSMOS_HRP")?,
        fee_denom: env_nonempty("OPENKMS_COSMOS_FEE_DENOM")?,
        fee_amount: env_nonempty("OPENKMS_COSMOS_FEE_AMOUNT")?,
        gas_limit: env_u64("OPENKMS_COSMOS_GAS_LIMIT")?,
        transfer_amount: env_u64("OPENKMS_COSMOS_TRANSFER_AMOUNT")?,
        chain_id: env_nonempty("OPENKMS_COSMOS_CHAIN_ID")?,
    })
}

fn decode_b64_32(name: &str, b64: &str) -> Result<[u8; 32]> {
    let bytes = B64
        .decode(b64.trim().as_bytes())
        .with_context(|| format!("decode {name} as base64"))?;
    if bytes.len() != 32 {
        bail!(
            "{name}: expected 32 raw bytes after base64 decode, got {}",
            bytes.len()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn solana_pubkey_from_seed(seed: &[u8; 32]) -> Pubkey {
    let sk = SigningKey::from_bytes(seed);
    Pubkey::from(sk.verifying_key().to_bytes())
}

fn rpc_call_blocking(
    client: &reqwest::blocking::Client,
    rpc_url: &str,
    method: &str,
    params: Value,
) -> Result<Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let resp: Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .with_context(|| format!("POST {method}"))?
        .error_for_status()
        .with_context(|| format!("{method} returned error status"))?
        .json()
        .with_context(|| format!("decode JSON for {method}"))?;
    if let Some(err) = resp.get("error") {
        bail!("{method} RPC error: {err}");
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("{method} missing result field"))
}

fn latest_blockhash_blocking(client: &reqwest::blocking::Client, rpc_url: &str) -> Result<Hash> {
    let result = rpc_call_blocking(
        client,
        rpc_url,
        "getLatestBlockhash",
        json!([{ "commitment": "confirmed" }]),
    )?;
    let blockhash = result
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("getLatestBlockhash missing value.blockhash"))?;
    Hash::from_str(blockhash).context("parse latest blockhash")
}

fn solana_json(p: &SolanaParams) -> Result<Value> {
    let seed = decode_b64_32("OPENKMS_SOLANA_SIGNER_SEED_B64", &p.seed_b64)?;
    let signer = solana_pubkey_from_seed(&seed);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .context("build HTTP client")?;
    let blockhash =
        latest_blockhash_blocking(&client, p.rpc_url.trim()).context("fetch blockhash")?;
    let ix = system_instruction::transfer(&signer, &signer, p.lamports);
    let message = LegacyMessage::new_with_blockhash(&[ix], Some(&signer), &blockhash);
    let versioned = VersionedMessage::Legacy(message);
    let raw_message = versioned.serialize();

    Ok(json!({
        "label": p.label,
        "message_b64": B64.encode(&raw_message),
        "expected_chain_id": p.expected_chain_id,
    }))
}

fn run_solana(cli: &Cli, args: &SolanaArgs) -> Result<()> {
    let p = SolanaParams::from(args);
    let body = solana_json(&p)?;
    emit(cli, &body)
}

fn trim_rest_base(url: &str) -> &str {
    url.trim_end_matches('/')
}

fn find_json_field<'a>(value: &'a Value, field: &str) -> Option<&'a Value> {
    match value {
        Value::Object(map) => map
            .get(field)
            .or_else(|| map.values().find_map(|child| find_json_field(child, field))),
        Value::Array(items) => items.iter().find_map(|child| find_json_field(child, field)),
        _ => None,
    }
}

fn parse_u64_field(value: &Value, field: &str) -> Result<u64> {
    let raw = find_json_field(value, field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing string field {field}"))?;
    raw.parse()
        .with_context(|| format!("parse {field} value {raw:?} as u64"))
}

fn fetch_account_state_blocking(
    client: &reqwest::blocking::Client,
    rest_url: &str,
    address: &str,
) -> Result<(u64, u64)> {
    let url = format!(
        "{}/cosmos/auth/v1beta1/accounts/{}",
        trim_rest_base(rest_url),
        address
    );
    let resp = client.get(&url).send().context("GET account")?;
    let status = resp.status();
    let body_text = resp.text().context("read account response body")?;
    if !status.is_success() {
        bail!("GET account returned HTTP {status}; url={url}; body={body_text}");
    }
    let body: Value = serde_json::from_str(&body_text).context("decode account JSON")?;
    Ok((
        parse_u64_field(&body, "account_number")?,
        parse_u64_field(&body, "sequence")?,
    ))
}

fn secp_pubkeys(scalar: &[u8; 32]) -> Result<([u8; 33], [u8; 65])> {
    let sk = Secp256k1SigningKey::from_slice(scalar).context("invalid secp256k1 scalar")?;
    let vk = sk.verifying_key();
    let comp_point = vk.to_encoded_point(true);
    let uncomp_point = vk.to_encoded_point(false);
    let mut comp = [0u8; 33];
    let mut uncomp = [0u8; 65];
    comp.copy_from_slice(comp_point.as_bytes());
    uncomp.copy_from_slice(uncomp_point.as_bytes());
    Ok((comp, uncomp))
}

struct CosmosSignDocInputs<'a> {
    signer_compressed: &'a [u8; 33],
    chain_id: &'a str,
    from_addr: &'a str,
    amount: u64,
    amount_denom: &'a str,
    fee_amount: &'a str,
    fee_denom: &'a str,
    gas_limit: u64,
    account_number: u64,
    sequence: u64,
}

fn build_cosmos_sign_doc_bytes(inputs: &CosmosSignDocInputs<'_>) -> Result<Vec<u8>> {
    let mut send_bytes = Vec::new();
    MsgSend {
        from_address: inputs.from_addr.to_string(),
        to_address: inputs.from_addr.to_string(),
        amount: vec![Coin {
            denom: inputs.amount_denom.to_string(),
            amount: inputs.amount.to_string(),
        }],
    }
    .encode(&mut send_bytes)
    .context("encode MsgSend")?;

    let body = TxBody {
        messages: vec![cosmrs::Any {
            type_url: MSG_SEND_TYPE_URL.to_string(),
            value: send_bytes,
        }],
        memo: "openkms remote e2e fixture".to_string(),
        timeout_height: 0,
        extension_options: vec![],
        non_critical_extension_options: vec![],
    };
    let mut body_bytes = Vec::new();
    body.encode(&mut body_bytes).context("encode TxBody")?;

    let mut pubkey_bytes = Vec::new();
    ProtoSecp256k1PubKey {
        key: inputs.signer_compressed.to_vec(),
    }
    .encode(&mut pubkey_bytes)
    .context("encode secp256k1 pubkey")?;

    let auth_info = ProtoAuthInfo {
        signer_infos: vec![SignerInfo {
            public_key: Some(cosmrs::Any {
                type_url: PUBKEY_TYPE_URL.to_string(),
                value: pubkey_bytes,
            }),
            mode_info: Some(ModeInfo {
                sum: Some(mode_info::Sum::Single(Single {
                    mode: SignMode::Direct as i32,
                })),
            }),
            sequence: inputs.sequence,
        }],
        fee: Some(Fee {
            amount: vec![Coin {
                denom: inputs.fee_denom.to_string(),
                amount: inputs.fee_amount.to_string(),
            }],
            gas_limit: inputs.gas_limit,
            payer: String::new(),
            granter: String::new(),
        }),
        ..Default::default()
    };
    let mut auth_info_bytes = Vec::new();
    auth_info
        .encode(&mut auth_info_bytes)
        .context("encode AuthInfo")?;

    let sign_doc = ProtoSignDoc {
        body_bytes: body_bytes.clone(),
        auth_info_bytes: auth_info_bytes.clone(),
        chain_id: inputs.chain_id.to_string(),
        account_number: inputs.account_number,
    };
    let mut sign_doc_bytes = Vec::new();
    sign_doc
        .encode(&mut sign_doc_bytes)
        .context("encode SignDoc")?;
    Ok(sign_doc_bytes)
}

fn cosmos_json(p: &CosmosParams) -> Result<Value> {
    let scalar = decode_b64_32("OPENKMS_COSMOS_SIGNER_SCALAR_B64", &p.scalar_b64)?;
    let (comp, uncomp) = secp_pubkeys(&scalar)?;
    let signer_addr = derive_address(&comp, &uncomp, AddressStyle::Cosmos, &p.hrp)
        .context("derive signer address")?;

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .context("build HTTP client")?;

    let chain_id = p.chain_id.trim();
    if chain_id.is_empty() {
        bail!("OPENKMS_COSMOS_CHAIN_ID is empty");
    }

    let (account_number, sequence) =
        fetch_account_state_blocking(&client, p.rest_url.trim(), &signer_addr)
            .with_context(|| {
                format!(
                    "fetch account state for {signer_addr} — account must exist on chain (send a small inbound transfer first if 404)"
                )
            })?;

    let sign_doc_bytes = build_cosmos_sign_doc_bytes(&CosmosSignDocInputs {
        signer_compressed: &comp,
        chain_id,
        from_addr: &signer_addr,
        amount: p.transfer_amount,
        amount_denom: &p.fee_denom,
        fee_amount: &p.fee_amount,
        fee_denom: &p.fee_denom,
        gas_limit: p.gas_limit,
        account_number,
        sequence,
    })?;

    Ok(json!({
        "label": p.label,
        "sign_doc_b64": B64.encode(&sign_doc_bytes),
        "expected_chain_id": chain_id,
    }))
}

fn run_cosmos(cli: &Cli, args: &CosmosArgs) -> Result<()> {
    let p = CosmosParams::from(args);
    let body = cosmos_json(&p)?;
    emit(cli, &body)
}

fn compact_b64_line(body: &Value) -> Result<String> {
    let compact = serde_json::to_string(body).context("serialize compact JSON")?;
    Ok(B64.encode(compact.as_bytes()))
}

fn run_both(cli: &Cli) -> Result<()> {
    if cli.write_json.is_some() {
        bail!("--write-json is not supported with `both`; run `solana` and `cosmos` separately");
    }
    validate_both_subcommand_env()?;
    let sp = solana_params_from_env_for_both()?;
    let cp = cosmos_params_from_env_for_both()?;
    let v1 = solana_json(&sp)?;
    let v2 = cosmos_json(&cp)?;
    if cli.show_json {
        eprintln!("--- Solana JSON (POST /sign/solana body) ---");
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&v1).context("serialize solana JSON")?
        );
        eprintln!("--- Cosmos JSON (POST /sign/cosmos body) ---");
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&v2).context("serialize cosmos JSON")?
        );
    }
    let l1 = compact_b64_line(&v1)?;
    let l2 = compact_b64_line(&v2)?;
    let mut out = std::io::stdout().lock();
    eprintln!("OPENKMS_REMOTE_E2E_SOLANA_REQUEST_B64 (next stdout line):");
    writeln!(out, "{l1}").context("write solana b64 line")?;
    eprintln!("OPENKMS_REMOTE_E2E_COSMOS_REQUEST_B64 (next stdout line):");
    writeln!(out, "{l2}").context("write cosmos b64 line")?;
    Ok(())
}

fn emit(cli: &Cli, body: &Value) -> Result<()> {
    let json_text = serde_json::to_string_pretty(body).context("serialize JSON")?;
    if cli.show_json {
        eprintln!("{json_text}");
    }
    if let Some(path) = &cli.write_json {
        std::fs::write(path, format!("{json_text}\n"))
            .with_context(|| format!("write {}", path.display()))?;
    }
    let compact = serde_json::to_string(body).context("serialize compact JSON")?;
    let line = B64.encode(compact.as_bytes());
    std::io::stdout()
        .write_all(line.as_bytes())
        .context("write base64 to stdout")?;
    Ok(())
}

fn main() -> Result<()> {
    preload_local_dotenv().context("preload .secrets / .vars (or OPENKMS_*_FILE)")?;
    promote_legacy_remote_e2e_label();
    let cli = Cli::parse();
    match &cli.command {
        Commands::Solana(args) => run_solana(&cli, args),
        Commands::Cosmos(args) => run_cosmos(&cli, args),
        Commands::Both => run_both(&cli),
    }
}
