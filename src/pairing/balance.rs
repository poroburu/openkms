//! On-chain balance queries for auto-pair `most` / `least` selection.

use std::collections::HashMap;

use anyhow::{Context, Result, anyhow};
use rand_core::{OsRng, RngCore};
use serde_json::json;

use crate::{
    chain::Chain,
    config::PairingConfig,
    pairing::{PairAsset, PickStrategy},
};

#[derive(Clone)]
pub struct BalanceRanker {
    solana_rpc_url: Option<String>,
    cosmos_rest_url: Option<String>,
    timeout_ms: u64,
    client: reqwest::Client,
}

impl BalanceRanker {
    pub fn new(pairing: &PairingConfig) -> Self {
        let timeout = pairing.balance.query_timeout_ms.max(100);
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(timeout))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            solana_rpc_url: pairing.balance.solana_rpc_url.clone(),
            cosmos_rest_url: pairing.balance.cosmos_rest_url.clone(),
            timeout_ms: timeout,
            client,
        }
    }

    pub async fn query_balance(
        &self,
        chain: Chain,
        asset: &PairAsset,
        address: &str,
    ) -> Result<u128> {
        match chain {
            Chain::Solana => self.solana_balance(asset, address).await,
            Chain::Cosmos => self.cosmos_balance(asset, address).await,
            Chain::Unknown => Err(anyhow!("unknown chain")),
        }
    }
}

pub async fn select_label(
    ranker: &BalanceRanker,
    chain: Chain,
    pick: PickStrategy,
    asset: Option<&PairAsset>,
    candidates: &[String],
    addresses: &HashMap<String, String>,
) -> Result<String> {
    if candidates.is_empty() {
        return Err(anyhow!("no candidates"));
    }
    if candidates.len() == 1 {
        return Ok(candidates[0].clone());
    }

    match pick {
        PickStrategy::Random => {
            let idx = (rand_index() as usize) % candidates.len();
            Ok(candidates[idx].clone())
        }
        PickStrategy::Most | PickStrategy::Least => {
            let asset = asset.ok_or_else(|| anyhow!("asset required for most/least"))?;
            let mut scored: Vec<(String, u128)> = Vec::new();
            for label in candidates {
                let addr = addresses
                    .get(label)
                    .ok_or_else(|| anyhow!("missing address for key {label}"))?;
                let bal = ranker.query_balance(chain, asset, addr).await?;
                scored.push((label.clone(), bal));
            }
            scored.sort_by(|a, b| {
                let ord = a.1.cmp(&b.1);
                if ord == std::cmp::Ordering::Equal {
                    a.0.cmp(&b.0)
                } else {
                    ord
                }
            });
            let label = match pick {
                PickStrategy::Most => scored.last().map(|s| s.0.clone()),
                PickStrategy::Least => scored.first().map(|s| s.0.clone()),
                PickStrategy::Random => unreachable!(),
            };
            label.ok_or_else(|| anyhow!("no label selected"))
        }
    }
}

fn rand_index() -> u32 {
    let mut buf = [0u8; 4];
    OsRng.fill_bytes(&mut buf);
    u32::from_le_bytes(buf)
}

impl BalanceRanker {
    async fn solana_balance(&self, asset: &PairAsset, address: &str) -> Result<u128> {
        let rpc = self
            .solana_rpc_url
            .as_deref()
            .ok_or_else(|| anyhow!("pairing.balance.solana_rpc_url not configured"))?;
        match asset {
            PairAsset::Native => {
                let result = rpc_call(&self.client, rpc, "getBalance", json!([address])).await?;
                let lamports = result
                    .get("value")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| anyhow!("getBalance missing value"))?;
                Ok(lamports as u128)
            }
            PairAsset::Spl { mint } => {
                // Largest token account for owner+mint (simplified v1).
                let result = rpc_call(
                    &self.client,
                    rpc,
                    "getTokenAccountsByOwner",
                    json!([
                        address,
                        { "mint": mint },
                        { "encoding": "jsonParsed" }
                    ]),
                )
                .await?;
                let accounts = result
                    .get("value")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| anyhow!("getTokenAccountsByOwner missing value"))?;
                let mut max_amt: u128 = 0;
                for acct in accounts {
                    let amt = acct
                        .pointer("/account/data/parsed/info/tokenAmount/amount")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse::<u128>().ok())
                        .unwrap_or(0);
                    max_amt = max_amt.max(amt);
                }
                Ok(max_amt)
            }
            PairAsset::Denom { .. } => Err(anyhow!("denom asset not valid for solana")),
        }
    }

    async fn cosmos_balance(&self, asset: &PairAsset, address: &str) -> Result<u128> {
        let rest = self
            .cosmos_rest_url
            .as_deref()
            .ok_or_else(|| anyhow!("pairing.balance.cosmos_rest_url not configured"))?;
        let (denom, path_addr) = match asset {
            PairAsset::Native => ("uatom", address),
            PairAsset::Denom { denom } => (denom.as_str(), address),
            PairAsset::Spl { .. } => return Err(anyhow!("spl asset not valid for cosmos")),
        };
        let url = format!(
            "{}/cosmos/bank/v1beta1/balances/{path_addr}/by_denom?denom={denom}",
            rest.trim_end_matches('/')
        );
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .context("cosmos balance request")?;
        if !resp.status().is_success() {
            return Err(anyhow!("cosmos balance HTTP {}", resp.status()));
        }
        let body: serde_json::Value = resp.json().await.context("cosmos balance json")?;
        let amount = body
            .pointer("/balance/amount")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("cosmos balance missing amount"))?;
        amount
            .parse::<u128>()
            .context("parse cosmos balance amount")
    }
}

async fn rpc_call(
    client: &reqwest::Client,
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params
    });
    let resp = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("rpc {method}"))?;
    let status = resp.status();
    let v: serde_json::Value = resp.json().await.context("rpc json")?;
    if !status.is_success() {
        return Err(anyhow!("rpc HTTP {status}"));
    }
    if let Some(err) = v.get("error") {
        return Err(anyhow!("rpc error: {err}"));
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("rpc missing result"))
}
