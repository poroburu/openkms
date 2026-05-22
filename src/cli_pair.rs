//! `openkms pair` — client requests and operator approval.

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use reqwest::header::AUTHORIZATION;
use serde::Deserialize;

use openkms::{
    config::Config,
    pairing::{PairAsset, PickStrategy},
};

use super::CliCtx;

#[derive(Subcommand, Debug)]
pub enum PairCommand {
    /// Show key pool capacity (`GET /pair/pool`).
    Pool {
        #[arg(long, default_value = "http://127.0.0.1:9443")]
        url: String,
    },
    /// Submit a pairing request (`POST /pair/request`).
    Request {
        #[arg(long, default_value = "http://127.0.0.1:9443")]
        url: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        chain: Option<String>,
        #[arg(long)]
        pick: Option<String>,
        #[arg(long, default_value = "native")]
        asset: Option<String>,
        #[arg(long)]
        display_name: Option<String>,
        /// Client-generated bearer (`okms_` + 64 hex). Omit for server-mint on approve.
        #[arg(long)]
        bearer: Option<String>,
    },
    /// List pending and active pairings (admin).
    List {
        #[arg(long, default_value = "http://127.0.0.1:9443")]
        url: String,
        #[arg(long, env = "OPENKMS_ADMIN_TOKEN")]
        admin_token: Option<String>,
    },
    /// Approve a pending request (admin); prints bearer token once.
    Approve {
        #[arg(long, default_value = "http://127.0.0.1:9443")]
        url: String,
        request_id: String,
        #[arg(long)]
        label: Option<String>,
        #[arg(long, env = "OPENKMS_ADMIN_TOKEN")]
        admin_token: Option<String>,
    },
    /// Reject a pending request (admin).
    Reject {
        #[arg(long, default_value = "http://127.0.0.1:9443")]
        url: String,
        request_id: String,
        #[arg(long, env = "OPENKMS_ADMIN_TOKEN")]
        admin_token: Option<String>,
    },
    /// Revoke an active pairing (admin).
    Revoke {
        #[arg(long, default_value = "http://127.0.0.1:9443")]
        url: String,
        pairing_id: String,
        #[arg(long, env = "OPENKMS_ADMIN_TOKEN")]
        admin_token: Option<String>,
    },
}

pub async fn dispatch(ctx: &CliCtx, cmd: PairCommand) -> Result<()> {
    match cmd {
        PairCommand::Pool { url } => cmd_pool(&url).await,
        PairCommand::Request {
            url,
            client_id,
            label,
            chain,
            pick,
            asset,
            display_name,
            bearer,
        } => {
            cmd_request(
                &url,
                client_id,
                label,
                chain,
                pick,
                asset,
                display_name,
                bearer,
            )
            .await
        }
        PairCommand::List { url, admin_token } => {
            cmd_list(ctx, &url, admin_token.as_deref()).await
        }
        PairCommand::Approve {
            url,
            request_id,
            label,
            admin_token,
        } => cmd_approve(ctx, &url, &request_id, label, admin_token.as_deref()).await,
        PairCommand::Reject {
            url,
            request_id,
            admin_token,
        } => cmd_reject(ctx, &url, &request_id, admin_token.as_deref()).await,
        PairCommand::Revoke {
            url,
            pairing_id,
            admin_token,
        } => cmd_revoke(ctx, &url, &pairing_id, admin_token.as_deref()).await,
    }
}

async fn cmd_pool(url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/pair/pool", url.trim_end_matches('/')))
        .send()
        .await?;
    let body = resp.text().await?;
    println!("{body}");
    Ok(())
}

async fn cmd_request(
    url: &str,
    client_id: String,
    label: Option<String>,
    chain: Option<String>,
    pick: Option<String>,
    asset: Option<String>,
    display_name: Option<String>,
    bearer: Option<String>,
) -> Result<()> {
    let pick = pick.map(|p| parse_pick(&p)).transpose()?;
    let asset = asset.map(|a| parse_asset(&a)).transpose()?;
    let body = serde_json::json!({
        "client_id": client_id,
        "label": label,
        "chain": chain,
        "pick": pick,
        "asset": asset,
        "display_name": display_name,
        "bearer": bearer,
    });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/pair/request", url.trim_end_matches('/')))
        .json(&body)
        .send()
        .await?;
    let text = resp.text().await?;
    println!("{text}");
    Ok(())
}

async fn cmd_list(ctx: &CliCtx, url: &str, admin_token: Option<&str>) -> Result<()> {
    let token = resolve_admin_token(ctx, admin_token)?;
    let client = reqwest::Client::new();
    let base = url.trim_end_matches('/');
    let pending = client
        .get(format!("{base}/admin/pair/pending"))
        .header(AUTHORIZATION, bearer(&token))
        .send()
        .await?
        .text()
        .await?;
    let active = client
        .get(format!("{base}/admin/pair"))
        .header(AUTHORIZATION, bearer(&token))
        .send()
        .await?
        .text()
        .await?;
    println!("pending:\n{pending}\nactive:\n{active}");
    Ok(())
}

async fn cmd_approve(
    ctx: &CliCtx,
    url: &str,
    request_id: &str,
    label: Option<String>,
    admin_token: Option<&str>,
) -> Result<()> {
    let token = resolve_admin_token(ctx, admin_token)?;
    let body = serde_json::json!({ "label": label });
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/admin/pair/{request_id}/approve",
            url.trim_end_matches('/')
        ))
        .header(AUTHORIZATION, bearer(&token))
        .json(&body)
        .send()
        .await?;
    let text = resp.text().await?;
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
        if v.get("bearer_source").and_then(|s| s.as_str()) == Some("client") {
            println!("{text}");
            eprintln!("client bearer already on device — no token in approve response");
            return Ok(());
        }
    }
    println!("{text}");
    Ok(())
}

async fn cmd_reject(
    ctx: &CliCtx,
    url: &str,
    request_id: &str,
    admin_token: Option<&str>,
) -> Result<()> {
    let token = resolve_admin_token(ctx, admin_token)?;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/admin/pair/{request_id}/reject",
            url.trim_end_matches('/')
        ))
        .header(AUTHORIZATION, bearer(&token))
        .send()
        .await?;
    println!("{}", resp.text().await?);
    Ok(())
}

async fn cmd_revoke(
    ctx: &CliCtx,
    url: &str,
    pairing_id: &str,
    admin_token: Option<&str>,
) -> Result<()> {
    let token = resolve_admin_token(ctx, admin_token)?;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!(
            "{}/admin/pair/{pairing_id}",
            url.trim_end_matches('/')
        ))
        .header(AUTHORIZATION, bearer(&token))
        .send()
        .await?;
    println!("{}", resp.text().await?);
    Ok(())
}

fn resolve_admin_token(ctx: &CliCtx, override_token: Option<&str>) -> Result<String> {
    if let Some(t) = override_token {
        return Ok(t.to_string());
    }
    let cfg = Config::load(&ctx.config)?;
    Config::read_secret_file(&cfg.server.admin_token_file)
}

fn bearer(token: &str) -> String {
    format!("Bearer {token}")
}

fn parse_pick(s: &str) -> Result<PickStrategy> {
    match s.to_lowercase().as_str() {
        "most" => Ok(PickStrategy::Most),
        "least" => Ok(PickStrategy::Least),
        "random" => Ok(PickStrategy::Random),
        other => bail!("unknown pick strategy {other:?}"),
    }
}

fn parse_asset(s: &str) -> Result<PairAsset> {
    if s.eq_ignore_ascii_case("native") {
        return Ok(PairAsset::Native);
    }
    if let Some(mint) = s.strip_prefix("spl:") {
        return Ok(PairAsset::Spl {
            mint: mint.to_string(),
        });
    }
    if let Some(denom) = s.strip_prefix("denom:") {
        return Ok(PairAsset::Denom {
            denom: denom.to_string(),
        });
    }
    bail!("asset must be native, spl:<mint>, or denom:<denom>");
}
