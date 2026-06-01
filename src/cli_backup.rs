use std::fs;

use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::Args;
use openkms::{
    config::Config,
    vault::{hsm_types as H, ids, parse_u16_key_id},
};

use crate::{CliCtx, open_hsm, secure_perms};

#[derive(Args, Debug)]
pub(crate) struct BackupArgs {
    #[arg(long)]
    pub(crate) out: std::path::PathBuf,
}

#[derive(Args, Debug)]
pub(crate) struct RestoreArgs {
    #[arg(long = "in")]
    pub(crate) in_: std::path::PathBuf,
}

pub(crate) async fn backup(cli: &CliCtx, args: BackupArgs) -> Result<()> {
    let cfg = Config::load(&cli.config)?;
    let hsm = open_hsm(cli).await?;
    let client = hsm.client();
    let guard = client.lock().await;
    let mut exported = Vec::new();
    for k in &cfg.keys {
        let object_id = parse_u16_key_id(&k.key_id)?;
        let msg = guard
            .export_wrapped(ids::WRAP_KEY_ID, H::ObjectType::AsymmetricKey, object_id)
            .map_err(|e| anyhow!("export_wrapped({:?}): {e}", k.label))?;
        exported.push(ExportedKey {
            object_id,
            nonce: B64.encode(msg.nonce.0.as_slice()),
            ciphertext: B64.encode(&msg.ciphertext),
        });
    }
    fs::write(&args.out, serde_json::to_vec_pretty(&exported)?)?;
    secure_perms(&args.out)?;
    println!("backed up {} keys to {:?}", exported.len(), args.out);
    Ok(())
}

pub(crate) async fn restore(cli: &CliCtx, args: RestoreArgs) -> Result<()> {
    let bytes = fs::read(&args.in_)?;
    let parsed: Vec<ExportedKey> = serde_json::from_slice(&bytes)?;
    let hsm = open_hsm(cli).await?;
    let client = hsm.client();
    let guard = client.lock().await;
    for k in parsed {
        let nonce_bytes = B64.decode(&k.nonce)?;
        let ciphertext = B64.decode(&k.ciphertext)?;
        if nonce_bytes.len() != 13usize {
            return Err(anyhow!("bad wrap nonce length: {}", nonce_bytes.len()));
        }
        let msg = H::wrap::Message {
            nonce: H::wrap::Nonce::from(nonce_bytes.as_slice()),
            ciphertext,
        };
        let handle = guard
            .import_wrapped(ids::WRAP_KEY_ID, msg)
            .map_err(|e| anyhow!("import_wrapped(0x{:04x}): {e}", k.object_id))?;
        println!("restored 0x{:04x} -> {:?}", k.object_id, handle);
    }
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExportedKey {
    object_id: u16,
    nonce: String,
    ciphertext: String,
}
