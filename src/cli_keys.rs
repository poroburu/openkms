use std::{fs, path::Path, str::FromStr};

use anyhow::{Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::Subcommand;
use openkms::{
    chain::{Chain, cosmos::CosmosSigner, solana::SolanaSigner},
    config::Config,
    derive,
    vault::{hsm_types as H, ids, open_vaults, parse_key_id},
};
use zeroize::Zeroizing;

use crate::{
    ChainArg, CliCtx, open_hsm, open_hsm_as_provisioner_with_seed, parse_key_object_id,
    read_optional_file, secure_perms, seed_to_fixed,
};

#[derive(Subcommand, Debug)]
pub(crate) enum KeysCommand {
    /// List configured keys + their object IDs / addresses.
    List,

    /// Print the on-chain address for a configured key.
    Address {
        #[arg(long)]
        label: String,
    },

    /// Generate a new asymmetric key inside the HSM (Path A).
    Generate {
        #[arg(long)]
        label: String,
        #[arg(long, value_enum)]
        chain: ChainArg,
        #[arg(long, value_parser = parse_key_object_id)]
        object_id: u16,
        /// If set, authenticate as provisioner (#2) derived from this mnemonic — required for
        /// key creation unless you use `--auth-key-id 2` and a provisioner password elsewhere.
        #[arg(long)]
        mnemonic_file: Option<std::path::PathBuf>,
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
    },

    /// Derive a key from the ceremony mnemonic + BIP-32 / SLIP-10 path and
    /// import it into the HSM (Path B).
    Provision {
        #[arg(long)]
        label: String,
        #[arg(long, value_enum)]
        chain: ChainArg,
        #[arg(long, value_parser = parse_key_object_id)]
        object_id: u16,
        /// BIP-32 / SLIP-10 derivation path, e.g. `m/44'/118'/0'/0/0` for
        /// Cosmos or `m/44'/501'/0'/0'` for Solana.
        #[arg(long)]
        path: String,
        /// Mnemonic file (see `openkms setup --mnemonic-file`).
        #[arg(long)]
        mnemonic_file: std::path::PathBuf,
        /// Optional BIP-39 passphrase file.
        #[arg(long)]
        passphrase_file: Option<std::path::PathBuf>,
    },

    /// Export a key wrapped under the current wrap key.
    Export {
        #[arg(long, value_parser = parse_key_object_id)]
        object_id: u16,
        #[arg(long)]
        out: std::path::PathBuf,
    },

    /// Import a key previously exported with `Export`.
    Import {
        #[arg(long)]
        in_: std::path::PathBuf,
    },
}

pub(crate) async fn dispatch(cli: &CliCtx, cmd: KeysCommand) -> Result<()> {
    match cmd {
        KeysCommand::List => list(cli).await,
        KeysCommand::Address { label } => address(cli, &label).await,
        KeysCommand::Generate {
            label,
            chain,
            object_id,
            mnemonic_file,
            passphrase_file,
        } => {
            generate(
                cli,
                &label,
                chain.into(),
                object_id,
                mnemonic_file.as_deref(),
                passphrase_file.as_deref(),
            )
            .await
        }
        KeysCommand::Provision {
            label,
            chain,
            object_id,
            path,
            mnemonic_file,
            passphrase_file,
        } => {
            provision(
                cli,
                &label,
                chain.into(),
                object_id,
                &path,
                &mnemonic_file,
                passphrase_file.as_deref(),
            )
            .await
        }
        KeysCommand::Export { object_id, out } => export(cli, object_id, &out).await,
        KeysCommand::Import { in_ } => import(cli, &in_).await,
    }
}

async fn list(cli: &CliCtx) -> Result<()> {
    let cfg = Config::load(&cli.config)?;
    for k in &cfg.keys {
        println!(
            "{:<24}  chain={:<8}  vault={:<8}  key_id={:<10}  path={}",
            k.label,
            k.chain.as_str(),
            k.vault,
            k.key_id,
            k.derivation_path.clone().unwrap_or_else(|| "-".into())
        );
    }
    Ok(())
}

async fn address(cli: &CliCtx, label: &str) -> Result<()> {
    let cfg = Config::load(&cli.config)?;
    let key = cfg
        .keys
        .iter()
        .find(|k| k.label == label)
        .ok_or_else(|| anyhow!("no key labelled {label:?}"))?;
    let vaults = open_vaults(&cfg.vaults)?;
    let vault = vaults
        .get(&key.vault)
        .ok_or_else(|| anyhow!("unknown vault {:?}", key.vault))?;
    let driver = cfg.vault_driver(&key.vault)?;
    let key_id = parse_key_id(driver, &key.key_id)?;
    match key.chain {
        Chain::Solana => {
            let s = SolanaSigner::from_vault(vault.as_ref(), key, &key_id).await?;
            println!("{}", s.address);
        }
        Chain::Cosmos => {
            let s = CosmosSigner::from_vault(
                vault.as_ref(),
                key,
                &key_id,
                cfg.cosmos.accepted_pubkey_type_urls.iter().cloned(),
            )
            .await?;
            println!("{}", s.default_address);
        }
        Chain::Unknown => bail!("unknown chain for key {label:?}"),
    }
    Ok(())
}

async fn generate(
    cli: &CliCtx,
    label: &str,
    chain: Chain,
    object_id: u16,
    mnemonic_file: Option<&Path>,
    passphrase_file: Option<&Path>,
) -> Result<()> {
    let hsm = if let Some(path) = mnemonic_file {
        let phrase = fs::read_to_string(path)?;
        let passphrase = read_optional_file(passphrase_file)?.unwrap_or_default();
        let seed = derive::mnemonic_to_seed(phrase.trim(), &passphrase)?;
        let seed_arr = seed_to_fixed(seed.as_slice());
        open_hsm_as_provisioner_with_seed(cli, &seed_arr)?
    } else {
        open_hsm(cli).await?
    };
    let client = hsm.client();
    let guard = client.lock().await;
    let (alg, caps) = match chain {
        Chain::Solana => (H::AsymmetricAlg::Ed25519, H::Capability::SIGN_EDDSA),
        Chain::Cosmos => (H::AsymmetricAlg::EcK256, H::Capability::SIGN_ECDSA),
        Chain::Unknown => bail!("unknown chain"),
    };
    let caps = caps | H::Capability::EXPORTABLE_UNDER_WRAP;
    let id = guard
        .generate_asymmetric_key(
            object_id,
            H::ObjectLabel::from_str(label)?,
            H::Domain::DOM1,
            caps,
            alg,
        )
        .map_err(|e| anyhow!("generate_asymmetric_key: {e}"))?;
    println!("generated key object_id=0x{id:04x} algorithm={alg:?}");
    Ok(())
}

async fn provision(
    cli: &CliCtx,
    label: &str,
    chain: Chain,
    object_id: u16,
    path: &str,
    mnemonic_file: &Path,
    passphrase_file: Option<&Path>,
) -> Result<()> {
    let phrase = fs::read_to_string(mnemonic_file)?;
    let passphrase = read_optional_file(passphrase_file)?.unwrap_or_default();
    let seed = derive::mnemonic_to_seed(phrase.trim(), &passphrase)?;
    let seed_arr = seed_to_fixed(seed.as_slice());

    let hsm = open_hsm_as_provisioner_with_seed(cli, &seed_arr)?;

    let (alg, caps, key_bytes): (H::AsymmetricAlg, H::Capability, Zeroizing<Vec<u8>>) = match chain
    {
        Chain::Solana => {
            let sk = derive::derive_ed25519(&seed_arr, path)?;
            (
                H::AsymmetricAlg::Ed25519,
                H::Capability::SIGN_EDDSA,
                Zeroizing::new(sk.to_vec()),
            )
        }
        Chain::Cosmos => {
            let sk = derive::derive_secp256k1(&seed_arr, path)?;
            (
                H::AsymmetricAlg::EcK256,
                H::Capability::SIGN_ECDSA,
                Zeroizing::new(sk.to_vec()),
            )
        }
        Chain::Unknown => bail!("unknown chain"),
    };
    let caps = caps | H::Capability::EXPORTABLE_UNDER_WRAP;
    let client = hsm.client();
    let guard = client.lock().await;
    let id = guard
        .put_asymmetric_key(
            object_id,
            H::ObjectLabel::from_str(label)?,
            H::Domain::DOM1,
            caps,
            alg,
            key_bytes.to_vec(),
        )
        .map_err(|e| anyhow!("put_asymmetric_key: {e}"))?;
    println!("imported key object_id=0x{id:04x} path={path}");
    Ok(())
}

async fn export(cli: &CliCtx, object_id: u16, out: &Path) -> Result<()> {
    let hsm = open_hsm(cli).await?;
    let client = hsm.client();
    let guard = client.lock().await;
    let msg = guard
        .export_wrapped(ids::WRAP_KEY_ID, H::ObjectType::AsymmetricKey, object_id)
        .map_err(|e| anyhow!("export_wrapped: {e}"))?;
    let serialized = serde_json::to_vec(&ExportedKey {
        object_id,
        nonce: B64.encode(msg.nonce.0.as_slice()),
        ciphertext: B64.encode(&msg.ciphertext),
    })?;
    fs::write(out, serialized)?;
    secure_perms(out)?;
    println!("wrote {out:?}");
    Ok(())
}

async fn import(cli: &CliCtx, in_: &Path) -> Result<()> {
    let bytes = fs::read(in_)?;
    let parsed: ExportedKey = serde_json::from_slice(&bytes)?;
    let hsm = open_hsm(cli).await?;
    let client = hsm.client();
    let guard = client.lock().await;
    let nonce_bytes = B64.decode(parsed.nonce)?;
    let ciphertext = B64.decode(parsed.ciphertext)?;
    if nonce_bytes.len() != 13usize {
        return Err(anyhow!("bad wrap nonce length: {}", nonce_bytes.len()));
    }
    let msg = H::wrap::Message {
        nonce: H::wrap::Nonce::from(nonce_bytes.as_slice()),
        ciphertext,
    };
    let handle = guard
        .import_wrapped(ids::WRAP_KEY_ID, msg)
        .map_err(|e| anyhow!("import_wrapped: {e}"))?;
    println!(
        "imported object_id=0x{:04x} type={:?}",
        handle.object_id, handle.object_type
    );
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExportedKey {
    object_id: u16,
    nonce: String,
    ciphertext: String,
}
