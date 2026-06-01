use std::fs;

use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{Args, Subcommand};
use openkms::{
    derive::{self, mnemonic_to_seed},
    vault::ids,
};

use crate::{read_optional_file, seed_to_fixed};

#[derive(Subcommand, Debug)]
pub(crate) enum CeremonyCommand {
    /// Print 64 hex chars for `hsm-password` after `setup` (signer auth key #3).
    #[command(name = "print-signer-password")]
    SignerPassword(CeremonyMnemonicArgs),
    /// Print 64 hex chars for the provisioner auth key #2 (key management: generate / export / import).
    #[command(name = "print-provisioner-password")]
    ProvisionerPassword(CeremonyMnemonicArgs),
    /// Print base64 env lines for `generate_remote_e2e_request` (same mnemonic + paths as `keys provision`).
    #[command(name = "print-derived-signing-secrets")]
    DerivedSigningSecrets(CeremonyDerivedSigningArgs),
}

#[derive(Args, Debug)]
pub(crate) struct CeremonyDerivedSigningArgs {
    #[command(flatten)]
    mnemonic: CeremonyMnemonicArgs,
    /// SLIP-10 path for Solana (must match `keys provision`, e.g. `m/44'/501'/0'/0'`).
    #[arg(long)]
    solana_path: Option<String>,
    /// BIP-32 path for Cosmos secp256k1 (must match `keys provision`, e.g. `m/44'/118'/0'/0/0`).
    #[arg(long)]
    cosmos_path: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct CeremonyMnemonicArgs {
    #[arg(long)]
    mnemonic_file: std::path::PathBuf,
    /// Optional BIP-39 passphrase file — must match what you passed to `setup`.
    #[arg(long)]
    passphrase_file: Option<std::path::PathBuf>,
}

pub(crate) async fn dispatch(cmd: CeremonyCommand) -> Result<()> {
    match cmd {
        CeremonyCommand::SignerPassword(args) => print_signer_password(&args),
        CeremonyCommand::ProvisionerPassword(args) => print_provisioner_password(&args),
        CeremonyCommand::DerivedSigningSecrets(args) => print_derived_signing_secrets(&args),
    }
}

fn print_signer_password(args: &CeremonyMnemonicArgs) -> Result<()> {
    let phrase = fs::read_to_string(&args.mnemonic_file)
        .with_context(|| format!("read {:?}", args.mnemonic_file))?;
    let passphrase = read_optional_file(args.passphrase_file.as_deref())?.unwrap_or_default();
    let seed = mnemonic_to_seed(phrase.trim(), &passphrase)?;
    let secrets = derive::derive_ceremony(&seed_to_fixed(seed.as_slice()));
    println!("{}", hex::encode(secrets.signer_password.as_slice()));
    eprintln!(
        "Put this single line in [vaults.hsm].password_file (0600), with auth_key_id 3, after `setup`."
    );
    Ok(())
}

fn print_provisioner_password(args: &CeremonyMnemonicArgs) -> Result<()> {
    let phrase = fs::read_to_string(&args.mnemonic_file)
        .with_context(|| format!("read {:?}", args.mnemonic_file))?;
    let passphrase = read_optional_file(args.passphrase_file.as_deref())?.unwrap_or_default();
    let seed = mnemonic_to_seed(phrase.trim(), &passphrase)?;
    let secrets = derive::derive_ceremony(&seed_to_fixed(seed.as_slice()));
    println!("{}", hex::encode(secrets.provisioner_password.as_slice()));
    eprintln!(
        "Use with `--auth-key-id {}` for `keys generate`, `keys export`, and `keys import` \
         (not for `openkms run`, which should use the signer at #3).",
        ids::PROVISIONER_AUTH_KEY_ID
    );
    Ok(())
}

fn print_derived_signing_secrets(args: &CeremonyDerivedSigningArgs) -> Result<()> {
    if args.solana_path.is_none() && args.cosmos_path.is_none() {
        bail!("pass at least one of --solana-path or --cosmos-path");
    }
    let phrase = fs::read_to_string(&args.mnemonic.mnemonic_file)
        .with_context(|| format!("read {:?}", args.mnemonic.mnemonic_file))?;
    let passphrase =
        read_optional_file(args.mnemonic.passphrase_file.as_deref())?.unwrap_or_default();
    let seed = mnemonic_to_seed(phrase.trim(), &passphrase)?;
    let seed_arr = seed_to_fixed(seed.as_slice());

    if let Some(p) = args.solana_path.as_deref() {
        let sk = derive::derive_ed25519(&seed_arr, p)?;
        println!(
            "OPENKMS_SOLANA_SIGNER_SEED_B64={}",
            B64.encode(sk.as_slice())
        );
    }
    if let Some(p) = args.cosmos_path.as_deref() {
        let sk = derive::derive_secp256k1(&seed_arr, p)?;
        println!(
            "OPENKMS_COSMOS_SIGNER_SCALAR_B64={}",
            B64.encode(sk.as_slice())
        );
    }
    eprintln!(
        "These are recomputed from the mnemonic (not read from the HSM); paths must match `keys provision`."
    );
    Ok(())
}
