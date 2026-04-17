//! openKMS CLI entry point.
//!
//! All HSM operations go through the [`openkms::hsm::Hsm`] wrapper so the same
//! paths work against the real device (via `yubihsm-connector`), a USB-attached
//! YubiHSM2, or the in-process mockhsm used by tests and local development.

use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{Parser, Subcommand, ValueEnum};
use openkms::{
    audit::AuditLog,
    chain::{Chain, cosmos::CosmosSigner, solana::SolanaSigner},
    config::Config,
    derive::{self, SEED_LEN, mnemonic_from_entropy, mnemonic_to_seed},
    hsm::{Hsm, hsm_types as H, ids},
    server,
};
use tracing::{info, warn};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(name = "openkms", version, about)]
struct Cli {
    /// Path to the openkms config file.
    #[arg(long, short = 'c', env = "OPENKMS_CONFIG", default_value = "/etc/openkms/config.toml")]
    config: PathBuf,

    /// HSM connector URL (overrides the value in the config file).
    #[arg(long, env = "OPENKMS_CONNECTOR")]
    connector: Option<String>,

    /// Auth-key object id to log in with (overrides config).
    #[arg(long, env = "OPENKMS_AUTH_KEY_ID")]
    auth_key_id: Option<u16>,

    /// Use the in-process mockhsm (for development and CI).
    #[arg(long)]
    mock: bool,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Ping the HSM and print firmware / serial info.
    Detect,

    /// Generate a fresh 24-word BIP-39 mnemonic from the HSM's TRNG.
    NewMnemonic,

    /// Factory-reset the HSM and provision the three auth keys + wrap key
    /// deterministically from a BIP-39 mnemonic.
    Setup(SetupArgs),

    /// Sanity-test the HSM (ping + pseudo_random).
    Test,

    /// Key management subcommands.
    Keys {
        #[command(subcommand)]
        cmd: KeysCommand,
    },

    /// Back up all configured signing keys to a single wrap-encrypted blob.
    Backup(BackupArgs),

    /// Restore a previously-made backup blob on a fresh HSM.
    Restore(RestoreArgs),

    /// Run the signing service.
    Run,
}

#[derive(clap::Args, Debug)]
struct SetupArgs {
    /// Read the mnemonic from this file. Mutually exclusive with --prompt.
    #[arg(long)]
    mnemonic_file: Option<PathBuf>,

    /// Read the mnemonic interactively from the TTY.
    #[arg(long)]
    prompt: bool,

    /// Optional BIP-39 passphrase ("25th word"). Read from stdin if not set.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
enum KeysCommand {
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
        #[arg(long)]
        object_id: u16,
    },

    /// Derive a key from the ceremony mnemonic + BIP-32 / SLIP-10 path and
    /// import it into the HSM (Path B).
    Provision {
        #[arg(long)]
        label: String,
        #[arg(long, value_enum)]
        chain: ChainArg,
        #[arg(long)]
        object_id: u16,
        /// BIP-32 / SLIP-10 derivation path, e.g. `m/44'/118'/0'/0/0` for
        /// Cosmos or `m/44'/501'/0'/0'` for Solana.
        #[arg(long)]
        path: String,
        /// Mnemonic file (see `openkms setup --mnemonic-file`).
        #[arg(long)]
        mnemonic_file: PathBuf,
        /// Optional BIP-39 passphrase file.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },

    /// Export a key wrapped under the current wrap key.
    Export {
        #[arg(long)]
        object_id: u16,
        #[arg(long)]
        out: PathBuf,
    },

    /// Import a key previously exported with `Export`.
    Import {
        #[arg(long)]
        in_: PathBuf,
    },
}

#[derive(clap::Args, Debug)]
struct BackupArgs {
    #[arg(long)]
    out: PathBuf,
}

#[derive(clap::Args, Debug)]
struct RestoreArgs {
    #[arg(long = "in")]
    in_: PathBuf,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum ChainArg {
    Solana,
    Cosmos,
}

impl From<ChainArg> for Chain {
    fn from(a: ChainArg) -> Self {
        match a {
            ChainArg::Solana => Chain::Solana,
            ChainArg::Cosmos => Chain::Cosmos,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();
    let cli = Cli::parse();
    let Cli { config, connector, auth_key_id, mock, cmd } = cli;
    let ctx = CliCtx { config, connector, auth_key_id, mock };
    match cmd {
        Command::Detect => detect(&ctx).await,
        Command::NewMnemonic => new_mnemonic(&ctx).await,
        Command::Setup(args) => setup(&ctx, args).await,
        Command::Test => test_cmd(&ctx).await,
        Command::Keys { cmd } => keys_dispatch(&ctx, cmd).await,
        Command::Backup(a) => backup(&ctx, a).await,
        Command::Restore(a) => restore(&ctx, a).await,
        Command::Run => run_service(&ctx).await,
    }
}

#[derive(Debug)]
struct CliCtx {
    config: PathBuf,
    connector: Option<String>,
    auth_key_id: Option<u16>,
    mock: bool,
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).compact().init();
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

async fn detect(cli: &CliCtx) -> Result<()> {
    let hsm = open_hsm(cli).await?;
    let up = hsm.ping().await;
    println!("hsm_up: {up}");
    let client = hsm.client();
    let guard = client.lock().await;
    match guard.device_info() {
        Ok(info) => {
            println!(
                "firmware: {}.{}.{}  serial: {}",
                info.major_version, info.minor_version, info.build_version, info.serial_number
            );
        }
        Err(e) => {
            warn!("device_info failed: {e}");
        }
    }
    match guard.list_objects(&[]) {
        Ok(objs) => {
            println!("objects: {}", objs.len());
            for o in objs {
                println!("  id=0x{:04x} type={:?}", o.object_id, o.object_type);
            }
        }
        Err(e) => warn!("list_objects failed: {e}"),
    }
    Ok(())
}

async fn new_mnemonic(cli: &CliCtx) -> Result<()> {
    let hsm = open_hsm(cli).await?;
    let random = hsm.get_pseudo_random(32).await?;
    let mut ent = [0u8; 32];
    ent.copy_from_slice(&random);
    let phrase = mnemonic_from_entropy(&ent)?;
    println!("{phrase}");
    eprintln!(
        "\nSTORE THIS PHRASE OFFLINE. It is the root of every auth key and \
         wrap key that openKMS setup derives."
    );
    Ok(())
}

async fn setup(cli: &CliCtx, args: SetupArgs) -> Result<()> {
    let phrase = read_mnemonic(&args)?;
    let passphrase = read_optional_file(args.passphrase_file.as_deref())?.unwrap_or_default();
    let seed = mnemonic_to_seed(phrase.trim(), &passphrase)?;
    let secrets = derive::derive_ceremony(&seed_to_fixed(seed.as_slice()));

    let hsm = open_hsm(cli).await?;
    let client = hsm.client();
    let guard = client.lock().await;

    info!("resetting HSM to factory defaults");
    guard.reset_device().map_err(|e| anyhow!("reset_device: {e}"))?;
    drop(guard);
    // After a reset the session is invalid. Re-login as the factory default
    // auth key (id 1 / password "password") — this is the only key left.
    let default = Hsm::open_http(
        cli.connector.as_deref().unwrap_or("http://127.0.0.1:12345"),
        1,
        b"password",
    )
    .or_else(|_| Hsm::open_mock(1, b"password"))?;
    let client = default.client();
    let guard = client.lock().await;

    // Provision the ceremony auth key.
    install_auth_key(
        &guard,
        ids::CEREMONY_AUTH_KEY_ID,
        "openkms-ceremony",
        H::Capability::all(),
        H::Capability::all(),
        H::Domain::all(),
        &secrets.ceremony_password,
    )?;
    // Provisioner auth key: can put/import/export keys and auth keys in DOM1.
    install_auth_key(
        &guard,
        ids::PROVISIONER_AUTH_KEY_ID,
        "openkms-provisioner",
        H::Capability::PUT_ASYMMETRIC_KEY
            | H::Capability::IMPORT_WRAPPED
            | H::Capability::EXPORT_WRAPPED
            | H::Capability::DELETE_ASYMMETRIC_KEY,
        H::Capability::SIGN_ECDSA
            | H::Capability::SIGN_EDDSA
            | H::Capability::EXPORTABLE_UNDER_WRAP,
        H::Domain::DOM1,
        &secrets.provisioner_password,
    )?;
    // Signer auth key: can only call sign methods.
    install_auth_key(
        &guard,
        ids::SIGNER_AUTH_KEY_ID,
        "openkms-signer",
        H::Capability::SIGN_ECDSA
            | H::Capability::SIGN_EDDSA
            | H::Capability::GET_PSEUDO_RANDOM,
        H::Capability::empty(),
        H::Domain::DOM1,
        &secrets.signer_password,
    )?;

    // Install the wrap key so backup/restore is possible.
    guard
        .put_wrap_key(
            ids::WRAP_KEY_ID,
            H::ObjectLabel::from_str("openkms-wrap")?,
            H::Domain::DOM1,
            H::Capability::EXPORT_WRAPPED | H::Capability::IMPORT_WRAPPED,
            H::Capability::SIGN_ECDSA
                | H::Capability::SIGN_EDDSA
                | H::Capability::EXPORTABLE_UNDER_WRAP,
            H::WrapAlg::Aes256Ccm,
            secrets.wrap_key.to_vec(),
        )
        .map_err(|e| anyhow!("put_wrap_key: {e}"))?;

    // Finally, delete the factory default auth key so only openKMS's own
    // auth keys can log in.
    guard
        .delete_object(1, H::ObjectType::AuthenticationKey)
        .map_err(|e| anyhow!("delete factory auth key: {e}"))?;

    println!("openKMS setup complete:");
    println!("  ceremony_auth_key_id    = 0x{:04x}", ids::CEREMONY_AUTH_KEY_ID);
    println!("  provisioner_auth_key_id = 0x{:04x}", ids::PROVISIONER_AUTH_KEY_ID);
    println!("  signer_auth_key_id      = 0x{:04x}", ids::SIGNER_AUTH_KEY_ID);
    println!("  wrap_key_id             = 0x{:04x}", ids::WRAP_KEY_ID);
    Ok(())
}

fn install_auth_key(
    client: &H::Client,
    key_id: u16,
    label: &str,
    capabilities: H::Capability,
    delegated: H::Capability,
    domains: H::Domain,
    password: &Zeroizing<[u8; 32]>,
) -> Result<()> {
    let obj_label = H::ObjectLabel::from_str(label)?;
    let auth_key = H::AuthKey::derive_from_password(password.as_slice());
    client
        .put_authentication_key(
            key_id,
            obj_label,
            domains,
            capabilities,
            delegated,
            H::AuthAlg::YubicoAes,
            auth_key,
        )
        .map_err(|e| anyhow!("put_authentication_key({label}): {e}"))?;
    Ok(())
}

async fn test_cmd(cli: &CliCtx) -> Result<()> {
    let hsm = open_hsm(cli).await?;
    let up = hsm.ping().await;
    if !up {
        bail!("hsm ping failed");
    }
    let r = hsm.get_pseudo_random(16).await?;
    println!("ok — hsm responded with {} random bytes", r.len());
    Ok(())
}

// ---- keys subcommands ----

async fn keys_dispatch(cli: &CliCtx, cmd: KeysCommand) -> Result<()> {
    match cmd {
        KeysCommand::List => keys_list(cli).await,
        KeysCommand::Address { label } => keys_address(cli, &label).await,
        KeysCommand::Generate { label, chain, object_id } => {
            keys_generate(cli, &label, chain.into(), object_id).await
        }
        KeysCommand::Provision { label, chain, object_id, path, mnemonic_file, passphrase_file } => {
            keys_provision(cli, &label, chain.into(), object_id, &path, &mnemonic_file, passphrase_file.as_deref()).await
        }
        KeysCommand::Export { object_id, out } => keys_export(cli, object_id, &out).await,
        KeysCommand::Import { in_ } => keys_import(cli, &in_).await,
    }
}

async fn keys_list(cli: &CliCtx) -> Result<()> {
    let cfg = Config::load(&cli.config)?;
    for k in &cfg.keys {
        println!(
            "{:<24}  chain={:<8}  object_id=0x{:04x}  path={}",
            k.label,
            k.chain.as_str(),
            k.object_id,
            k.derivation_path.clone().unwrap_or_else(|| "-".into())
        );
    }
    Ok(())
}

async fn keys_address(cli: &CliCtx, label: &str) -> Result<()> {
    let cfg = Config::load(&cli.config)?;
    let key = cfg
        .keys
        .iter()
        .find(|k| k.label == label)
        .ok_or_else(|| anyhow!("no key labelled {label:?}"))?;
    let hsm = open_hsm(cli).await?;
    match key.chain {
        Chain::Solana => {
            let s = SolanaSigner::from_hsm(&hsm, key).await?;
            println!("{}", s.address);
        }
        Chain::Cosmos => {
            let s =
                CosmosSigner::from_hsm(&hsm, key, cfg.cosmos.accepted_pubkey_type_urls.iter().cloned())
                    .await?;
            println!("{}", s.default_address);
        }
        Chain::Unknown => bail!("unknown chain for key {label:?}"),
    }
    Ok(())
}

async fn keys_generate(cli: &CliCtx, label: &str, chain: Chain, object_id: u16) -> Result<()> {
    let hsm = open_hsm(cli).await?;
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

async fn keys_provision(
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
    let seed = mnemonic_to_seed(phrase.trim(), &passphrase)?;
    let seed = seed_to_fixed(seed.as_slice());
    let (alg, caps, key_bytes): (H::AsymmetricAlg, H::Capability, Zeroizing<Vec<u8>>) = match chain
    {
        Chain::Solana => {
            let sk = derive::derive_ed25519(&seed, path)?;
            (
                H::AsymmetricAlg::Ed25519,
                H::Capability::SIGN_EDDSA,
                Zeroizing::new(sk.to_vec()),
            )
        }
        Chain::Cosmos => {
            let sk = derive::derive_secp256k1(&seed, path)?;
            (
                H::AsymmetricAlg::EcK256,
                H::Capability::SIGN_ECDSA,
                Zeroizing::new(sk.to_vec()),
            )
        }
        Chain::Unknown => bail!("unknown chain"),
    };
    let caps = caps | H::Capability::EXPORTABLE_UNDER_WRAP;
    let hsm = open_hsm(cli).await?;
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

async fn keys_export(cli: &CliCtx, object_id: u16, out: &Path) -> Result<()> {
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

async fn keys_import(cli: &CliCtx, in_: &Path) -> Result<()> {
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

async fn backup(cli: &CliCtx, args: BackupArgs) -> Result<()> {
    let cfg = Config::load(&cli.config)?;
    let hsm = open_hsm(cli).await?;
    let client = hsm.client();
    let guard = client.lock().await;
    let mut exported = Vec::new();
    for k in &cfg.keys {
        let msg = guard
            .export_wrapped(ids::WRAP_KEY_ID, H::ObjectType::AsymmetricKey, k.object_id)
            .map_err(|e| anyhow!("export_wrapped({:?}): {e}", k.label))?;
        exported.push(ExportedKey {
            object_id: k.object_id,
            nonce: B64.encode(msg.nonce.0.as_slice()),
            ciphertext: B64.encode(&msg.ciphertext),
        });
    }
    fs::write(&args.out, serde_json::to_vec_pretty(&exported)?)?;
    secure_perms(&args.out)?;
    println!("backed up {} keys to {:?}", exported.len(), args.out);
    Ok(())
}

async fn restore(cli: &CliCtx, args: RestoreArgs) -> Result<()> {
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

async fn run_service(cli: &CliCtx) -> Result<()> {
    let cfg = Config::load(&cli.config)?;
    let signer_token = Config::read_secret_file(&cfg.server.signer_token_file)?;
    let admin_token = Config::read_secret_file(&cfg.server.admin_token_file)?;
    let password = Config::read_secret_file(&cfg.hsm.password_file)?;
    let hsm = if cli.mock {
        Hsm::open_mock(cfg.hsm.auth_key_id, password.as_bytes())?
    } else {
        Hsm::open_http(&cfg.hsm.connector_url, cfg.hsm.auth_key_id, password.as_bytes())?
    };
    // Warm-up: open audit log now so we fail fast if the directory is bad.
    let _ = AuditLog::open(&cfg.audit)?;
    let state = server::AppState::build(cfg, hsm, signer_token, admin_token).await?;
    server::serve(state).await
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn open_hsm(cli: &CliCtx) -> Result<Hsm> {
    if cli.mock {
        let auth = cli.auth_key_id.unwrap_or(1);
        return Hsm::open_mock(auth, b"password");
    }
    // Prefer CLI overrides; fall back to config. If no config file is present
    // and we're not using --mock, insist on --connector.
    let cfg = Config::load(&cli.config).ok();
    let connector = cli
        .connector
        .clone()
        .or_else(|| cfg.as_ref().map(|c| c.hsm.connector_url.clone()))
        .ok_or_else(|| anyhow!("--connector or [hsm].connector_url is required"))?;
    let auth_key_id = cli
        .auth_key_id
        .or_else(|| cfg.as_ref().map(|c| c.hsm.auth_key_id))
        .unwrap_or(ids::SIGNER_AUTH_KEY_ID);
    let password = if let Some(c) = cfg.as_ref() {
        Config::read_secret_file(&c.hsm.password_file)?
    } else {
        std::env::var("OPENKMS_HSM_PASSWORD").context("set OPENKMS_HSM_PASSWORD or use a config")?
    };
    Hsm::open_http(&connector, auth_key_id, password.as_bytes())
}

fn read_mnemonic(args: &SetupArgs) -> Result<String> {
    if let Some(path) = args.mnemonic_file.as_ref() {
        return Ok(fs::read_to_string(path)?);
    }
    if args.prompt {
        return rpassword::prompt_password("mnemonic: ").context("reading mnemonic from stdin");
    }
    Err(anyhow!("must pass --mnemonic-file or --prompt"))
}

fn read_optional_file(path: Option<&Path>) -> Result<Option<String>> {
    match path {
        Some(p) => Ok(Some(fs::read_to_string(p)?.trim().to_string())),
        None => Ok(None),
    }
}

fn seed_to_fixed(bytes: &[u8]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

fn secure_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    let _ = path;
    Ok(())
}

