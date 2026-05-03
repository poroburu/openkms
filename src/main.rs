//! openKMS CLI entry point.
//!
//! All HSM operations go through the [`openkms::hsm::Hsm`] wrapper so the same
//! paths work against the real device (via `yubihsm-connector`), a USB-attached
//! YubiHSM2, or the in-process mockhsm used by tests and local development.

mod cli_backup;
mod cli_ceremony;
mod cli_keys;

use std::{
    fs,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};
use clap::{Parser, Subcommand, ValueEnum};
use openkms::{
    audit::AuditLog,
    chain::Chain,
    config::Config,
    derive::{self, SEED_LEN, mnemonic_from_entropy, mnemonic_to_seed},
    hsm::{Hsm, hsm_types as H, ids, provisioner_auth_capabilities_setup},
    server,
};
use tracing::{info, warn};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(name = "openkms", version, about)]
struct Cli {
    /// Path to the openkms config file.
    #[arg(
        long,
        short = 'c',
        env = "OPENKMS_CONFIG",
        default_value = "/etc/openkms/config.toml"
    )]
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
        cmd: cli_keys::KeysCommand,
    },

    /// Back up all configured signing keys to a single wrap-encrypted blob.
    Backup(cli_backup::BackupArgs),

    /// Restore a previously-made backup blob on a fresh HSM.
    Restore(cli_backup::RestoreArgs),

    /// Print mnemonic-derived ceremony secrets (operator tooling).
    Ceremony {
        #[command(subcommand)]
        cmd: cli_ceremony::CeremonyCommand,
    },

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

#[derive(Copy, Clone, Debug, ValueEnum)]
pub(crate) enum ChainArg {
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
    let Cli {
        config,
        connector,
        auth_key_id,
        mock,
        cmd,
    } = cli;
    let ctx = CliCtx {
        config,
        connector,
        auth_key_id,
        mock,
    };
    match cmd {
        Command::Detect => detect(&ctx).await,
        Command::NewMnemonic => new_mnemonic(&ctx).await,
        Command::Setup(args) => setup(&ctx, args).await,
        Command::Test => test_cmd(&ctx).await,
        Command::Keys { cmd } => cli_keys::dispatch(&ctx, cmd).await,
        Command::Backup(a) => cli_backup::backup(&ctx, a).await,
        Command::Restore(a) => cli_backup::restore(&ctx, a).await,
        Command::Ceremony { cmd } => cli_ceremony::dispatch(cmd).await,
        Command::Run => run_service(&ctx).await,
    }
}

#[derive(Debug)]
pub(crate) struct CliCtx {
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

/// Object id for CLI `--object-id`: decimal (`256`) or hex (`0x0100`), aligned with config.toml.
fn parse_key_object_id(s: &str) -> Result<u16, String> {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u16::from_str_radix(rest, 16).map_err(|e| e.to_string())
    } else {
        t.parse::<u16>().map_err(|e| e.to_string())
    }
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
    if cli.mock {
        bail!(
            "`openkms setup` talks to a real YubiHSM over yubihsm-connector; remove `--mock` on hardware"
        );
    }
    let phrase = read_mnemonic(&args)?;
    let passphrase = read_optional_file(args.passphrase_file.as_deref())?.unwrap_or_default();
    let seed = mnemonic_to_seed(phrase.trim(), &passphrase)?;
    let secrets = derive::derive_ceremony(&seed_to_fixed(seed.as_slice()));

    let cfg = Config::load(&cli.config).ok();
    let connector_str = cli
        .connector
        .clone()
        .or_else(|| cfg.as_ref().map(|c| c.hsm.connector_url.clone()))
        .ok_or_else(|| anyhow!("--connector or [hsm].connector_url is required for setup"))?;

    // Before reset we must authenticate using secrets tied to this mnemonic (or
    // factory defaults). Do not use `open_hsm(cli)` here: `--auth-key-id` and the
    // config password file are often the signer key (#3) after a prior setup,
    // and partial runs can leave slot 1 empty while provisioner (#2) remains.
    let hsm = open_hsm_for_setup(&connector_str, &secrets)?;
    let client = hsm.client();
    let guard = client.lock().await;

    info!("resetting HSM to factory defaults");
    guard
        .reset_device()
        .map_err(|e| anyhow!("reset_device: {e}"))?;
    drop(guard);
    drop(hsm);
    // `yubihsm::Client::reset_device` does not return HSM command failures (it only
    // debug-logs them). If the session could not reset — e.g. an older provisioner
    // auth key without reset-device capability — the module is unchanged.
    // After a real reset, mnemonic-derived keys at #2/#3 are gone; if we can
    // still open as provisioner #2, reset never took effect.
    if let Ok(stale) = Hsm::open_http(
        &connector_str,
        ids::PROVISIONER_AUTH_KEY_ID,
        secrets.provisioner_password.as_slice(),
    ) {
        drop(stale);
        bail!(
            "`reset_device` did not wipe this YubiHSM: provisioner auth key #{} still accepts your mnemonic-derived password. \
             Sessions opened via provisioner recovery cannot reset unless that auth key includes reset-device capability; \
             older openkms builds omitted it, so the reset command was rejected silently by the firmware. \
             Factory-reset the module with YubiHSM Manager or `yubihsm-auth`, then run `openkms setup` again on an up-to-date openkms binary.",
            ids::PROVISIONER_AUTH_KEY_ID
        );
    }
    // After a reset the session is invalid. Re-login as the factory default
    // auth key (id 1 / password "password") — this is the only key left.
    //
    // The YubiHSM typically disconnects/re-enumerates on USB right after reset;
    // the connector often returns transient errors for a second or two.
    const REOPEN_ATTEMPTS: u32 = 30;
    const REOPEN_GAP_MS: u64 = 500;
    let mut reopened: Option<Hsm> = None;
    let mut last_msg = String::new();
    for attempt in 1..=REOPEN_ATTEMPTS {
        match Hsm::open_http(&connector_str, 1, b"password") {
            Ok(h) => {
                reopened = Some(h);
                break;
            }
            Err(e) => {
                last_msg = e.to_string();
                warn!(
                    "re-open HSM after reset (factory auth #1) attempt {attempt}/{REOPEN_ATTEMPTS}: {last_msg}"
                );
                if attempt < REOPEN_ATTEMPTS {
                    tokio::time::sleep(Duration::from_millis(REOPEN_GAP_MS)).await;
                }
            }
        }
    }
    let default = reopened.ok_or_else(|| {
        let mut detail = format!(
            "re-open HSM after reset as factory auth key #1 failed after {REOPEN_ATTEMPTS} tries ({last_msg}). \
             The module often re-enumerates on USB after reset; try \
             `sudo systemctl restart yubihsm-connector`, wait a few seconds, \
             `curl -sS http://127.0.0.1:12345/connector/status`, then run `openkms setup` again with the same mnemonic."
        );
        if last_msg.contains("auth key not found") {
            detail.push_str(
                " If setup started via provisioner recovery (#2) and `reset_device` could not run \
                 (older builds omitted reset-device from the provisioner key), the HSM was never reset — reinstall \
                 openkms and retry, or factory-reset the module with YubiHSM Manager / `yubihsm-auth`."
            );
        }
        anyhow!("{detail}")
    })?;
    let client = default.client();
    let guard = client.lock().await;

    // Slot 1 is still the factory default authentication key after reset; it
    // cannot be overwritten in place (see yubihsm `setup.rs`). Install
    // provisioner + signer in free slots first, then reconnect as provisioner,
    // delete object 1, and install the ceremony key there.
    //
    // Provisioner: signing-key lifecycle plus setup-time auth/wrap management.
    // Delegated caps and domains must be broad enough that this key can later
    // create `openkms-ceremony` (Capability::all() / Domain::all()); YubiHSM
    // rejects children whose privileges exceed the parent's delegation.
    install_auth_key(
        &guard,
        ids::PROVISIONER_AUTH_KEY_ID,
        "openkms-provisioner",
        provisioner_auth_capabilities_setup(),
        H::Capability::all(),
        H::Domain::all(),
        &secrets.provisioner_password,
    )?;
    // Signer auth key: can only call sign methods.
    install_auth_key(
        &guard,
        ids::SIGNER_AUTH_KEY_ID,
        "openkms-signer",
        H::Capability::SIGN_ECDSA | H::Capability::SIGN_EDDSA | H::Capability::GET_PSEUDO_RANDOM,
        H::Capability::empty(),
        H::Domain::DOM1,
        &secrets.signer_password,
    )?;

    drop(guard);
    drop(default);

    let provisioned = Hsm::open_http(
        &connector_str,
        ids::PROVISIONER_AUTH_KEY_ID,
        secrets.provisioner_password.as_slice(),
    )
    .map_err(|e| {
        anyhow!(
            "re-open HSM as provisioner auth key #{} after installing keys: {e}",
            ids::PROVISIONER_AUTH_KEY_ID
        )
    })?;
    let client = provisioned.client();
    let guard = client.lock().await;

    guard
        .delete_object(1, H::ObjectType::AuthenticationKey)
        .map_err(|e| anyhow!("delete factory auth key: {e}"))?;

    install_auth_key(
        &guard,
        ids::CEREMONY_AUTH_KEY_ID,
        "openkms-ceremony",
        H::Capability::all(),
        H::Capability::all(),
        H::Domain::all(),
        &secrets.ceremony_password,
    )?;

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

    println!("openKMS setup complete:");
    println!(
        "  ceremony_auth_key_id    = 0x{:04x}",
        ids::CEREMONY_AUTH_KEY_ID
    );
    println!(
        "  provisioner_auth_key_id = 0x{:04x}",
        ids::PROVISIONER_AUTH_KEY_ID
    );
    println!(
        "  signer_auth_key_id      = 0x{:04x}",
        ids::SIGNER_AUTH_KEY_ID
    );
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

async fn run_service(cli: &CliCtx) -> Result<()> {
    let cfg = Config::load(&cli.config)?;
    let signer_token = Config::read_secret_file(&cfg.server.signer_token_file)?;
    let admin_token = Config::read_secret_file(&cfg.server.admin_token_file)?;
    let password = Config::read_hsm_password_file(&cfg.hsm.password_file)?;
    let hsm = if cli.mock {
        Hsm::open_mock(cfg.hsm.auth_key_id, password.as_slice())?
    } else {
        Hsm::open_http(
            &cfg.hsm.connector_url,
            cfg.hsm.auth_key_id,
            password.as_slice(),
        )?
    };
    // Warm-up: open audit log now so we fail fast if the directory is bad.
    let _ = AuditLog::open(&cfg.audit)?;
    let state = server::AppState::build(cfg, hsm, signer_token, admin_token).await?;
    server::serve(state).await
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// First step of `openkms setup`: open a session so we can call `reset_device`.
/// Tries factory default auth key #1 with password `password`, then provisioner
/// #2 using the mnemonic-derived password (same run) to recover from a
/// partial setup (factory key deleted, ceremony not yet installed) or a device
/// that was fully provisioned and still has keys 2/3.
fn open_hsm_for_setup(connector_url: &str, secrets: &derive::CeremonySecrets) -> Result<Hsm> {
    match Hsm::open_http(connector_url, 1, b"password") {
        Ok(hsm) => Ok(hsm),
        Err(e1) => {
            let msg = e1.to_string();
            if setup_should_retry_with_provisioner(&msg) {
                warn!(
                    "setup: factory default auth #1 failed ({msg}); trying provisioner auth #0x{:04x} from mnemonic",
                    ids::PROVISIONER_AUTH_KEY_ID
                );
                Hsm::open_http(
                    connector_url,
                    ids::PROVISIONER_AUTH_KEY_ID,
                    secrets.provisioner_password.as_slice(),
                )
                .map_err(|e2| {
                    anyhow!(
                        "open HSM for setup: factory auth #1 (`password`) failed ({e1}); \
                         provisioner auth #{} (derived from this mnemonic) failed ({e2}). \
                         For a fresh YubiHSM use factory defaults; if setup stopped after deleting the factory key, \
                         use this same mnemonic so provisioner #2 matches.",
                        ids::PROVISIONER_AUTH_KEY_ID
                    )
                })
            } else {
                Err(anyhow!(
                    "open HSM for setup with factory default auth #1 (`password`): {e1}"
                ))
            }
        }
    }
}

fn setup_should_retry_with_provisioner(err_msg: &str) -> bool {
    err_msg.contains("auth key not found")
        || err_msg.contains("cryptogram mismatch")
        || err_msg.contains("invalid credentials for authentication key")
}

/// Open as provisioner auth key #2 using ceremony derivation from the setup mnemonic.
/// Required for `keys provision`: signer #3 cannot put asymmetric keys.
fn open_hsm_as_provisioner_with_seed(cli: &CliCtx, seed: &[u8; SEED_LEN]) -> Result<Hsm> {
    let secrets = derive::derive_ceremony(seed);
    if cli.mock {
        return Hsm::open_mock(
            ids::PROVISIONER_AUTH_KEY_ID,
            secrets.provisioner_password.as_slice(),
        );
    }
    let cfg = Config::load(&cli.config).ok();
    let connector = cli
        .connector
        .clone()
        .or_else(|| cfg.as_ref().map(|c| c.hsm.connector_url.clone()))
        .ok_or_else(|| anyhow!("--connector or [hsm].connector_url is required"))?;
    Hsm::open_http(
        &connector,
        ids::PROVISIONER_AUTH_KEY_ID,
        secrets.provisioner_password.as_slice(),
    )
    .map_err(|e| {
        anyhow!(
            "open HSM as provisioner auth #{} (same mnemonic as setup): {e}",
            ids::PROVISIONER_AUTH_KEY_ID
        )
    })
}

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
        Config::read_hsm_password_file(&c.hsm.password_file)?
    } else {
        let s = std::env::var("OPENKMS_HSM_PASSWORD")
            .context("set OPENKMS_HSM_PASSWORD or use a config")?;
        Zeroizing::new(s.into_bytes())
    };
    Hsm::open_http(&connector, auth_key_id, password.as_slice())
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
