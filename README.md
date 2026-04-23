# openKMS

YubiHSM2-backed transaction signer for **Cosmos**, **Solana**, and (coming
soon) **EVM** chains. Designed for a homelab Raspberry Pi that signs for a
trading agent such as [Openclaw](#openclaw-integration): small, deny-by-default,
and never emits raw key material.

```
┌─────────────────────┐      HTTP+Bearer      ┌────────────────────────┐
│  Openclaw strategy  │  ───────────────────► │  openKMS HTTP server   │
│  (constructs tx)    │                       │  axum + policy + audit │
└─────────────────────┘                       │  replay + metrics      │
                                              │                        │
                                              │ Arc<Mutex<Client>>      │
                                              └────────────┬───────────┘
                                                           │ yubihsm
                                                           ▼
                                              ┌────────────────────────┐
                                              │ yubihsm-connector      │
                                              │   localhost:12345      │
                                              └────────────┬───────────┘
                                                           │ USB
                                                           ▼
                                                   ┌───────────────┐
                                                   │  YubiHSM 2    │
                                                   └───────────────┘
```

## Contents

- [Features](#features)
- [Security model](#security-model)
- [Quick start](#quick-start)
- [Ceremony](#ceremony)
- [Configuration](#configuration)
- [Policy authoring guide](#policy-authoring-guide)
- [HTTP API](#http-api)
- [Openclaw integration](#openclaw-integration)
- [Deployment (systemd)](#deployment-systemd)
- [Operations](#operations)
- [Backup & restore](#backup--restore)
- [Testing](#testing)
- [Architecture](#architecture)

---

## Features

- **HSM-only signing.** Private keys are generated or imported into the
  YubiHSM2 and never leave as plaintext. Ed25519 (Solana), secp256k1
  (Cosmos / EVM) supported today; secp256r1 (P-256) is wired in for future
  chains.
- **Deterministic ceremony.** One BIP-39 mnemonic derives three auth keys
  (ceremony / provisioner / signer) *and* the symmetric wrap key via
  HKDF-SHA256 with domain-separated info labels. Lose the HSM → re-derive
  a replacement from the same mnemonic.
- **Per-key policy engine.** Per-minute / per-hour / per-day rate limits,
  per-tx amount caps, rolling daily spend caps, program / Msg-type /
  recipient allowlists, and a kill switch.
- **Replay cache.** Bounded LRU of signing-digest → signature pairs. Safe
  because Ed25519 is deterministic and ECDSA uses RFC-6979.
- **Audit log.** Append-only JSONL with optional HMAC-SHA256 chain for
  tamper detection.
- **Prometheus metrics.** Signs, denials, replay hits, inflight, HSM up /
  down, errors — exposed on `/metrics`.
- **Chain-agnostic core.** Add another chain by implementing the
  `ChainSigner` trait; the HSM, policy, audit, and replay layers are
  blockchain-independent.

## Security model

The service itself speaks plain HTTP. Keep it on loopback, over an SSH tunnel,
or behind a reverse proxy / load balancer that terminates TLS before exposing
it on a wider network.

### What the HSM guarantees

- Signing keys exist only inside the HSM. All signing operations go
  through `yubihsm::Client::sign_*` — the service never sees the private
  scalar.
- Signing requires a live SCP03 session authenticated by one of three
  long-term auth keys:
  - **Ceremony** (object id `0x0001`) — full privileges for setup,
    factory reset, and backup.  Password is held **offline** during
    normal operation.
  - **Provisioner** (object id `0x0002`) — can add/remove asymmetric
    keys in domain `DOM1` and run `export_wrapped`/`import_wrapped`.
    Used by `openkms keys ...` and `openkms backup/restore`.
  - **Signer** (object id `0x0003`) — can only sign. This is the key the
    running service logs in with. Zero mutation privileges.
- Backups are AES-256-CCM wrap-encrypted under a 256-bit symmetric wrap
  key that itself lives only in the HSM.

### What the HSM does **not** protect

- **Message content.** The YubiHSM signs any 32-byte digest or raw Ed25519
  message it is handed. The policy engine and the chain-specific decoders
  in `src/chain/*.rs` are what prevent the service from signing an
  attacker-controlled payload.
- **Signer host compromise.** If `root` on the Pi is compromised, the
  attacker can talk to `yubihsm-connector` and ask for signatures just
  like openKMS does — bounded by the policy engine and the per-key kill
  switch. Harden the host; treat compromise of the signer VM as
  equivalent to "one tx per rate-limit tick until the admin hits the kill
  switch".
- **Side-channel of the connector.** The HSM is USB-attached; a
  privileged local attacker can sniff the SCP03 session keys that
  `yubihsm-connector` uses. The mitigating invariant is the signer auth
  key's *minimal* capability set: it can only sign — no export, no key
  mutation.

### Recovery paths

| Scenario                    | Recovery                                                                   |
| --------------------------- | -------------------------------------------------------------------------- |
| HSM lost / destroyed        | Buy new HSM → `openkms setup --mnemonic-file <m>` → `openkms restore`.     |
| Auth key password compromised | `openkms setup` (factory reset) → chain accounts remain because keys were `EXPORTABLE_UNDER_WRAP`d before the reset. |
| Policy bug (unexpected sign) | Admin `POST /admin/keys/<label>/disable`, investigate `audit.jsonl`, edit `config.toml`, restart the service. |
| Mnemonic compromised        | **All bets off** — rotate every on-chain account. The mnemonic is the root of trust. |
| Raspberry Pi compromised    | Revoke signer bearer token; disable all keys from a safe machine; rotate on-chain.                 |

## Quick start

```bash
# 1) Build the binary (on the Pi or cross-compile with aarch64 target).
cargo build --release

# 2) Ceremony — ONE-TIME: create a 24-word mnemonic from the HSM's TRNG.
./target/release/openkms --mock new-mnemonic > /secure/usb/mnemonic.txt

# 3) Factory-reset + provision the HSM from that mnemonic.
./target/release/openkms setup --mnemonic-file /secure/usb/mnemonic.txt

# 4) Provision a signing key (Path B: deterministic derivation).
./target/release/openkms keys provision \
    --label cosmos-hub-0 \
    --chain cosmos \
    --object-id 0x0100 \
    --path "m/44'/118'/0'/0/0" \
    --mnemonic-file /secure/usb/mnemonic.txt

# 5) Back up every signing key to a wrap-encrypted blob. Store this next
# to the mnemonic; it can be restored onto a replacement HSM.
./target/release/openkms backup --out /secure/usb/openkms-backup.json

# 6) Run the service.
./target/release/openkms run
```

## Ceremony

The ceremony is the one-time operation that seeds the HSM with everything
derived from a single BIP-39 mnemonic:

```
BIP-39 mnemonic + optional passphrase
            │
            ▼   PBKDF2-HMAC-SHA512 (BIP-39)
      64-byte seed
            │
            ▼   HKDF-SHA256, domain-separated info labels
      ┌─────┴─────┬─────────────┬─────────────┐
      ▼           ▼             ▼             ▼
 ceremony_pw  provisioner_pw  signer_pw   wrap_key
 (32 bytes)    (32 bytes)    (32 bytes)   (32 bytes)
```

The ceremony produces exactly **four** secrets. All three auth keys are
installed via `put_authentication_key` (deriving AES-session material from
their passwords with Yubico's standard PBKDF2 transform) and the wrap key
is installed with `put_wrap_key` using algorithm `Aes256Ccm`.

> The factory-default auth key (`id=1`, password `"password"`) is deleted
> at the end of setup so only openKMS-owned auth keys can log in.

### Path A vs Path B

Every signing key on the HSM can be created one of two ways:

- **Path A — HSM-native generation** (`openkms keys generate`). The HSM's
  TRNG picks the scalar. Most paranoid, but you now *must* keep the wrap
  backup current, because the private key has never existed outside the
  HSM and is lost if the device dies.
- **Path B — mnemonic-derived import** (`openkms keys provision`). The
  private scalar is derived on the host from the ceremony mnemonic + a
  BIP-32 (secp256k1) or SLIP-10 (Ed25519) path, then imported via
  `put_asymmetric_key`. Wrap backup still makes sense, but even if it's
  lost you can re-derive the same key from the mnemonic.

Both paths set `EXPORTABLE_UNDER_WRAP` so the key can be re-homed onto a
replacement HSM.

## Configuration

`config.toml` lives at `/etc/openkms/config.toml`. A minimal example:

```toml
[server]
listen             = "127.0.0.1:9443"
signer_token_file  = "/etc/openkms/signer.token"
admin_token_file   = "/etc/openkms/admin.token"
inflight_limit     = 64
replay_window_secs = 120

[hsm]
connector_url   = "http://127.0.0.1:12345"
auth_key_id     = 3                  # signer auth key
password_file   = "/etc/openkms/hsm-password"

[audit]
path          = "/var/lib/openkms/audit.jsonl"
hmac_key_file = "/etc/openkms/audit-hmac.key"   # optional

state_dir = "/var/lib/openkms"

[cosmos]
accepted_pubkey_type_urls = [
  "/cosmos.crypto.secp256k1.PubKey",
  "/ethermint.crypto.v1.ethsecp256k1.PubKey",
  "/injective.crypto.v1beta1.ethsecp256k1.PubKey",
]

[[keys]]
label            = "cosmos-hub-0"
chain            = "cosmos"
object_id        = 0x0100
derivation_path  = "m/44'/118'/0'/0/0"
address_style    = "cosmos"
default_hrp      = "cosmos"

[keys.policy]
enabled              = true
max_signs_per_minute = 6
max_signs_per_hour   = 120
max_signs_per_day    = 500
daily_cap_lamports   = "5000000000"    # 5_000 ATOM, uatom
per_tx_cap_lamports  = "500000000"     # 500 ATOM per tx

  [[keys.policy.allowed_messages]]
  type_url          = "/cosmos.bank.v1beta1.MsgSend"
  allowed_recipients = ["cosmos1...", "cosmos1..."]
  per_tx_cap         = { uatom = "500000000" }

  [[keys.policy.allowed_messages]]
  type_url          = "/cosmwasm.wasm.v1.MsgExecuteContract"
  allowed_contracts = ["cosmos1contract..."]
  allowed_methods   = ["swap", "provide_liquidity"]

[[keys]]
label     = "solana-hot-0"
chain     = "solana"
object_id = 0x0101

[keys.policy]
enabled              = true
max_signs_per_minute = 30
max_signs_per_day    = 5000
per_tx_cap_lamports  = "5000000000"

  [[keys.policy.allowed_programs]]
  id      = "11111111111111111111111111111111"    # System Program
  comment = "transfers"

  [[keys.policy.allowed_programs]]
  id      = "ComputeBudget111111111111111111111111111111"
```

### File-permission checks

All secret files (`signer.token`, `admin.token`, `hsm-password`,
`audit-hmac.key`) **must** be mode `0600` or openKMS refuses to start.

## Policy authoring guide

Each `[keys.policy]` block is evaluated in this order, fail-closed:

1. **`enabled = false`** or admin-set kill switch → deny with reason
   `"key disabled"`.
2. **Rate limits** (`max_signs_per_minute` / `_per_hour` / `_per_day`).
   Uses `governor` tokens under the hood; consumed regardless of eventual
   cache hit so a flood of duplicate requests still counts.
3. **Per-tx cap** — rejects if the `intent`'s outgoing transfers sum
   beyond `per_tx_cap_lamports` (treated as integer units in the chain's
   smallest denomination).
4. **Daily cap** — a rolling 24-hour window of accepted-signed transfer
   totals; trips once you've signed more than `daily_cap_lamports` in
   that window.
5. **Allowlists** — `allowed_programs`, `allowed_messages`,
   `allowed_recipients`. Any referenced program ID / Msg type URL /
   recipient not in the list denies the request. Empty list ⇒ disabled
   category (i.e. `allowed_messages = []` means "no Cosmos Msg types
   are permitted from this key").

The policy engine has an internal `reload` path that preserves runtime
counters by key label, but the `openkms run` binary does not currently wire
that to `SIGHUP` or another live config-reload hook. Today, edit the TOML and
restart the service to apply changes.

## HTTP API

All endpoints are JSON. Every signing request must include a
`Authorization: Bearer <token>` header whose value matches the contents
of `signer_token_file`. Admin endpoints use a separate token.

### `GET /health`

```json
{ "status": "ok", "hsm_up": true }
```

### `GET /keys`

```json
[
  {
    "label": "cosmos-hub-0",
    "chain": "cosmos",
    "address": "cosmos1abcd...",
    "enabled": true,
    "object_id": 256,
    "derivation_path": "m/44'/118'/0'/0/0"
  }
]
```

### `POST /sign/solana`

Request:
```json
{
  "label": "solana-hot-0",
  "expected_chain_id": "mainnet-beta",
  "message_b64": "<base64 VersionedMessage>",
  "address_lookup_tables": [
    { "key": "<ALT pubkey>", "addresses": ["<base58>", "..."] }
  ]
}
```

Response:
```json
{ "signature_b64": "<base64 64-byte ed25519>" }
```

### `POST /sign/cosmos`

Request:
```json
{
  "label": "cosmos-hub-0",
  "sign_doc_b64": "<base64 proto-encoded SignDoc>",
  "expected_chain_id": "cosmoshub-4"
}
```

Response:
```json
{
  "signature_b64": "<base64 64-byte compact low-s ECDSA>",
  "signer_address": "cosmos1abcd..."
}
```

### `POST /admin/keys/<label>/disable` · `/enable`

Requires admin bearer token. Persists state in `state_dir/key-flags.json`.
Response:
```json
{ "label": "cosmos-hub-0", "enabled": false }
```

### `GET /metrics`

Prometheus text exposition. Ships metrics like
`openkms_signs_total{chain,label}`, `openkms_denials_total{reason}`,
`openkms_replay_hits_total`, `openkms_hsm_up`.

### Example curl

```bash
SIGNER_TOKEN=$(cat /etc/openkms/signer.token)

# Solana — delegate base64 serialization to whatever builds your tx.
curl -sX POST http://127.0.0.1:9443/sign/solana \
  -H "Authorization: Bearer $SIGNER_TOKEN" \
  -H "content-type: application/json" \
  -d "$(cat <<EOF
{ "label": "solana-hot-0",
  "message_b64": "$MSG_B64" }
EOF
)"

# Cosmos
curl -sX POST http://127.0.0.1:9443/sign/cosmos \
  -H "Authorization: Bearer $SIGNER_TOKEN" \
  -H "content-type: application/json" \
  -d "$(cat <<EOF
{ "label": "cosmos-hub-0",
  "sign_doc_b64": "$SIGN_DOC_B64",
  "expected_chain_id": "$CHAIN_ID" }
EOF
)"

# Kill switch from a separate machine
curl -sX POST \
  -H "Authorization: Bearer $(cat admin.token)" \
  http://pi.local:9443/admin/keys/solana-hot-0/disable
```

## Openclaw integration

Openclaw is the target consumer — an autonomous trading agent that
continuously proposes trades to openKMS for signing. The policy engine is
designed so that a buggy strategy cannot drain an account unsupervised:

- **Per-tx cap** limits the damage of any single bad trade.
- **Daily cap** limits the damage of sustained bad strategies.
- **Allowlists** prevent the strategy from calling an arbitrary contract.
- **Rate limits** bound the tps even if the strategy is in a tight loop.
- **Kill switch** (admin API) is the "stop everything" button the trader
  or a watchdog hits if the audit stream looks wrong.

Typical Openclaw flow:

```
strategy  ──► build tx  ──► POST /sign/{chain}  ──► openKMS
                                                     │
                                                     ▼
                              policy ok? ─ yes ──► HSM sign ──► signature
                              policy ok? ─ no  ──► 403 + audit deny record
```

Signed transactions are returned as base64 signatures; Openclaw combines
them with the transaction body and submits to the chain RPC. openKMS
never broadcasts — it only signs.

## Deployment (systemd)

See [`deploy/README.md`](deploy/README.md). Summary:

- `deploy/yubihsm-connector.service` — runs the upstream Yubico connector.
- `deploy/openkms.service` — the signer. Runs as a dedicated
  `openkms:openkms` system user with `NoNewPrivileges=true`,
  `ProtectSystem=strict`, `PrivateTmp=true`, `PrivateUsers=true`,
  `MemoryDenyWriteExecute=true`, and a `SystemCallFilter=@system-service`
  seccomp allowlist.
- `deploy/99-yubihsm.rules` — udev rule granting `plugdev` access to the
  HSM USB node so the connector user (and *only* the connector user) can
  speak to it.

## Operations

- **Config changes** — update `/etc/openkms/config.toml` and restart the
  service. There is no live `SIGHUP` reload hook in the current binary.
- **Kill switch** —
  `curl -HBearer ... /admin/keys/<label>/disable`. Persists in
  `/var/lib/openkms/key-flags.json`, so a restart keeps the switch off.
- **Tail the audit log** —
  `sudo tail -F /var/lib/openkms/audit.jsonl | jq .`.
- **Prometheus scrape** —
  `scrape_config: { static_configs: [{ targets: ["pi.local:9443"] }] }`
  on `/metrics`.

## Backup & restore

```bash
# From the old HSM (requires provisioner auth key).
openkms backup --out /secure/usb/openkms-backup.json

# Replace / factory-new HSM.
openkms setup --mnemonic-file /secure/usb/mnemonic.txt

# Restore every signing key, wrapped under the deterministic wrap key.
openkms restore --in /secure/usb/openkms-backup.json
```

The mnemonic is the *root* of the system — it re-derives the wrap key,
so an attacker who has the backup blob but not the mnemonic cannot
decrypt the wrapped signing keys.

## Testing

```bash
cargo test                          # unit tests + integration tests over real TCP sockets
cargo test --test integration       # integration tests explicitly

# Hardware tests (talk to a real YubiHSM2 via yubihsm-connector).
OPENKMS_HARDWARE_TESTS=1 cargo test --test integration -- --ignored
```

Default tests use `yubihsm::Connector::mockhsm` and hit the server through a
real bound socket with `reqwest` — no hardware required.

The ignored hardware test is intentionally strict once enabled: if
`OPENKMS_HARDWARE_TESTS=1`, an unreachable connector fails the run instead of
silently skipping. That keeps "green" hardware reports honest.

For clean-machine validation, see the checked-in GitHub Actions workflow in
`.github/workflows/ci.yml`.

For staging smoke tests against a real remote deployment, see
[`docs/remote-e2e.md`](docs/remote-e2e.md) and
`.github/workflows/remote-e2e.yml`.

## Architecture

```
src/
├── main.rs        CLI entry (detect, setup, keys, backup/restore, run)
├── lib.rs         crate root
├── config.rs      TOML loader + 0600 enforcement + validation
├── hsm.rs         Arc<Mutex<yubihsm::Client>> with mockhsm shim
├── derive.rs      BIP39 + BIP32 + SLIP-10 + HKDF ceremony
├── sig.rs         ECDSA DER<->compact + low-s normalization
├── chain/
│   ├── mod.rs     ChainSigner trait, Intent trait, Chain enum, requests
│   ├── solana.rs  VersionedMessage decode + ALT resolve + Ed25519 sign
│   └── cosmos.rs  SignDoc decode + chain_id + pubkey check + secp256k1 sign
├── policy/        per-key rate limit + caps + allowlist + kill switch
├── audit.rs       append-only JSONL with optional HMAC chain
├── metrics.rs     Prometheus counters + gauges
├── replay.rs      LRU replay cache for deterministic signatures
├── admin.rs       admin plane (kill switch, persistent flags)
└── server.rs      axum router wiring everything together

tests/
└── integration.rs end-to-end tests hitting the server over a real TCP socket
                   + hardware-gated tests (#[ignore]) for the real HSM
```

Adding a new chain:

1. Create `src/chain/<chain>.rs` implementing `ChainSigner`.
2. Add a `Chain::<Chain>` variant, a `SignRequest` route in `server.rs`,
   and any required `[cosmos]`-equivalent settings in `config.rs`.
3. Extend the policy engine's `Intent`-level checks if the new chain has
   semantics the generic checks can't express (e.g. per-call_data
   allowlisting for EVM).

The HSM, policy, audit, admin, metrics, and replay layers are chain-agnostic
and don't need changes.

## License

TBD. Intended for personal / homelab use; not yet published to crates.io.
