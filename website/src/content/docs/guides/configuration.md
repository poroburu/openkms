---
title: Configuration
description: Every block in config.toml — server, HSM, audit, state, Cosmos defaults, and per-key policy.
---

**Docs path:** Operate / Configuration

`config.toml` normally lives at `/etc/openkms/config.toml`. The canonical
example in the repository is
[`examples/config.toml`](https://github.com/poroburu/openkms/blob/main/examples/config.toml).
The drift test in
[`tests/docs_drift.rs`](https://github.com/poroburu/openkms/blob/main/tests/docs_drift.rs)
parses and `.validate()`-checks that file, so documented field names stay live.

The loader rejects duplicate key labels, duplicate `object_id` values, missing
policy blocks, and invalid allowlist strings before the service starts.
Evaluation order for the policy fields is in
[Policy Authoring](/openkms/guides/policy-authoring/).

## `[server]`

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `listen` | yes | — | Bind address. `127.0.0.1:9443` for loopback / reverse proxy; `0.0.0.0:PORT` only on a hardened staging host. |
| `admin_token_file` | yes | — | Bearer token for `/admin/*`. Must be `0600`. |
| `inflight_limit` | no | `64` | Max concurrent in-flight signing requests. Excess returns `503` from the buffer/limit layer. |
| `replay_window_secs` | no | `120` | Replay-cache lifetime for deterministic signatures. |

## `[hsm]`

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `connector_url` | yes | — | `yubihsm-connector` HTTP endpoint, normally on loopback. |
| `auth_key_id` | yes | — | YubiHSM auth-key slot the runtime authenticates as. `3` is the signer slot from `openkms setup`. |
| `password_file` | yes | — | 64 hex digits (32 bytes) for the signer auth-key password. Generate with `openkms ceremony print-signer-password`. Must be `0600`. |

## `[audit]`

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `path` | yes | — | Append-only JSONL audit log (typically under `state_dir`). |
| `hmac_key_file` | no | — | When set, every audit record includes an HMAC of the prior chain. The key file must be `0600`. |

## `[pairing]`

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `enabled` | no | `true` | When false, `POST /pair/request` is rejected. |
| `pending_ttl_secs` | no | `900` | Pending request expiry. |
| `max_pending` | no | `32` | Max concurrent pending requests. |
| `reveal_addresses` | no | `false` | When true, `GET /pair/pool` may include allocatable key addresses. |

Clients may include an optional `bearer` field on `POST /pair/request` (`okms_` + 64 hex). openKMS stores only a hash until the operator approves; omit `bearer` for server-mint on approve.

### `[pairing.balance]`

Required for auto `pick: most` or `pick: least`.

| Field | Description |
| --- | --- |
| `solana_rpc_url` | Solana JSON-RPC for `getBalance` / SPL balances. |
| `cosmos_rest_url` | Cosmos REST base for bank balances. |
| `query_timeout_ms` | RPC timeout (default `2000`). |

## `state_dir`

Top-level path used for runtime persistence: admin policy overlays,
pairing state (`pairing.json`), kill-switch flags, and the audit log when
`[audit].path` is relative. Set this on a writable, dedicated directory (e.g.
`/var/lib/openkms`).

## `[cosmos]`

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `accepted_pubkey_type_urls` | no | secp256k1, Ethermint ethsecp256k1, Injective ethsecp256k1 | `AuthInfo.signer_infos[].public_key.type_url` values the decoder will accept. Add chain-specific URLs without code changes. |

## `[[keys]]`

One block per signing key.

| Field | Required | Default | Description |
| --- | --- | --- | --- |
| `label` | yes | — | Stable identifier used in HTTP requests and the audit log. |
| `chain` | yes | — | `solana` or `cosmos`. |
| `object_id` | yes | — | YubiHSM asymmetric-key object id (decimal or `0x0100`). |
| `derivation_path` | no | — | BIP-32 / SLIP-10 path used when `keys provision` imports a deterministic key (Cosmos: `m/44'/118'/0'/0/0`; Solana: `m/44'/501'/0'/0'`). |
| `address_style` | no | `cosmos` | `cosmos`, `evm`, or `solana`. Drives address derivation and recipient comparisons. |
| `default_hrp` | no | — | Bech32 prefix for Cosmos-style derivations (e.g. `cosmos`, `osmo`). |
| `allocatable` | no | `false` | When true, key may be assigned via auto pairing (`pick` + `chain`). |
| `policy` | yes | — | `[keys.policy]` block (see below). |

### Solana `[[keys]]` example

```toml
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
  id      = "11111111111111111111111111111111"
  comment = "system transfers"
```

### Cosmos `[[keys]]` example

```toml
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
daily_cap_lamports   = "5000000000"
per_tx_cap_lamports  = "500000000"

  [[keys.policy.allowed_messages]]
  type_url           = "/cosmos.bank.v1beta1.MsgSend"
  allowed_recipients = ["cosmos1replace_me"]
  per_tx_cap         = { uatom = "500000000" }
```

## `[keys.policy]`

| Field | Default | Description |
| --- | --- | --- |
| `enabled` | `false` | Master switch for the key. The admin kill switch and overlays can override this at runtime. |
| `max_signs_per_minute` | unset | Token-bucket rate limit. |
| `max_signs_per_hour` | unset | Token-bucket rate limit. |
| `max_signs_per_day` | unset | Token-bucket rate limit. |
| `per_tx_cap_lamports` | unset | Solana keys: cap on outgoing lamport totals per signed transaction. Cosmos keys: prefer denom-keyed `per_tx_cap` inside `[[allowed_messages]]`. |
| `daily_cap_lamports` | unset | Solana keys: cap on accepted signed transfers in a rolling 24h window. |
| `[[keys.policy.allowed_programs]]` | empty | Solana program allowlist (`id`, optional `comment`). Empty means no programs are permitted. |
| `[[keys.policy.allowed_messages]]` | empty | Cosmos message-type allowlist with optional `allowed_recipients`, `allowed_contracts`, `allowed_methods`, and denom-keyed `per_tx_cap`. Empty means no Cosmos message types are permitted. |
| `[[keys.policy.allowed_recipients]]` | empty | Recipient allowlist tied to a `program` family. |

Empty allowlists are meaningful: a Solana key with no `allowed_programs` and a
Cosmos key with no `allowed_messages` will deny every signing request.

## Secret files

These must be mode `0600` or openKMS refuses to start:

- `signer.token`
- `admin.token`
- `hsm-password`
- `audit-hmac.key` (when `hmac_key_file` is set)
