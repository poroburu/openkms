---
title: Policy Authoring
description: How per-key signing policy is evaluated.
---

**Docs path:** Operate / Policy Authoring

Every `[[keys]]` entry must include a `[keys.policy]` block. Policy evaluation
is fail-closed and runs before the HSM signs.

## Evaluation Order

1. `enabled = false` or an admin-set kill switch denies the request.
2. Rate limits consume tokens for `max_signs_per_minute`, `max_signs_per_hour`, and `max_signs_per_day`.
3. Per-transaction and rolling-daily caps reject transfers that exceed the
   configured limits (chain-specific shape — see below).
4. Allowlists check invoked Solana programs, Cosmos message type URLs, and
   recipients.

Empty allowlists are meaningful. A Solana key with no `allowed_programs` and a
Cosmos key with no `allowed_messages` will deny every signing request.

## Caps are chain-shaped

Cap field names share a `_lamports` suffix for historical reasons. The shapes
operators care about differ per chain. See
[Configuration](/openkms/guides/configuration/) for the full schema.

### Solana keys

Use `per_tx_cap_lamports` and `daily_cap_lamports` directly on the key policy.
The values are decimal strings of native lamports, summed across outgoing
transfers in the signed transaction:

```toml
[keys.policy]
per_tx_cap_lamports = "5000000000"
daily_cap_lamports  = "20000000000"
```

### Cosmos keys

Cosmos messages carry denom-aware coin amounts, so caps live on the message
allowlist instead. Each `[[allowed_messages]]` entry can pin a denom-keyed
`per_tx_cap`:

```toml
[[keys.policy.allowed_messages]]
type_url           = "/cosmos.bank.v1beta1.MsgSend"
allowed_recipients = ["cosmos1..."]
per_tx_cap         = { uatom = "500000000" }
```

`per_tx_cap_lamports` and `daily_cap_lamports` on Cosmos keys still parse and
apply to anything the engine measures in lamport-equivalent units, but
denom-keyed `per_tx_cap` is the source of truth for `MsgSend` and similar
amount-bearing messages. Authoring policy without a `per_tx_cap` block on a
Cosmos `MsgSend` allowlist entry is a drift signal — every accepted transfer
will pass without an amount check.

## Operational Notes

The policy engine has an internal reload path that preserves runtime counters
by key label, but the `openkms run` binary does not currently wire that to
`SIGHUP` or another live reload hook. Edit the TOML and restart the service to
apply changes.

Admin API policy overlays are the exception for per-key operating limits. Server,
HSM, chain, and baseline key configuration stay in `config.toml`; trusted admin
workflows can apply partial policy overlays through
`PATCH /admin/keys/{label}/policy`. These overlays are persisted under
`state_dir`, survive restarts, and are merged over the config baseline before the
policy engine evaluates signing requests.

Signer agents can read `GET /policy/{label}` to see the effective policy and
live counters before they ask for a signature. Admin agents can read
`GET /admin/keys/{label}/policy` to also see whether the effective policy came
from config alone or from config plus an overlay.

Use the admin API as the kill switch:

```bash
curl -sX POST \
  -H "Authorization: Bearer $(cat admin.token)" \
  http://pi.local:9443/admin/keys/solana-hot-0/disable
```
