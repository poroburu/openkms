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
3. Per-transaction caps reject outgoing transfer totals above `per_tx_cap_lamports`.
4. Daily caps reject once accepted signed transfer totals exceed `daily_cap_lamports` in the rolling window.
5. Allowlists check invoked Solana programs, Cosmos message type URLs, and recipients.

Empty allowlists are meaningful. For example, `allowed_messages = []` means no
Cosmos message types are permitted from that key.

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
