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

Use the admin API as the kill switch:

```bash
curl -sX POST \
  -H "Authorization: Bearer $(cat admin.token)" \
  http://pi.local:9443/admin/keys/solana-hot-0/disable
```
