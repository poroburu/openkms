---
title: Configuration
description: Configure server, HSM, audit, and per-key policy settings.
---

`config.toml` normally lives at `/etc/openkms/config.toml`. The canonical
example in the repository is
[`examples/config.toml`](https://github.com/poroburu/openkms/blob/main/examples/config.toml);
tests parse and validate that file so documented field names stay live.

## Minimal Shape

```toml
[server]
listen             = "127.0.0.1:9443"
signer_token_file  = "/etc/openkms/signer.token"
admin_token_file   = "/etc/openkms/admin.token"

[hsm]
connector_url = "http://127.0.0.1:12345"
auth_key_id   = 3
password_file = "/etc/openkms/hsm-password"

[[keys]]
label     = "solana-hot-0"
chain     = "solana"
object_id = 0x0101

[keys.policy]
enabled = true

  [[keys.policy.allowed_programs]]
  id = "11111111111111111111111111111111"
```

## Secret Files

All secret files must be mode `0600` or openKMS refuses to start:

- `signer.token`
- `admin.token`
- `hsm-password`
- `audit-hmac.key`

The loader also rejects duplicate key labels, duplicate object IDs, missing
policy blocks, and invalid allowlist strings before the service starts.
