---
title: Google Cloud KMS Vault
description: Google Cloud KMS signing backend — not yet implemented.
---

**Docs path:** Vaults / Google Cloud KMS

**Status: not implemented.** Config blocks with `driver = "cloudkms"` fail at
startup with a clear error until this driver is completed.

## Expected driver string

```toml
[vaults.gcp]
driver = "cloudkms"
```

Stub implementation:
[`src/vault/cloudkms.rs`](https://github.com/poroburu/openkms/blob/main/src/vault/cloudkms.rs).

## Planned config (subject to change)

| Field | Description |
| --- | --- |
| `driver` | `cloudkms` |
| `project_id` | GCP project id. |
| `location` | KMS key ring location. |
| `key_ring` | Key ring name. |
| `key_name` | Crypto key name. |

## Related docs

- [Vaults Overview](/openkms/vaults/overview/)
