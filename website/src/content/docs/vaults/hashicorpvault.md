---
title: HashiCorp Vault
description: HashiCorp Vault signing backend — not yet implemented.
---

**Docs path:** Vaults / HashiCorp Vault

**Status: not implemented.** Config blocks with `driver = "hashicorpvault"` fail
at startup with a clear error until this driver is completed.

## Expected driver string

```toml
[vaults.hcv]
driver = "hashicorpvault"
```

Stub implementation:
[`src/vault/hashicorp.rs`](https://github.com/poroburu/openkms/blob/main/src/vault/hashicorp.rs).

## Planned config (subject to change)

| Field | Description |
| --- | --- |
| `driver` | `hashicorpvault` |
| `address` | Vault server URL. |
| `mount` | Transit secrets engine mount path. |
| `key_name` | Transit key name. |

## Related docs

- [Vaults Overview](/openkms/vaults/overview/)
