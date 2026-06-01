---
title: Azure Key Vault
description: Azure Key Vault signing backend — not yet implemented.
---

**Docs path:** Vaults / Azure Key Vault

**Status: not implemented.** Config blocks with `driver = "azure"` fail at
startup with a clear error until this driver is completed.

## Expected driver string

```toml
[vaults.azure]
driver = "azure"
```

Stub implementation:
[`src/vault/azure.rs`](https://github.com/poroburu/openkms/blob/main/src/vault/azure.rs).

## Planned config (subject to change)

| Field | Description |
| --- | --- |
| `driver` | `azure` |
| `vault_url` | Azure Key Vault URI. |
| `key_name` | Key name within the vault. |

## Related docs

- [Vaults Overview](/openkms/vaults/overview/)
