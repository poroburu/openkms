---
title: File Vault (dev)
description: File-based vault for local development and CI — keys.json format and config.
---

**Docs path:** Vaults / File (dev)

The `file` driver loads raw signing material from a JSON file on disk and signs
in-process. **Never use this driver in production.** It exists for local
development, integration tests, and CI lanes that do not have a YubiHSM attached.

Implementation:
[`src/vault/file.rs`](https://github.com/poroburu/openkms/blob/main/src/vault/file.rs).

## Config

```toml
[vaults.dev]
driver = "file"
path   = "/etc/openkms/keys.json"
```

| Field | Required | Description |
| --- | --- | --- |
| `driver` | yes | Must be `file`. |
| `path` | yes | Path to the keys JSON file. Must be mode `0600` or openKMS refuses to start. |

## keys.json format

The file is a JSON array of key entries:

```json
[
  {
    "name": "sol-dev",
    "algorithm": "ed25519",
    "secret_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  },
  {
    "name": "cosmos-dev",
    "algorithm": "secp256k1",
    "secret_hex": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  }
]
```

| Field | Description |
| --- | --- |
| `name` | Label referenced by `key_id` in config. Must be unique within the file. |
| `algorithm` | `ed25519` (Solana) or `secp256k1` (Cosmos). |
| `secret_hex` | 32-byte raw secret as 64 hex digits. |

## Key binding

```toml
[[keys]]
label  = "solana-dev"
chain  = "solana"
vault  = "dev"
key_id = "sol-dev"

[[keys]]
label  = "cosmos-dev"
chain  = "cosmos"
vault  = "dev"
key_id = "cosmos-dev"
```

`key_id` must match the `name` field in `keys.json`.

## Related docs

- [Vaults Overview](/openkms/vaults/overview/)
- [Testing and Automation](/openkms/operations/testing/)
