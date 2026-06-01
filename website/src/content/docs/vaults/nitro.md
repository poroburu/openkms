---
title: AWS Nitro Enclaves Vault
description: AWS Nitro Enclaves TEE signing backend — not yet implemented.
---

**Docs path:** Vaults / AWS Nitro Enclaves

**Status: not implemented.** Config blocks with `driver = "nitro"` fail at
startup with a clear error until this driver is completed.

## Expected driver string

```toml
[vaults.nitro]
driver = "nitro"
```

Stub implementation:
[`src/vault/nitro.rs`](https://github.com/poroburu/openkms/blob/main/src/vault/nitro.rs).

## Planned config (subject to change)

| Field | Description |
| --- | --- |
| `driver` | `nitro` |
| `enclave_endpoint` | VSock or local proxy endpoint for the enclave signer. |

## Related docs

- [Vaults Overview](/openkms/vaults/overview/)
