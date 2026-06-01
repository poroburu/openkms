---
title: AWS KMS Vault
description: AWS KMS signing backend — not yet implemented.
---

**Docs path:** Vaults / AWS KMS

**Status: not implemented.** Config blocks with `driver = "awskms"` fail at
startup with a clear error until this driver is completed.

## Expected driver string

```toml
[vaults.aws]
driver = "awskms"
```

Stub implementation:
[`src/vault/aws.rs`](https://github.com/poroburu/openkms/blob/main/src/vault/aws.rs).

## Planned config (subject to change)

| Field | Description |
| --- | --- |
| `driver` | `awskms` |
| `region` | AWS region for the KMS client. |
| `key_id` | KMS key ARN or alias for signing operations. |

## Related docs

- [Vaults Overview](/openkms/vaults/overview/)
