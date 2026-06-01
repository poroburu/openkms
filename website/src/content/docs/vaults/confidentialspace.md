---
title: GCP Confidential Space Vault
description: Google Cloud Confidential Space TEE signing backend — not yet implemented.
---

**Docs path:** Vaults / GCP Confidential Space

**Status: not implemented.** Config blocks with `driver = "confidentialspace"`
fail at startup with a clear error until this driver is completed.

## Expected driver string

```toml
[vaults.gcp_tee]
driver = "confidentialspace"
```

Stub implementation:
[`src/vault/confidentialspace.rs`](https://github.com/poroburu/openkms/blob/main/src/vault/confidentialspace.rs).

## Planned config (subject to change)

| Field | Description |
| --- | --- |
| `driver` | `confidentialspace` |
| `workload_identity` | GCP workload identity configuration for the Confidential Space workload. |

## Related docs

- [Vaults Overview](/openkms/vaults/overview/)
