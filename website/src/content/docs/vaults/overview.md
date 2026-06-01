---
title: Vaults Overview
description: Pluggable signing vault backends — registry, multi-vault config, and driver-specific key identifiers.
---

**Docs path:** Vaults / Overview

openKMS routes every signing operation through a **vault**: a named backend that
holds or reaches signing keys. Vaults are declared in config as `[vaults.<name>]`
blocks; each key in `[[keys]]` names a vault and a driver-specific `key_id`.

This replaces the older top-level `[hsm]` block and per-key `object_id` field.

## Registry model

```toml
[vaults.hsm]
driver        = "yubihsm"
connector_url = "http://127.0.0.1:12345"
auth_key_id   = 3
password_file = "/etc/openkms/hsm-password"

[vaults.dev]
driver = "file"
path   = "/etc/openkms/keys.json"

[[keys]]
label  = "cosmos-hub-0"
chain  = "cosmos"
vault  = "hsm"
key_id = "0x0100"

[[keys]]
label  = "solana-dev"
chain  = "solana"
vault  = "dev"
key_id = "sol-dev"
```

Each vault block must include `driver`. Driver-specific fields are documented on
the pages below. The loader rejects unknown drivers, duplicate key labels, and
duplicate `(vault, key_id)` pairs before the service starts.

## Available drivers

| Driver | Page | Status |
| --- | --- | --- |
| `yubihsm` | [YubiHSM](/openkms/vaults/yubihsm/) | Production |
| `file` | [File (dev)](/openkms/vaults/file/) | Dev / CI only |
| `awskms` | [AWS KMS](/openkms/vaults/awskms/) | Not implemented |
| `azure` | [Azure Key Vault](/openkms/vaults/azure/) | Not implemented |
| `cloudkms` | [Google Cloud KMS](/openkms/vaults/cloudkms/) | Not implemented |
| `hashicorpvault` | [HashiCorp Vault](/openkms/vaults/hashicorpvault/) | Not implemented |
| `nitro` | [AWS Nitro Enclaves](/openkms/vaults/nitro/) | Not implemented |
| `confidentialspace` | [GCP Confidential Space](/openkms/vaults/confidentialspace/) | Not implemented |

## Ceremony and backup CLI

`openkms setup`, `openkms keys provision`, `openkms backup`, and related
ceremony commands still talk directly to a **YubiHSM** vault. Config must
include at least one `[vaults.*]` block with `driver = "yubihsm"` for those
commands. The CLI `--object-id` flags refer to YubiHSM object slots; runtime
config uses `key_id` on `[[keys]]` instead.

## Health and metrics

`/health` exposes `vault_up` after the first probe (see
[HTTP API](/openkms/reference/http-api/)). Prometheus gauge `openkms_vault_up`
tracks the same state.

## Related docs

- [Configuration](/openkms/guides/configuration/) — server, audit, state, Cosmos
  defaults, and per-key policy blocks.
- [Architecture](/openkms/reference/architecture/) — vault trait and request flow.
