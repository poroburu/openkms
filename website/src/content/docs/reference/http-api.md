---
title: HTTP API
description: Public HTTP routes and the generated OpenAPI source of truth.
---

**Docs path:** Reference / HTTP API

All JSON endpoints use bearer-token authentication where noted. Signing routes
use the token in `signer_token_file`; admin routes use `admin_token_file`.

The machine-readable API source of truth is the committed
[`openapi/openkms.v1.json`](https://github.com/poroburu/openkms/blob/main/openapi/openkms.v1.json)
spec. CI regenerates it from Rust code and fails when it drifts.

Direct artifact links:

- [OpenAPI JSON](https://github.com/poroburu/openkms/blob/main/openapi/openkms.v1.json)
- [OpenAPI generator](https://github.com/poroburu/openkms/blob/main/src/openapi.rs)

## Routes

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | none | Health check and HSM probe state. |
| `GET` | `/keys` | none | List configured keys and runtime enabled state. |
| `GET` | `/policy` | signer bearer | List effective signing policies and live usage counters. |
| `GET` | `/policy/{label}` | signer bearer | Read one key's effective policy before signing. |
| `POST` | `/sign/solana` | signer bearer | Sign a Solana `VersionedMessage`. |
| `POST` | `/sign/cosmos` | signer bearer | Sign a Cosmos SDK `SignDoc`. |
| `GET` | `/admin/policy` | admin bearer | List policies with baseline and overlay metadata. |
| `GET` | `/admin/keys/{label}/policy` | admin bearer | Read one key policy with admin metadata. |
| `PATCH` | `/admin/keys/{label}/policy` | admin bearer | Persist a partial per-key policy overlay. |
| `DELETE` | `/admin/keys/{label}/policy` | admin bearer | Clear a policy overlay and return to config baseline. |
| `POST` | `/admin/keys/{label}/enable` | admin bearer | Enable a configured key. |
| `POST` | `/admin/keys/{label}/disable` | admin bearer | Disable a configured key. |
| `GET` | `/metrics` | none | Prometheus text exposition. |

## Policy Inspection

Signer agents should read policy before requesting signatures:

```bash
curl -sS \
  -H "Authorization: Bearer $(cat signer.token)" \
  http://pi.local:9443/policy/solana-hot-0
```

Responses include key identity, the effective policy, and runtime counters:

```json
{
  "label": "solana-hot-0",
  "chain": "solana",
  "effective_enabled": true,
  "policy": {
    "enabled": true,
    "max_signs_per_minute": 30,
    "max_signs_per_day": 5000,
    "per_tx_cap_lamports": "5000000000",
    "allowed_programs": [{ "id": "11111111111111111111111111111111" }]
  },
  "runtime": {
    "enabled_override": null,
    "daily_spend": [{ "token": "native", "spent": "0", "cap": null }],
    "sign_counts": {
      "per_minute": { "limit": 30, "used": 0, "window_secs": 60 }
    }
  }
}
```

The runtime sign counters are accepted policy evaluations inside each window.
They help agents self-throttle, but the policy engine remains authoritative.

## Admin Policy Overlays

Admin policy mutation stores a partial overlay under `state_dir`; it does not
rewrite `config.toml`. The effective policy is the config baseline plus the
persisted overlay. Non-null fields in a `PATCH` replace the corresponding
baseline policy field. Use `DELETE /admin/keys/{label}/policy` to clear the
whole overlay.

```bash
curl -sS -X PATCH \
  -H "Authorization: Bearer $(cat admin.token)" \
  -H "Content-Type: application/json" \
  http://pi.local:9443/admin/keys/solana-hot-0/policy \
  -d '{ "max_signs_per_minute": 5, "per_tx_cap_lamports": "1000000" }'
```

## Solana Signing

```json
{
  "label": "solana-hot-0",
  "expected_chain_id": "mainnet-beta",
  "message_b64": "<base64 VersionedMessage>",
  "address_lookup_tables": [
    { "key": "<ALT pubkey>", "addresses": ["<base58>", "..."] }
  ]
}
```

Response:

```json
{ "signature_b64": "<base64 64-byte ed25519>" }
```

## Cosmos Signing

```json
{
  "label": "cosmos-hub-0",
  "sign_doc_b64": "<base64 proto-encoded SignDoc>",
  "expected_chain_id": "cosmoshub-4"
}
```

Response:

```json
{ "signature_b64": "<base64 64-byte compact low-s ECDSA>" }
```

## Error Shape

JSON API errors use this shape:

```json
{ "error": "human-readable reason" }
```

Policy denials return `403` or `429` depending on the denial reason. Decode
errors return `400`, unknown labels return `404`, and HSM/internal failures
return `500`.
