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
| `POST` | `/sign/solana` | signer bearer | Sign a Solana `VersionedMessage`. |
| `POST` | `/sign/cosmos` | signer bearer | Sign a Cosmos SDK `SignDoc`. |
| `POST` | `/admin/keys/{label}/enable` | admin bearer | Enable a configured key. |
| `POST` | `/admin/keys/{label}/disable` | admin bearer | Disable a configured key. |
| `GET` | `/metrics` | none | Prometheus text exposition. |

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
