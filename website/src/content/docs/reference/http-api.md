---
title: HTTP API
description: Public HTTP routes and the generated OpenAPI source of truth.
---

**Docs path:** Reference / HTTP API

JSON signing routes use a **per-client pairing bearer** scoped to one key label. Admin routes use `admin_token_file`.

The machine-readable API source of truth is the committed
[`openapi/openkms.v1.json`](https://github.com/poroburu/openkms/blob/main/openapi/openkms.v1.json)
spec. CI regenerates it from Rust code and fails when it drifts.

## Routes

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | none | Health check and HSM probe state. |
| `GET` | `/keys` | none | Key pool capacity summary (same as `/pair/pool`). |
| `GET` | `/pair/pool` | none | Pool counts per chain (no addresses by default). |
| `POST` | `/pair/request` | none | Request labeled or auto pairing. |
| `GET` | `/policy` | pairing bearer | Policy for the paired label only. |
| `GET` | `/policy/{label}` | pairing bearer **or** `?request_id=` | Read policy (label must match token). While a pairing request is pending, poll with `?request_id=<id>` (no bearer): `{"status":"pending",…}`. After operator approve, the next poll returns `{"status":"approved","token":"okms_…","policy":{…}}` once; then use the bearer on later calls. |
| `POST` | `/sign/solana` | pairing bearer | Sign a Solana `VersionedMessage`. |
| `POST` | `/sign/cosmos` | pairing bearer | Sign a Cosmos SDK `SignDoc`. |
| `GET` | `/admin/pair/pending` | admin | Pending pairing requests. |
| `GET` | `/admin/pair` | admin | Active pairings. |
| `GET` | `/admin/pair/pool` | admin | Full pool with addresses. |
| `POST` | `/admin/pair/{id}/approve` | admin | Approve; returns bearer token once. |
| `POST` | `/admin/pair/{id}/reject` | admin | Reject pending request. |
| `DELETE` | `/admin/pair/{id}` | admin | Revoke pairing (frees allocatable slot). |
| `GET` | `/admin/policy` | admin | List policies with baseline and overlay metadata. |
| `GET` | `/admin/keys/{label}/policy` | admin | Read one key policy with admin metadata. |
| `PATCH` | `/admin/keys/{label}/policy` | admin | Persist a partial per-key policy overlay. |
| `DELETE` | `/admin/keys/{label}/policy` | admin | Clear a policy overlay. |
| `POST` | `/admin/keys/{label}/enable` | admin | Enable a configured key. |
| `POST` | `/admin/keys/{label}/disable` | admin | Disable a configured key. |
| `GET` | `/metrics` | none | Prometheus text exposition. |

## Pairing

**Labeled request** (client knows the key):

```json
{ "client_id": "pay-laptop", "label": "solana-hot-0" }
```

**Labeled request with client-generated bearer** (recommended for laptop clients):

```json
{
  "client_id": "pay-laptop",
  "label": "solana-hot-0",
  "bearer": "okms_<64 hex chars>"
}
```

Generate on the client (`okms_$(openssl rand -hex 32)`), save to a mode-`0600` file, then include the same string in `bearer`. openKMS stores only a SHA-256 hash until the operator approves. Use TLS on untrusted networks — the bearer crosses the wire in the request body.

If `bearer` is omitted, the server mints a token on approve (legacy path).

**Auto request** (assign an unused allocatable key):

```json
{
  "client_id": "pay-laptop",
  "chain": "solana",
  "pick": "least",
  "asset": { "kind": "native" }
}
```

`pick` is `most`, `least`, or `random`. `most`/`least` require `[pairing.balance]` RPC URLs in config.

Operator approval:

```bash
openkms pair list
openkms pair approve <request_id>
```

The approve response includes `bearer_source` (`server` or `client`). When `server`, a `token` field is present (shown once). When `client`, the bearer was submitted on `POST /pair/request` and is not repeated — use the value already saved on the device. Server-mint pairings may also deliver the token once via `GET /policy/{label}?request_id=…` poll after approval. Store bearer files at mode `0600` and pass `Authorization: Bearer …` on `/policy` and `/sign/*`.

## Policy inspection

```bash
curl -sS \
  -H "Authorization: Bearer $(cat openkms.token)" \
  http://pi.local:9443/policy/solana-hot-0
```

See the OpenAPI spec for request/response schemas and admin policy overlay details.
