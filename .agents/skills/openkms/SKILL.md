---
name: openkms
description: Use the openKMS HTTP API safely for Solana and Cosmos signing. Use when an agent needs to inspect openKMS keys, read signing policy limits, request signatures, or administer subordinate signing policies.
---

# openKMS

openKMS is a signing boundary, not a broadcaster. Build the transaction, ask openKMS to sign it, attach the returned signature, then broadcast through the chain RPC yourself.

## Before Signing

1. Read `GET /policy/{label}` with the signer bearer token.
2. Confirm `effective_enabled` is `true`.
3. Check `policy` for allowed programs, message type URLs, recipients, per-transaction caps, and daily caps.
4. Check `runtime.daily_spend` and `runtime.sign_counts` to avoid predictable denials.
5. Only submit a signing request if the transaction fits the effective policy.

Use `GET /policy` when choosing among configured keys.

## Signing

Use the signer bearer token only for routine signing.

Solana:

```bash
curl -sS -X POST "$OPENKMS_BASE_URL/sign/solana" \
  -H "Authorization: Bearer $OPENKMS_SIGNER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"solana-hot-0","message_b64":"<base64 VersionedMessage>"}'
```

Cosmos:

```bash
curl -sS -X POST "$OPENKMS_BASE_URL/sign/cosmos" \
  -H "Authorization: Bearer $OPENKMS_SIGNER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"cosmos-hub-0","sign_doc_b64":"<base64 SignDoc>","expected_chain_id":"cosmoshub-4"}'
```

Successful responses contain `signature_b64`. Policy denials return `403` or `429`; decode errors return `400`; unknown labels return `404`.

## Admin Use

Use the admin bearer token only for trusted operator workflows or supervisor agents.

- `GET /admin/policy`: inspect effective policies with baseline and overlay metadata.
- `GET /admin/keys/{label}/policy`: inspect one key.
- `PATCH /admin/keys/{label}/policy`: persist a policy overlay under `state_dir`.
- `DELETE /admin/keys/{label}/policy`: clear the overlay and return to `config.toml` baseline.
- `POST /admin/keys/{label}/disable`: kill switch.
- `POST /admin/keys/{label}/enable`: re-enable after review.

Never put bearer tokens in prompts, logs, PR descriptions, or committed files.

## Security Rules

- Treat openKMS plain HTTP as safe only on loopback, a tunnel, a private tailnet, or behind TLS termination.
- Do not assume `/keys` or `/metrics` are private unless the deployment network makes them private.
- The HSM protects private key material; policy protects signing intent. If policy allows a bad transaction, openKMS can still sign it.
- Empty allowlists deny that dimension. A Solana key needs allowed programs; a Cosmos key needs allowed message type URLs.
