# Remote E2E Smoke Tests

This repo now carries two separate automation lanes:

- `.github/workflows/ci.yml` for clean-machine validation against `mockhsm`
- `.github/workflows/remote-e2e.yml` for staging smoke tests against a real
  deployed `openkms` instance

The remote lane is intentionally a smoke test, not a load test. Its job is to
prove that a real deployment can answer `/health`, `/keys`, `/metrics`, and a
safe signing request built for a devnet or testnet account.

## Why keep this separate from CI?

`mockhsm` gives fast, deterministic coverage for routing, decoding, and most
policy behavior, but it does not prove:

- the real `yubihsm-connector` is reachable
- the deployed host has the expected file permissions and systemd wiring
- the staging URL, bearer tokens, and network path work outside one machine

Treat the remote smoke lane as a release/staging gate, not as a replacement for
the fast CI job.

## Workflow inputs

`remote-e2e.yml` reads these secrets:

- `OPENKMS_BASE_URL`: reachable base URL such as `https://signer-staging.example.com`
- `OPENKMS_SIGNER_TOKEN`: signer bearer token for the staging environment
- `OPENKMS_REMOTE_E2E_REQUEST_B64`: base64-encoded JSON request body for one
  safe signing call

Optional variables:

- `OPENKMS_SIGN_PATH`: request path, defaults to `/sign/solana`
- `OPENKMS_EXPECT_KEY_LABEL`: if set, the smoke test asserts that `/keys`
  includes this label

## Building the request fixture

The request body must match the current HTTP API shape. Example Solana fixture:

```json
{
  "label": "solana-hot-0",
  "message_b64": "<base64 VersionedMessage>"
}
```

Example Cosmos fixture:

```json
{
  "label": "cosmos-hub-0",
  "sign_doc_b64": "<base64 SignDoc>",
  "expected_chain_id": "theta-testnet-001"
}
```

Encode the JSON into one line before storing it as a secret:

```bash
base64 -w0 request.json
```

Use a payload that signs for a staging-only key and a devnet/testnet account.
The service never broadcasts, so the caller that constructs this request should
also own the separate "submit to chain" step if you want a fuller system test.

## Local dry run

You can run the same smoke script outside GitHub Actions:

```bash
OPENKMS_BASE_URL="https://signer-staging.example.com" \
OPENKMS_SIGNER_TOKEN="..." \
OPENKMS_SIGN_PATH="/sign/solana" \
OPENKMS_EXPECT_KEY_LABEL="solana-hot-0" \
OPENKMS_SIGN_REQUEST_FILE="./request.json" \
./scripts/remote_e2e_smoke.sh
```

If the staging service is only reachable inside a private network, run the
workflow from a self-hosted runner in that network or invoke the script from an
operator machine with equivalent access.
