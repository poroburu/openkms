# Broadcast E2E

This repo now carries three separate automation lanes:

- `.github/workflows/ci.yml` for clean-machine repository checks against `mockhsm`
- `.github/workflows/remote-e2e.yml` for smoke tests against a real deployed
  `openkms` instance
- `.github/workflows/broadcast-e2e.yml` for live Solana and Cosmos testnet
  broadcasts through a local `openkms` server started inside GitHub Actions

The broadcast lane is intentionally manual-only (`workflow_dispatch`) at first.
It spends real testnet funds, depends on live RPC availability, and is meant to
validate end-to-end transaction assembly and submission without turning routine
repository checks into noisy, flaky runs.

## What it validates

Each job in `broadcast-e2e.yml`:

1. boots a local `openkms` HTTP server backed by `mockhsm`
2. provisions a funded throwaway signer key from GitHub secrets
3. builds a fresh transaction using live chain state
4. submits the signing request through `/sign/solana` or `/sign/cosmos`
5. assembles the signed transaction client-side
6. broadcasts it to testnet and waits for acceptance / confirmation

This complements `remote-e2e.yml` rather than replacing it:

- `remote-e2e.yml` proves the deployed signer is reachable and can sign
- `broadcast-e2e.yml` proves the local client flow can sign and land a real
  transaction on-chain

## Required secrets and variables

## Generating local key material

For local dry runs, use `scripts/generate_broadcast_key_material.sh` to create
throwaway Solana and Cosmos keys inside Docker images instead of installing the
CLIs directly on your machine:

```bash
bash ./scripts/generate_broadcast_key_material.sh both ./.tmp/broadcast-keys
set -a
source ./.tmp/broadcast-keys/broadcast-keys.env
set +a
```

If you want to replace previously generated keys in the same directory, rerun
the script with `-f`:

```bash
bash ./scripts/generate_broadcast_key_material.sh --force both ./.tmp/broadcast-keys
```

The script writes:

- `./.tmp/broadcast-keys/broadcast-keys.env` with ready-to-export env vars
- `solana/id.json` plus the derived address
- `cosmos/key.json` plus the exported unarmored hex private key

You can override the container images it uses with:

- `OPENKMS_SOLANA_CLI_IMAGE`
- `OPENKMS_COSMOS_CLI_IMAGE`

### Solana

Secrets:

- `OPENKMS_SOLANA_RPC_URL`: devnet or testnet JSON-RPC URL
- `OPENKMS_SOLANA_SIGNER_SEED_B64`: base64 of the raw 32-byte Ed25519 seed for
  a funded throwaway signer account

Optional variables:

- `OPENKMS_SOLANA_TRANSFER_LAMPORTS`: transfer amount, defaults to `5000`
- `OPENKMS_SOLANA_CONFIRM_TIMEOUT_SECS`: confirmation timeout, defaults to `90`

### Cosmos

Secrets:

- `OPENKMS_COSMOS_REST_URL`: REST/LCD base URL for the target testnet
- `OPENKMS_COSMOS_SIGNER_SCALAR_B64`: base64 of the raw 32-byte secp256k1
  scalar for a funded throwaway signer account

Variables:

- `OPENKMS_COSMOS_FEE_DENOM`: fee denomination, such as `uatom`
- `OPENKMS_COSMOS_FEE_AMOUNT`: fee amount to include in `AuthInfo`

Optional variables:

- `OPENKMS_COSMOS_CHAIN_ID`: if unset, the test queries node info at runtime
- `OPENKMS_COSMOS_HRP`: address prefix, defaults to `cosmos`
- `OPENKMS_COSMOS_GAS_LIMIT`: gas limit, defaults to `200000`
- `OPENKMS_COSMOS_TRANSFER_AMOUNT`: transfer amount, defaults to `1`
- `OPENKMS_COSMOS_CONFIRM_TIMEOUT_SECS`: confirmation timeout, defaults to `90`

## Operational guidance

- Use disposable accounts with only the minimum testnet funds needed to cover
  the tiny transfer plus fees.
- Keep Solana and Cosmos signers separate so one chain can be rotated without
  affecting the other.
- Expect some environmental flake from RPCs and testnets; treat this workflow as
  a manual verification or release gate, not a per-push signal.
- If you rotate a funded signer, update the corresponding secret and re-fund the
  derived address before running the workflow again.
