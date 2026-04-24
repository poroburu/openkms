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

- `./.tmp/broadcast-keys/broadcast-keys.env` with ready-to-export env vars,
  including the resolved `OPENKMS_SOLANA_CLI_IMAGE` /
  `OPENKMS_COSMOS_CLI_IMAGE` values, `OPENKMS_SOLANA_SIGNER_SEED_B64` and
  `OPENKMS_SOLANA_SIGNER_ADDRESS` (Solana), `OPENKMS_COSMOS_SIGNER_SCALAR_B64`
  and `OPENKMS_COSMOS_SIGNER_ADDRESS` (Cosmos), `OPENKMS_COSMOS_CHAIN_REGISTRY_URL`,
  plus Cosmos broadcast lines (`OPENKMS_COSMOS_REST_URL`, fee denom/amount,
  optional `OPENKMS_COSMOS_CHAIN_ID` / `OPENKMS_COSMOS_HRP`) from the same
  `chain.json` used for the Gaia image tag — enough to run
  `run_broadcast_e2e.sh cosmos` after sourcing (RPC for Solana still comes from
  the run script default or `OPENKMS_SOLANA_RPC_URL`).
- `solana/id.json` plus `solana/address.txt`
- `cosmos/key.json` plus `cosmos/private.hex`

You can override the container images and Cosmos key name with:

- `OPENKMS_SOLANA_CLI_IMAGE`
- `OPENKMS_COSMOS_CLI_IMAGE`
- `OPENKMS_COSMOS_CHAIN_REGISTRY_URL` (also used for Gaia tag resolution and
  the Cosmos broadcast snippet)
- `OPENKMS_COSMOS_KEY_NAME` (Cosmos key label inside the temporary keyring)

## Running broadcast tests locally

Use `scripts/run_broadcast_e2e.sh` to source key material (optional), set
`OPENKMS_BROADCAST_TESTS=1`, apply defaults (Solana devnet RPC; Cosmos REST/fee
/chain id from [chain-registry](https://github.com/cosmos/chain-registry) when
unset), then run the ignored `cargo` integration tests:

```bash
# After: bash ./scripts/generate_broadcast_key_material.sh both ./.tmp/broadcast-keys
./scripts/run_broadcast_e2e.sh solana --env-file ./.tmp/broadcast-keys
./scripts/run_broadcast_e2e.sh cosmos --env-file ./.tmp/broadcast-keys
./scripts/run_broadcast_e2e.sh both --env-file ./.tmp/broadcast-keys
```

Override Cosmos REST or fee flags only when you do not want registry defaults,
for example:

```bash
./scripts/run_broadcast_e2e.sh cosmos --env-file ./.tmp/broadcast-keys \
  --cosmos-rest 'https://YOUR_LCD' \
  --cosmos-fee-denom uatom \
  --cosmos-fee-amount 2000
```

Pass extra `cargo test` arguments after `--`. Preview without running:

```bash
./scripts/run_broadcast_e2e.sh solana -e ./.tmp/broadcast-keys --dry-run
```

If `--env-file` is omitted, the script looks for
`./.tmp/broadcast-keys/broadcast-keys.env`. If that file is missing, it skips
sourcing so you can rely on variables already exported (for example in CI).

**Solana:** fund the signer pubkey on the cluster you use (`OPENKMS_SOLANA_RPC_URL`)
before running the broadcast test. The test only checks balance (transfer plus
`OPENKMS_SOLANA_FEE_RESERVE_LAMPORTS`); it does **not** obtain SOL automatically.
**Cosmos:** fund the signer so it exists on chain before the first run (see the
Cosmos variables subsection below).

### Environment variables (broadcast tests)

The subsections below list variables read by the broadcast **test binaries**
(`tests/broadcast_*_e2e.rs`). `OPENKMS_COSMOS_CHAIN_REGISTRY_URL` is only read by
`run_broadcast_e2e.sh` and keygen when filling defaults, not by Rust. Keygen also
writes `OPENKMS_SOLANA_SIGNER_ADDRESS`, `OPENKMS_COSMOS_SIGNER_ADDRESS`, and the
resolved CLI image lines for convenience; the tests ignore those.

**Gate:** `OPENKMS_BROADCAST_TESTS` must be exactly `1` or the ignored tests exit
early. `run_broadcast_e2e.sh` and `.github/workflows/broadcast-e2e.yml` set this.

#### Solana

**Required for `cargo test`:**

- `OPENKMS_SOLANA_RPC_URL` — JSON-RPC base URL for the cluster you fund against.
  `run_broadcast_e2e.sh` sets `https://api.devnet.solana.com` if still unset after
  sourcing the env file.
- `OPENKMS_SOLANA_SIGNER_SEED_B64` — base64 of the raw 32-byte Ed25519 seed.

**Optional (defaults in parentheses):**

- `OPENKMS_SOLANA_CHAIN_ID` (`devnet`) — cluster label sent to `/sign/solana`;
  must match the RPC cluster.
- `OPENKMS_SOLANA_TRANSFER_LAMPORTS` (`5000`)
- `OPENKMS_SOLANA_FEE_RESERVE_LAMPORTS` (`50000`) — reserved on top of the
  transfer in the balance check.
- `OPENKMS_SOLANA_CONFIRM_TIMEOUT_SECS` (`90`)

#### Cosmos

**Required for `cargo test`:**

- `OPENKMS_COSMOS_REST_URL` — REST/LCD base URL. Filled from chain-registry when
  you use `run_broadcast_e2e.sh` with those vars unset, or from
  `broadcast-keys.env` after keygen.
- `OPENKMS_COSMOS_SIGNER_SCALAR_B64` — base64 of the raw 32-byte secp256k1
  scalar. The derived address must **already exist in chain state** (at least one
  inbound transfer is enough); otherwise
  `GET .../cosmos/auth/v1beta1/accounts/{addr}` returns **404** until the account
  exists.
- `OPENKMS_COSMOS_FEE_DENOM` — fee denomination for `AuthInfo` (e.g. `uatom`).
- `OPENKMS_COSMOS_FEE_AMOUNT` — fee amount in that denom as a digit string (e.g.
  `4000`), matching what keygen / `run_broadcast_e2e.sh` print.

**Optional (defaults in parentheses):**

- `OPENKMS_COSMOS_CHAIN_REGISTRY_URL` — *(shell scripts only)* raw `chain.json`
  URL for `run_broadcast_e2e.sh` and keygen when filling REST/fee defaults
  (default: ICS Provider testnet registry entry).
- `OPENKMS_COSMOS_CHAIN_ID` — if unset, the test queries node info at runtime;
  the run script may set it from `chain_id` in `chain.json`.
- `OPENKMS_COSMOS_HRP` (`cosmos`) — bech32 prefix; the run script may set it from
  `bech32_prefix` when unset.
- `OPENKMS_COSMOS_AMOUNT_DENOM` (fee denom) — denom for `MsgSend` coins.
- `OPENKMS_COSMOS_GAS_LIMIT` (`200000`) — gas limit in the signed tx; when the
  run script computes `OPENKMS_COSMOS_FEE_AMOUNT` from registry gas prices, it
  uses `ceil(price × OPENKMS_COSMOS_GAS_LIMIT)` with the same limit value.
- `OPENKMS_COSMOS_TRANSFER_AMOUNT` (`1`)
- `OPENKMS_COSMOS_CONFIRM_TIMEOUT_SECS` (`90`)

Defaults for REST/fee/chain metadata match the **Cosmos ICS Provider testnet**
[`testnets/cosmosicsprovidertestnet/chain.json`](https://github.com/cosmos/chain-registry/blob/master/testnets/cosmosicsprovidertestnet/chain.json)
(`chain_id` **provider**, `uatom`, REST such as
`https://rest.provider-sentry-01.hub-testnet.polypore.xyz`).

#### GitHub Actions (`.github/workflows/broadcast-e2e.yml`)

The workflow runs `cargo test` directly (not `run_broadcast_e2e.sh`). Map values
as follows; any optional variable omitted in the workflow uses the test binary
defaults above.

| Variable | Solana job | Cosmos job |
| --- | --- | --- |
| `OPENKMS_BROADCAST_TESTS` | `1` | `1` |
| `OPENKMS_SOLANA_RPC_URL` | secret | — |
| `OPENKMS_SOLANA_SIGNER_SEED_B64` | secret | — |
| `OPENKMS_SOLANA_TRANSFER_LAMPORTS` | repo variable (optional) | — |
| `OPENKMS_SOLANA_CONFIRM_TIMEOUT_SECS` | repo variable (optional) | — |
| `OPENKMS_COSMOS_REST_URL` | — | secret |
| `OPENKMS_COSMOS_SIGNER_SCALAR_B64` | — | secret |
| `OPENKMS_COSMOS_CHAIN_ID` | — | repo variable (optional) |
| `OPENKMS_COSMOS_HRP` | — | repo variable (optional) |
| `OPENKMS_COSMOS_FEE_DENOM` | — | repo variable (**required** non-empty) |
| `OPENKMS_COSMOS_FEE_AMOUNT` | — | repo variable (**required** non-empty) |
| `OPENKMS_COSMOS_GAS_LIMIT` | — | repo variable (optional) |
| `OPENKMS_COSMOS_TRANSFER_AMOUNT` | — | repo variable (optional) |
| `OPENKMS_COSMOS_CONFIRM_TIMEOUT_SECS` | — | repo variable (optional) |

Solana job does not set `OPENKMS_SOLANA_CHAIN_ID` or
`OPENKMS_SOLANA_FEE_RESERVE_LAMPORTS` (harness defaults apply). Cosmos job does not
set `OPENKMS_COSMOS_CHAIN_REGISTRY_URL`, `OPENKMS_COSMOS_AMOUNT_DENOM`, or
registry-only fields — supply REST and fees explicitly for CI.

## Operational guidance

- Use disposable accounts with only the minimum testnet funds needed to cover
  the tiny transfer plus fees.
- Keep Solana and Cosmos signers separate so one chain can be rotated without
  affecting the other.
- Expect some environmental flake from RPCs and testnets; treat this workflow as
  a manual verification or release gate, not a per-push signal.
- If you rotate a funded signer, update the corresponding secret and re-fund the
  derived address before running the workflow again.
