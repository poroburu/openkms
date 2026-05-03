#!/usr/bin/env bash
# Run live broadcast integration tests (Solana and/or Cosmos) with a consistent
# environment: optionally source throwaway key material, set
# OPENKMS_BROADCAST_TESTS=1, validate required variables, then invoke cargo test.
#
# Typical local flow (after generate_broadcast_key_material.sh):
#   ./scripts/run_broadcast_e2e.sh both --env-file ./.tmp/broadcast-keys

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/e2e_defaults.sh"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run_broadcast_e2e.sh [options] <solana|cosmos|both> [-- <cargo test args...>]

Description:
  Sources optional key env (see --env-file), exports OPENKMS_BROADCAST_TESTS=1,
  applies defaults where safe, checks required variables for the chosen target,
  then runs the ignored broadcast e2e tests with --nocapture.

Options:
  -e, --env-file PATH   File broadcast-keys.env or a directory containing it.
                        Default: ./.tmp/broadcast-keys/broadcast-keys.env
                        If the path does not exist, sourcing is skipped (useful
                        when all variables are already exported, e.g. CI).
  --solana-rpc URL      Export OPENKMS_SOLANA_RPC_URL (after env file). For
                        solana/both, defaults to https://api.devnet.solana.com if
                        still unset after sourcing.
  --solana-chain-id ID  Export OPENKMS_SOLANA_CHAIN_ID.
  --cosmos-rest URL     Export OPENKMS_COSMOS_REST_URL.
  --cosmos-fee-denom D  Export OPENKMS_COSMOS_FEE_DENOM.
  --cosmos-fee-amount A Export OPENKMS_COSMOS_FEE_AMOUNT.
  -n, --dry-run         Print the cargo command and exit without running it.
  -h, --help            Show this help.

  For cosmos/both, if OPENKMS_COSMOS_REST_URL / FEE_DENOM / FEE_AMOUNT are
  unset, defaults are downloaded from chain-registry (see
  OPENKMS_COSMOS_CHAIN_REGISTRY_URL).

Environment:
  Any OPENKMS_* variable the tests read can be set before invoking this script.
  Values from --env-file are loaded first; CLI flags above override afterward.
  Fund signers on the target clusters before running; tests do not use faucets
  (see docs/broadcast-e2e.md).
  OPENKMS_COSMOS_CHAIN_REGISTRY_URL defaults to the shared Cosmos ICS Provider
  testnet chain-registry entry; override to point at another chain.json.

Examples:
  ./scripts/run_broadcast_e2e.sh solana --env-file ./.tmp/broadcast-keys
  ./scripts/run_broadcast_e2e.sh cosmos --env-file ./.tmp/broadcast-keys
  ./scripts/run_broadcast_e2e.sh cosmos --env-file ./.tmp/broadcast-keys \
    --cosmos-rest 'https://lcd-cosmos-testnet.example.com' \
    --cosmos-fee-denom uatom --cosmos-fee-amount 2000
  ./scripts/run_broadcast_e2e.sh both -e ./.tmp/broadcast-keys \
    --cosmos-rest 'https://…' --cosmos-fee-denom uatom --cosmos-fee-amount 2000
EOF
}

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "error: missing required environment variable: $name" >&2
    exit 1
  fi
}

require_opt_value() {
  local opt="$1"
  local val="${2:-}"
  if [[ -z "$val" ]]; then
    echo "error: option $opt requires a value" >&2
    exit 1
  fi
}

resolve_env_file_path() {
  local p="$1"
  if [[ -d "$p" ]]; then
    printf '%s\n' "${p%/}/broadcast-keys.env"
  else
    printf '%s\n' "$p"
  fi
}

# Fill missing OPENKMS_COSMOS_* broadcast variables from the shared E2E defaults.
apply_cosmos_chain_registry_defaults() {
  case "$TARGET" in
    cosmos | both) ;;
    *) return 0 ;;
  esac

  if [[ -n "${OPENKMS_COSMOS_REST_URL:-}" && -n "${OPENKMS_COSMOS_FEE_DENOM:-}" && -n "${OPENKMS_COSMOS_FEE_AMOUNT:-}" ]]; then
    return 0
  fi

  local gas="${OPENKMS_COSMOS_GAS_LIMIT:-$OPENKMS_DEFAULT_COSMOS_GAS_LIMIT}"
  openkms_fetch_cosmos_registry_defaults "$gas" || exit 1

  if [[ -z "${OPENKMS_COSMOS_REST_URL:-}" ]]; then
    export OPENKMS_COSMOS_REST_URL="$OPENKMS_FETCH_COSMOS_REST_URL"
    echo "note: OPENKMS_COSMOS_REST_URL unset; using ${OPENKMS_COSMOS_REST_URL}" >&2
  fi
  if [[ -z "${OPENKMS_COSMOS_FEE_DENOM:-}" ]]; then
    export OPENKMS_COSMOS_FEE_DENOM="$OPENKMS_FETCH_COSMOS_FEE_DENOM"
    echo "note: OPENKMS_COSMOS_FEE_DENOM unset; using ${OPENKMS_COSMOS_FEE_DENOM}" >&2
  fi
  if [[ -z "${OPENKMS_COSMOS_FEE_AMOUNT:-}" ]]; then
    export OPENKMS_COSMOS_FEE_AMOUNT="$OPENKMS_FETCH_COSMOS_FEE_AMOUNT"
    echo "note: OPENKMS_COSMOS_FEE_AMOUNT unset; using ${OPENKMS_COSMOS_FEE_AMOUNT} (ceil(gas_price × OPENKMS_COSMOS_GAS_LIMIT=${gas}))" >&2
  fi
  if [[ -z "${OPENKMS_COSMOS_CHAIN_ID:-}" && -n "${OPENKMS_FETCH_COSMOS_CHAIN_ID}" ]]; then
    export OPENKMS_COSMOS_CHAIN_ID="$OPENKMS_FETCH_COSMOS_CHAIN_ID"
    echo "note: OPENKMS_COSMOS_CHAIN_ID unset; using ${OPENKMS_COSMOS_CHAIN_ID}" >&2
  fi
  if [[ -z "${OPENKMS_COSMOS_HRP:-}" && -n "${OPENKMS_FETCH_COSMOS_HRP}" ]]; then
    export OPENKMS_COSMOS_HRP="$OPENKMS_FETCH_COSMOS_HRP"
    echo "note: OPENKMS_COSMOS_HRP unset; using ${OPENKMS_COSMOS_HRP}" >&2
  fi
}

ENV_FILE_DEFAULT="./.tmp/broadcast-keys/broadcast-keys.env"
ENV_FILE=""
DRY_RUN=0
TARGET=""
CARGO_EXTRA=()
SOLANA_RPC_DEFAULT="$OPENKMS_DEFAULT_SOLANA_RPC_URL"

while (($# > 0)); do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    -n | --dry-run)
      DRY_RUN=1
      shift
      ;;
    -e | --env-file)
      require_opt_value "$1" "${2:-}"
      ENV_FILE="$2"
      shift 2
      ;;
    --solana-rpc)
      require_opt_value "$1" "${2:-}"
      export OPENKMS_SOLANA_RPC_URL="$2"
      shift 2
      ;;
    --solana-chain-id)
      require_opt_value "$1" "${2:-}"
      export OPENKMS_SOLANA_CHAIN_ID="$2"
      shift 2
      ;;
    --cosmos-rest)
      require_opt_value "$1" "${2:-}"
      export OPENKMS_COSMOS_REST_URL="$2"
      shift 2
      ;;
    --cosmos-fee-denom)
      require_opt_value "$1" "${2:-}"
      export OPENKMS_COSMOS_FEE_DENOM="$2"
      shift 2
      ;;
    --cosmos-fee-amount)
      require_opt_value "$1" "${2:-}"
      export OPENKMS_COSMOS_FEE_AMOUNT="$2"
      shift 2
      ;;
    --)
      shift
      CARGO_EXTRA=("$@")
      break
      ;;
    solana | cosmos | both)
      if [[ -n "$TARGET" ]]; then
        echo "error: multiple targets specified (already have: $TARGET)" >&2
        exit 1
      fi
      TARGET="$1"
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$TARGET" ]]; then
  echo "error: specify exactly one target: solana, cosmos, or both" >&2
  usage >&2
  exit 1
fi

if [[ -z "$ENV_FILE" ]]; then
  ENV_FILE="$ENV_FILE_DEFAULT"
fi

RESOLVED_ENV="$(resolve_env_file_path "$ENV_FILE")"
if [[ -f "$RESOLVED_ENV" ]]; then
  echo "sourcing: $RESOLVED_ENV"
  set -a
  # shellcheck disable=SC1090
  source "$RESOLVED_ENV"
  set +a
elif [[ -e "$RESOLVED_ENV" ]]; then
  echo "error: env path exists but is not a file: $RESOLVED_ENV" >&2
  exit 1
else
  echo "note: env file not found ($RESOLVED_ENV); continuing with current environment"
fi

export OPENKMS_BROADCAST_TESTS=1

case "$TARGET" in
  solana | both)
    if [[ -z "${OPENKMS_SOLANA_RPC_URL:-}" ]]; then
      export OPENKMS_SOLANA_RPC_URL="$SOLANA_RPC_DEFAULT"
      echo "note: OPENKMS_SOLANA_RPC_URL unset; using default devnet RPC"
    fi
    ;;
esac

apply_cosmos_chain_registry_defaults

case "$TARGET" in
  solana)
    require_var OPENKMS_SOLANA_RPC_URL
    require_var OPENKMS_SOLANA_SIGNER_SEED_B64
    ;;
  cosmos)
    require_var OPENKMS_COSMOS_REST_URL
    require_var OPENKMS_COSMOS_SIGNER_SCALAR_B64
    require_var OPENKMS_COSMOS_FEE_DENOM
    require_var OPENKMS_COSMOS_FEE_AMOUNT
    ;;
  both)
    require_var OPENKMS_SOLANA_RPC_URL
    require_var OPENKMS_SOLANA_SIGNER_SEED_B64
    require_var OPENKMS_COSMOS_REST_URL
    require_var OPENKMS_COSMOS_SIGNER_SCALAR_B64
    require_var OPENKMS_COSMOS_FEE_DENOM
    require_var OPENKMS_COSMOS_FEE_AMOUNT
    ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

case "$TARGET" in
  solana) TEST_ARGS=(--test broadcast_solana_e2e) ;;
  cosmos) TEST_ARGS=(--test broadcast_cosmos_e2e) ;;
  both) TEST_ARGS=(--test broadcast_solana_e2e --test broadcast_cosmos_e2e) ;;
esac

CMD=(cargo test "${TEST_ARGS[@]}" -- --ignored --nocapture "${CARGO_EXTRA[@]}")
echo "running: ${CMD[*]}"

if [[ "$DRY_RUN" == "1" ]]; then
  echo "(dry-run: not executing)"
  exit 0
fi

exec "${CMD[@]}"
