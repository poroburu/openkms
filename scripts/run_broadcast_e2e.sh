#!/usr/bin/env bash
# Run live broadcast integration tests (Solana and/or Cosmos) with a consistent
# environment: optionally source throwaway key material, set
# OPENKMS_BROADCAST_TESTS=1, validate required variables, then invoke cargo test.
#
# Typical local flow (after generate_broadcast_key_material.sh):
#   ./scripts/run_broadcast_e2e.sh both --env-file ./.tmp/broadcast-keys

set -euo pipefail

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
  OPENKMS_COSMOS_CHAIN_REGISTRY_URL defaults to the Cosmos ICS Provider testnet
  entry in chain-registry; override to point at another chain.json.

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

# Fill missing OPENKMS_COSMOS_* broadcast variables from chain-registry chain.json
# (default: Cosmos ICS Provider testnet — same URL as generate_broadcast_key_material.sh).
apply_cosmos_chain_registry_defaults() {
  case "$TARGET" in
    cosmos | both) ;;
    *) return 0 ;;
  esac

  if [[ -n "${OPENKMS_COSMOS_REST_URL:-}" && -n "${OPENKMS_COSMOS_FEE_DENOM:-}" && -n "${OPENKMS_COSMOS_FEE_AMOUNT:-}" ]]; then
    return 0
  fi

  command -v curl >/dev/null 2>&1 || {
    echo "error: curl is required to fetch Cosmos chain-registry defaults" >&2
    exit 1
  }
  command -v python3 >/dev/null 2>&1 || {
    echo "error: python3 is required to parse chain-registry JSON" >&2
    exit 1
  }

  local reg="${OPENKMS_COSMOS_CHAIN_REGISTRY_URL:-https://raw.githubusercontent.com/cosmos/chain-registry/master/testnets/cosmosicsprovidertestnet/chain.json}"
  local gas="${OPENKMS_COSMOS_GAS_LIMIT:-200000}"

  echo "note: fetching Cosmos broadcast defaults from chain-registry" >&2
  local json
  json="$(curl -fsSL "$reg")" || {
    echo "error: could not download: $reg" >&2
    exit 1
  }

  # Do not pipe JSON into `python3 - <<'PY'`: stdin is the script, not the payload.
  local tmp
  tmp="$(mktemp)" || exit 1
  printf '%s\n' "$json" > "$tmp"

  local outs
  outs="$(python3 - "$tmp" "$gas" <<'PY'
import json, math, sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    j = json.load(f)
gas = int(sys.argv[2])

rests = (j.get("apis") or {}).get("rest") or []
if not rests:
    raise SystemExit("chain.json: missing apis.rest")
rest = str(rests[0].get("address") or "").strip()
if not rest:
    raise SystemExit("chain.json: empty apis.rest[0].address")

fts = (j.get("fees") or {}).get("fee_tokens") or []
if not fts:
    raise SystemExit("chain.json: missing fees.fee_tokens")
ft = fts[0]
denom = str(ft.get("denom") or "").strip()
if not denom:
    raise SystemExit("chain.json: empty fee denom")

price = None
for key in ("average_gas_price", "low_gas_price", "high_gas_price", "fixed_min_gas_price"):
    v = ft.get(key)
    if v is not None and v != "":
        price = float(v)
        break
if price is None:
    price = 0.02

amount = max(1, int(math.ceil(price * gas)))
cid = str(j.get("chain_id") or "").strip()
hrp = str(j.get("bech32_prefix") or "cosmos").strip()
print(rest)
print(denom)
print(amount)
print(cid)
print(hrp)
PY
)" || {
    rm -f "$tmp"
    echo "error: failed to parse chain-registry JSON (see OPENKMS_COSMOS_CHAIN_REGISTRY_URL)" >&2
    exit 1
  }
  rm -f "$tmp"

  local -a lines=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    lines+=("${line//$'\r'/}")
  done <<< "$outs"

  if ((${#lines[@]} < 5)); then
    echo "error: unexpected chain-registry parse output" >&2
    exit 1
  fi

  if [[ -z "${OPENKMS_COSMOS_REST_URL:-}" ]]; then
    export OPENKMS_COSMOS_REST_URL="${lines[0]}"
    echo "note: OPENKMS_COSMOS_REST_URL unset; using ${OPENKMS_COSMOS_REST_URL}" >&2
  fi
  if [[ -z "${OPENKMS_COSMOS_FEE_DENOM:-}" ]]; then
    export OPENKMS_COSMOS_FEE_DENOM="${lines[1]}"
    echo "note: OPENKMS_COSMOS_FEE_DENOM unset; using ${OPENKMS_COSMOS_FEE_DENOM}" >&2
  fi
  if [[ -z "${OPENKMS_COSMOS_FEE_AMOUNT:-}" ]]; then
    export OPENKMS_COSMOS_FEE_AMOUNT="${lines[2]}"
    echo "note: OPENKMS_COSMOS_FEE_AMOUNT unset; using ${OPENKMS_COSMOS_FEE_AMOUNT} (ceil(gas_price × OPENKMS_COSMOS_GAS_LIMIT=${gas}))" >&2
  fi
  if [[ -z "${OPENKMS_COSMOS_CHAIN_ID:-}" && -n "${lines[3]}" ]]; then
    export OPENKMS_COSMOS_CHAIN_ID="${lines[3]}"
    echo "note: OPENKMS_COSMOS_CHAIN_ID unset; using ${OPENKMS_COSMOS_CHAIN_ID}" >&2
  fi
  if [[ -z "${OPENKMS_COSMOS_HRP:-}" && -n "${lines[4]}" ]]; then
    export OPENKMS_COSMOS_HRP="${lines[4]}"
    echo "note: OPENKMS_COSMOS_HRP unset; using ${OPENKMS_COSMOS_HRP}" >&2
  fi
}

ENV_FILE_DEFAULT="./.tmp/broadcast-keys/broadcast-keys.env"
ENV_FILE=""
DRY_RUN=0
TARGET=""
CARGO_EXTRA=()
SOLANA_RPC_DEFAULT="https://api.devnet.solana.com"

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
