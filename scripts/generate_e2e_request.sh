#!/usr/bin/env bash
# Materialize ./.tmp/remote-keys/broadcast-keys.env from the ceremony mnemonic (same
# derivation as `keys provision`), then run scripts/generate_remote_e2e_request.sh.
#
#   ./scripts/generate_e2e_request.sh materialize --mnemonic-file /path/to/mnemonic.txt
#   ./scripts/generate_e2e_request.sh both
#
# Override directory: OPENKMS_REMOTE_E2E_ENV_DIR or --env-dir on the forward pass.
# Open binary: OPENKMS_BIN (defaults to `openkms` in PATH, else target/release or debug).
#
# See docs/remote-e2e.md.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE_GEN="$ROOT/scripts/generate_remote_e2e_request.sh"
DEFAULT_ENV_DIR="$ROOT/.tmp/remote-keys"

resolve_openkms_bin() {
  if [[ -n "${OPENKMS_BIN:-}" ]]; then
    printf '%s\n' "$OPENKMS_BIN"
    return
  fi
  if command -v openkms >/dev/null 2>&1; then
    command -v openkms
    return
  fi
  if [[ -x "$ROOT/target/release/openkms" ]]; then
    printf '%s\n' "$ROOT/target/release/openkms"
    return
  fi
  if [[ -x "$ROOT/target/debug/openkms" ]]; then
    printf '%s\n' "$ROOT/target/debug/openkms"
    return
  fi
  echo "error: openkms not found; install or set OPENKMS_BIN or build (cargo build)" >&2
  exit 1
}

usage() {
  cat <<EOF
Usage:
  $0 materialize [options]
  $0 [--env-dir DIR] [same args as scripts/generate_remote_e2e_request.sh]

materialize — write broadcast-keys.env under the env directory (default ${DEFAULT_ENV_DIR}):
  --mnemonic-file PATH     required
  --passphrase-file PATH   optional BIP-39 passphrase file
  --solana-path PATH       default m/44'/501'/0'/0'
  --cosmos-path PATH       default m/44'/118'/0'/0/0'
  --solana-label NAME      default solana-hot-0 (must match [[keys]] label on signer)
  --cosmos-label NAME      default cosmos-hub-0
  --out-dir DIR            default ${DEFAULT_ENV_DIR}
  --solana-rpc-url URL     default https://api.devnet.solana.com
  --solana-chain-id ID     default devnet (must match RPC cluster)
  --solana-transfer-lamports N   default 5000
  --cosmos-rest-url URL    if omitted, filled from chain-registry (needs curl)
  --cosmos-chain-id ID     if omitted with --cosmos-rest-url, from registry when fetched
  --cosmos-hrp HRP         if omitted, from registry when fetched
  --cosmos-fee-denom D     if omitted, from registry when fetched
  --cosmos-fee-amount N    if omitted, computed from registry gas price × gas limit
  --cosmos-gas-limit N     default 200000
  --cosmos-transfer-amount N     default 1
  OPENKMS_COSMOS_CHAIN_REGISTRY_URL  optional; default ICS provider testnet chain.json

Forward pass — sources DIR/broadcast-keys.env via generate_remote_e2e_request.sh -e:
  --env-dir DIR   override OPENKMS_REMOTE_E2E_ENV_DIR (default ${DEFAULT_ENV_DIR})
  -h, --help      this help

Examples:
  $0 materialize --mnemonic-file /etc/openkms/mnemonic.txt --out-dir ./.tmp/remote-keys
  OPENKMS_REMOTE_E2E_ENV_DIR=./.tmp/remote-keys $0 both
EOF
}

require_opt() {
  local opt="$1" val="${2:-}"
  if [[ -z "$val" ]]; then
    echo "error: $opt requires a value" >&2
    exit 1
  fi
}

# Fetch REST URL, fee denom, fee amount, chain_id, hrp from chain-registry (same default as run_broadcast_e2e.sh).
fetch_cosmos_registry_env() {
  command -v curl >/dev/null 2>&1 || {
    echo "error: curl required to fetch Cosmos defaults (or pass --cosmos-rest-url and related flags)" >&2
    exit 1
  }
  command -v python3 >/dev/null 2>&1 || {
    echo "error: python3 required to parse chain-registry JSON" >&2
    exit 1
  }

  local reg="${OPENKMS_COSMOS_CHAIN_REGISTRY_URL:-https://raw.githubusercontent.com/cosmos/chain-registry/master/testnets/cosmosicsprovidertestnet/chain.json}"
  local gas="${COSMOS_GAS_LIMIT:-200000}"
  echo "note: fetching Cosmos defaults from chain-registry ($reg)" >&2
  local json tmp outs
  json="$(curl -fsSL "$reg")" || {
    echo "error: could not download: $reg" >&2
    exit 1
  }
  tmp="$(mktemp)" || exit 1
  printf '%s\n' "$json" >"$tmp"
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
    echo "error: failed to parse chain-registry JSON" >&2
    exit 1
  }
  rm -f "$tmp"

  local -a lines=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    lines+=("${line//$'\r'/}")
  done <<<"$outs"

  if ((${#lines[@]} < 5)); then
    echo "error: unexpected chain-registry parse output" >&2
    exit 1
  fi

  COSMOS_FETCH_REST="${lines[0]}"
  COSMOS_FETCH_FEE_DENOM="${lines[1]}"
  COSMOS_FETCH_FEE_AMOUNT="${lines[2]}"
  COSMOS_FETCH_CHAIN_ID="${lines[3]}"
  COSMOS_FETCH_HRP="${lines[4]}"
}

cmd_materialize() {
  local mnemonic_file="" passphrase_file=""
  local solana_path="m/44'/501'/0'/0'"
  local cosmos_path="m/44'/118'/0'/0/0"
  local sol_label="solana-hot-0" cos_label="cosmos-hub-0"
  local out_dir="$DEFAULT_ENV_DIR"
  local sol_rpc="https://api.devnet.solana.com" sol_cid="devnet" sol_lamports="5000"
  local cos_rest="" cos_cid="" cos_hrp="" cos_fee_denom="" cos_fee_amt="" cos_gas="200000" cos_xfer="1"

  while (($# > 0)); do
    case "$1" in
      --mnemonic-file)
        require_opt "$1" "${2:-}"
        mnemonic_file="$2"
        shift 2
        ;;
      --passphrase-file)
        require_opt "$1" "${2:-}"
        passphrase_file="$2"
        shift 2
        ;;
      --solana-path)
        require_opt "$1" "${2:-}"
        solana_path="$2"
        shift 2
        ;;
      --cosmos-path)
        require_opt "$1" "${2:-}"
        cosmos_path="$2"
        shift 2
        ;;
      --solana-label)
        require_opt "$1" "${2:-}"
        sol_label="$2"
        shift 2
        ;;
      --cosmos-label)
        require_opt "$1" "${2:-}"
        cos_label="$2"
        shift 2
        ;;
      --out-dir)
        require_opt "$1" "${2:-}"
        out_dir="$2"
        shift 2
        ;;
      --solana-rpc-url)
        require_opt "$1" "${2:-}"
        sol_rpc="$2"
        shift 2
        ;;
      --solana-chain-id)
        require_opt "$1" "${2:-}"
        sol_cid="$2"
        shift 2
        ;;
      --solana-transfer-lamports)
        require_opt "$1" "${2:-}"
        sol_lamports="$2"
        shift 2
        ;;
      --cosmos-rest-url)
        require_opt "$1" "${2:-}"
        cos_rest="$2"
        shift 2
        ;;
      --cosmos-chain-id)
        require_opt "$1" "${2:-}"
        cos_cid="$2"
        shift 2
        ;;
      --cosmos-hrp)
        require_opt "$1" "${2:-}"
        cos_hrp="$2"
        shift 2
        ;;
      --cosmos-fee-denom)
        require_opt "$1" "${2:-}"
        cos_fee_denom="$2"
        shift 2
        ;;
      --cosmos-fee-amount)
        require_opt "$1" "${2:-}"
        cos_fee_amt="$2"
        shift 2
        ;;
      --cosmos-gas-limit)
        require_opt "$1" "${2:-}"
        cos_gas="$2"
        shift 2
        ;;
      --cosmos-transfer-amount)
        require_opt "$1" "${2:-}"
        cos_xfer="$2"
        shift 2
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        echo "error: unknown materialize option: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done

  [[ -n "$mnemonic_file" ]] || {
    echo "error: materialize requires --mnemonic-file" >&2
    exit 1
  }
  [[ -f "$mnemonic_file" ]] || {
    echo "error: mnemonic file not found: $mnemonic_file" >&2
    exit 1
  }
  [[ -n "$passphrase_file" ]] && [[ ! -f "$passphrase_file" ]] && {
    echo "error: passphrase file not found: $passphrase_file" >&2
    exit 1
  }

  local OPENKMS_BIN
  OPENKMS_BIN="$(resolve_openkms_bin)"

  local -a okms=(ceremony print-derived-signing-secrets --mnemonic-file "$mnemonic_file" --solana-path "$solana_path" --cosmos-path "$cosmos_path")
  [[ -n "$passphrase_file" ]] && okms+=(--passphrase-file "$passphrase_file")

  local derived_out seed_line scalar_line
  derived_out="$("${OPENKMS_BIN}" "${okms[@]}" 2>/dev/null)" || {
    echo "error: openkms ceremony print-derived-signing-secrets failed (set OPENKMS_BIN?)" >&2
    exit 1
  }
  seed_line="$(printf '%s\n' "$derived_out" | grep '^OPENKMS_SOLANA_SIGNER_SEED_B64=' || true)"
  scalar_line="$(printf '%s\n' "$derived_out" | grep '^OPENKMS_COSMOS_SIGNER_SCALAR_B64=' || true)"
  [[ -n "$seed_line" && -n "$scalar_line" ]] || {
    echo "error: could not parse OPENKMS_SOLANA_SIGNER_SEED_B64 / OPENKMS_COSMOS_SIGNER_SCALAR_B64 from openkms output" >&2
    exit 1
  }

  COSMOS_GAS_LIMIT="$cos_gas"
  if [[ -z "$cos_rest" || -z "$cos_fee_denom" || -z "$cos_fee_amt" || -z "$cos_cid" || -z "$cos_hrp" ]]; then
    fetch_cosmos_registry_env
    [[ -z "$cos_rest" ]] && cos_rest="$COSMOS_FETCH_REST"
    [[ -z "$cos_fee_denom" ]] && cos_fee_denom="$COSMOS_FETCH_FEE_DENOM"
    [[ -z "$cos_fee_amt" ]] && cos_fee_amt="$COSMOS_FETCH_FEE_AMOUNT"
    [[ -z "$cos_cid" ]] && cos_cid="$COSMOS_FETCH_CHAIN_ID"
    [[ -z "$cos_hrp" ]] && cos_hrp="$COSMOS_FETCH_HRP"
  fi

  mkdir -p "$out_dir"
  local env_file="$out_dir/broadcast-keys.env"
  umask 077
  {
    echo "# Generated by scripts/generate_e2e_request.sh materialize"
    echo "# Derivation paths must match \`keys provision\`."
    echo "$seed_line"
    echo "$scalar_line"
    echo
    echo "OPENKMS_REMOTE_E2E_SOLANA_LABEL=$sol_label"
    echo "OPENKMS_REMOTE_E2E_COSMOS_LABEL=$cos_label"
    echo
    echo "# Solana — OPENKMS_SOLANA_CHAIN_ID must match OPENKMS_SOLANA_RPC_URL"
    echo "OPENKMS_SOLANA_RPC_URL=$sol_rpc"
    echo "OPENKMS_SOLANA_CHAIN_ID=$sol_cid"
    echo "OPENKMS_SOLANA_TRANSFER_LAMPORTS=$sol_lamports"
    echo
    echo "# Cosmos — REST must serve OPENKMS_COSMOS_CHAIN_ID"
    echo "OPENKMS_COSMOS_REST_URL=$cos_rest"
    echo "OPENKMS_COSMOS_CHAIN_ID=$cos_cid"
    echo "OPENKMS_COSMOS_HRP=$cos_hrp"
    echo "OPENKMS_COSMOS_FEE_DENOM=$cos_fee_denom"
    echo "OPENKMS_COSMOS_FEE_AMOUNT=$cos_fee_amt"
    echo "OPENKMS_COSMOS_GAS_LIMIT=$cos_gas"
    echo "OPENKMS_COSMOS_TRANSFER_AMOUNT=$cos_xfer"
  } >"$env_file"
  chmod 600 "$env_file" || true
  echo "Wrote $env_file (mode 600). Run: $0 both" >&2
}

# --- main ---

ENV_DIR="${OPENKMS_REMOTE_E2E_ENV_DIR:-$DEFAULT_ENV_DIR}"
FORWARD_ARGS=()
MODE=forward

while (($# > 0)); do
  case "$1" in
    materialize | init)
      MODE=materialize
      shift
      cmd_materialize "$@"
      exit 0
      ;;
    --env-dir | -e)
      require_opt "$1" "${2:-}"
      ENV_DIR="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      FORWARD_ARGS+=("$1")
      shift
      ;;
  esac
done

if [[ "$MODE" == forward ]]; then
  if [[ -f "${ENV_DIR}/broadcast-keys.env" ]]; then
    exec "$REMOTE_GEN" -e "$ENV_DIR" "${FORWARD_ARGS[@]}"
  else
    echo "note: ${ENV_DIR}/broadcast-keys.env missing — run \`$0 materialize --mnemonic-file …\` or set OPENKMS_REMOTE_E2E_ENV_DIR" >&2
    exec "$REMOTE_GEN" "${FORWARD_ARGS[@]}"
  fi
fi
