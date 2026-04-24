#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/generate_broadcast_key_material.sh [-f|--force] [solana|cosmos|both] [out_dir]

Description:
  Generate throwaway Solana and/or Cosmos key material inside Docker images and
  write the results into an output directory plus a ready-to-source `.env`
  snippet.

Defaults:
  target  = both
  out_dir = ./.tmp/broadcast-keys

Environment overrides:
  OPENKMS_SOLANA_CLI_IMAGE  Docker image with solana-keygen installed
  OPENKMS_COSMOS_CLI_IMAGE  Docker image with gaiad installed
  OPENKMS_COSMOS_CHAIN_REGISTRY_URL  chain.json URL used to resolve the Gaia tag
  OPENKMS_COSMOS_KEY_NAME   Cosmos key name inside the temporary keyring

Outputs:
  <out_dir>/broadcast-keys.env
  <out_dir>/solana/id.json
  <out_dir>/solana/address.txt
  <out_dir>/cosmos/key.json
  <out_dir>/cosmos/private.hex
EOF
}

require_cmd() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || {
    echo "missing required command: $name" >&2
    exit 1
  }
}

FORCE=0
POSITIONAL=()
while (($# > 0)); do
  case "$1" in
    -f|--force)
      FORCE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

TARGET="${POSITIONAL[0]:-both}"
OUT_DIR="${POSITIONAL[1]:-./.tmp/broadcast-keys}"

case "$TARGET" in
  solana|cosmos|both) ;;
  *)
    echo "unsupported target: $TARGET" >&2
    usage >&2
    exit 1
    ;;
esac

require_cmd docker
require_cmd curl
require_cmd python3

SOLANA_CLI_IMAGE="${OPENKMS_SOLANA_CLI_IMAGE:-andreaskasper/solana:cli}"
COSMOS_CHAIN_REGISTRY_URL="${OPENKMS_COSMOS_CHAIN_REGISTRY_URL:-https://raw.githubusercontent.com/cosmos/chain-registry/master/testnets/cosmosicsprovidertestnet/chain.json}"
COSMOS_KEY_NAME="${OPENKMS_COSMOS_KEY_NAME:-openkms-broadcast}"
DOCKER_USER="$(id -u):$(id -g)"

mkdir -p "$OUT_DIR"
OUT_DIR_ABS="$(python3 - "$OUT_DIR" <<'PY'
import pathlib
import sys

print(pathlib.Path(sys.argv[1]).resolve())
PY
)"
ENV_FILE="$OUT_DIR_ABS/broadcast-keys.env"

solana_seed_b64=""
solana_address=""
cosmos_scalar_b64=""
cosmos_address=""

resolve_cosmos_cli_image() {
  if [[ -n "${OPENKMS_COSMOS_CLI_IMAGE:-}" ]]; then
    printf '%s\n' "$OPENKMS_COSMOS_CLI_IMAGE"
    return
  fi

  local tag
  tag="$(
    python3 -c '
import json
import sys
import urllib.request

url = sys.argv[1]
with urllib.request.urlopen(url) as resp:
    body = json.load(resp)

codebase = body.get("codebase") or {}
tag = codebase.get("tag") or codebase.get("recommended_version")
if not tag:
    raise SystemExit("chain-registry chain.json missing codebase.tag/recommended_version")
print(tag)
' "$COSMOS_CHAIN_REGISTRY_URL"
  )"

  printf 'ghcr.io/cosmos/gaia:%s\n' "$tag"
}

COSMOS_CLI_IMAGE="$(resolve_cosmos_cli_image)"

# Optional broadcast env lines for broadcast-keys.env (Cosmos ICS Provider testnet).
COSMOS_BROADCAST_ENV_SNIPPET="$(
  python3 - "$COSMOS_CHAIN_REGISTRY_URL" 200000 <<'PY'
import json, math, sys, urllib.request

url = sys.argv[1]
gas = int(sys.argv[2])
with urllib.request.urlopen(url) as r:
    j = json.load(r)

rests = (j.get("apis") or {}).get("rest") or []
if not rests:
    raise SystemExit("chain.json: missing apis.rest")
rest = str(rests[0].get("address") or "").strip()
fts = (j.get("fees") or {}).get("fee_tokens") or []
if not fts:
    raise SystemExit("chain.json: missing fees.fee_tokens")
ft = fts[0]
denom = str(ft.get("denom") or "").strip()
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
print(f"OPENKMS_COSMOS_REST_URL={rest}")
print(f"OPENKMS_COSMOS_FEE_DENOM={denom}")
print(f"OPENKMS_COSMOS_FEE_AMOUNT={amount}")
if cid:
    print(f"OPENKMS_COSMOS_CHAIN_ID={cid}")
if hrp:
    print(f"OPENKMS_COSMOS_HRP={hrp}")
PY
)" || COSMOS_BROADCAST_ENV_SNIPPET=""

preflight_output_dirs() {
  local dirs=()
  case "$TARGET" in
    solana)
      dirs+=("$OUT_DIR_ABS/solana")
      ;;
    cosmos)
      dirs+=("$OUT_DIR_ABS/cosmos")
      ;;
    both)
      dirs+=("$OUT_DIR_ABS/solana" "$OUT_DIR_ABS/cosmos")
      ;;
  esac

  local existing=()
  local dir
  for dir in "${dirs[@]}"; do
    if [[ -e "$dir" ]]; then
      existing+=("$dir")
    fi
  done

  if ((${#existing[@]} == 0)); then
    return
  fi

  if [[ "$FORCE" == "1" ]]; then
    for dir in "${existing[@]}"; do
      rm -rf "$dir"
    done
    return
  fi

  echo "existing key output directories detected:" >&2
  for dir in "${existing[@]}"; do
    echo "  - $dir" >&2
  done
  echo "rerun with -f/--force to replace the existing key material in all listed directories" >&2
  exit 1
}

prepare_output_dir() {
  local dir="$1"
  mkdir -p "$dir"
}

preflight_output_dirs

generate_solana() {
  local dir="$OUT_DIR_ABS/solana"
  prepare_output_dir "$dir"

  docker run --rm \
    -v "$dir:/work" \
    --entrypoint sh \
    "$SOLANA_CLI_IMAGE" \
    -lc '
      export PATH="/root/.local/share/solana/install/active_release/bin:$PATH"
      solana-keygen new \
        --silent \
        --no-bip39-passphrase \
        --force \
        --outfile /work/id.json > /work/keygen.txt
      solana-keygen pubkey /work/id.json > /work/address.txt
      chown -R '"$DOCKER_USER"' /work
    '

  solana_seed_b64="$(python3 - "$dir/id.json" <<'PY'
import base64
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    raw = json.load(fh)

if len(raw) < 32:
    raise SystemExit("Solana keypair JSON does not contain 32 seed bytes")

seed = bytes(raw[:32])
print(base64.b64encode(seed).decode("ascii"))
PY
)"
  solana_address="$(python3 - "$dir/address.txt" <<'PY'
from pathlib import Path
import sys

print(Path(sys.argv[1]).read_text(encoding="utf-8").strip())
PY
)"
}

generate_cosmos() {
  local dir="$OUT_DIR_ABS/cosmos"
  prepare_output_dir "$dir"
  mkdir -p "$dir/home"

  docker run --rm \
    --user "$DOCKER_USER" \
    -v "$dir:/work" \
    --entrypoint sh \
    "$COSMOS_CLI_IMAGE" \
    -lc "
      export HOME=/work/home
      printf '\n' | gaiad keys add '$COSMOS_KEY_NAME' --keyring-backend test --output json --no-backup > /work/key.json
      gaiad keys export '$COSMOS_KEY_NAME' --unsafe --unarmored-hex --yes --keyring-backend test > /work/private.hex
    "

  cosmos_scalar_b64="$(python3 - "$dir/private.hex" <<'PY'
import base64
from pathlib import Path
import sys

hex_key = Path(sys.argv[1]).read_text(encoding="utf-8").strip()
raw = bytes.fromhex(hex_key)
if len(raw) != 32:
    raise SystemExit(f"expected 32-byte Cosmos scalar, got {len(raw)} bytes")
print(base64.b64encode(raw).decode("ascii"))
PY
)"
  cosmos_address="$(python3 - "$dir/key.json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as fh:
    body = json.load(fh)

address = body.get("address")
if not address:
    raise SystemExit("Cosmos key JSON missing address")
print(address)
PY
)"
}

case "$TARGET" in
  solana)
    generate_solana
    ;;
  cosmos)
    generate_cosmos
    ;;
  both)
    generate_solana
    generate_cosmos
    ;;
esac

{
  echo "# Generated by scripts/generate_broadcast_key_material.sh"
  echo "# CLI images"
  echo "OPENKMS_SOLANA_CLI_IMAGE=$SOLANA_CLI_IMAGE"
  echo "OPENKMS_COSMOS_CLI_IMAGE=$COSMOS_CLI_IMAGE"
  echo
  if [[ -n "$solana_seed_b64" ]]; then
    echo "# Solana"
    echo "OPENKMS_SOLANA_SIGNER_SEED_B64=$solana_seed_b64"
    echo "OPENKMS_SOLANA_SIGNER_ADDRESS=$solana_address"
    echo
  fi
  if [[ -n "$cosmos_scalar_b64" ]]; then
    echo "# Cosmos"
    echo "OPENKMS_COSMOS_SIGNER_SCALAR_B64=$cosmos_scalar_b64"
    echo "OPENKMS_COSMOS_SIGNER_ADDRESS=$cosmos_address"
    echo
    echo "# Cosmos broadcast (from chain-registry: testnets/cosmosicsprovidertestnet/chain.json)"
    echo "OPENKMS_COSMOS_CHAIN_REGISTRY_URL=$COSMOS_CHAIN_REGISTRY_URL"
    if [[ -n "${COSMOS_BROADCAST_ENV_SNIPPET:-}" ]]; then
      printf '%s\n' "$COSMOS_BROADCAST_ENV_SNIPPET"
    fi
    echo
  fi
} > "$ENV_FILE"

echo "wrote key material to: $OUT_DIR_ABS"
echo "env snippet: $ENV_FILE"
if [[ -n "$solana_address" ]]; then
  echo "solana address: $solana_address"
fi
if [[ -n "$cosmos_address" ]]; then
  echo "cosmos address: $cosmos_address"
fi
