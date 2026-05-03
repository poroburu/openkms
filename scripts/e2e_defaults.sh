#!/usr/bin/env bash
# Shared defaults for E2E helper scripts. Source this file; do not execute it.

OPENKMS_DEFAULT_SOLANA_RPC_URL="https://api.devnet.solana.com"
OPENKMS_DEFAULT_SOLANA_CHAIN_ID="devnet"
OPENKMS_DEFAULT_SOLANA_TRANSFER_LAMPORTS="5000"
OPENKMS_DEFAULT_COSMOS_CHAIN_REGISTRY_URL="https://raw.githubusercontent.com/cosmos/chain-registry/master/testnets/cosmosicsprovidertestnet/chain.json"
OPENKMS_DEFAULT_COSMOS_GAS_LIMIT="200000"
OPENKMS_DEFAULT_COSMOS_TRANSFER_AMOUNT="1"

openkms_fetch_cosmos_registry_defaults() {
  local gas="${1:-$OPENKMS_DEFAULT_COSMOS_GAS_LIMIT}"
  local reg="${OPENKMS_COSMOS_CHAIN_REGISTRY_URL:-$OPENKMS_DEFAULT_COSMOS_CHAIN_REGISTRY_URL}"

  command -v curl >/dev/null 2>&1 || {
    echo "error: curl is required to fetch Cosmos chain-registry defaults" >&2
    return 1
  }
  command -v python3 >/dev/null 2>&1 || {
    echo "error: python3 is required to parse chain-registry JSON" >&2
    return 1
  }

  echo "note: fetching Cosmos defaults from chain-registry ($reg)" >&2
  local json tmp outs
  json="$(curl -fsSL "$reg")" || {
    echo "error: could not download: $reg" >&2
    return 1
  }
  tmp="$(mktemp)" || return 1
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

fee_tokens = (j.get("fees") or {}).get("fee_tokens") or []
if not fee_tokens:
    raise SystemExit("chain.json: missing fees.fee_tokens")
fee_token = fee_tokens[0]
denom = str(fee_token.get("denom") or "").strip()
if not denom:
    raise SystemExit("chain.json: empty fee denom")

price = None
for key in ("average_gas_price", "low_gas_price", "high_gas_price", "fixed_min_gas_price"):
    value = fee_token.get(key)
    if value is not None and value != "":
        price = float(value)
        break
if price is None:
    price = 0.02

amount = max(1, int(math.ceil(price * gas)))
chain_id = str(j.get("chain_id") or "").strip()
hrp = str(j.get("bech32_prefix") or "cosmos").strip()
print(rest)
print(denom)
print(amount)
print(chain_id)
print(hrp)
PY
)" || {
    rm -f "$tmp"
    echo "error: failed to parse chain-registry JSON (see OPENKMS_COSMOS_CHAIN_REGISTRY_URL)" >&2
    return 1
  }
  rm -f "$tmp"

  local -a lines=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    lines+=("${line//$'\r'/}")
  done <<<"$outs"

  if ((${#lines[@]} < 5)); then
    echo "error: unexpected chain-registry parse output" >&2
    return 1
  fi

  OPENKMS_FETCH_COSMOS_REST_URL="${lines[0]}"
  OPENKMS_FETCH_COSMOS_FEE_DENOM="${lines[1]}"
  OPENKMS_FETCH_COSMOS_FEE_AMOUNT="${lines[2]}"
  OPENKMS_FETCH_COSMOS_CHAIN_ID="${lines[3]}"
  OPENKMS_FETCH_COSMOS_HRP="${lines[4]}"
}
