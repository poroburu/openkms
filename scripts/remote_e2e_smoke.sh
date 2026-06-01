#!/usr/bin/env bash
set -euo pipefail

require_env() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "missing required env: $name" >&2
    exit 1
  fi
}

require_env OPENKMS_BASE_URL
require_env OPENKMS_SIGNER_TOKEN

# Documentation URLs often use example.com, which does not resolve on the public internet.
warn_if_base_url_placeholder() {
  local u="${OPENKMS_BASE_URL,,}"
  if [[ "$u" == *"example.com"* || "$u" == *"example.net"* || "$u" == *"example.org"* ]]; then
    echo "remote_e2e_smoke: OPENKMS_BASE_URL uses an example.* host — DNS will fail; set a real signer URL (see docs/remote-e2e.md, section on gh act)." >&2
  fi
}
warn_if_base_url_placeholder

run_health() {
  local health_json="$1"
  # First /health may return "vault_up": null (cold start); second returns a boolean.
  curl -fsS "${OPENKMS_BASE_URL}/health" -o /dev/null
  curl -fsS "${OPENKMS_BASE_URL}/health" > "$health_json"
  python3 - "$health_json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    body = json.load(fh)

assert body.get("status") == "ok", body
assert isinstance(body.get("vault_up"), bool), body
print(f"health ok: vault_up={body['vault_up']}")
PY
}

run_keys_single() {
  local keys_json="$1"
  local expected="${2:-}"
  curl -fsS "${OPENKMS_BASE_URL}/keys" > "$keys_json"
  python3 - "$keys_json" "$expected" <<'PY'
import json
import sys

path = sys.argv[1]
expected = sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    body = json.load(fh)

assert isinstance(body, list), body
labels = {entry.get("label") for entry in body if isinstance(entry, dict)}
if expected:
    assert expected in labels, {"expected": expected, "labels": sorted(labels)}
print(f"keys ok: {sorted(labels)}")
PY
}

run_keys_dual() {
  local keys_json="$1"
  curl -fsS "${OPENKMS_BASE_URL}/keys" > "$keys_json"
  python3 - "$keys_json" <<'PY'
import json
import os
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    body = json.load(fh)

assert isinstance(body, list), body
labels = {entry.get("label") for entry in body if isinstance(entry, dict)}
sol = os.environ.get("OPENKMS_EXPECT_SOLANA_KEY_LABEL", "").strip()
cos = os.environ.get("OPENKMS_EXPECT_COSMOS_KEY_LABEL", "").strip()
if sol:
    assert sol in labels, {"expected_solana": sol, "labels": sorted(labels)}
if cos:
    assert cos in labels, {"expected_cosmos": cos, "labels": sorted(labels)}
print(f"keys ok: {sorted(labels)}")
PY
}

run_metrics() {
  local metrics_txt="$1"
  curl -fsS "${OPENKMS_BASE_URL}/metrics" > "$metrics_txt"
  grep -q "openkms_" "$metrics_txt"
  echo "metrics ok"
}

sign_once() {
  local sign_path="$1"
  local request_file="$2"
  local sign_json="$3"

  if [[ -z "${sign_path}" ]]; then
    echo "error: sign path is empty" >&2
    exit 1
  fi
  curl -fsS \
    -H "Authorization: Bearer ${OPENKMS_SIGNER_TOKEN}" \
    -H "content-type: application/json" \
    --data @"${request_file}" \
    "${OPENKMS_BASE_URL}${sign_path}" > "$sign_json"

  python3 - "$sign_json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    body = json.load(fh)

sig = body.get("signature_b64")
assert isinstance(sig, str) and sig.strip(), body
print("sign ok")
PY
}

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

health_json="$tmp_dir/health.json"
keys_json="$tmp_dir/keys.json"
metrics_txt="$tmp_dir/metrics.txt"

if [[ "${OPENKMS_REMOTE_E2E_CHAIN:-}" == "both" ]]; then
  require_env OPENKMS_SIGN_REQUEST_FILE_SOLANA
  require_env OPENKMS_SIGN_REQUEST_FILE_COSMOS
  require_env OPENKMS_SIGN_PATH_SOLANA
  require_env OPENKMS_SIGN_PATH_COSMOS
  run_health "$health_json"
  run_keys_dual "$keys_json"
  run_metrics "$metrics_txt"
  sign_once "${OPENKMS_SIGN_PATH_SOLANA}" "${OPENKMS_SIGN_REQUEST_FILE_SOLANA}" "$tmp_dir/sign-solana.json"
  sign_once "${OPENKMS_SIGN_PATH_COSMOS}" "${OPENKMS_SIGN_REQUEST_FILE_COSMOS}" "$tmp_dir/sign-cosmos.json"
  exit 0
fi

require_env OPENKMS_SIGN_REQUEST_FILE
require_env OPENKMS_SIGN_PATH

run_health "$health_json"
run_keys_single "$keys_json" "${OPENKMS_EXPECT_KEY_LABEL:-}"
run_metrics "$metrics_txt"
sign_once "${OPENKMS_SIGN_PATH}" "${OPENKMS_SIGN_REQUEST_FILE}" "$tmp_dir/sign.json"
