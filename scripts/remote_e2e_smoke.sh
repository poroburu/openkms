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
require_env OPENKMS_SIGN_REQUEST_FILE

OPENKMS_SIGN_PATH="${OPENKMS_SIGN_PATH:-/sign/solana}"
OPENKMS_EXPECT_KEY_LABEL="${OPENKMS_EXPECT_KEY_LABEL:-}"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

health_json="$tmp_dir/health.json"
keys_json="$tmp_dir/keys.json"
metrics_txt="$tmp_dir/metrics.txt"
sign_json="$tmp_dir/sign.json"

curl -fsS "${OPENKMS_BASE_URL}/health" > "$health_json"
python3 - "$health_json" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    body = json.load(fh)

assert body.get("status") == "ok", body
assert isinstance(body.get("hsm_up"), bool), body
print(f"health ok: hsm_up={body['hsm_up']}")
PY

curl -fsS "${OPENKMS_BASE_URL}/keys" > "$keys_json"
python3 - "$keys_json" "$OPENKMS_EXPECT_KEY_LABEL" <<'PY'
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

curl -fsS "${OPENKMS_BASE_URL}/metrics" > "$metrics_txt"
grep -q "openkms_" "$metrics_txt"
echo "metrics ok"

curl -fsS \
  -H "Authorization: Bearer ${OPENKMS_SIGNER_TOKEN}" \
  -H "content-type: application/json" \
  --data @"${OPENKMS_SIGN_REQUEST_FILE}" \
  "${OPENKMS_BASE_URL}${OPENKMS_SIGN_PATH}" > "$sign_json"

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
