#!/usr/bin/env bash
# Single entrypoint for remote smoke: validate env, decode OPENKMS_SIGN_REQUEST_B64,
# run remote_e2e_smoke.sh. Keeps GitHub Actions / act / operator docs in sync with
# one script (see docs/remote-e2e.md).
#
# Usage:
#   ./scripts/run_remote_e2e_job.sh solana|cosmos
#
# Required env:
#   OPENKMS_BASE_URL
#   OPENKMS_SIGNER_TOKEN
#   OPENKMS_SIGN_REQUEST_B64   (compact sign JSON, base64; GitHub maps secrets here)
#
# Optional:
#   OPENKMS_SIGN_PATH          (defaults: /sign/solana or /sign/cosmos from subcommand)
#   OPENKMS_EXPECT_KEY_LABEL   (passed through to remote_e2e_smoke.sh)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/run_remote_e2e_job.sh solana|cosmos

Environment (required unless noted):
  OPENKMS_BASE_URL           Signer HTTP base URL
  OPENKMS_SIGNER_TOKEN       Bearer token for /sign/*
  OPENKMS_SIGN_REQUEST_B64   Base64 of compact JSON sign body

Optional:
  OPENKMS_SIGN_PATH          Override path (default /sign/solana or /sign/cosmos)
  OPENKMS_EXPECT_KEY_LABEL   If set, /keys must include this label

See docs/remote-e2e.md.
EOF
}

case "${1:-}" in
  -h | --help)
    usage
    exit 0
    ;;
  solana | cosmos) ;;
  *)
    echo "error: specify solana or cosmos (got: ${1:-})" >&2
    usage >&2
    exit 1
    ;;
esac

CHAIN="$1"

require_nonempty() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "error: missing or empty required env: $name" >&2
    exit 1
  fi
}

require_nonempty OPENKMS_BASE_URL
require_nonempty OPENKMS_SIGNER_TOKEN
require_nonempty OPENKMS_SIGN_REQUEST_B64

case "$CHAIN" in
  solana)
    export OPENKMS_SIGN_PATH="${OPENKMS_SIGN_PATH:-/sign/solana}"
    req_file="request-solana.json"
    ;;
  cosmos)
    export OPENKMS_SIGN_PATH="${OPENKMS_SIGN_PATH:-/sign/cosmos}"
    req_file="request-cosmos.json"
    ;;
esac

printf '%s' "${OPENKMS_SIGN_REQUEST_B64}" | base64 --decode >"$req_file"
export OPENKMS_SIGN_REQUEST_FILE="$req_file"

chmod +x ./scripts/remote_e2e_smoke.sh
# Do not use `if ./remote_e2e_smoke.sh; then ... fi` and then `$?` — when the test
# fails, bash can leave `$?` as 0 for the whole `if`, so the job would falsely succeed.
set +e
./scripts/remote_e2e_smoke.sh
ec=$?
set -e
if [[ "$ec" -ne 0 && "${ACT:-}" == "true" ]]; then
  echo "remote-e2e: smoke failed under ACT=true (exit $ec)." >&2
  echo "  The workflow expects Tailscale in the act container, then curl to OPENKMS_BASE_URL" >&2
  echo "  (your Pi on the tailnet). If Tailscale failed or curl cannot reach the Pi, see" >&2
  echo "  docs/remote-e2e.md (Local gh act: --container-options NET_ADMIN + /dev/net/tun;" >&2
  echo "  ACLs, Pi listen address)." >&2
fi
exit "$ec"
