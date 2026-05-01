#!/usr/bin/env bash
# Build JSON for remote smoke signing; print base64 for OPENKMS_REMOTE_E2E_*_REQUEST_B64 secrets
# (base64 of the JSON, no trailing newline). Subcommand `both`: two stdout lines
# (Solana, Cosmos); stderr labels each with OPENKMS_REMOTE_E2E_*_REQUEST_B64.
# Preloads ./.secrets then ./.vars (or OPENKMS_*_FILE).
#
# Optional: -e DIR|FILE  — source broadcast-keys.env first (same layout as
# scripts/generate_broadcast_key_material.sh / run_broadcast_e2e.sh), so you do
# not duplicate OPENKMS_SOLANA_* / OPENKMS_COSMOS_* tuning. Example:
#   ./scripts/generate_remote_e2e_request.sh -e ./.tmp/broadcast-keys both
# If OPENKMS_BROADCAST_KEYS_FILE is set and -e is not used, that path is sourced
# when it exists (file, or DIR/broadcast-keys.env).
#
# See docs/remote-e2e.md.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/generate_remote_e2e_request.sh [-e|--env-file DIR|FILE] [-- <same args as cargo bin>]

  -e, --env-file   Source broadcast-keys.env (if DIR, uses DIR/broadcast-keys.env).
                   Exported vars are visible to the Rust binary; .secrets/.vars
                   still load afterward and only fill unset keys.

Environment:
  OPENKMS_BROADCAST_KEYS_FILE   Optional default env file or directory (when -e omitted).
EOF
}

resolve_broadcast_env_path() {
  local p="$1"
  if [[ -d "$p" ]]; then
    printf '%s\n' "${p%/}/broadcast-keys.env"
  else
    printf '%s\n' "$p"
  fi
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ENV_SOURCE=""
while (($# > 0)); do
  case "$1" in
    -h | --help)
      usage
      exit 0
      ;;
    -e | --env-file)
      if [[ -z "${2:-}" ]]; then
        echo "error: $1 requires a path" >&2
        exit 1
      fi
      ENV_SOURCE="$2"
      shift 2
      ;;
    *)
      break
      ;;
  esac
done

if [[ -z "$ENV_SOURCE" && -n "${OPENKMS_BROADCAST_KEYS_FILE:-}" ]]; then
  ENV_SOURCE="$OPENKMS_BROADCAST_KEYS_FILE"
fi

if [[ -n "$ENV_SOURCE" ]]; then
  env_path="$(resolve_broadcast_env_path "$ENV_SOURCE")"
  if [[ ! -f "$env_path" ]]; then
    echo "error: broadcast env file not found: $env_path" >&2
    exit 1
  fi
  set -a
  # shellcheck disable=SC1090
  source "$env_path"
  set +a
fi

exec cargo run --quiet --bin generate_remote_e2e_request -- "$@"
