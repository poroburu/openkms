#!/usr/bin/env bash
# Generate a systemd drop-in fragment so openkms (under deploy/openkms.service)
# accepts TCP from GitHub-hosted Actions runners when openkms listens on a
# non-loopback address. Prefer a reverse proxy to 127.0.0.1 instead — see
# docs/remote-e2e.md.
set -euo pipefail

usage() {
  echo "usage: $0 [-o FILE]" >&2
  echo "  Writes [Service] + IPAddressAllow= lines from https://api.github.com/meta (actions)." >&2
  echo "  Default: stdout. After install: sudo systemctl daemon-reload && sudo systemctl restart openkms" >&2
  exit 1
}

out=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o)
      [[ $# -ge 2 ]] || usage
      out="$2"
      shift 2
      ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

emit() {
  curl -fsS https://api.github.com/meta | python3 -c '
import json, sys

m = json.load(sys.stdin)
actions = m.get("actions") or []
if not actions:
    print("meta JSON missing actions list", file=sys.stderr)
    sys.exit(1)

per_line = 32
print("# Generated from https://api.github.com/meta (field actions).")
print("# Regenerate when GitHub expands ranges; see docs/remote-e2e.md.")
print("[Service]")
for i in range(0, len(actions), per_line):
    batch = actions[i : i + per_line]
    print("IPAddressAllow=" + " ".join(batch))
'
}

if [[ -n "$out" ]]; then
  tmp="${out}.tmp.$$"
  emit > "$tmp"
  chmod 0644 "$tmp"
  mv "$tmp" "$out"
else
  emit
fi
