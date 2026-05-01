#!/usr/bin/env bash
# Install openkms + yubihsm-connector on a Linux host for GitHub Actions
# remote-e2e (Tailscale → signer HTTP). Run from repo root or pass OPENKMS_REPO.
#
# Usage:
#   sudo ./deploy/install-remote-e2e-host.sh
#
# Requires: apt (Debian/Ubuntu/Raspberry Pi OS), rustc/cargo for building.
# When run via sudo, cargo is resolved from the invoking user's ~/.cargo/bin
# (root's PATH usually does not include rustup).
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${OPENKMS_REPO:-$SCRIPT_DIR/..}" && pwd)"

die() {
  echo "error: $*" >&2
  exit 1
}

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo)"

# Resolve cargo: sudo resets PATH so ~/.cargo/bin is missing for root.
resolve_cargo() {
  local c uhome
  c="$(command -v cargo 2>/dev/null || true)"
  if [[ -n "$c" ]]; then
    printf '%s\n' "$c"
    return 0
  fi
  if [[ -n "${SUDO_USER:-}" ]]; then
    uhome="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
    if [[ -x "${uhome}/.cargo/bin/cargo" ]]; then
      printf '%s\n' "${uhome}/.cargo/bin/cargo"
      return 0
    fi
  fi
  if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    printf '%s\n' "${HOME}/.cargo/bin/cargo"
    return 0
  fi
  return 1
}

CARGO="$(resolve_cargo)" || die "install Rust (cargo) first (rustup: ~/.cargo/bin/cargo)"

BIN_SRC="$REPO_ROOT/target/mock-release/openkms"
if [[ ! -x "$BIN_SRC" ]]; then
  echo "building openkms (mock-release profile)…"
  if [[ -n "${SUDO_USER:-}" ]] && [[ "$(id -un)" == "root" ]]; then
    sudo -u "$SUDO_USER" -H bash -lc "cd $(printf '%q' "$REPO_ROOT") && exec $(printf '%q' "$CARGO") build --profile mock-release"
  else
    (cd "$REPO_ROOT" && exec "$CARGO" build --profile mock-release)
  fi
  BIN_SRC="$REPO_ROOT/target/mock-release/openkms"
fi
[[ -x "$BIN_SRC" ]] || die "missing binary after build: $BIN_SRC"

echo "installing packages…"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq yubihsm-connector

if ! id -u yubihsm-connector &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin yubihsm-connector
fi
usermod -aG plugdev yubihsm-connector 2>/dev/null || true
if ! id -u openkms &>/dev/null; then
  useradd --system --home-dir /var/lib/openkms --shell /usr/sbin/nologin openkms
fi

install -d -m 0750 -o openkms -g openkms /etc/openkms
install -d -m 0700 -o openkms -g openkms /var/lib/openkms
install -d -m 0700 -o openkms -g openkms /var/log/openkms

if [[ ! -f /etc/yubihsm-connector.yaml ]]; then
  cat >/etc/yubihsm-connector.yaml <<'YAML'
listen: "127.0.0.1:12345"
log: "-"
YAML
  chmod 0644 /etc/yubihsm-connector.yaml
fi

install -m 0755 "$BIN_SRC" /usr/local/bin/openkms

install -m 0644 "$REPO_ROOT/deploy/openkms.service" /etc/systemd/system/openkms.service
install -m 0644 "$REPO_ROOT/deploy/yubihsm-connector.service" /etc/systemd/system/yubihsm-connector.service
install -m 0644 "$REPO_ROOT/deploy/99-yubihsm.rules" /etc/udev/rules.d/99-yubihsm.rules
udevadm control --reload-rules && udevadm trigger || true

install -d /etc/systemd/system/openkms.service.d
install -m 0644 "$REPO_ROOT/deploy/openkms.service.d/tailnet.conf" \
  /etc/systemd/system/openkms.service.d/tailnet.conf

gen_secret() { openssl rand -hex 24; }

if [[ ! -f /etc/openkms/signer.token ]]; then
  gen_secret >/etc/openkms/signer.token
  chown openkms:openkms /etc/openkms/signer.token
  chmod 0600 /etc/openkms/signer.token
fi
if [[ ! -f /etc/openkms/admin.token ]]; then
  gen_secret >/etc/openkms/admin.token
  chown openkms:openkms /etc/openkms/admin.token
  chmod 0600 /etc/openkms/admin.token
fi
if [[ ! -f /etc/openkms/audit-hmac.key ]]; then
  openssl rand 32 >/etc/openkms/audit-hmac.key
  chown openkms:openkms /etc/openkms/audit-hmac.key
  chmod 0600 /etc/openkms/audit-hmac.key
fi
if [[ ! -f /etc/openkms/hsm-password ]]; then
  install -m 0600 -o openkms -g openkms "$REPO_ROOT/examples/hsm-password" /etc/openkms/hsm-password
  echo "installed placeholder /etc/openkms/hsm-password — replace after openkms setup if needed"
fi

if [[ ! -f /etc/openkms/config.toml ]]; then
  install -m 0600 -o openkms -g openkms "$REPO_ROOT/deploy/config.remote-e2e.toml" /etc/openkms/config.toml
else
  echo "keeping existing /etc/openkms/config.toml"
fi

systemctl daemon-reload
systemctl enable yubihsm-connector.service
systemctl restart yubihsm-connector.service

systemctl enable openkms.service
if systemctl restart openkms.service; then
  OPENKMS_STARTED=1
else
  OPENKMS_STARTED=0
  echo "warning: openkms.service failed to start (expected until HSM is provisioned and secrets match)."
fi

SIGNER="$(cat /etc/openkms/signer.token)"
TS_NAME=""
if command -v tailscale >/dev/null && tailscale status &>/dev/null; then
  TS_NAME="$(tailscale status 2>/dev/null | awk -v h="$(hostname -s)" '$2==h { print $2; exit }')"
fi
HOST_HINT="${TS_NAME:-$(hostname -s)}"

echo ""
echo "=== Remote E2E host install complete ==="
echo "Listen: 0.0.0.0:8443 (Tailscale peers allowed via systemd drop-in + ACLs)."
echo ""
echo "GitHub secret OPENKMS_BASE_URL (example):"
echo "  http://${HOST_HINT}:8443"
echo ""
echo "GitHub secret OPENKMS_SIGNER_TOKEN:"
echo "  ${SIGNER}"
echo ""
echo "Next steps on this machine:"
echo "  1. Replace /etc/openkms/hsm-password if your auth-key password differs."
echo "  2. Run ceremony: openkms setup / keys provision so object IDs 0x0100 and 0x0101 exist."
echo "  3. Update cosmos policy: set allowed_recipients to your address:"
echo "       sudo -u openkms OPENKMS_CONFIG=/etc/openkms/config.toml \\"
echo "         /usr/local/bin/openkms keys address --label cosmos-hub-0"
echo "     then edit /etc/openkms/config.toml (see deploy/config.remote-e2e.toml comments)."
echo "  4. Regenerate OPENKMS_REMOTE_E2E_*_REQUEST_B64 with scripts/generate_remote_e2e_request.sh"
echo "     and paste into GitHub Actions secrets."
echo "  5. In Tailscale ACLs, allow tag:ci (or TAILSCALE_OAUTH_TAGS) to tcp:8443 on this host."
echo ""
echo "Template for other secrets: deploy/github-remote-e2e.env.example"
if [[ "${OPENKMS_STARTED}" -eq 1 ]]; then
  echo ""
  echo "openkms.service is active. Check: curl -sS \"http://127.0.0.1:8443/health\""
fi
