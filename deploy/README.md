# openKMS deployment

This directory holds the systemd units and supporting files needed to run
openKMS on a Raspberry Pi (aarch64) or any Linux box that a YubiHSM2 is
attached to.

## Files

- `openkms.service` — main signer service (runs `openkms run`).
- `yubihsm-connector.service` — Yubico's `yubihsm-connector` daemon that
  exposes the HSM over `http://127.0.0.1:12345`.
- `99-yubihsm.rules` — udev rule that gives `plugdev` access to the HSM USB
  device node (install into `/etc/udev/rules.d/`).
- `nginx-openkms-remote-e2e.conf.example` — optional TLS reverse proxy in front
  of loopback-bound openkms (GitHub Actions `remote-e2e.yml`).
- `config.remote-e2e.toml` — **`listen = "0.0.0.0:8443"`** staging template for
  Tailscale-reachable smoke tests ([`../docs/remote-e2e.md`](../docs/remote-e2e.md)).
- `openkms.service.d/tailnet.conf` — systemd drop-in **`IPAddressAllow=100.64.0.0/10`**
  so Tailscale peers are not blocked by the stock unit (RFC1918-only allows).
- `install-remote-e2e-host.sh` — installs connector + openkms + tokens + drop-in
  (see below).
- `github-remote-e2e.env.example` — checklist of GitHub Actions secrets to set.
- `../examples/*` — placeholder config and secret file templates for first
  bootstrapping. Replace the placeholder contents before starting the service.

## Remote E2E host (GitHub `workflow_dispatch`)

From the repo root on the Pi (or any staging Linux host with a YubiHSM2):

```bash
sudo ./deploy/install-remote-e2e-host.sh
```

This installs **`yubihsm-connector`**, builds **`mock-release`** if needed, lays
out **`/etc/openkms`**, enables **`openkms.service.d/tailnet.conf`**, and prints
**`OPENKMS_BASE_URL`** / **`OPENKMS_SIGNER_TOKEN`** for GitHub. The service may
stay failed until you finish **`openkms setup`**, provision keys at **`0x0100`**
and **`0x0101`**, update cosmos **`allowed_recipients`**, and regenerate smoke
request secrets — follow the script’s “Next steps” and
[`../docs/remote-e2e.md`](../docs/remote-e2e.md).

## First-time install

```bash
# 1) System users.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin yubihsm-connector
sudo useradd --system --home-dir /var/lib/openkms --shell /usr/sbin/nologin openkms

# 2) Config + state dirs.
sudo install -d -m 0750 -o openkms -g openkms /etc/openkms
sudo install -d -m 0700 -o openkms -g openkms /var/lib/openkms
sudo install -d -m 0700 -o openkms -g openkms /var/log/openkms

# 3) Binary. Use `mock-release` for an optimized build that still supports `--mock`
#    (see `[profile.mock-release]` in ../Cargo.toml). Plain `--release` cannot.
cargo build --profile mock-release
sudo install -m 0755 target/mock-release/openkms /usr/local/bin/openkms
# Cross-compile from another machine:
#   cargo build --profile mock-release --target aarch64-unknown-linux-gnu
# sudo install -m 0755 target/aarch64-unknown-linux-gnu/mock-release/openkms /usr/local/bin/openkms

# 4) Configs (all 0600).
sudo install -m 0600 -o openkms -g openkms examples/config.toml    /etc/openkms/config.toml
sudo install -m 0600 -o openkms -g openkms examples/signer.token   /etc/openkms/signer.token
sudo install -m 0600 -o openkms -g openkms examples/admin.token    /etc/openkms/admin.token
sudo install -m 0600 -o openkms -g openkms examples/hsm-password   /etc/openkms/hsm-password

# 5) Systemd units.
sudo install -m 0644 deploy/openkms.service            /etc/systemd/system/openkms.service
sudo install -m 0644 deploy/yubihsm-connector.service  /etc/systemd/system/yubihsm-connector.service
sudo install -m 0644 deploy/99-yubihsm.rules           /etc/udev/rules.d/99-yubihsm.rules
sudo udevadm control --reload-rules && sudo udevadm trigger

sudo systemctl daemon-reload
sudo systemctl enable --now yubihsm-connector.service
sudo systemctl enable --now openkms.service
```

## Hardening summary

Both units are written with a deny-by-default posture:

- `NoNewPrivileges=true`, `CapabilityBoundingSet=`, `PrivateUsers=true`,
  `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`.
- openKMS additionally uses `MemoryDenyWriteExecute=true`, a filtered
  seccomp allowlist (`SystemCallFilter=@system-service`), and IP allowlist
  entries that keep it from dialling the public internet.
- The HSM password, signer bearer token, and admin bearer token live in
  `/etc/openkms/*` with mode `0600`, owned by `openkms:openkms`.
- State (audit log, `key-flags.json`) lives in `/var/lib/openkms`, mode
  `0700`, so only the service account can read it.

Review the unit files and tune the `IPAddressAllow=` entries and
`MemoryHigh=`/`TasksMax=` to match the footprint of your homelab.

For remote smoke tests against a staging deployment, see
[`../docs/remote-e2e.md`](../docs/remote-e2e.md).

### GitHub Actions `remote-e2e.yml`

**Tailscale (default workflow):** CI joins your tailnet; traffic is from Tailscale
**`100.64.0.0/10`**. Use **`openkms.service.d/tailnet.conf`** or equivalent so the
unit allows CGNAT peers — **`install-remote-e2e-host.sh`** installs this drop-in.

**Without Tailscale:** hosted runners use **public** IPs. The default
**`openkms.service`** sandbox allows localhost and RFC1918/ULA only, so **direct**
**`0.0.0.0`** binds reject GitHub unless you add **`actions`** CIDRs or a proxy:

- **Preferred:** TLS reverse proxy → **`http://127.0.0.1:<port>`**, openkms
  **`listen`** stays loopback. Example fragment:
  [`nginx-openkms-remote-e2e.conf.example`](nginx-openkms-remote-e2e.conf.example).
- **Direct exposure:** merge CIDRs from **`https://api.github.com/meta`** (`actions`)
  into **`IPAddressAllow=`**, e.g. with
  [`../scripts/gen_github_actions_systemd_dropin.sh`](../scripts/gen_github_actions_systemd_dropin.sh).
- **Dedicated staging only:** a drop-in can clear **`IPAddressDeny=`** / allow all
  peers; do not use that pattern on a general homelab node.
