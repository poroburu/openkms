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
- `../examples/*` — placeholder config and secret file templates for first
  bootstrapping. Replace the placeholder contents before starting the service.

## First-time install

```bash
# 1) System users.
sudo useradd --system --no-create-home --shell /usr/sbin/nologin yubihsm-connector
sudo useradd --system --home-dir /var/lib/openkms --shell /usr/sbin/nologin openkms

# 2) Config + state dirs.
sudo install -d -m 0750 -o openkms -g openkms /etc/openkms
sudo install -d -m 0700 -o openkms -g openkms /var/lib/openkms
sudo install -d -m 0700 -o openkms -g openkms /var/log/openkms

# 3) Binary.
sudo install -m 0755 target/aarch64-unknown-linux-gnu/release/openkms /usr/local/bin/openkms

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
