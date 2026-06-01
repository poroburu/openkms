---
title: YubiHSM Vault
description: Production YubiHSM2 driver — prerequisite packages, connector setup, and openKMS config.
---

**Docs path:** Vaults / YubiHSM

The `yubihsm` driver is the production signing backend. openKMS talks to
Yubico's `yubihsm-connector` over HTTP on loopback; the connector owns USB
access to the YubiHSM 2 device.

## Prerequisites

Complete these steps **before** configuring openKMS.

### 1. Hardware

You need a [YubiHSM 2](https://www.yubico.com/product/yubihsm-2/) USB device.

### 2. Packages (Debian / Ubuntu / Raspberry Pi OS)

On Debian-family distros the connector is available as an apt package. This
pulls in USB and libusb dependencies automatically — no separate libusb install
is required.

```bash
sudo apt-get update
sudo apt-get install -y yubihsm-connector
```

The repository install script
[`deploy/install-remote-e2e-host.sh`](https://github.com/poroburu/openkms/blob/main/deploy/install-remote-e2e-host.sh)
uses the same package on staging hosts.

### 3. Other Linux

Download connector binaries from
[YubiHSM2 Releases](https://developers.yubico.com/YubiHSM2/Releases). For manual
HSM operations you may also install `yubihsm-shell` from the same release page.
See Yubico's
[Practical Guide](https://developers.yubico.com/YubiHSM2/Usage_Guides/YubiHSM_quick_start_tutorial.html)
for shell usage.

### 4. System user and udev

Create a dedicated system user and grant USB access via udev:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin yubihsm-connector
sudo usermod -aG plugdev yubihsm-connector
sudo install -m 0644 deploy/99-yubihsm.rules /etc/udev/rules.d/99-yubihsm.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

The checked-in rule is
[`deploy/99-yubihsm.rules`](https://github.com/poroburu/openkms/blob/main/deploy/99-yubihsm.rules).
Full operator steps are in
[`deploy/README.md`](https://github.com/poroburu/openkms/blob/main/deploy/README.md).

### 5. Connector configuration

Create `/etc/yubihsm-connector.yaml` if it does not exist:

```yaml
listen: "127.0.0.1:12345"
log: "-"
```

Install the systemd unit from the repository:

```bash
sudo install -m 0644 deploy/yubihsm-connector.service /etc/systemd/system/yubihsm-connector.service
sudo systemctl daemon-reload
sudo systemctl enable --now yubihsm-connector.service
```

Unit file:
[`deploy/yubihsm-connector.service`](https://github.com/poroburu/openkms/blob/main/deploy/yubihsm-connector.service).

### 6. Verify

```bash
sudo systemctl status yubihsm-connector
curl -sS http://127.0.0.1:12345/connector/status
```

A healthy connector returns JSON with device status. If the HSM is unplugged or
permissions are wrong, the status endpoint reports the failure before openKMS
starts.

### 7. Ceremony

After the connector is running, follow
[Quick Start](/openkms/guides/quick-start/) to factory-reset the HSM, derive
signer passwords, and provision keys. Wrap-encrypted backup and restore are in
[Backup and Restore](/openkms/operations/backup-restore/).

CLI commands use `--object-id` for YubiHSM object slots (e.g. `0x0100`). Runtime
signing config uses `key_id` on `[[keys]]` with the same value.

## openKMS config

```toml
[vaults.hsm]
driver        = "yubihsm"
connector_url = "http://127.0.0.1:12345"
auth_key_id   = 3
password_file = "/etc/openkms/hsm-password"
```

| Field | Required | Description |
| --- | --- | --- |
| `driver` | yes | Must be `yubihsm`. |
| `connector_url` | yes* | HTTP endpoint for `yubihsm-connector`. Normally loopback. |
| `auth_key_id` | yes | YubiHSM auth-key slot the runtime authenticates as. Slot `3` is the signer key from `openkms setup`. |
| `password_file` | yes* | 64 hex digits (32 bytes) for the signer auth-key password. Generate with `openkms ceremony print-signer-password`. Must be mode `0600`. |
| `mock` | no | When `true`, use in-process mockhsm instead of the connector. **Tests and CI only** — skips `connector_url` and `password_file` enforcement. |

\* Not required when `mock = true`.

### Key binding

```toml
[[keys]]
label  = "cosmos-hub-0"
chain  = "cosmos"
vault  = "hsm"
key_id = "0x0100"
```

`key_id` is the YubiHSM asymmetric-key object id (hex `0x0100` or decimal `256`).

## Related docs

- [Vaults Overview](/openkms/vaults/overview/)
- [Deployment](/openkms/operations/deployment/)
- [Security Model](/openkms/concepts/security-model/)
