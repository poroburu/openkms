---
title: Deployment
description: Systemd deployment, host hardening, and remote smoke-test setup.
---

**Docs path:** Operate / Deployment

The deployment assets stay in the repository root so operators and workflows can
reference stable paths:

- [`deploy/README.md`](https://github.com/poroburu/openkms/blob/main/deploy/README.md)
- [`deploy/openkms.service`](https://github.com/poroburu/openkms/blob/main/deploy/openkms.service)
- [`deploy/yubihsm-connector.service`](https://github.com/poroburu/openkms/blob/main/deploy/yubihsm-connector.service)
- [`deploy/99-yubihsm.rules`](https://github.com/poroburu/openkms/blob/main/deploy/99-yubihsm.rules)

## Hardening Summary

The service runs as a dedicated `openkms:openkms` system user and the checked-in
unit enables hardening controls including:

- `NoNewPrivileges=true`
- `ProtectSystem=strict`
- `PrivateTmp=true`
- `PrivateUsers=true`
- `MemoryDenyWriteExecute=true`
- `SystemCallFilter=@system-service`

The YubiHSM connector runs separately and owns USB access. openKMS talks to the
connector over HTTP, normally on loopback.

## Remote E2E

GitHub-hosted remote smoke tests join Tailscale first, then use
`OPENKMS_BASE_URL` on the tailnet. The full operator runbook stays at
[`docs/remote-e2e.md`](https://github.com/poroburu/openkms/blob/main/docs/remote-e2e.md).
