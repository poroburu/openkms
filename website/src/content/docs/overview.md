---
title: Overview
description: Deny-by-default signing for Solana and Cosmos, backed by a YubiHSM2 you own.
---

**Docs path:** Start / Overview

openKMS is a deny-by-default signing API for Solana and Cosmos, backed by a
YubiHSM2 you actually own. Autonomous strategies (the kind of trading agents
[Openclaw](/openkms/guides/openclaw-integration/) is built around) request
signatures over plain HTTP. Per-key policy stops the bad trades before the
hardware ever touches them.

Private keys never leave the YubiHSM2. The runtime auth key the service binds
as can sign, but cannot export or mutate keys. There is no plaintext egress.

The `0.1.0-rc.1` release is a stable prototype snapshot: small,
fail-closed, designed for a homelab Raspberry Pi that signs for a strategy.

## Five gates between the strategy and your keys

Every signing request crosses these layers in order. Each is fail-closed and
emits to the audit log.

```text
Strategy --> Auth --> Decode --> Policy --> Replay --> SigningVault
                                                           |
                                                       Signature
```

1. **Auth** — bearer token in `signer_token_file`; admin token is separate.
2. **Decode** — chain-specific (Solana `VersionedMessage`, Cosmos `SignDoc`).
3. **Policy** — rate limits, per-tx and rolling daily caps, program / message
   / recipient allowlists, kill switch.
4. **Replay** — cache for deterministic signatures over a configured window.
5. **Signing vault** — sign inside the configured backend (YubiHSM2 in
   production). Append-only audit log + Prometheus counters update on accept
   and on every denial.

## Trust split

- **Host plane** runs the HTTP server, policy, replay cache, audit log, and
  metrics on a hardened systemd unit.
- **HSM plane** holds signing keys, the wrap key, and the runtime auth key
  inside the YubiHSM2 (production `yubihsm` vault driver).

A privileged attacker on the host can ask the connector for signatures within
the policy. Policy is the blast-radius bound; the HSM is the key-egress bound.

## Documentation map

- [Quick Start](/openkms/guides/quick-start/) — local build, ceremony, key
  provisioning, backup, and service start.
- [Configuration](/openkms/guides/configuration/) — every block in the
  canonical TOML.
- [Vaults](/openkms/vaults/overview/) — signing backend drivers (`yubihsm`,
  `file`, cloud / TEE stubs).
- [Policy Authoring](/openkms/guides/policy-authoring/) — how the policy
  engine evaluates a signing request.
- [Openclaw Integration](/openkms/guides/openclaw-integration/) — how a
  trading agent should call openKMS as a signing boundary.
- [Security Model](/openkms/concepts/security-model/) — what the HSM does and
  does not protect.
- [Deployment](/openkms/operations/deployment/) — systemd, host hardening,
  reverse proxy.
- [Backup and Restore](/openkms/operations/backup-restore/) — wrap-encrypted
  recovery from the ceremony mnemonic.
- [Testing and Automation](/openkms/operations/testing/) — local commands and
  CI lanes.
- [HTTP API](/openkms/reference/http-api/) — public routes and link to the
  generated OpenAPI.
- [Architecture](/openkms/reference/architecture/) — module layout and
  request flow.

## Source of truth

Documentation describes these artifacts; it is never authoritative on its own.

- HTTP API: [`openapi/openkms.v1.json`](https://github.com/poroburu/openkms/blob/main/openapi/openkms.v1.json) (CI rebuilds and diffs it from [`src/openapi.rs`](https://github.com/poroburu/openkms/blob/main/src/openapi.rs)).
- Config: [`examples/config.toml`](https://github.com/poroburu/openkms/blob/main/examples/config.toml) (parsed and `.validate()`-checked in [`tests/docs_drift.rs`](https://github.com/poroburu/openkms/blob/main/tests/docs_drift.rs)).
- Agent guidance: [`.agents/skills/openkms/SKILL.md`](https://github.com/poroburu/openkms/blob/main/.agents/skills/openkms/SKILL.md).
- Contributor / CI runbooks: [`docs/remote-e2e.md`](https://github.com/poroburu/openkms/blob/main/docs/remote-e2e.md), [`docs/broadcast-e2e.md`](https://github.com/poroburu/openkms/blob/main/docs/broadcast-e2e.md), [`deploy/README.md`](https://github.com/poroburu/openkms/blob/main/deploy/README.md).
