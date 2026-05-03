---
title: Overview
description: What openKMS is and the guarantees it is designed to provide.
---

openKMS is a YubiHSM2-backed transaction signer for Cosmos and Solana. It is
designed for a small operator setup, such as a Raspberry Pi signing for an
automated trading strategy, where the strategy can request signatures but
cannot extract raw key material.

The current `0.1.0-rc.1` release is a stable prototype snapshot: small,
deny-by-default, and explicit about the security boundary between transaction
construction, policy evaluation, and HSM signing.

```text
Openclaw strategy
  -> HTTP + bearer token
  -> openKMS axum server
  -> policy, replay cache, audit log, metrics
  -> yubihsm-connector
  -> YubiHSM2
```

## Core Capabilities

- HSM-only signing for Ed25519 Solana keys and secp256k1 Cosmos keys.
- Deterministic setup ceremony from one BIP-39 mnemonic.
- Per-key policy with rate limits, amount caps, allowlists, and a kill switch.
- Append-only JSONL audit log with optional HMAC chaining.
- Prometheus metrics on `/metrics`.
- Chain-agnostic core: add a chain by implementing the Rust `ChainSigner` trait.

## Documentation Map

- [Quick Start](./guides/quick-start.md) covers local build, ceremony, key provisioning, backup, and service start.
- [Security Model](./concepts/security-model.md) explains what the HSM does and does not protect.
- [Configuration](./guides/configuration.md) describes the canonical TOML shape.
- [HTTP API](./reference/http-api.md) documents the public routes and links to generated OpenAPI.
- [Deployment](./operations/deployment.md) points at the checked-in systemd and host hardening runbook.
