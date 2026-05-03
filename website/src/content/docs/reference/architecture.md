---
title: Architecture
description: How the signer, policy engine, HSM wrapper, audit log, metrics, and replay cache fit together.
---

openKMS is intentionally small. The HTTP server wires chain-specific decoding
to shared security and observability layers.

```text
src/
├── main.rs        CLI entry
├── config.rs      TOML loader, permission checks, validation
├── hsm.rs         YubiHSM client wrapper and mock HSM support
├── derive.rs      BIP-39, BIP-32, SLIP-10, and HKDF ceremony
├── sig.rs         ECDSA DER/compact conversion and low-s normalization
├── chain/
│   ├── mod.rs     ChainSigner trait, Intent trait, Chain enum
│   ├── solana.rs  VersionedMessage decode and Ed25519 signing
│   └── cosmos.rs  SignDoc decode and secp256k1 signing
├── policy/        Rate limits, caps, allowlists, kill switch
├── audit.rs       Append-only JSONL with optional HMAC chain
├── metrics.rs     Prometheus counters and gauges
├── replay.rs      Replay cache for deterministic signatures
├── admin.rs       Persistent admin kill-switch flags
└── server.rs      Axum router
```

## Request Flow

```text
HTTP request
  -> bearer-token middleware
  -> chain-specific decode
  -> policy evaluation
  -> replay cache check
  -> HSM signing
  -> audit record
  -> metrics update
```

## Adding A Chain

1. Create `src/chain/<chain>.rs` implementing `ChainSigner`.
2. Add a `Chain::<Chain>` variant.
3. Add a signing route in `server.rs`.
4. Add any chain-specific config in `config.rs`.
5. Extend policy checks only when generic `Intent` semantics are not enough.

The HSM, policy, audit, admin, metrics, and replay layers are chain-agnostic.
