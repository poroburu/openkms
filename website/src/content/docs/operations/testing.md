---
title: Testing And Automation
description: Local test commands, CI lanes, and live smoke-test runbooks.
---

**Docs path:** Operate / Testing And Automation

Run the default test suite without hardware:

```bash
cargo test --all-targets
```

Run the integration tests explicitly:

```bash
cargo test --test integration
```

Hardware tests are opt-in and intentionally strict once enabled:

```bash
OPENKMS_HARDWARE_TESTS=1 cargo test --test integration -- --ignored
```

## Automation Lanes

- [`ci.yml`](https://github.com/poroburu/openkms/blob/main/.github/workflows/ci.yml) runs formatting, clippy, tests, docs drift checks, rustdoc, OpenAPI drift checks, and website build checks.
- [`remote-e2e.yml`](https://github.com/poroburu/openkms/blob/main/.github/workflows/remote-e2e.yml) is a manual staging smoke test against a deployed signer.
- [`broadcast-e2e.yml`](https://github.com/poroburu/openkms/blob/main/.github/workflows/broadcast-e2e.yml) is a manual live testnet broadcast gate.

The E2E wrapper scripts share Solana and Cosmos default resolution through
[`scripts/e2e_defaults.sh`](https://github.com/poroburu/openkms/blob/main/scripts/e2e_defaults.sh).

## Contributor / CI runbooks

The two long-form runbooks below are for openKMS contributors and CI
maintainers — they cover GitHub Actions wiring, Tailscale OAuth, `gh act`
quirks on Docker Desktop / WSL2, throwaway Docker keygen, and devnet funding.
Operator consumers running openKMS for their agent can skip them.

- [`docs/remote-e2e.md`](https://github.com/poroburu/openkms/blob/main/docs/remote-e2e.md) — operator procedure for `remote-e2e.yml`.
- [`docs/broadcast-e2e.md`](https://github.com/poroburu/openkms/blob/main/docs/broadcast-e2e.md) — operator procedure for `broadcast-e2e.yml`.
