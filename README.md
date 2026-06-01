<p align="center">
  <img src="brand/logo.svg" alt="openKMS" width="96" height="96" />
</p>

# openKMS

YubiHSM2-backed transaction signer for **Cosmos** and **Solana**. The
`0.1.0-rc.1` release is a stable prototype snapshot: small, deny-by-default,
designed for a homelab Raspberry Pi that signs for a trading agent, and never
emits raw key material.

## Highlights

- **HSM-only signing.** Private keys are generated or imported into the YubiHSM2
  and never leave as plaintext.
- **Deterministic ceremony.** One BIP-39 mnemonic derives ceremony,
  provisioner, signer, and wrap-key material.
- **Per-key policy.** Rate limits, spend caps, program/message/recipient
  allowlists, and an admin kill switch guard signing.
- **Operational checks.** CI covers formatting, clippy, tests, docs drift,
  rustdoc, OpenAPI drift, and website build health.

## Documentation

The docs website lives in [`website/`](website/) and is published from the
GitHub Pages workflow. Start there for long-form guides:

- [Overview](website/src/content/docs/overview.md)
- [Quick start](website/src/content/docs/guides/quick-start.md)
- [Security model](website/src/content/docs/concepts/security-model.md)
- [Configuration](website/src/content/docs/guides/configuration.md)
- [Policy authoring](website/src/content/docs/guides/policy-authoring.md)
- [Openclaw integration](website/src/content/docs/guides/openclaw-integration.md)
- [Deployment](website/src/content/docs/operations/deployment.md)
- [Backup and restore](website/src/content/docs/operations/backup-restore.md)
- [Testing and automation](website/src/content/docs/operations/testing.md)
- [HTTP API](website/src/content/docs/reference/http-api.md)
- [Architecture](website/src/content/docs/reference/architecture.md)

Vault drivers:

- [Vaults overview](website/src/content/docs/vaults/overview.md)
- [YubiHSM](website/src/content/docs/vaults/yubihsm.md)
- [File (dev)](website/src/content/docs/vaults/file.md)
- [AWS KMS](website/src/content/docs/vaults/awskms.md)
- [Azure Key Vault](website/src/content/docs/vaults/azure.md)
- [Google Cloud KMS](website/src/content/docs/vaults/cloudkms.md)
- [HashiCorp Vault](website/src/content/docs/vaults/hashicorpvault.md)
- [AWS Nitro Enclaves](website/src/content/docs/vaults/nitro.md)
- [GCP Confidential Space](website/src/content/docs/vaults/confidentialspace.md)

Operator and contributor runbooks remain at stable repository paths:

- [`deploy/README.md`](deploy/README.md) — operator install runbook
- [`docs/remote-e2e.md`](docs/remote-e2e.md) — contributor / CI-maintainer runbook for `remote-e2e.yml`
- [`docs/broadcast-e2e.md`](docs/broadcast-e2e.md) — contributor / CI-maintainer runbook for `broadcast-e2e.yml`

The canonical example configuration is [`examples/config.toml`](examples/config.toml).
The generated HTTP API spec is [`openapi/openkms.v1.json`](openapi/openkms.v1.json).
An AgentSkills-compatible OpenKMS operating guide for OpenClaw and other agents
is committed at [`.agents/skills/openkms/SKILL.md`](.agents/skills/openkms/SKILL.md).

## Quick Start

Copy this as one mock-HSM script, then adjust labels, object IDs, and paths
before using it against real hardware.

```bash
set -euo pipefail

cargo build --profile mock-release
./target/mock-release/openkms --mock new-mnemonic > /secure/usb/mnemonic.txt
./target/mock-release/openkms setup --mnemonic-file /secure/usb/mnemonic.txt
./target/mock-release/openkms keys provision \
  --label cosmos-hub-0 \
  --chain cosmos \
  --object-id 0x0100 \
  --path "m/44'/118'/0'/0/0" \
  --mnemonic-file /secure/usb/mnemonic.txt
./target/mock-release/openkms backup --out /secure/usb/openkms-backup.json
./target/mock-release/openkms run
```

## Automation Lanes

- [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs fast repository
  checks: format, clippy, default tests, docs drift, rustdoc, OpenAPI drift,
  website build, and the mock remote shell regression.
- [`.github/workflows/remote-e2e.yml`](.github/workflows/remote-e2e.yml) is a
  manual staging smoke test against a deployed signer. The runbook is
  [`docs/remote-e2e.md`](docs/remote-e2e.md).
- [`.github/workflows/broadcast-e2e.yml`](.github/workflows/broadcast-e2e.yml)
  is a manual live testnet broadcast gate. The runbook is
  [`docs/broadcast-e2e.md`](docs/broadcast-e2e.md).

E2E wrapper scripts share Solana/Cosmos default resolution through
[`scripts/e2e_defaults.sh`](scripts/e2e_defaults.sh). Keep operator flags in
each script's `--help`.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features
```

Build the docs website from `website/`:

```bash
npm install
npm run build
```

## License

Licensed under Apache-2.0. See [`Cargo.toml`](Cargo.toml) for package metadata.
