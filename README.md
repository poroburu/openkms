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
- [HTTP API](website/src/content/docs/reference/http-api.md)
- [Architecture](website/src/content/docs/reference/architecture.md)

Operator runbooks remain at stable repository paths:

- [`docs/remote-e2e.md`](docs/remote-e2e.md)
- [`docs/broadcast-e2e.md`](docs/broadcast-e2e.md)
- [`deploy/README.md`](deploy/README.md)

The canonical example configuration is [`examples/config.toml`](examples/config.toml).
The generated HTTP API spec is [`openapi/openkms.v1.json`](openapi/openkms.v1.json).

## Quick Start

```bash
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
