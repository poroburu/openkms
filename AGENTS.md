# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

openKMS is a single-crate Rust project (no workspace, no monorepo). It is a YubiHSM2-backed transaction signer for Cosmos and Solana chains. See `README.md` for full documentation.

### System dependency

`libssl-dev` (and `pkg-config`) must be installed for the `openssl-sys` crate to compile. The update script handles this.

### Build, lint, and test commands

All standard commands are in `README.md` § Testing and the CI workflow at `.github/workflows/ci.yml`:

- **Format check:** `cargo fmt --check`
- **Lint:** `cargo clippy --all-targets -- -D warnings`
- **Test:** `cargo test --all-targets` (uses MockHSM, no hardware needed)
- **Build (dev):** `cargo build`
- **Build (optimized + mock support):** `cargo build --profile mock-release`

### Running the server locally (mock mode)

The server can run without a physical YubiHSM2 using the `--mock` flag:

1. Create secret files (must be `chmod 600`):
   - `signer.token` — bearer token for sign endpoints
   - `admin.token` — bearer token for admin endpoints
   - `hsm-password` — HSM login password (use `password` for mock)
2. Write a `config.toml` pointing to those files with `connector_url = "mock"` and `auth_key_id = 1`.
3. Run: `OPENKMS_CONFIG=/path/to/config.toml ./target/mock-release/openkms --mock run`

The MockHSM is ephemeral (in-process), so keys configured in `[[keys]]` blocks must be generated/provisioned at startup or omitted. Running with zero `[[keys]]` entries is valid and exercises health, metrics, and auth rejection.

### Gotchas

- Secret files referenced in `config.toml` (tokens, passwords) **must** be mode `0600` or the service refuses to start.
- Cross-compilation to `aarch64-unknown-linux-gnu` is configured in `.cargo/config.toml` but is only needed for Raspberry Pi deployment, not for local dev/test.
- Hardware-gated tests (`#[ignore]`) require `OPENKMS_HARDWARE_TESTS=1` and a real YubiHSM2 + `yubihsm-connector`. They are intentionally skipped in normal `cargo test`.
- Broadcast E2E tests require testnet RPC access and are gated behind `OPENKMS_BROADCAST_TESTS=1`.
