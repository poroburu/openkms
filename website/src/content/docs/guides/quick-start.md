---
title: Quick Start
description: Build openKMS, create the ceremony mnemonic, provision a key, and run the signer.
---

**Docs path:** Start / Quick Start

Build an optimized binary that still supports the in-process mock HSM:

```bash
cargo build --profile mock-release
```

Create a 24-word ceremony mnemonic from the HSM's random source:

```bash
./target/mock-release/openkms --mock new-mnemonic > /secure/usb/mnemonic.txt
```

Factory-reset and provision the HSM from that mnemonic:

```bash
./target/mock-release/openkms setup --mnemonic-file /secure/usb/mnemonic.txt
```

Derive the runtime signer password that `[vaults.hsm].password_file` in
`config.toml` points at:

```bash
./target/mock-release/openkms ceremony print-signer-password \
  --mnemonic-file /secure/usb/mnemonic.txt > /etc/openkms/hsm-password
chmod 600 /etc/openkms/hsm-password
```

Provision a signing key. This example imports a deterministic Cosmos key derived
from the ceremony mnemonic:

```bash
./target/mock-release/openkms keys provision \
  --label cosmos-hub-0 \
  --chain cosmos \
  --object-id 0x0100 \
  --path "m/44'/118'/0'/0/0" \
  --mnemonic-file /secure/usb/mnemonic.txt
```

`keys provision` and `keys generate` create asymmetric keys, which the signer
auth key (slot 3) is intentionally not allowed to do. Passing `--mnemonic-file`
makes the CLI authenticate as the provisioner (slot 2) for the duration of the
command. To use a stored provisioner password instead, pass
`--auth-key-id 2` on the global CLI and configure that password through the
normal `[vaults.hsm].password_file` mechanism.

Back up every signing key to a wrap-encrypted blob:

```bash
./target/mock-release/openkms backup --out /secure/usb/openkms-backup.json
```

Run the service:

```bash
./target/mock-release/openkms run
```

## Copy As One Script

For a mock-HSM dry run, copy this whole block and adjust labels, object IDs, and
paths before using it against real hardware.

```bash
set -euo pipefail

cargo build --profile mock-release
./target/mock-release/openkms --mock new-mnemonic > /secure/usb/mnemonic.txt
./target/mock-release/openkms setup --mnemonic-file /secure/usb/mnemonic.txt
./target/mock-release/openkms ceremony print-signer-password \
  --mnemonic-file /secure/usb/mnemonic.txt > /etc/openkms/hsm-password
chmod 600 /etc/openkms/hsm-password
./target/mock-release/openkms keys provision \
  --label cosmos-hub-0 \
  --chain cosmos \
  --object-id 0x0100 \
  --path "m/44'/118'/0'/0/0" \
  --mnemonic-file /secure/usb/mnemonic.txt
./target/mock-release/openkms backup --out /secure/usb/openkms-backup.json
./target/mock-release/openkms run
```

## Key Creation Paths

openKMS supports two key creation paths:

- HSM-native generation with `openkms keys generate`. The HSM TRNG picks the scalar, so the wrap backup must stay current.
- Mnemonic-derived import with `openkms keys provision`. The host derives the scalar from the ceremony mnemonic and imports it into the HSM.

Both paths set `EXPORTABLE_UNDER_WRAP` so keys can be restored to a replacement
HSM using the deterministic wrap key.
