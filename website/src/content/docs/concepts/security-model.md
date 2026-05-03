---
title: Security Model
description: What the HSM protects, what still depends on the host, and how recovery works.
---

**Docs path:** Start / Security Model

openKMS speaks plain HTTP. Keep it on loopback, behind an SSH tunnel, or behind
a reverse proxy or load balancer that terminates TLS before wider exposure.

## What The HSM Guarantees

- Signing keys exist only inside the YubiHSM2.
- Signing operations go through `yubihsm::Client::sign_*`.
- The running service authenticates as the signer auth key, which can sign but cannot export or mutate keys.
- Backups are AES-256-CCM wrap-encrypted under a symmetric wrap key that lives in the HSM.

The setup ceremony installs three long-term auth keys:

- Ceremony key: full privileges for setup, factory reset, and backup.
- Provisioner key: adds and removes asymmetric keys and runs wrapped export/import.
- Signer key: signs only; this is the key used by the running service.

## What The HSM Does Not Protect

- Message content. The chain decoders and policy engine decide whether a transaction is acceptable before the HSM signs.
- Signer host compromise. A privileged attacker on the host can ask the connector for signatures within policy limits.
- Connector side channels. The signer auth key's minimal capability set is the main mitigation.

## Recovery Paths

| Scenario | Recovery |
| --- | --- |
| HSM lost or destroyed | Buy a new HSM, run `openkms setup --mnemonic-file <m>`, then `openkms restore`. |
| Auth key password compromised | Factory reset and restore wrapped signing keys. |
| Policy bug | Disable the affected key through the admin API, inspect `audit.jsonl`, edit config, and restart. |
| Mnemonic compromised | Rotate every on-chain account. The mnemonic is the root of trust. |
| Raspberry Pi compromised | Revoke bearer tokens, disable keys from a safe host, and rotate on-chain accounts. |
