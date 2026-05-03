---
title: Backup And Restore
description: Recover signing keys using the deterministic wrap key and ceremony mnemonic.
---

**Docs path:** Operate / Backup And Restore

Backups are wrap-encrypted under the deterministic wrap key derived during the
ceremony. Store the backup blob next to the ceremony mnemonic. An attacker with
the backup but not the mnemonic cannot decrypt the wrapped signing keys.

Create a backup from the old HSM:

```bash
openkms backup --out /secure/usb/openkms-backup.json
```

Prepare a replacement HSM:

```bash
openkms setup --mnemonic-file /secure/usb/mnemonic.txt
```

Restore every signing key:

```bash
openkms restore --in /secure/usb/openkms-backup.json
```

If the mnemonic is compromised, rotate every on-chain account. It is the root of
trust for the system.
