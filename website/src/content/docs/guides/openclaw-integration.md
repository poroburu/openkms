---
title: Openclaw Integration
description: How trading agents should use openKMS as a signing boundary.
---

Openclaw is the target consumer: an autonomous trading agent that constructs
transactions and asks openKMS for signatures. openKMS never broadcasts. It
returns signatures that the agent combines with the transaction body and submits
to the chain RPC.

```text
strategy
  -> build transaction
  -> POST /sign/{chain}
  -> policy evaluation
  -> HSM signature
  -> strategy broadcasts through chain RPC
```

The policy engine is designed so a buggy strategy cannot drain an account
unsupervised:

- Per-transaction caps limit damage from one bad trade.
- Daily caps limit sustained bad behavior.
- Allowlists prevent arbitrary program or contract calls.
- Rate limits bound request floods.
- The admin kill switch can stop a key without deleting it.
