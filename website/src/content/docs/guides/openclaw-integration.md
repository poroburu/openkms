---
title: Openclaw Integration
description: How trading agents should use openKMS as a signing boundary.
---

**Docs path:** Operate / Openclaw Integration

Openclaw is the target consumer: an autonomous trading agent that constructs
transactions and asks openKMS for signatures. openKMS never broadcasts. It
returns signatures that the agent combines with the transaction body and submits
to the chain RPC.

```text
strategy
  -> GET /policy/{label}
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

Openclaw agents should treat policy inspection as part of their signing loop.
Before building a trade or transfer, read `GET /policy/{label}` with the signer
token, then compare the intended transaction against the effective allowlists,
caps, and runtime counters. If `effective_enabled` is false, if a daily cap is
nearly exhausted, or if a rate window is already at its limit, the agent should
wait, choose another configured key, or escalate to an operator instead of
probing `/sign/*` until it is denied.

This repository also ships an AgentSkills-compatible operating guide at
[`.agents/skills/openkms/SKILL.md`](https://github.com/poroburu/openkms/blob/main/.agents/skills/openkms/SKILL.md).
In an Openclaw workspace, that path is a project-agent skill location; copy or
allowlist the skill for agents that should know how to use the openKMS HTTP API
and policy endpoints. The skill contains agent instructions only. It is not part
of the signer runtime configuration and does not grant access without the
appropriate bearer token.

Trusted supervisor agents and dashboards can use the admin token to inspect and
manage subordinate policy overlays via `/admin/policy` and
`/admin/keys/{label}/policy`. Do not give routine trading agents the admin token.
