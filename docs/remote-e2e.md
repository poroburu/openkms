# Remote E2E Smoke Tests

[`README.md`](../README.md) owns the short map of repository automation lanes.
This file owns the detailed operator procedure for `.github/workflows/remote-e2e.yml`.

The remote lane is intentionally a smoke test, not a load test. Its job is to
prove that a real deployment can answer `/health`, `/keys`, `/metrics`, and safe
**Solana** then **Cosmos** signing requests (sequential jobs, one fixture per chain; Cosmos `needs` Solana).

## Request builder and smoke runner (CI + operators)

The same tooling serves **two** audiences; you do not maintain two different
request formats.

- **`scripts/generate_remote_e2e_request.sh`** (Rust binary **`generate_remote_e2e_request`**) builds the compact JSON bodies the HTTP API expects and prints **base64** suitable for GitHub Actions secrets, `act` `.secrets`, or ad‑hoc testing.
- **`scripts/run_remote_e2e_job.sh`** is the **single entrypoint** GitHub Actions and
  operators should use: it checks required env vars, decodes **`OPENKMS_SIGN_REQUEST_B64`**
  into a fixture file, sets **`OPENKMS_SIGN_PATH`** (`/sign/solana` or `/sign/cosmos`),
  then runs **`remote_e2e_smoke.sh`**. Keeps `.github/workflows/remote-e2e.yml` and
  local/`act` runs aligned.
- **`scripts/remote_e2e_smoke.sh`** implements the HTTP checks (**`/health`**, **`/keys`**,
  **`/metrics`**, **`POST`** sign) once **`OPENKMS_SIGN_REQUEST_FILE`** and **`OPENKMS_SIGN_PATH`**
  are set (the job script sets them for you).
- **`scripts/e2e_defaults.sh`** owns shared Solana and Cosmos default resolution
  for E2E wrapper scripts.

**Self-contained CI** — Any workflow that brings up `openkms` on the runner (for
example the pattern in [`broadcast-e2e.md`](broadcast-e2e.md)) can use the **same**
generator to produce Solana/Cosmos fixtures and run **`remote_e2e_smoke.sh`**
against the local listener (`OPENKMS_BASE_URL` pointing at `localhost` or the
service container). The request bytes are identical to what you would paste into
`remote-e2e.yml` secrets for staging.

**End users and operators** — The same commands document how to verify **their**
deployments: build requests from keys they own, set **`OPENKMS_BASE_URL`** and
**`OPENKMS_SIGNER_TOKEN`**, run the smoke script from a laptop or internal runner,
or wire the generated base64 into **`remote-e2e.yml`** for a recurring staging gate.

## Why keep this separate from CI?

`mockhsm` gives fast, deterministic coverage for routing, decoding, and most
policy behavior, but it does not prove:

- the real `yubihsm-connector` is reachable
- the deployed host has the expected file permissions and systemd wiring
- the staging URL, bearer tokens, and network path work outside one machine

Treat the remote smoke lane as a release/staging gate, not as a replacement for
the fast repo-check lane.

If you want to validate full chain submission, use
[`broadcast-e2e.md`](broadcast-e2e.md) and
`.github/workflows/broadcast-e2e.yml`. Keep that separate from this workflow so
signer deployment failures stay distinct from testnet RPC or fee/nonce issues.

## Workflow inputs

In GitHub: **Settings → Secrets and variables → Actions → Secrets** (repository
scope). Missing values surface as errors from **`scripts/run_remote_e2e_job.sh`**
or from the Tailscale action.

`remote-e2e.yml` reads these **secrets**:

- `TAILSCALE_OAUTH_CLIENT_ID` / `TAILSCALE_OAUTH_CLIENT_SECRET`: [Tailscale OAuth API client](https://tailscale.com/s/oauth-clients) with **`auth_keys`** scope and tags matching the workflow (see **`TAILSCALE_OAUTH_TAGS`** below). This avoids the deprecated **`authkey`** input on `tailscale/github-action`. ([Tailnet Lock](https://tailscale.com/kb/1226/tailnet-lock) deployments may still require a **pre-signed auth key** instead — fork the workflow to pass **`authkey`** per the action README.)
- `OPENKMS_BASE_URL`: signer HTTP base URL reachable **on the tailnet after** the Tailscale step (e.g. **`http://my-pi:8443`**, **`http://100.x.y.z:8443`**). The same secret is used on **github.com** and under **`gh act`** once the job has joined the tailnet.
- `OPENKMS_SIGNER_TOKEN`: signer bearer token for the staging environment
- `OPENKMS_REMOTE_E2E_SOLANA_REQUEST_B64`: base64-encoded JSON for **`POST /sign/solana`**
- `OPENKMS_REMOTE_E2E_COSMOS_REQUEST_B64`: base64-encoded JSON for **`POST /sign/cosmos`**

Optional **secrets**:

- `OPENKMS_TAILSCALE_PING_HOST`: passed to the Tailscale action’s **`ping`** input — a **comma-separated** list of tailnet machines (MagicDNS short name like **`my-pi`**, FQDN, or **`100.x`** address) the action **`tailscale ping`**s after **`tailscale up`** until one responds (waits for mesh convergence). Often the **same host** as in **`OPENKMS_BASE_URL`** (hostname only, no `http://`). **Unset** to skip ping and go straight to smoke.

Optional **variables**:

- `TAILSCALE_OAUTH_TAGS`: comma-separated [ACL tags](https://tailscale.com/kb/1068/tags) for CI nodes (must match your OAuth client), e.g. **`tag:ci`**. If unset, the workflow defaults to **`tag:ci`** — create that tag on the client and allow it in ACLs to reach your signer.

- `OPENKMS_EXPECT_SOLANA_KEY_LABEL`: if set, the **Solana** job asserts this label
  appears in `GET /keys`
- `OPENKMS_EXPECT_COSMOS_KEY_LABEL`: if set, the **Cosmos** job asserts this label
  appears in `GET /keys`

If you previously used `OPENKMS_REMOTE_E2E_REQUEST_B64` or `OPENKMS_EXPECT_KEY_LABEL`,
rename those GitHub items to **`OPENKMS_REMOTE_E2E_SOLANA_REQUEST_B64`** and
**`OPENKMS_EXPECT_SOLANA_KEY_LABEL`** (same values).

Sign paths are fixed per job (`/sign/solana` and `/sign/cosmos`).

The workflow runs **`scripts/run_remote_e2e_job.sh`** (normal `run:` steps, not a
composite action) so [act](https://github.com/nektos/act) and GitHub both execute the
same shell as operators. Ensure `OPENKMS_REMOTE_E2E_*_REQUEST_B64` exist in your
`.secrets` when using `gh act workflow_dispatch -W .github/workflows/remote-e2e.yml`.
Self-contained regression for this script lives in **`tests/remote_e2e_job_shell.rs`**
and runs in its **own CI job** under **`ci.yml`** (`cargo test --test remote_e2e_job_shell -- --ignored`)
so the main **`cargo test`** log stays shorter; all Rust jobs share **`rust-cache`**
with **`shared-key: openkms`** to reuse compiled deps.

## Tailscale path (default in `remote-e2e.yml`)

The workflow runs **`tailscale/github-action@v4`** after checkout so smoke **`curl`**
traffic goes over your **tailnet**, not from GitHub’s public **`meta` `actions`**
addresses directly to your home IP.

- **`TAILSCALE_OAUTH_*`** credentials must tag runners so your [ACLs](https://tailscale.com/kb/1018/acls) allow **`tag:ci`** (or whatever **`TAILSCALE_OAUTH_TAGS`** is) to reach the signer’s **`OPENKMS_BASE_URL`** host and port.
- **`OPENKMS_BASE_URL`** should use a host/port the **runner can resolve and reach only
  after** Tailscale is connected (MagicDNS name of the Pi, **`100.x`**, or subnet
  router target — whatever your tailnet uses).
- **`OPENKMS_TAILSCALE_PING_HOST`** (optional) should name the same machine or an
  adjacent tailnet hop so the action waits until **`tailscale ping`** succeeds before
  **`remote_e2e_smoke.sh`** runs.

On the signer, you still need **`openkms`** (or nginx in front of it) listening on an
address the **tailnet peer** can reach — set **`[server].listen`** to **`0.0.0.0:PORT`**
on a dedicated staging host, or to the Pi’s **`100.x`** / tailscale interface address,
or terminate TLS on **nginx** and keep openkms on **`127.0.0.1`** — plus ACLs that allow
the CI node’s tag or user to the signer’s port.

### Checklist: Pi (or staging host) for remote smoke

1. **Tailscale on the Pi** — Install and log in; note MagicDNS name and **`100.x`**.
2. **ACLs** — Allow your CI OAuth tag (e.g. **`tag:ci`**) to **`tcp:PORT`** on the Pi
   (same **`PORT`** as in **`OPENKMS_BASE_URL`**).
3. **HTTP listen** — Either **`listen = "0.0.0.0:8443"`** (example) in **`config.toml`**
   so tailnet peers can connect, **or** keep **`127.0.0.1:9443`** and put **nginx** (or
   similar) on **`443`/`8443`** with **`proxy_pass`** to loopback (see
   [`deploy/nginx-openkms-remote-e2e.conf.example`](../deploy/nginx-openkms-remote-e2e.conf.example)).
4. **systemd `IPAddressAllow=`** — Peers from the tailnet are **`100.64.0.0/10`** (and
   IPv6 ULA if you use it). The stock [`deploy/openkms.service`](../deploy/openkms.service)
   allows RFC1918 private ranges **but not** **`100.64.0.0/10`**, so **direct** binds to
   **`0.0.0.0`** still see **dropped** connections from CI unless you add a drop-in
   **`IPAddressAllow=100.64.0.0/10`** (or use nginx so the peer is **localhost**).
5. **`yubihsm-connector`** — **`Requires=`** / running; **`[hsm].connector_url`** reachable
   from the **`openkms`** process.
6. **Bearer token** — **`/etc/openkms/signer.token`** matches **`OPENKMS_SIGNER_TOKEN`**
   in GitHub / **`.secrets`**.
7. **Request fixtures** — Secrets **`OPENKMS_REMOTE_E2E_*_REQUEST_B64`** must match keys
   and policy on the Pi (generate with **`scripts/generate_remote_e2e_request.sh`**).
8. **Optional labels** — Repo vars **`OPENKMS_EXPECT_*_KEY_LABEL`** must match **`GET /keys`**
   if set.

## Staging deployment: reachability from GitHub-hosted runners

**If you remove the Tailscale step** (or run smoke manually without tailnet), each
job’s `curl` calls originate from **[GitHub’s published Actions IP ranges](https://api.github.com/meta)** (the JSON
`actions` array), not from your LAN. Two pieces of the stock homelab layout block
that path unless you adjust them:

1. **`[server].listen`** in `/etc/openkms/config.toml` — the checked-in
   [`examples/config.toml`](../examples/config.toml) uses **`127.0.0.1`**, which
   only accepts connections **on the signer host itself**. Nothing on the public
   internet (or on another machine) can reach it.
2. **`deploy/openkms.service`** — **`IPAddressDeny=any`** plus **`IPAddressAllow=`**
   for localhost and private-space prefixes. Traffic whose **peer** is a GitHub
   runner public address is **not** in that allowlist, so the service cgroup drops
   the connection even if you bind **`0.0.0.0`**.

**Recommended (keeps systemd hardening):** put **TLS** on a reverse proxy
(nginx, Caddy, Traefik, cloud LB) that listens on **`443`** (or another public
port), and **`proxy_pass`** to **`http://127.0.0.1:9443`**. Leave openkms on
**`listen = "127.0.0.1:9443"`**. From openkms’s perspective, every request is from
**localhost**, which matches the unit’s **`IPAddressAllow=`** rules. Set
**`OPENKMS_BASE_URL`** in GitHub secrets to **`https://your-staging-host`** (see
[`deploy/nginx-openkms-remote-e2e.conf.example`](../deploy/nginx-openkms-remote-e2e.conf.example)).

**Alternative (openkms bound on `0.0.0.0` without a local proxy):** extend the
unit’s allowlist with GitHub’s **`actions`** CIDRs (they change over time; refresh
when runs start failing with timeouts):

```bash
sudo install -d /etc/systemd/system/openkms.service.d
./scripts/gen_github_actions_systemd_dropin.sh \
  -o /etc/systemd/system/openkms.service.d/github-actions.conf
sudo systemctl daemon-reload
sudo systemctl restart openkms
```

**Staging-only escape hatch:** a drop-in that clears **`IPAddressDeny=`** /
**`IPAddressAllow=`** exposes the process network namespace without the unit’s IP
sandbox — only use on a **dedicated** staging host, with other controls (firewall,
TLS, rate limits). See [`deploy/README.md`](../deploy/README.md).

### Local `gh act` and common `curl` failures

**Same path as GitHub:** `remote-e2e.yml` runs **`tailscale/github-action@v4`**, then **`curl`** uses **`OPENKMS_BASE_URL`**. Put
the same **`TAILSCALE_OAUTH_*`**, **`OPENKMS_BASE_URL`**, and smoke secrets in **`.secrets`**
(and **`TAILSCALE_OAUTH_TAGS`** / label vars in **`.vars`**) as for Actions.

**Set up job fails on `docker pull`:** If you see **`authentication required` / `incorrect username or password`** while pulling **`catthehacker/ubuntu:act-latest`**, that is **Docker registry auth**, not this workflow. Try **`docker pull catthehacker/ubuntu:act-latest`** in a normal shell: fix **`docker login`** (Docker Hub) if you use a paid/registry account, or **`docker logout`** and retry anonymous pulls; clear stale entries in **`~/.docker/config.json`**; on **Docker Desktop** (WSL2), confirm you are logged into the right account or reset credentials in **Settings**.

**Why `gh act` can still fail:** [nektos/act](https://github.com/nektos/act) sets **`ACT=true`**
and runs steps inside Docker. **`tailscaled`** usually needs **`/dev/net/tun`** and
**`CAP_NET_ADMIN`**. Without them the Tailscale step often fails with **`503 Service Unavailable: no backend`**.

Configure **`--container-options "--cap-add=NET_ADMIN --device /dev/net/tun"`** on the
**`act` / `gh act`** CLI, in **`.actrc`**, or in your **VS Code / Cursor GitHub Local Actions**
runner extension settings (same flags act would receive). Syntax varies by tool; see **`act --help`**.

```bash
gh act -W .github/workflows/remote-e2e.yml -j solana --secret-file .secrets --var-file .vars \
  --container-options "--cap-add=NET_ADMIN --device /dev/net/tun"
```

If **`tailscaled` still fails** (some Docker Desktop / WSL setups), fall back to
**`--privileged`** for local debugging only — broader than the line above.

**Local act vs `node24`:** Older **act**/`gh act` rejects actions whose **`action.yml`** uses **`runs.using: node24`** (e.g. **`tailscale/github-action@v4`**, **`Swatinem/rust-cache@v2.9.1`**). **`actions/checkout@v4`** is still **node20**, which is one reason **`broadcast-e2e.yml`** can look easier under act than workflows that pull **node24** actions. **Upgrade [nektos/act](https://github.com/nektos/act/releases)** (or the **`gh extension`** that bundles it) for local runs. This repo **pins** **`Swatinem/rust-cache@v2.9.1`** in **`ci.yml`** / **`broadcast-e2e.yml`** while staying on the **v2** line.

See [Tailscale’s GitHub Action README](https://github.com/tailscale/github-action).

The **stable** path for “CI always reaches the Pi the same way” is **`workflow_dispatch` on github.com**;
use **`gh act`** when you want to exercise the workflow locally and accept Docker/Tailscale tuning.

The smoke step runs **`curl`** against **`OPENKMS_BASE_URL`** from **inside** the job
environment. `gh act` may redact the hostname in logs (`***`); compare with your
`.secrets` when debugging.

**`curl: (6) Could not resolve host`** — **`OPENKMS_BASE_URL`** uses a name that
does not resolve (often **`…example.com`** placeholders from docs). Use a real DNS
name or a private name your network resolves. See also the warning in
`scripts/remote_e2e_smoke.sh` when the URL contains `example.*`.

**`curl: (7) Failed to connect … port N`** — after Tailscale, DNS worked but nothing
accepted TCP (timeout or refused):

- **Tailscale did not complete** — check the Tailscale action log, OAuth tags vs ACLs,
  and **`OPENKMS_TAILSCALE_PING_HOST`** if set (must be reachable from the CI node).
- **`http://host`** without a port uses **port 80**. If the signer only speaks **HTTPS**,
  use **`https://…`** (port **443** unless you include **`:port`**).
- **Pi listen address** — openkms (or nginx) must listen on an interface the tailnet
  peer can reach (**`0.0.0.0`**, **`tailscale0`**, etc.), not only **`127.0.0.1`**, unless
  you terminate TLS on the same host and **`proxy_pass`** to localhost (see staging
  section above).
- **Firewall** on the Pi or path — ensure the tagged CI node can open the port in
  **`OPENKMS_BASE_URL`**.

[act usage](https://nektosact.com/usage) has more on container networking.

### `actions/cache` / `Swatinem/rust-cache` under act

act starts a small **embedded** GitHub cache–compatible server by default (so
`actions/cache` and **`rust-cache`** can reserve/upload entries). A log like
**`reserveCache failed: connect ECONNREFUSED 10.x.x.x:port`** usually means the
**runner container** cannot reach the host URL act published (default bind uses an
**outbound** host IP that Docker does not route on WSL2 / some Linux setups).

**Keep the built-in server and fix routing** — fixed port, listen on all interfaces,
and an **external** URL the container can use (same idea as act’s artifact server):

```text
--cache-server-addr 0.0.0.0
--cache-server-port 5390
--cache-server-external-url http://host.docker.internal:5390
```

Put those lines in **`.actrc`** or pass them on the CLI. On Linux without
`host.docker.internal`, try **`http://172.17.0.1:5390`** or add
**`--add-host=host.docker.internal:host-gateway`** via act’s container options (see
your `act` / `gh act` version).

**Skip caching locally** — **`--no-cache-server`**: no cache API, no save/restore
warnings; each act run pays a full `cargo` fetch/build cost unless your own mounts
speed that up.

**External cache only** — if **`ACTIONS_CACHE_URL`** is already set in the
environment, act does **not** start its embedded server (you would point that at
another cache implementation yourself; most people use the flags above instead).

`scripts/remote_e2e_smoke.sh` **never** chooses a chain for you: set
**`OPENKMS_SIGN_PATH`** (e.g. `/sign/solana` or `/sign/cosmos`) together with
**`OPENKMS_SIGN_REQUEST_FILE`**, or set **`OPENKMS_REMOTE_E2E_CHAIN=both`** with
**`OPENKMS_SIGN_PATH_SOLANA`**, **`OPENKMS_SIGN_PATH_COSMOS`**,
**`OPENKMS_SIGN_REQUEST_FILE_SOLANA`**, and **`OPENKMS_SIGN_REQUEST_FILE_COSMOS`**
to run one health/keys/metrics cycle and then both sign calls. Optional
**`OPENKMS_EXPECT_SOLANA_KEY_LABEL`** / **`OPENKMS_EXPECT_COSMOS_KEY_LABEL`** apply
only in `both` mode (each is checked against `GET /keys` when non-empty).

For single-chain runs, the workflow maps **`OPENKMS_EXPECT_SOLANA_KEY_LABEL`** /
**`OPENKMS_EXPECT_COSMOS_KEY_LABEL`** into **`OPENKMS_EXPECT_KEY_LABEL`** per job;
the script still reads **`OPENKMS_EXPECT_KEY_LABEL`** for that check.

## Building the request fixture

The request body must match the current HTTP API shape. Example Solana fixture:

```json
{
  "label": "solana-hot-0",
  "message_b64": "<base64 VersionedMessage>"
}
```

Example Cosmos fixture:

```json
{
  "label": "cosmos-hub-0",
  "sign_doc_b64": "<base64 SignDoc>",
  "expected_chain_id": "theta-testnet-001"
}
```

Encode each JSON body before storing it as a secret (GNU `base64`):

```bash
base64 -w0 request-solana.json   # value for OPENKMS_REMOTE_E2E_SOLANA_REQUEST_B64
base64 -w0 request-cosmos.json   # value for OPENKMS_REMOTE_E2E_COSMOS_REQUEST_B64
```

### Generating request secrets with the helper

Use `scripts/generate_remote_e2e_request.sh` (wraps `cargo run --bin
generate_remote_e2e_request`) to build the same JSON shape the server expects,
then print **base64 of the compact JSON** on stdout (suitable for pasting into
the GitHub secret or `act`’s `.secrets`). The shell wrapper accepts **`-e` /
`--env-file`** pointing at **`broadcast-keys.env`** or its parent directory (same
artifact as [`broadcast-e2e.md`](broadcast-e2e.md) / `generate_broadcast_key_material.sh`):
that sources the throwaway keys plus Solana/Cosmos tuning so you are not
re-entering RPC, chain id, fees, lamports, and gas/transfer amounts that already
match the broadcast integration tests. From the repo root the **Rust** binary
then loads **`./.secrets`** then **`./.vars`** (same `KEY=value` format as [act’s secret and var files](https://nektosact.com/usage/index.html?highlight=secret#secrets)),
only setting variables that are not already in the environment—so remote key
labels can stay in `.secrets` while chain tuning comes from `-e`. Override paths
with **`OPENKMS_SECRETS_FILE`** and **`OPENKMS_VARS_FILE`**. If you omit **`-e`**,
you can set **`OPENKMS_BROADCAST_KEYS_FILE`** to the same path so every run picks
it up without repeating the flag.

If you still have a single **`OPENKMS_REMOTE_E2E_LABEL`** line (older layout),
the binary copies it into **`OPENKMS_REMOTE_E2E_SOLANA_LABEL`** and
**`OPENKMS_REMOTE_E2E_COSMOS_LABEL`** when those are unset—enough for `both` when
both chains use the same key label string, or as a stopgap until you add
explicit per-chain label variables.

The **binary** still has **no implicit chain defaults** (nothing guessed from
RPC alone). Use flags, **`.vars`**, or **`-e broadcast-keys.env`** (which encodes
the same devnet + chain-registry defaults as the broadcast lane) so
`expected_chain_id` and fee fields are explicit.

**Solana** (uses `getLatestBlockhash` on **`OPENKMS_SOLANA_RPC_URL`**; builds a
small **self-transfer** so the signer pubkey is the sole required signer):

```bash
./scripts/generate_remote_e2e_request.sh solana \
  --label 'solana-hot-0' \
  --seed-b64 "$OPENKMS_SOLANA_SIGNER_SEED_B64" \
  --rpc-url 'https://api.devnet.solana.com' \
  --expected-chain-id devnet \
  --lamports 5000
```

Required env names (if you omit equivalent flags): `OPENKMS_REMOTE_E2E_SOLANA_LABEL`,
`OPENKMS_SOLANA_SIGNER_SEED_B64`, `OPENKMS_SOLANA_RPC_URL`, `OPENKMS_SOLANA_CHAIN_ID`,
`OPENKMS_SOLANA_TRANSFER_LAMPORTS`. **`OPENKMS_SOLANA_CHAIN_ID` must match the RPC**
(e.g. `devnet` with `https://api.devnet.solana.com`); the tool does not infer it.

**Cosmos** (uses **`OPENKMS_COSMOS_CHAIN_ID`** and REST for account number /
sequence; builds a **MsgSend to self**):

```bash
./scripts/generate_remote_e2e_request.sh cosmos \
  --label 'cosmos-hub-0' \
  --rest-url 'https://YOUR_LCD' \
  --scalar-b64 "$OPENKMS_COSMOS_SIGNER_SCALAR_B64" \
  --hrp cosmos \
  --fee-denom uatom \
  --fee-amount 4000 \
  --gas-limit 200000 \
  --transfer-amount 1 \
  --chain-id provider
```

Required env names (if you omit flags): `OPENKMS_REMOTE_E2E_COSMOS_LABEL`,
`OPENKMS_COSMOS_REST_URL`, `OPENKMS_COSMOS_SIGNER_SCALAR_B64`, `OPENKMS_COSMOS_HRP`,
`OPENKMS_COSMOS_FEE_DENOM`, `OPENKMS_COSMOS_FEE_AMOUNT`, `OPENKMS_COSMOS_GAS_LIMIT`,
`OPENKMS_COSMOS_TRANSFER_AMOUNT`, `OPENKMS_COSMOS_CHAIN_ID`.

**Both** (env-only; prints **two base64 lines on stdout** (Solana, then Cosmos). The
binary writes a short **stderr** line before each (`OPENKMS_REMOTE_E2E_SOLANA_REQUEST_B64` /
`OPENKMS_REMOTE_E2E_COSMOS_REQUEST_B64`) so you can tell them apart when the terminal wraps.
`--write-json` is not supported—run `solana` and `cosmos` separately if you need files):

You only need **`generate_broadcast_key_material.sh`** when creating a **new**
`./.tmp/broadcast-keys` tree. If that directory already exists (e.g. funded
broadcast wallets) and you must **not** run `-f/--force`, skip keygen entirely:
put **`OPENKMS_REMOTE_E2E_SOLANA_LABEL`** / **`OPENKMS_REMOTE_E2E_COSMOS_LABEL`**
in **`.secrets`** (or `.vars`), then point the helper at the existing env file:

```bash
./scripts/generate_remote_e2e_request.sh -e ./.tmp/broadcast-keys both
```

If **`broadcast-keys.env`** is missing newer tuning lines (`OPENKMS_SOLANA_RPC_URL`,
`OPENKMS_SOLANA_CHAIN_ID`, …), regenerate the file from existing keys (no Docker,
wallets unchanged):

```bash
./scripts/generate_broadcast_key_material.sh --refresh-env ./.tmp/broadcast-keys
```

Then run `./scripts/generate_remote_e2e_request.sh -e ./.tmp/broadcast-keys both` again.

Or set everything by hand (same variable names as broadcast tests):

```bash
export OPENKMS_REMOTE_E2E_SOLANA_LABEL=… OPENKMS_SOLANA_SIGNER_SEED_B64=… \
  OPENKMS_SOLANA_RPC_URL=… OPENKMS_SOLANA_CHAIN_ID=… OPENKMS_SOLANA_TRANSFER_LAMPORTS=5000 \
  OPENKMS_REMOTE_E2E_COSMOS_LABEL=… OPENKMS_COSMOS_REST_URL=… OPENKMS_COSMOS_SIGNER_SCALAR_B64=… \
  OPENKMS_COSMOS_HRP=cosmos OPENKMS_COSMOS_FEE_DENOM=uatom OPENKMS_COSMOS_FEE_AMOUNT=4000 \
  OPENKMS_COSMOS_GAS_LIMIT=200000 OPENKMS_COSMOS_TRANSFER_AMOUNT=1 OPENKMS_COSMOS_CHAIN_ID=…
./scripts/generate_remote_e2e_request.sh both
```

Useful flags: `--show-json` (pretty JSON to stderr), `--write-json path` (single
subcommands only).

Use a payload that signs for a staging-only key and a devnet/testnet account.
The service never broadcasts, so the caller that constructs this request should
also own the separate "submit to chain" step if you want a fuller system test.

## Local dry run

**Recommended (matches `remote-e2e.yml`):** use **`run_remote_e2e_job.sh`** so you
decode the same secret shape and hit the same paths as CI:

```bash
export OPENKMS_BASE_URL="https://your-signer.example.com"
export OPENKMS_SIGNER_TOKEN="..."
export OPENKMS_SIGN_REQUEST_B64="…"   # e.g. value of OPENKMS_REMOTE_E2E_SOLANA_REQUEST_B64
export OPENKMS_EXPECT_KEY_LABEL="solana-hot-0"   # optional
chmod +x ./scripts/run_remote_e2e_job.sh ./scripts/remote_e2e_smoke.sh
./scripts/run_remote_e2e_job.sh solana
./scripts/run_remote_e2e_job.sh cosmos   # second shell with cosmos B64 + label
```

**Advanced:** call **`remote_e2e_smoke.sh`** alone when you already have a JSON file
and want full control (e.g. **`OPENKMS_REMOTE_E2E_CHAIN=both`**). Then **set
`OPENKMS_SIGN_PATH`** and **`OPENKMS_SIGN_REQUEST_FILE`** yourself (no defaults).

**Two separate invocations** (direct smoke script):

```bash
export OPENKMS_BASE_URL="https://signer-staging.example.com"
export OPENKMS_SIGNER_TOKEN="..."

OPENKMS_SIGN_PATH="/sign/solana" \
OPENKMS_EXPECT_KEY_LABEL="solana-hot-0" \
OPENKMS_SIGN_REQUEST_FILE="./request-solana.json" \
./scripts/remote_e2e_smoke.sh

OPENKMS_SIGN_PATH="/sign/cosmos" \
OPENKMS_EXPECT_KEY_LABEL="cosmos-hub-0" \
OPENKMS_SIGN_REQUEST_FILE="./request-cosmos.json" \
./scripts/remote_e2e_smoke.sh
```

**Single process, both chains** (`OPENKMS_REMOTE_E2E_CHAIN=both`):

```bash
export OPENKMS_BASE_URL="https://signer-staging.example.com"
export OPENKMS_SIGNER_TOKEN="..."
export OPENKMS_REMOTE_E2E_CHAIN=both
export OPENKMS_SIGN_PATH_SOLANA=/sign/solana
export OPENKMS_SIGN_PATH_COSMOS=/sign/cosmos
export OPENKMS_SIGN_REQUEST_FILE_SOLANA=./request-solana.json
export OPENKMS_SIGN_REQUEST_FILE_COSMOS=./request-cosmos.json
# optional: OPENKMS_EXPECT_SOLANA_KEY_LABEL=… OPENKMS_EXPECT_COSMOS_KEY_LABEL=…
./scripts/remote_e2e_smoke.sh
```

If the staging service is only reachable inside a private network, run the
workflow from a self-hosted runner in that network or invoke the script from an
operator machine with equivalent access.
