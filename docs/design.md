# ZoeyMCP design

Status: **draft for review**. Nothing here is built yet.

ZoeyMCP is a self-hosted proxy that lets AI agents use outside services and MCP servers **without
ever holding a real credential**, and that puts a human approval of the **exact arguments** in front
of every consequential action. It is built for one operator running a few agents, on their own
hardware: a homelab, a VPS or a desktop.

## 1. Why another proxy

The parts exist separately, but not together:

- **Credential proxies** swap a placeholder for a real secret on the way out. The ones we looked at
  don't refresh OAuth tokens (rotating refresh tokens especially), or they have no per-route
  method/path/parameter policy, or both.
- **MCP gateways** federate many MCP servers for many users. They are built around an enterprise
  identity provider, a database and an admin console. They are much larger than one operator
  needs, and approvals, where they exist at all, happen away from the chat where the operator
  already is.
- **MCP itself** has no standard approval primitive. A client's "allow this tool?" prompt usually
  names the tool, not its arguments, so the human approves without seeing what will be sent.

ZoeyMCP combines a small credential vault, a secretless MCP gateway with argument-level approvals,
and an admin portal and CLI for onboarding. It should stay small enough for one person to read.

## 2. Requirements

**Must** = not traded away by any design choice. **Should** = a goal; a design may trade it off and
say so.

### 2.1 Secrets and boundaries

| ID | Requirement | Kind |
| --- | --- | --- |
| R1 | No real secret is ever present in an agent's container, its code sandbox, or the gateway: not in env, files or memory. Agents hold **placeholders** that are worthless outside the deployment | Must |
| R2 | Real secrets live only in the vault: in its **encrypted store** (§4.5), or optionally in its own environment. Config references secrets **by name**, never by value | Must |
| R3 | Each placeholder works only on its own routes. One client's placeholder never works on another's route. Caller identity is **cryptographic or kernel-checked first** (a key, a token, a Unix socket peer uid); source-address pins are defense in depth | Must |
| R4 | Every route is **default deny**: an explicit method and path allowlist, optional forced or stripped query parameters, optional limits on resource IDs in the path | Must |
| R5 | All outbound traffic can go through an egress proxy (HTTP CONNECT): the built-in `zoeymcp egress` role (§4.7), or the operator's own, configured from an exported allowlist | Must |
| R6 | A policy that must hold against the model lives in the vault or gateway, never in the agent or its sandbox (which can be assumed to reach the vault) | Must |

### 2.2 Credentials

| ID | Requirement | Kind |
| --- | --- | --- |
| R10 | Credential kinds: static header (bearer or custom), query-parameter key, secret in a path template, HTTP basic, and **OAuth 2 refresh** for confidential clients and public PKCE clients | Must |
| R11 | OAuth: **rotating refresh tokens persisted** in the store; extra token-request parameters (e.g. `resource`, `audience`); access tokens cached and refreshed shortly before expiry; refreshes go through the egress proxy | Must |
| R12 | New providers are added **by config**, not code: token URL, client ID/secret references, extra parameters, whether it rotates | Should |
| R13 | Rotating a secret needs **no redeploy**. For refresh tokens given as `env:` seeds, the docs explain **seed vs live** and how to force a re-seed | Must |
| R14 | Losing the master key or the state volume means re-entering secrets and re-consenting rotating providers; recovery is documented per credential kind | Should |
| R15 | Non-HTTP secrets (an SMTP password) are held by vault **connectors** with their own fixed policy (e.g. a fixed recipient list) | Should |
| R16 | Secrets at rest are **encrypted** under a key hierarchy derived from one required master key (§4.5). Each secret is **bound to its use**: the origins it may be sent to, and for connectors their fixed constraints (host, sender, recipients). Changing a binding needs the secret to be entered again | Must |

### 2.3 Onboarding

| ID | Requirement | Kind |
| --- | --- | --- |
| R20 | OAuth consent can run **in the admin portal** (the primary flow) or from the **CLI** (headless). Either way, the granted scopes are shown, scopes beyond the expected ones are flagged, and tokens go **straight into the store**: nothing is written to the operator's disk or printed | Must |
| R21 | **One generic onboarding for MCP servers:** protected-resource metadata (RFC 9728) → authorization-server metadata (RFC 8414) → dynamic client registration where offered (RFC 7591) → PKCE (RFC 8252) | Should |
| R22 | Onboarding fetches the server's tool list for **review**: the operator picks the tools, classifies each as `allow` or `approve`, and the definitions are pinned (R33) | Should |
| R23 | OAuth works when the portal is used from **another machine**: if the loopback redirect can't reach the vault, the operator pastes the redirected URL into the portal, and the vault completes the exchange | Should |

### 2.4 Gateway and tools

| ID | Requirement | Kind |
| --- | --- | --- |
| R30 | Agents reach upstream MCP servers only through the gateway, and the gateway reaches them only through the vault. Vault routes for upstream MCP servers accept only the **gateway's identity**, so the tool filter can't be bypassed | Must |
| R31 | Each server has an explicit **tool allowlist**. Resources, prompts, sampling and server-initiated elicitation are **off** unless enabled per server | Must |
| R32 | **Per-client scoping:** each client (agent) sees only the servers and tools assigned to it | Must |
| R33 | **Tool pinning:** the gateway records a hash of each reviewed tool definition (name, description, input schema, annotations). A new or changed tool is hidden and reported until re-reviewed; this blocks "rug pull" changes and description poisoning | Must |
| R34 | **Native toolkits:** the operator's own Python tools run in the gateway, with no secrets, calling the vault with placeholders. They are installed in a **gateway-only image**; the vault always runs the official image, unmodified (§3.1) | Must |
| R35 | **stdio-only MCP servers** run in their own container behind a stdio-to-HTTP bridge. No third-party server code runs in an agent's container or in the vault. A bridge reaches the outside through vault routes, or, if the server can't be pointed at the vault, through the egress proxy with its own allowlist. A bridge that must hold a **real secret itself** is a flagged exception to R2: `check` warns, the docs state the cost, and its allowlist is narrowed to that provider | Must |
| R36 | Server-side streaming (SSE / streamable HTTP) passes through without buffering | Must |
| R37 | Batch-shaped tools are easy to write, for clients whose code sandboxes can't call MCP tools in a loop | Should |
| R38 | Tool descriptions stay short, and the docs note that clients should load tools lazily where they can | Should |
| R39 | The gateway depends only on the **MCP spec**, not on any one client's internals | Must |

### 2.5 Approvals and content

| ID | Requirement | Kind |
| --- | --- | --- |
| R40 | A tool marked **consequential** runs only after the operator approves the **exact arguments**, rendered by gateway code, not by text the model wrote | Must |
| R41 | Approvals **fail closed**: no reply channel, timeout, error, or a client without elicitation support all mean declined. An approval covers **one call**, and nothing persists | Must |
| R42 | The rendered approval **can't hide content**: plain text only, Unicode format characters (category Cf: zero-width, bidi overrides, tags) and control characters rejected, and the whole text under a configurable budget (default 3,000 characters). If it doesn't fit, the call is refused rather than truncated | Must |
| R43 | The arguments executed are **byte-identical** to the arguments shown | Must |
| R44 | One pending approval per tool per client: a second call while one waits is refused, so prompts can't be merged or confused | Must |
| R45 | Approver back ends: **MCP elicitation** (the default, synchronous; the prompt appears in the operator's own client) and **out-of-band approvers** hosted in the vault (Telegram, and an approval queue in the portal), for clients that shouldn't be trusted to relay approvals or for approvals that must wait | Should |
| R46 | A **ledger** of consequential calls: time, client, tool, hash of the arguments, decision, result | Should |
| R48 | **Vault-enforced approvals:** for routes marked `vault_approval`, the **vault** holds the request, renders the approval from the request itself, and forwards it only on approval, so even a fully compromised gateway can't skip it. Each approval happens in exactly one place: those routes skip the gateway's elicitation | Should |
| R47 | Content from upstream is **data, not instructions**. The gateway can wrap results from a server in untrusted-content markers. Toolkits that need sender identity (e.g. mail) verify it in code and label failures | Should |

### 2.6 Admin portal

| ID | Requirement | Kind |
| --- | --- | --- |
| R60 | The vault serves an **admin portal** on its admin listener: write-only secret entry, OAuth and MCP onboarding, credential health, the approval ledger, tool-drift review and re-pinning, and (in managed mode) policy editing | Must |
| R61 | **No endpoint returns a secret**, to the portal, the CLI or anyone else. The portal shows metadata only | Must |
| R62 | **Passkey login** (WebAuthn, user verification required). **Step-up** (a fresh passkey assertion) for every security-relevant save: writing a secret, changing policy, re-pinning a tool, moving a tool from `approve` to `allow`, changing a connector's constraints | Must |
| R63 | **Browser hardening:** strict `Host` and `Origin` allowlists (stopping DNS rebinding), `Sec-Fetch-Site: same-origin` on state-changing requests, `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'`, `SameSite=Strict` session cookies, no third-party assets. The OAuth callback is the only exception (§7.3) | Must |
| R64 | **One source of truth for policy**, chosen per deployment: **managed** (the portal is the source; export/import YAML) or **declarative** (a config file or env var is the source; the portal can't edit policy and produces diffs to commit instead). Never both | Must |
| R65 | **Bootstrap:** a random **one-time setup code**, fetched with `docker exec`, never logged, valid for 15 minutes and invalidated when the first passkey is enrolled. Recovery from lost passkeys follows the same path, so it needs host access | Must |
| R66 | Managed policy is **versioned**: every save is a new version with its diff, authenticated with a config key (§4.5) and a monotonic counter, so a replayed older version is refused. One-click rollback creates a new version | Must |

### 2.7 Deployment and verification

| ID | Requirement | Kind |
| --- | --- | --- |
| R50 | Containers run unprivileged: read-only root filesystem, `no-new-privileges`, minimal capabilities (none, except where the single-container tier needs `SETUID`/`SETGID` to drop privileges, §3.3), non-root uids, tmpfs for scratch | Must |
| R51 | **No bind mounts needed.** Declarative config can come from a file, an env var holding YAML, or stdin; managed policy lives in the vault's state volume | Must |
| R52 | Exact pinned dependencies with hashes (`--require-hashes`). Images are reproducible from the repo, published with digests, and labelled with a source content hash. No runtime package installs | Must |
| R53 | `zoeymcp check` validates config statically: every secret reference resolvable, every placeholder unique, every consequential route bound to the gateway's identity, no route without a method/path allowlist, every included tool classified | Must |
| R54 | **Route self-test:** run the vault with the real config but every upstream swapped for a built-in echo server, so a deployment can test its policy before deploying; designed to be mutation-tested | Must |
| R55 | Security behavior has **effect tests** (a refused call really is refused), not only config checks | Must |
| R56 | Access logs are JSON lines on stdout, with credentials, placeholders and setup codes never logged | Must |
| R57 | Single operator, a few agents. Multi-tenant features and SSO are **non-goals** | Must |
| R58 | Two shipped **deployment tiers** (§3.3): a **standard** single container (two uids, Unix socket) and a **hardened** compose (separate containers, no gateway egress). The docs state plainly what the standard tier gives up | Must |
| R59 | Acceptance is defined by **service shapes** (§8.1): fakes of each shape in CI; the product is done when every shape passes end to end, refusals included | Must |

## 3. Architecture

```text
 operator's browser / CLI                       deployment
 ────────────────────────                       ──────────────────────────────────────────────────────

 admin portal (passkey) ─────────────────────────────────────────────────┐
 docker exec … zoeymcp <admin cmd>  ───────────────────────────────────┐ │
                                                                       ▼ ▼
                                    ┌─────────────┐ MCP          ┌──────────────────────┐
                                    │   agent     │─────────────▶│  zoeymcp gateway     │
                                    │ (any MCP    │◀─elicitation─│  NO secrets          │
                                    │  client)    │              │  allowlist, pins,    │
                                    └──────┬──────┘              │  approvals, toolkits │
                                           │ code sandbox        └──────────┬───────────┘
                                           │ (may reach the vault;          │ gateway identity
                                           │  gateway routes refuse it)     ▼
                                           │                     ┌──────────────────────┐
                                           └────────────────────▶│  zoeymcp vault       │
                                                                 │  encrypted store     │
                                                                 │  route policy        │
                                                                 │  OAuth, connectors   │
                                                                 │  admin portal        │
                                                                 └──────────┬───────────┘
                                                                            │ egress (proxy)
                                                                            ▼
                                            providers, remote MCP servers, zoeymcp bridge
                                            (stdio MCP server in its own container)
```

| Role | Command | Holds secrets | State | Image |
| --- | --- | --- | --- | --- |
| **vault** | `zoeymcp vault` | yes (store + master key) | store, policy versions, portal accounts | official, unmodified |
| **gateway** | `zoeymcp gateway` | no | ledger | official, or a derived gateway-only image with toolkits |
| **bridge** | `zoeymcp bridge -- <cmd> …` | no (placeholders) | none | derived per stdio server |
| **egress** (optional) | `zoeymcp egress` | no; it only tunnels TLS and never sees plaintext | none | official |
| **CLI** | `zoeymcp keygen / setup-code / secret / login / review / check / selftest` | only while running, never written | none | official, or installed with `pip` |

### 3.1 Why the vault is separate from the gateway

The gateway parses MCP traffic from agents and from third-party servers, and it runs the
operator's own toolkit code and its dependencies. That makes it the likeliest place for code
execution to land, whether through a parser bug (`pydantic-core` is Rust, and some HTTP parsers
are C) or, more likely, through the supply chain. The vault never parses MCP and never loads
toolkits: it is an HTTP policy proxy with credential injection.

Encryption at rest protects the disk, not the running process: whichever process holds the master
key can decrypt everything. So the question is which code runs next to the key:

| | Key in the gateway | Key in a separate vault (this design) |
| --- | --- | --- |
| Attacker gets | the master key and the store: every credential, usable from anywhere | the gateway's identity, and a path to the vault only |
| Can misuse | everything | only the routes bound to the gateway, inside their policy (fixed recipients, path allowlists, rate limits) |
| After the fix | rotate every secret at every provider; re-consent every OAuth grant | rotate the gateway identity (§4.5) and restart; no provider secret leaked |

Secrets never cross the gateway–vault link: the vault injects them into the outbound request
itself, and there is **no API that returns a secret**. A compromised gateway can still call its
routes, so it could skip the approvals the gateway runs. Routes marked `vault_approval` close that
gap: the vault itself holds the request until the operator approves it (§6.4).

**The image matters as much as the process.** Python runs every `.pth` file in `site-packages` at
interpreter start, before any ZoeyMCP code. If the vault ran an image with toolkit dependencies
installed, those dependencies would run next to the master key. So the vault **always** runs the
official image, unmodified, and `check` warns when the vault's image digest isn't an official
release. Toolkits go into a derived image used **only** by the gateway.

### 3.2 Identity

- **Gateway → vault:**
  - In the standard tier, a **Unix socket** whose peer uid the vault checks (`SO_PEERCRED`).
  - In the hardened tier, a **gateway key** derived from the master key (§4.5) and given to the
    gateway's environment. `zoeymcp keygen` prints both.
  - Routes marked `caller: gateway` accept nothing else.
- **Agents → gateway:** a **client token** per agent. Optional source-address pins add defense in
  depth.
- **Sandbox scripts → vault** (the opt-in `direct` routes): a **placeholder** per route and client.
  Optional source-address pins add defense in depth.
- **Why addresses aren't enough:** Docker's default capabilities include `NET_RAW`, and bridge
  networks don't stop spoofing, so an address is a hint, not an identity. All shipped containers
  drop `NET_RAW`.
- **The approval channel is only as trustworthy as the client that renders it.** With elicitation,
  a compromised agent runtime could auto-accept. For that threat, use the out-of-band approver
  (§6.3), which trusts no agent code.

### 3.3 Deployment tiers

| | **Standard** (single container) | **Hardened** (compose) |
| --- | --- | --- |
| Shape | one container; a small entrypoint starts as root with only `SETUID`/`SETGID`, starts the vault as uid 10001 and the gateway as uid 10002, then drops both capabilities | separate vault, gateway and bridge containers on dedicated networks |
| Secrets | the master key only in the vault process's env (removed before the gateway starts); `/state/vault` is `0700`, owned by the vault uid. The gateway can't read the vault's state or its `/proc/<pid>/environ` | the master key only in the vault container |
| Gateway → vault | Unix socket, peer uid checked | gateway key over the `internal` network |
| Gateway egress | **yes**: it shares the vault's network namespace, so a compromised gateway can send tool results anywhere | **none**: the gateway's only network peers are agents and the vault |
| Admin listener | in the gateway's network namespace; protected by passkey auth, not by reachability | on the vault's `egress` address only; the gateway can't reach it |
| Publishing ports | works | the gateway is on internal networks only; LAN access uses the `lan` profile (§3.4) |
| Use for | evaluation, desktop clients, low-stakes setups | **anything that moves money, sends mail or touches personal data** |

The README quickstart uses the standard tier, and says on the same page when to move to the
hardened one.

### 3.4 Hardened topology

| Network | Docker `internal` | Members | Allows |
| --- | --- | --- | --- |
| `agents` | yes | agents, gateway | agents → gateway |
| `internal` | yes | gateway, vault, bridges | gateway → vault (gateway key); gateway → bridges; bridges → vault (their placeholders) |
| `egress` | no | vault only | vault → internet or an egress proxy; the admin listener |
| `direct` (opt-in) | yes | agent sandboxes, vault | plain API routes for scripts |

```yaml
x-hardened: &hardened
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  tmpfs: [/tmp]

networks:
  agents:   {internal: true}
  internal: {internal: true}
  egress:   {}

services:
  vault:
    <<: *hardened
    image: ghcr.io/ryanleeupc/zoeymcp@sha256:…          # official, unmodified
    command: [vault]
    user: "10001:10001"
    environment:
      ZOEYMCP_MASTER_KEY: ${ZOEYMCP_MASTER_KEY:?run zoeymcp keygen}
      ZOEYMCP_MODE: managed                              # or declarative + ZOEYMCP_CONFIG
    networks: [internal, egress]
    ports: ["127.0.0.1:8081:8081"]                       # admin portal, host loopback only
    volumes: [vault-state:/state]

  gateway:
    <<: *hardened
    image: ghcr.io/ryanleeupc/zoeymcp@sha256:…          # or your derived toolkit image
    command: [gateway, --vault, http://vault:8080]
    user: "10002:10002"
    environment:
      ZOEYMCP_GATEWAY_KEY: ${ZOEYMCP_GATEWAY_KEY:?run zoeymcp keygen}
    networks: [agents, internal]
    volumes: [gateway-state:/state]

volumes: {vault-state: {}, gateway-state: {}}
```

- **`agents` must be internal too.** A non-internal network would give the gateway internet egress
  through the back door. Docker doesn't publish ports from internal-only networks, so LAN access
  goes through the `lan` profile (below).
- **Subnets are left to Docker** unless the operator pins addresses for defense in depth;
  identity doesn't depend on them (§3.2).
- **Bridges** reach the outside through vault routes where the server takes a base-URL override.
  Otherwise, they go through the egress proxy (below), each bridge on **its own network** shared
  only with the proxy, so the proxy's per-source allowlist can't be fooled by a spoofed address.
- **The gateway gets its config from the vault** (§4.6), so there is one config, not two.

Optional compose profiles:

| Profile | Adds | Notes |
| --- | --- | --- |
| `lan` | an inbound proxy (pinned Caddy) on a published port and on `agents`, forwarding only to the gateway, **with TLS** | so desktop clients on the LAN can connect without client tokens crossing the LAN in cleartext. The proxy has egress but holds no secrets; client tokens, not addresses, identify clients |
| `egress-proxy` | the built-in `zoeymcp egress` role (§4.7): a CONNECT-only allowlist proxy for bridges that can't use vault routes, and optionally for the vault | per-source allowlists come straight from the policy. Operators who run their own proxy use `check --emit-egress-allowlist` instead |

## 4. The vault

An async HTTP reverse proxy (Starlette, uvicorn and httpx: the stack the MCP SDK already pins, but
the vault process never imports the MCP SDK or any toolkit).

### 4.1 Request handling

For each request, in order:

1. Match a **route** by path prefix. No match → 404.
2. **Identify the caller:** the gateway (socket peer uid or gateway key), or a placeholder from
   where the route expects it (bearer header by default, or a named header or query parameter).
   It must be an identity the route accepts, and match its source-address pins if it has any.
   Otherwise → 403. Every identity failure gets the same 403, so a caller learns nothing about
   which check failed. The placeholder is removed before forwarding.
3. Check **method + path** against the route's rules (§4.2). No rule → 403.
4. Apply **query policy**: forced parameters overwrite whatever was sent; stripped ones are
   removed; unknown ones are kept unless `query.allow` is set.
5. Apply **header policy**: hop-by-hop headers, and `Authorization`/`Cookie` from the caller, are
   dropped unless the route allows them; a configurable `Host`.
6. **Inject the credential** (§4.3). The store refuses to decrypt a secret whose **binding**
   doesn't cover this request's origin (§4.5).
7. Forward through the egress proxy. Streamed bodies (SSE) pass through unbuffered; a size limit
   applies to request bodies.
8. **Scrub the response.** Upstreams sometimes echo credentials in error bodies, especially
   query-parameter and path secrets that appear in echoed URLs.
   - Response headers are always scrubbed. Non-streamed text and JSON bodies under 1 MB are
     scrubbed by default (configurable).
   - Matching covers the secret as raw bytes, **percent-encoded**, **JSON-escaped**, and for basic
     auth **base64** of `user:secret`. Each match is replaced with `[REDACTED]`.
   - The vault asks upstreams for `Accept-Encoding: identity`, or decompresses before scanning,
     and recomputes `Content-Length`.
   - Streamed and larger bodies aren't scrubbed. The docs say so.
9. Log one JSON line: route, method, path template (not the raw path), status, bytes, duration,
   caller identity name. No placeholders, no secrets, no query values.

### 4.2 Path rules

Paths are matched segment by segment:

- `*` matches one segment; `**` (last position only) matches the rest.
- `{name}` captures one segment, constrained by the rule's `params`, as an exact list or a regex
  anchored to the whole segment.
- Paths are normalized **before** matching. Percent-decoding happens once; then encoded slashes,
  `..`, empty segments, backslashes and non-ASCII in the path are refused. The upstream gets the
  normalized form.

```yaml
rules:
  - methods: [GET]
    paths: [/api/docs/{doc}/tables/**]
    params: {doc: [d7Q2xk]}
  - methods: [PATCH, POST]
    paths: [/api/docs/{doc}/tables/{table}/records]
    params: {doc: [d7Q2xk], table: {regex: "[A-Za-z0-9_]{1,64}"}}
```

### 4.3 Credential kinds

| Kind | Injects | Notes |
| --- | --- | --- |
| `header` | `Authorization: Bearer <secret>`, or any header and format | static |
| `query` | `?<param>=<secret>` | the caller can't supply that parameter (it's stripped first) |
| `path` | the secret into a path template, e.g. `/bot{secret}/…` | for APIs that put the key in the URL |
| `basic` | HTTP basic from a username and a secret | |
| `oauth2` | `Authorization: Bearer <access token>` | see below |

**OAuth 2** (`oauth2`):

- **Grants:** `refresh_token` (the normal case), with a confidential client (ID and secret) or a
  public one (ID only, consented with PKCE). `client_credentials` too, for service accounts.
- **Extra token parameters** come from config (`resource`, `audience`, `scope`).
- **Caching:** access tokens are cached in memory and refreshed `refresh_skew` seconds (default
  120) before expiry. A 401 from the upstream triggers one refresh and one retry, for idempotent
  methods only. Concurrent requests share one in-flight refresh.
- **Rotation:** with `rotates: true`, each new refresh token is written to the store before the
  access token is used.
  - A refresh token kept in the store is simply replaced in place, and onboarding (portal or CLI)
    writes a fresh one there directly.
  - A refresh token given as `env:` is only a **seed**. It is used when the store holds none, or
    when its fingerprint differs from the one the store was seeded from **and**
    `reseed: on-change` is set. The default is `reseed: never`, so a stale env can't overwrite a
    live token. Every refresh logs the seed-vs-live decision.
- **Failure:** a refresh error (e.g. `invalid_grant`) makes the route answer 502 with a stable
  error code. The portal shows "re-consent needed" for that credential. It is never retried in a
  tight loop.

### 4.4 Connectors

For secrets that aren't an HTTP header swap. v1 ships one:

- **`smtp`:** `POST` a JSON `{subject, body, in_reply_to?}`. The vault builds the message with a
  **fixed From and a fixed recipient list from config**, so the request can't name recipients, add
  headers or attach files. Unknown JSON keys → 400.
  - It sends over implicit TLS or STARTTLS, through the egress proxy via CONNECT.
  - It enforces daily send limits and the same text rules as approvals (no Cf/control characters,
    length limits).
  - It returns the Message-ID. A failed send is never retried.
  - The SMTP password is **bound** to the host, port, From and recipient list (§4.5). A changed
    recipient list needs the password to be entered again.

Connectors are routes like any other, and send connectors accept only `caller: gateway`.

### 4.5 Keys, the store, and bindings

**Master key:** `ZOEYMCP_MASTER_KEY` is **required**; the vault refuses to start without it. It
holds 32 random bytes, base64url-encoded, made by `zoeymcp keygen`. Every other key is derived from
it with HKDF-SHA256, with a separate context for each purpose:

| Key | HKDF context | Use |
| --- | --- | --- |
| `K_store` | `zoeymcp/store/v1` | AES-256-GCM encryption of store entries |
| `K_config` | `zoeymcp/config/v1` | HMAC over managed policy versions and their counter (§4.6) |
| `K_gateway` | `zoeymcp/gateway/v1/gen-<N>` | the gateway key in the hardened tier. Rotated by bumping `gateway_key_generation` |

**Gateway key rotation:**
- After `gateway_key_generation` is bumped to N, the vault still accepts generation N-1, but only
  **until the first request authenticated with generation N arrives, and for at most 5 minutes**.
  The old generation is then retired.
- The retirement is persisted in the vault's state and authenticated with `K_config`, so a vault
  restart doesn't bring back N-1.
- `--immediate` (portal option or CLI flag) retires N-1 at once, for a suspected leak.
- While N-1 is still accepted, the portal shows `rotation pending: gateway still on gen N-1`.

There is no derived admin credential: admin access starts from a one-time setup code (§7.2), so
it can be revoked without touching the master key.

**Store entries:**

- One file on the vault's state volume, written atomically (temp file + rename).
- Each entry is encrypted with `K_store` and a random nonce. Its authenticated data binds:
  - the format version and key ID;
  - the secret's **name**, so ciphertexts can't be swapped between entries;
  - its **binding**: the origins it may be sent to (for OAuth, the token endpoint plus the
    resource origins) and, for connectors, their fixed constraints (host, port, sender,
    recipients). The binding is set when the secret is written.
- At use, the vault checks the request against the binding. A route whose upstream has changed,
  or a connector whose constraints have changed, **can't use the secret** until the secret is
  entered again for the new binding. This holds even when the policy was edited by someone holding
  a stolen admin session.
- **Metadata in the clear:** name, binding, created/updated time, key ID, and for OAuth, expiry and
  the last refresh result. Health can be shown without decrypting anything.

**What bindings don't cover:** widening path or method rules on the **same** origin, adding
callers, or moving a tool from `approve` to `allow`. Those are policy changes, guarded by passkey
step-up (R62) and versioning (R66).

**Secret sources** in config: `store:<name>` (the default, encrypted and bound) or `env:<VAR>`
(allowed for simple setups and seeds; not bound). `check` warns on `env:` for a long-lived secret.

**Key rotation:**

1. Set `ZOEYMCP_MASTER_KEY_PREVIOUS` to the old key and `ZOEYMCP_MASTER_KEY` to the new one.
2. On start, the vault re-encrypts every entry and re-authenticates the policy versions. The
   gateway key changes too, so update it at the same time; the old one follows the same
   ratchet-or-5-minutes rule as a generation bump.
3. Remove the old key afterwards.

**Losing the key or the volume:** every secret must be entered again, and every rotating OAuth
credential re-consented (R14).

### 4.6 Policy: managed and declarative modes

Policy covers routes, credentials (minus their values), connectors, clients, servers, tool
selections and pins, and approval settings. It is **one document**, owned by the vault. The
gateway fetches its part over its authenticated link at start and whenever policy changes. That
part contains no secrets, and the gateway can't write policy.

| | **Managed** (default) | **Declarative** |
| --- | --- | --- |
| Source of truth | versions in `/state/policy/`, edited in the portal | `ZOEYMCP_CONFIG` (YAML in env), `--config <file>`, or stdin, read at start and on `SIGHUP` |
| Portal policy editing | yes, with step-up | **no**: the portal shows the policy, and for onboarding and tool drift it produces a **YAML diff to commit** |
| History | every save a version, with its diff; rollback creates a new version | the operator's git |
| Export / import | YAML export and import | n/a |
| Seed | `ZOEYMCP_CONFIG`, if set, seeds version 1 on first start only | n/a |

- **Integrity:** each managed version, and the counter, are authenticated with `K_config`. The
  vault refuses a version older than the highest it has seen, which catches a replayed file.
  This doesn't help if the whole volume is restored from a backup, or if the vault's own uid is
  compromised. It is a cheap integrity check, not a boundary.
- **Validation:** every save (managed) or load (declarative) runs `check` first. A policy that
  fails is rejected, and the running one stays.

### 4.7 The egress role

`zoeymcp egress` is an optional, built-in, CONNECT-only allowlist proxy (stdlib asyncio), deployed
by the `egress-proxy` compose profile. It holds no secrets: it only tunnels TLS, and the vault and
bridges verify certificates end to end.

**What it protects, honestly:**
- **Bridges** are the main reason it exists. They run third-party code, and the proxy limits each
  bridge to its own declared hosts.
- **For the vault**, the allowlist comes from the same policy the vault already enforces. So
  routing the vault through it adds the private-address guard below, but no protection against a
  bad policy edit; secret bindings (§4.5) cover that. Using it for the vault is optional.

**Sources and allowlists:**
- **One listener per source,** each on its own Docker network shared only with that source. The
  listener a connection arrives on identifies the source, and nothing on that network can
  impersonate another source.
- **A bridge's allowlist** is the `egress:` list on its server entry (`host:port` pairs).
- **The vault's allowlist** is every route upstream, OAuth token endpoint and connector
  `host:port` in the policy.
- **Policy:** the role reads its part from the vault, as the gateway does, using an egress token
  that only grants reading the allowlists. On a policy change, new tunnels use the new
  allowlist, and open tunnels to destinations that were removed are closed.

**Per connection:**
1. Read the request line and headers, bounded to 8 KB and 10 seconds. Anything but `CONNECT` →
   405. Plain-HTTP forwarding doesn't exist.
2. `host:port` must match the listener's allowlist exactly. Hostnames are compared lowercase after
   IDNA normalization; an IP literal matches only if it is listed literally.
3. Resolve the name, then refuse loopback, private (RFC 1918), CGNAT (`100.64.0.0/10`),
   link-local (including `169.254.169.254`), multicast and reserved addresses, and IPv4-mapped
   IPv6 forms of these. A destination can opt out with `allow_private: true` (for a self-hosted
   service on the LAN).
4. Connect to **the address that was checked**: no second lookup, so a hostname can't be made to
   resolve elsewhere between the check and the connection (DNS rebinding).
5. Answer `200`, then copy bytes both ways, with an idle timeout and a maximum tunnel duration.

**Limits:** concurrent tunnels per listener, and a bound on the time to establish a tunnel. It
doesn't cache, authenticate users, inspect TLS, or forward anything but CONNECT tunnels.

**Logs:** one JSON line per tunnel: source, host, port, resolved address, result, bytes each way,
duration.

**Bring your own proxy:** `zoeymcp check --emit-egress-allowlist` prints the same per-source
allowlists, as plain `host:port` lists and as a Squid snippet, for operators who already run an
egress proxy. They set `egress_proxy` to their own and skip the role.

## 5. The gateway

An MCP server (streamable HTTP, official `mcp` SDK) that fronts **servers** of three kinds:

| Kind | What it is |
| --- | --- |
| `remote` | an upstream MCP server, reached **through a vault route** that injects its credential |
| `bridge` | a stdio MCP server running in a `zoeymcp bridge` container (the same as `remote` on the wire) |
| `toolkit` | Python tools installed in the gateway's image (§5.3) |

**Endpoints:** one MCP endpoint per server, `/s/<server>/mcp`. The client configures one entry per
server, which keeps tool names unprefixed and lets the client apply its own per-server trust
settings. Each endpoint checks the client's token, its optional source pin, and whether that
client is assigned the server.

**Upstream sessions:** one upstream MCP session per (client, server) by default, so two agents
never share state on a stateful server (a browser, a database transaction). `shared_session: true`
on a server opts into one shared session. It is meant for stateless servers, and for bridges
whose subprocess is slow to start. The docs warn that sharing a session with a stateful server
leaks state between agents.

### 5.1 Filtering and pinning

On connecting to a `remote`/`bridge` server, the gateway lists its tools and compares each with the
server's **review pins** (a sha256 of the canonical JSON of name, description, input schema and
annotations):

- A tool that's in `tools.include` and matches its pin is exposed. Its description and schema are
  passed through **as reviewed**.
- A tool that's in `include` but whose definition changed is **hidden** and reported as
  `tool-drift`. The portal shows a badge and a side-by-side diff of the old and new definitions.
  - Re-pinning takes a step-up in managed mode.
  - In declarative mode, it produces a YAML diff to commit.
- A tool not in `include` is hidden and reported once, as `tool-unreviewed`.
- **Strict mode** (`on_drift: fail`) refuses the whole server until it's re-reviewed.
- `tools/list_changed` notifications re-run the comparison.
- `resources`, `prompts`, `sampling`, `elicitation` and `roots` stay off unless enabled per server.
  An upstream server's own elicitation requests are refused by default, because their text is
  written by a third party.

### 5.2 Approvals

Each included tool has a policy: `allow` (no prompt) or `approve`.

- There is **no implicit default**: `check` fails on an included tool that is in neither list.
- Upstream annotations (`readOnlyHint`, `destructiveHint`) are hints only, because the upstream
  controls them. During review, the portal **pre-fills** the `allow`/`approve` choice from
  `readOnlyHint`, labelled "suggested by the server", and nothing is saved until the operator
  confirms. At runtime, annotations are never consulted.
- Keep `allow` for calls that really are routine: a prompt on every call teaches the operator to
  approve without reading.

For an `approve` call:

1. **Validate** the arguments against the reviewed input schema, using `jsonschema` (pinned, in
   the gateway only), and reject `additionalProperties` where the schema forbids them.
   - Upstream schemas are untrusted input, so validation runs within size and depth limits, and
     remote `$ref`s are never fetched.
   - A `pattern` in a schema can hang validation if the regex is badly written, so patterns are
     highlighted during review.
   - This runs for `allow` tools too, not only `approve` ones.
2. **Canonicalize** them: parse, then re-serialize as the exact JSON object that will be forwarded.
3. **Render** the approval text: `<server> → <tool>`, then the arguments as indented JSON. JSON
   escaping makes the rendering unambiguous: a newline inside a value appears as `\n` and can't fake
   another field. Toolkit tools may supply their own renderer (e.g. a mail body shown as
   paragraphs), as long as it follows the same rules.
4. **Check the text:** no Cf or control characters (other than the renderer's own newlines), and
   under `budget_chars`. Otherwise the call is refused **before** anyone is asked.
5. **Lock** the tool for this client. If it's already waiting, the call is refused as busy.
6. **Ask** the configured approver. Anything but an explicit accept within `timeout` means
   declined.
7. On accept, forward **the canonical object from step 2**: it's the same object that was rendered,
   so it can't differ from the text shown.
8. **Ledger:** time, client, server, tool, sha256 of the canonical arguments, decision, upstream
   result status.
9. **Return** the result, or a plain error: `declined by operator`, `no answer in time`,
   `refused: <reason>`.

### 5.3 Toolkits

A toolkit is a Python module installed into a **derived gateway image** (`FROM` the official one,
dependencies pinned with hashes). It is never loaded from a writable path, and never installed in
the vault's image.

```python
from zoeymcp.toolkit import Toolkit, approve, text

tk = Toolkit("mail")

@tk.tool(consequential=True)
async def send_note(ctx, subject: text(max=150, single_line=True),
                    body: text(max=2700)) -> str:
    """Send a note to the configured recipient."""
    cfg = await ctx.vault.get_json("/mail/config")
    await approve(ctx, f"Send to {cfg['to']}?\nSubject: {subject}\n\n{body}")
    sent = await ctx.vault.post_json("/mail/send", {"subject": subject, "body": body})
    return f"sent ({sent['message_id']})"
```

- **`ctx.vault`** is an HTTP client already authenticated as the gateway. In the hardened tier it
  is the only way out: the gateway has no other egress.
- **`text(...)`** validators enforce the plain-text rules (no Cf/control characters, length,
  single-line).
- **`approve(ctx, message)`** runs steps 4–8 of §5.2 with the toolkit's own message. The toolkit is
  responsible for sending exactly what it showed. Tests drive that property for each shipped
  toolkit (§8).
- **Plain HTTP endpoints:** toolkits can expose `GET` endpoints (e.g. a status feed for a scheduled
  monitor that compares output hashes), restricted to configured clients.

v1 ships example toolkits only. Real ones live in the operator's own repo and image.

### 5.4 Untrusted content

Per server, `wrap_results: true` wraps text results in a delimiter pair with a one-line notice that
the content is data from `<server>`. This doesn't make content safe; it makes the boundary visible
to the model and to log readers. Toolkits that read authenticated content (e.g. mail) should verify
the sender in code and say `VERIFIED`/`UNVERIFIED` explicitly.

## 6. Approver back ends

### 6.1 `elicitation` (default)

The gateway sends an MCP `elicitation/create` with the rendered text and an empty requested schema.
Only `accept` counts. `decline`, `cancel`, a timeout, an error, or a client that didn't advertise
elicitation support all mean declined.

Elicitation is **synchronous**: it is a request/response tied to the client's active tool call,
and if the client times out the call, the prompt is orphaned anyway. Its timeout is therefore
kept within what clients allow for a tool call (typically 60–300 s). Approvals that must wait
longer use an out-of-band approver (§6.3), which supports `pending` + `check_approval`.

### 6.2 What it trusts

The client: that it shows the text whole, doesn't auto-accept, and doesn't let an "always allow"
answer persist. Different clients behave differently; the docs keep a per-client notes page for
clients that have been checked.

### 6.3 Out-of-band approvers (hosted in the vault)

Out-of-band approvers run **in the vault**, which already holds the bot token and hosts the
passkey-protected portal. That makes them independent of both the agent runtime and the gateway.

- **`telegram`:** a **dedicated bot** sends the operator a DM in plain text, with Approve / Deny
  buttons.
  - The vault long-polls the Bot API itself.
  - It acts only on a button press from the configured user ID in the configured chat, carrying
    the request's nonce, while the request is pending and unexpired.
- **`portal`:** a pending-approvals queue in the admin portal. Approving one is a step-up action,
  so it needs a fresh passkey assertion.
- **Waiting:** approvals can wait longer (configurable, e.g. hours). While waiting, the tool call
  either blocks (short waits) or returns `pending <id>`, with a `check_approval` tool on that
  server for the result (long waits).

More back ends (ntfy, Matrix, Web Push) can follow the same interface later.

### 6.4 Vault-enforced approvals

A route marked `vault_approval: required` (typically send connectors, trading or payment tools) is
approved **by the vault**, not the gateway:

1. **The gateway forwards** the call without eliciting: each approval happens in exactly one
   place.
2. **The vault parses what it will approve:**
   - For a **connector**, it reads the connector's known fields.
   - For an upstream **MCP route**, it reads the JSON-RPC envelope with the stdlib `json` module
     (never the MCP SDK). On these routes it accepts only a single, non-batched
     `application/json` request. A `tools/call` for a tool listed under `vault_approval` is held;
     any other method passes through only if the route's policy allows it. This is the one place
     the vault reads MCP, and it reads only the envelope.
3. **It renders and checks** the approval text with the same rules and budget as §5.2: the shared
   text-rule code lives in `common/`.
4. **It asks** an out-of-band approver (§6.3).
5. **On approval, it forwards exactly the bytes it held,** injecting the credential only then. Any
   other answer means nothing is sent.
6. **Ledger** entries are written by the vault.

Even a fully compromised gateway can't skip these approvals. It can only queue requests, which the
operator sees and denies.

## 7. Admin portal, onboarding and CLI

### 7.1 Portal

Served by the vault on `admin_listen`, from static files in the official image. It is plain
HTML/JS with no third-party assets, calling a JSON API on the same origin.

| Area | What it does | Step-up |
| --- | --- | --- |
| Secrets | list names and metadata, enter, replace, delete. **Never shows a value** | write, delete |
| Credentials | health (expiry, last refresh, re-consent needed), OAuth connect | connect |
| MCP servers | onboard by URL (§7.4), review tools, classify `allow`/`approve`, re-pin drifted tools with a side-by-side diff | save (managed) |
| Policy (managed) | edit routes, connectors, clients and approvals; history with diffs; rollback; export/import YAML | every save |
| Policy (declarative) | read-only view; generated YAML diffs to commit | — |
| Approvals | the queue of pending vault-held and out-of-band approvals (§6.3, §6.4) | approve |
| Ledger | consequential calls: decision, argument hash, result | — |
| Passkeys | enrol, name and remove passkeys | every change |

### 7.2 Authentication and bootstrap

- **First start:** the vault creates a random **setup code** and logs only `setup pending: run
  zoeymcp setup-code`.
- **Getting the code:** `docker exec <vault> zoeymcp setup-code` prints it, over a local admin
  socket that only the vault's uid can open. It is valid for 15 minutes, works once, and is
  invalidated when the first passkey is enrolled.
- **Login:** a passkey (WebAuthn, `userVerification: required`). Several passkeys can be enrolled.
  Sessions are short-lived, with `SameSite=Strict` cookies.
- **Verifier:** our own, strict and small, using only `cryptography`, with **no CBOR library** in
  the vault.
  - **Enrolment:** it requests `attestation: "none"`. The browser's `getPublicKey()` supplies the
    key in standard DER form, and `getPublicKeyAlgorithm()` the algorithm. The credential ID is
    read from fixed offsets in `authenticatorData`. If the browser returns no key, enrolment is
    refused with a clear message. Trust in the new key comes from the session that started the
    enrolment (setup code or step-up), not from attestation.
  - **Assertions:** `authenticatorData` has a fixed layout (site-ID hash, flags, counter). The
    signature covers `authenticatorData` followed by the SHA-256 of `clientDataJSON`, which is
    plain JSON. If the extensions flag is set, the signature still covers the whole byte string,
    but extensions are never parsed.
  - **Checks:** the request type, a single-use server-side challenge, the exact origin, the
    site-ID hash, and the user-present and user-verified flags. The signature counter is checked
    for regressions as a warning only, because many passkeys always report 0.
  - **Algorithms:** ES256 (`-7`), EdDSA (`-8`), and RS256 (`-257`, for Windows Hello on some
    TPMs). Nothing else.
  - This is the subset of WebAuthn we need, not full spec coverage (no attestation formats, no
    extensions), and the docs say so.
- **Step-up:** each security-relevant save (the table in §7.1) needs a fresh passkey assertion,
  bound to that request. A stolen session cookie can browse, but it can't change anything that
  matters.
- **Recovery:** if all passkeys are lost, `docker exec … zoeymcp setup-code` issues a new code,
  which allows enrolling a new passkey. Recovery therefore needs host access, which is the right
  bar.
- **Secure context:** WebAuthn works only on `localhost` or over HTTPS with a valid certificate.
  Browsers refuse passkeys on pages with certificate errors. So the portal is used through
  `localhost` (on the host, or via an SSH tunnel), or behind HTTPS with a real certificate (a
  reverse proxy, or a tailnet's HTTPS certificates). Plain HTTP over the LAN doesn't work, by
  design.

### 7.3 Browser hardening

- `Host` must be in the configured allowlist (by default `localhost`, `127.0.0.1` and the
  configured public name). This stops DNS-rebinding attacks against the loopback listener.
- State-changing requests need `Origin` in the allowlist and `Sec-Fetch-Site: same-origin`, plus a
  CSRF token.
- On every response: `Content-Security-Policy: default-src 'self'; frame-ancestors 'none';
  base-uri 'none'; form-action 'self'`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, and `Cache-Control: no-store` on API responses.
- **The OAuth callback is the one exception.** It arrives as a cross-site, top-level navigation,
  so the same-origin rule and the strict cookie don't apply to it. It accepts only a top-level
  `GET`, and it is validated by a **single-use, server-side `state`**: tied to the portal session
  that started the flow, expiring in 10 minutes, and not dependent on the session cookie arriving.
  It does nothing except complete that one exchange.

### 7.4 OAuth and MCP onboarding

- **OAuth for a configured credential:**
  1. The vault runs PKCE (with a client secret, if confidential) and the operator approves in a new
     tab.
  2. The callback reaches the vault, which exchanges the code through the egress proxy, shows the
     granted scopes, flags any outside `expected_scopes`, and writes the refresh token to the store
     with its binding.
- **From another machine:** the redirect URI is loopback (`http://127.0.0.1:<port>/callback`),
  which points at the **browser's** machine. When the portal isn't open on the vault's host,
  the modal says: *after approving, copy the `http://127.0.0.1…` URL from the address bar and paste
  it here.* The vault takes `code` and `state` from it, checks the `state`, and completes the
  exchange. The PKCE verifier never leaves the vault.
- **MCP server by URL:**
  1. The vault reads the server's protected-resource metadata, then its authorization server's
     metadata.
  2. It registers a client dynamically if offered (or uses a given client ID), and runs the OAuth
     flow above.
  3. It calls `tools/list` with the new token.
  4. The portal shows the tools for review: pick, classify, pin. Managed mode saves (with step-up);
     declarative mode produces the YAML diff.
- **Provider quirks:** some providers accept loopback redirects only for "desktop/native" client
  types. Provider profiles (§8.1) say which client type to register.

### 7.5 CLI

Everything the portal does is also scriptable, for headless setups:

| Command | Where it runs | Does |
| --- | --- | --- |
| `zoeymcp keygen` | anywhere | prints a new master key and the matching generation-1 gateway key |
| `zoeymcp gateway-key` | `docker exec` in the vault | prints the gateway key for the current `gateway_key_generation` |
| `zoeymcp setup-code` | `docker exec` in the vault | prints a one-time setup code |
| `zoeymcp secret set NAME --origin …` | `docker exec` in the vault | reads the value from a prompt or stdin (never argv), stores it with its binding |
| `zoeymcp login <credential>` / `login --mcp <url>` | `docker exec` in the vault | the onboarding of §7.4, with the paste-the-redirect-URL step; tokens go straight into the store |
| `zoeymcp review <server>` | `docker exec` | drift diff and new pins |
| `zoeymcp policy export / import` | `docker exec` | managed-mode YAML round trip |
| `zoeymcp check` / `selftest` | anywhere | §2.7, §8; `check --emit-egress-allowlist` prints the per-source allowlists (plain `host:port` lists and a Squid snippet) for operators who run their own proxy |

Admin commands run inside the vault container and use the local admin socket, so they need host
access instead of a passkey.

## 8. Testing and verification

### 8.1 Acceptance: service shapes

The product is defined by the **shapes** of the services it must front. Each shape has:

- **A fake provider in the test suite** that behaves like the real thing where it matters:
  - auth flows, token expiry and 401s, rotation, `invalid_grant`;
  - dynamic client registration endpoints;
  - SSE streams and `list_changed`;
  - for MCP, fakes built on the real `mcp` SDK.
- **An end-to-end acceptance test**, agent → gateway → vault → fake, covering the allowed calls
  **and** the refusals. It runs in both deployment tiers.
- **A provider profile** shipped with the product: a credential and route template, and the OAuth
  client type to register. Profiles double as documentation.
- **An optional live smoke test** against a real account, gated by env and run by hand. It never
  runs in CI.

ZoeyMCP is done when every shape passes. Shapes are named by pattern; providers are examples.

| # | Shape | Example providers | Milestone |
| --- | --- | --- | --- |
| **HTTP APIs** | | | |
| S1 | Static bearer, JSON, path allowlist, streamed responses | OpenAI-compatible inference APIs | M1 |
| S2 | Query-parameter key; one parameter forced, another stripped | Last.fm-style APIs | M1 |
| S3 | Secret in the URL path | Telegram Bot API | M1 |
| S4 | HTTP basic | Atlassian API tokens, Twilio | M1 |
| S5 | OAuth, confidential client, non-rotating refresh, scope check | Google APIs | M2 |
| S6 | OAuth, public PKCE client, **rotating** refresh tokens | Spotify | M2 |
| S7 | Resource-ID limits: one document ID, a different method set per path | Grist, Notion API | M1 |
| S8 | Read-only (GET-only) API | GitHub, Trello | M1 |
| **MCP** | | | |
| S9 | Remote MCP with OAuth discovery, client registration, `resource` parameter, rotating tokens | Linear, Notion, Atlassian remote MCP | M7 |
| S10 | Remote MCP with a static API key | many hosted servers | M3 |
| S11 | stdio server behind the bridge | reference servers (`time`, `fetch`) | M7 |
| S12 | **Hostile server** (fake only): tool definitions that change after review, injected instructions in descriptions and results, unrequested sampling and elicitation, secrets echoed in errors | — | M3, M4 |
| **SMTP** | | | |
| S13 | Implicit TLS (465) via CONNECT, fixed recipient | Gmail app password | M4 |
| S14 | STARTTLS (587) | generic | M4 |
| **Toolkits** | | | |
| S15 | Approved send: deny, accept and timeout, with byte-identical arguments | example mail toolkit | M4 |
| S16 | Batch tool | example records toolkit | M4 |

### 8.2 Other tests

- **Unit and property tests:**
  - path normalization (fuzzed), route matching, query policy;
  - the text rules, canonical JSON, review hashes;
  - **store crypto:** a tampered ciphertext, a swapped entry name, a changed binding and the wrong
    key all fail to decrypt;
  - HKDF contexts are distinct;
  - a policy-version replay is refused.
- **Effect tests** for each Must, run against real processes:
  - a gateway-only route refuses a placeholder and a spoofed source address;
  - a wrong placeholder is refused;
  - a forced parameter can't be overridden;
  - a declined, timed-out or errored approval sends nothing upstream;
  - an accepted one sends exactly the bytes shown;
  - a drifted tool is hidden;
  - a second pending approval is refused as busy;
  - an SMTP connector can't be made to add a recipient, and a changed recipient list makes the
    password unusable;
  - a route whose upstream changed can't use its old secret;
  - an echoed secret is scrubbed in each encoding (raw, percent-encoded, JSON-escaped, base64),
    including from a gzip-encoded body;
  - on a `vault_approval` route, a batched request, a non-JSON body or a `tools/call` hidden
    behind a different content type doesn't get past the hold, and a denied request sends
    nothing upstream;
  - a retired gateway key generation stays retired across a vault restart;
  - the egress role refuses a host outside the listener's allowlist, a plain-HTTP request, a name
    that resolves to a private or metadata address (including after a DNS change between two
    lookups), and one source's destinations on another source's listener;
  - no admin endpoint returns a secret;
  - in the **standard tier**, the gateway uid can't read `/state/vault` or the vault's environ;
  - in the **hardened tier**, the gateway can't reach the internet or the admin listener.
- **Portal security tests:**
  - a wrong `Host` (DNS rebinding) is refused;
  - a cross-origin `POST` is refused;
  - a save without step-up is refused;
  - an OAuth callback with a reused, expired or foreign `state` is refused;
  - a setup code is single-use and expires;
  - the WebAuthn verifier's test vectors pass: truncated `authenticatorData`, flags missing
    user-verified, a wrong origin, a wrong site-ID hash, a reused challenge, an unsupported
    algorithm, and a signature over altered bytes are all refused;
  - the CSP and the other headers are present on every response.
- **`zoeymcp selftest --cases cases.yaml`** starts the vault with the operator's **real** policy,
  with every upstream (and the egress proxy) replaced by an echo server that reports what it
  received.
  - A case file lists requests and expected outcomes: status, forwarded path, forced parameters
    present, credential injected, caller refused.
  - It is meant to run in CI and before every deploy, and to be **mutation-tested**: flip a rule,
    and the suite must fail.
- **The project's own CI** mutation-tests the policy code (e.g. `mutmut`) on the security-relevant
  modules.
- **Release checks:** dependency hashes, image content-hash label, SBOM, and a reproducible-build
  check.

## 9. Policy sketch

One document (managed export, or declarative config). Secrets appear only as references; values
live in the store.

```yaml
version: 1
mode: declarative
egress_proxy: http://egress-proxy:3128      # optional
gateway_key_generation: 1

admin:
  listen: 0.0.0.0:8081
  hosts: [localhost, 127.0.0.1, zoeymcp.tailnet.example]

credentials:
  example-api:  {kind: header, secret: "store:example-api"}
  music-stats:  {kind: query, param: api_key, secret: "store:music-stats"}
  notifier-bot: {kind: path, template: "/bot{secret}", secret: "store:notifier-bot"}
  broker-mcp:
    kind: oauth2
    token_url: https://auth.broker.example/oauth/token
    client_id: "store:broker-client-id"
    refresh_token: "store:broker-refresh"   # rotated in place
    rotates: true
    extra_params: {resource: https://mcp.broker.example/}
    expected_scopes: [read, trade]

connectors:
  mail-out:
    kind: smtp
    host: smtp.mail.example
    port: 465
    username: "store:mail-user"
    password: "store:mail-pass"             # bound to host, port, from and to
    from: "Agent <agent@mail.example>"
    to: [partner@mail.example]
    max_per_day: 20

routes:
  - name: stats                             # a direct route for a sandbox script
    prefix: /stats
    upstream: https://api.stats.example
    credential: music-stats
    callers: [{placeholder: ph-agent1-stats}]
    query: {force: {user: alice}, strip: [api_key]}
    rules: [{methods: [GET], paths: [/2.0/**]}]

  - name: broker-mcp
    prefix: /broker
    upstream: https://mcp.broker.example
    credential: broker-mcp
    callers: [gateway]
    stream: true
    rules: [{methods: [GET, POST, DELETE], paths: [/mcp]}]

  - name: mail-send
    prefix: /mail
    connector: mail-out
    callers: [gateway]
    rules: [{methods: [GET], paths: [/config]}, {methods: [POST], paths: [/send]}]

gateway:
  clients:
    agent1:
      token: ph-agent1-gw
      servers: [broker-read, broker-trade, mail]

  approvals:
    approver: elicitation
    timeout: 300
    budget_chars: 3000

  servers:
    broker-read:
      kind: remote
      route: broker-mcp
      path: /mcp
      tools:
        include: [get_quote, list_positions]
        allow: [get_quote, list_positions]
      review: {get_quote: "sha256:…", list_positions: "sha256:…"}

    broker-trade:
      kind: remote
      route: broker-mcp
      path: /mcp
      tools:
        include: [place_order, cancel_order]
        approve: [place_order, cancel_order]
      review: {place_order: "sha256:…", cancel_order: "sha256:…"}
      on_drift: fail

    mail:
      kind: toolkit
      module: my_toolkits.mail
```

Unknown keys are errors. Source-address pins, where wanted, are an optional `sources:` list on a
caller or client.

## 10. Repository layout (planned)

```text
deploy/
  compose.yaml            standard tier (single container)
  compose.hardened.yaml   hardened tier (§3.4)
src/zoeymcp/
  common/       policy schema + loading, text rules, canonical JSON, logging
  vault/        app, routing, path rules, credentials/, connectors/, store + keys, policy versions
  portal/       admin API, WebAuthn, sessions, static UI
  gateway/      app, upstream sessions, filtering + pins, approvals/, toolkit SDK, ledger
  bridge/       stdio ↔ streamable HTTP
  egress/       CONNECT-only allowlist proxy
  entrypoint/   the standard tier's privilege-dropping launcher
  cli/          keygen, setup-code, secret, login, review, policy, check, selftest
profiles/       provider profiles, one per acceptance shape
tests/
  fakes/        fake providers, one per shape
  acceptance/   end-to-end shape tests, both tiers
  unit/, effect/, portal/
examples/       example policies, example toolkits, a derived gateway image
docs/           design.md (this), threat-model.md, operations.md (rotation, recovery, seed vs live)
Dockerfile      multi-stage, hashed requirements, non-root, read-only friendly
```

## 11. Milestones

| # | Scope | Shapes |
| --- | --- | --- |
| M0 | Repo, CI, policy schema, `check`, text rules, canonical JSON, fake-provider harness | — |
| M1 | **Vault core:** routes, path rules, header/query/path/basic credentials, key hierarchy, store with bindings, local admin socket + `secret set` / `setup-code`, declarative mode, egress proxy, logs, `selftest`. **Both tiers:** the entrypoint and the hardened compose | S1–S4, S7, S8 |
| M2 | **OAuth:** refresh, rotation in the store, seed vs live; CLI `login <credential>` | S5, S6 |
| M3 | **Gateway:** `remote` servers through the vault, gateway identity and key rotation, policy fetch, per-client scoping, per-client upstream sessions, include + pins, schema validation, `review`; the `lan` compose profile | S10, S12 (drift, injection) |
| M4 | **Approvals:** elicitation back end, locks, ledger; toolkit SDK and the derived-image example; SMTP connector + example toolkits | S12 (sampling, elicitation), S13–S16 |
| M5 | **Portal v1:** setup code, passkeys, step-up, hardening, write-only secrets, OAuth connect (including pasting the redirect URL), credential health, ledger view | portal tests |
| M6 | **Portal v2:** tool-drift review and re-pin; **managed mode** with versioning, history, rollback, export/import | portal tests |
| M7 | `bridge`; the `egress` role, the `egress-proxy` profile and `--emit-egress-allowlist`; MCP onboarding by URL (discovery + DCR) in the portal and CLI | S9, S11 |
| M8 | **Vault-enforced approvals** (§6.4); out-of-band approvers in the vault (Telegram, the portal queue); image publishing with digests and SBOM | S3 end to end as the approver; S13/S15 again under `vault_approval` |

Each milestone ships with its effect tests and its shapes' acceptance tests. Nothing merges with a
failing mutation run on the policy modules. Managed mode is the default from M6 on; until then,
only declarative mode exists.

## 12. Decisions and open questions

### 12.1 Decided (2026-10-17)

| Question | Decision | Where |
| --- | --- | --- |
| Upstream sessions | per (client, server); `shared_session: true` opt-in for stateless servers | §5 |
| Long approvals | elicitation stays synchronous; `pending` + `check_approval` only with out-of-band approvers | §6.1, §6.3 |
| Response scrubbing | on by default for text/JSON bodies under 1 MB, covering common encodings; headers always | §4.1 |
| Schema validation | `jsonschema`, pinned, gateway only, with limits on size, depth and remote `$ref` | §5.2 |
| Tool classification | explicit and mandatory; the portal pre-fills from `readOnlyHint` as a labelled suggestion | §5.2 |
| Approvals that survive a gateway compromise | vault-enforced approvals on `vault_approval` routes; out-of-band approvers hosted in the vault | §6.3, §6.4 |
| Portal location | in the vault, with our own WebAuthn verifier: `cryptography` only, no CBOR, ES256/EdDSA/RS256 | §7.2 |
| LAN access to a hardened gateway | `lan` compose profile: an inbound proxy with TLS | §3.4 |
| Bridge egress and egress proxy | one optional `egress-proxy` profile with per-source allowlists generated from the policy; each bridge on its own network; a bridge holding a real secret is a flagged exception | §3.4, R35 |
| Gateway key rotation | ratchet on first use of the new generation, capped at 5 minutes; persisted; `--immediate` for a suspected leak | §4.5 |
| Egress proxy implementation | the built-in `zoeymcp egress` role, reading the policy directly; `check --emit-egress-allowlist` exports the allowlists for operators who run their own proxy. Squid (config drift, a large codebase), Smokescreen (needs client-certificate roles) and tinyproxy (no per-source lists, no private-address guard) were considered | §4.7 |

### 12.2 Open

None at the moment. New questions go here as the build raises them.
