# ZoeyMCP

A self-hosted proxy that lets AI agents use outside APIs and MCP servers **without ever holding a
real credential**, and that asks a human to approve the **exact arguments** of every consequential
action.

> **Not ready for use.** Early development: the vault, the gateway, approvals, toolkits and the
> admin portal work, but the bridge, onboarding by URL, managed mode and out-of-band approvers
> don't exist yet, and nothing has been reviewed or released.
> Don't deploy it. See [docs/design.md](docs/design.md) for where it's going,
> [docs/threat-model.md](docs/threat-model.md) for what it defends against, and
> [docs/operations.md](docs/operations.md) for running what exists.

Built so far:

- **M1, the vault core:** routes with default-deny method and path rules, header, query, path and
  basic credentials, an encrypted store whose secrets are bound to their origins, the local admin
  socket, the hardened compose, and `selftest`.
- **M2, OAuth:** refresh with single-flight and backoff; every new refresh token saved before it
  is used, so rotating tokens survive; env seeds promoted to a live token in the store;
  `zoeymcp login` (PKCE, by pasting the redirected address), `oauth status` and `oauth reset`;
  stable error codes for callers; profiles for Google and Spotify.
- **M3, the gateway:** an MCP server for remote MCP servers, in both protocol eras, holding no
  secret and reaching upstreams only through the vault. Per-agent client tokens (stored as
  hashes) and server assignments; tools served only when included and matching their pinned
  definition, with drift hidden and marked; arguments validated against the pinned schema and
  checked on the wire; results with hidden characters made visible; no sampling, elicitation or
  roots from upstreams. `zoeymcp review` to onboard and re-pin; both deployment tiers (a
  privilege-dropping single container, and a hardened compose with gateway key rotation); a
  TLS `lan` profile.
- **M4, approvals, mail and toolkits:** `approve` tools ask a human through the agent's own
  client (MCP elicitation, both protocol eras) with a gateway-rendered prompt that shows the
  exact call and can't hide text, then run that call once; a per-call lock, cooldown and hourly
  cap; a hash-chained, HMAC-keyed approval ledger with `zoeymcp ledger --verify`; approved calls
  that finish when the agent leaves or the gateway stops. The vault's SMTP connector sends with an
  app password it alone holds, to fixed recipients, over verified TLS, optionally through CONNECT,
  with idempotency keys, a rolling daily limit and a journal that never sends twice. Toolkits:
  Python tools in the gateway that reach upstreams only through vault slots, show a plan of exact
  writes and may send only those, once; an SDK with a test harness, example mail and records
  toolkits, and a derived-image recipe with a verifier.
- **M5, the admin portal v1:** served by the vault on its own listener, opt-in, at exact origins
  (`localhost`, or HTTPS behind your own proxy). One-time setup codes issued from the host,
  passkey sign-in with the vault's own verifier, two-half sessions, and a fresh passkey prompt
  bound to every change. Write-only secrets; OAuth connect by pasting the redirected address, or
  through the portal's callback, completed with a passkey; credential health (also
  `zoeymcp health`); the gateway's approval ledger pushed to an append-only copy in the vault,
  with the sends no call explains; and a read-only view of the declarative policy. An OAuth
  credential for a remote MCP server whose client you register yourself.

## Quickstart (standard tier)

One container, the gateway on `localhost:8090`, for one remote MCP server that takes an API
key. Build the image (`docker build -t zoeymcp:local .`), then:

```sh
docker run --rm zoeymcp:local keygen          # keep ZOEYMCP_MASTER_KEY; the gateway key isn't
docker run --rm zoeymcp:local client-token    # for the agent; put token_sha256 in the policy
```

Edit the policy inside [deploy/compose.yaml](deploy/compose.yaml): the server's URL in
`routes`, the client's `token_sha256`. Then:

```sh
export ZOEYMCP_MASTER_KEY=...
docker compose -f deploy/compose.yaml up -d
printf '%s' "$API_KEY" | docker compose -f deploy/compose.yaml exec -T zoeymcp zoeymcp secret set notes-key
docker compose -f deploy/compose.yaml exec zoeymcp zoeymcp review notes --add <tool>
```

Commit the snippet `review` prints, classifying each tool as `allow` or `approve`, recreate the
container, and point the agent at the server:

```json
{"mcpServers": {"notes": {"type": "http", "url": "http://localhost:8090/s/notes/mcp",
                          "headers": {"Authorization": "Bearer zgc1-..."}}}}
```

**When to move to the hardened tier** ([deploy/compose.hardened.yaml](deploy/compose.hardened.yaml)):
for anything that moves money, sends mail or touches personal data. In the standard tier the
gateway shares the vault's network namespace, so a compromised gateway has a way out; in the
hardened tier it has none. Both are in [docs/operations.md](docs/operations.md) (§9 onwards).

**The portal** is at `http://localhost:8081` in a browser on the same host, in both tiers. Issue
the one-time code that enrols your first passkey with
`docker compose -f deploy/compose.yaml exec zoeymcp zoeymcp setup-code`; operations.md §26 has the
rest, including reaching it from another machine.

## What it does

- **Vault:** holds the real secrets and swaps agents' placeholders for them on the way out.
  - Static keys, keys in query parameters or paths, and OAuth 2 refresh (including rotating refresh
    tokens).
  - A default-deny method/path policy per route, with each route pinned to the callers allowed to
    use it.
- **Gateway:** an MCP server in front of your MCP servers, holding no secrets.
  - Per-agent tool allowlists, and pinned tool definitions, so a changed tool is hidden until you
    re-review it.
  - Approvals that show you the exact arguments before a consequential call runs.
  - Your own Python tools, which run with no secrets.
- **Admin portal:** passkey login, and a passkey prompt for every change.
  - Write-only secret entry: values go in and are never shown again.
  - OAuth connect in the browser (PKCE), with tokens stored straight into the encrypted store.
  - Credential health, and the approval ledger as the vault received it.
  - Planned for M7: onboarding an MCP server by URL (discovery and client registration), ending
    in a first-time tool review and, in declarative mode, the YAML diff to commit. For M6: tool
    drift review and re-pinning in the browser, and managed mode (the portal as the policy's
    source, with versions and rollback). Until then, `zoeymcp review` does the reviewing.
- **Bridge (planned for M7):** runs a stdio-only MCP server in its own container and exposes it
  over HTTP.
- **Two deployment tiers:** a single container to get started, and a hardened compose, where the
  gateway has no internet access at all, for anything that moves money, sends mail or touches
  personal data.

Built for one operator running a few agents. Multi-tenant features and SSO are non-goals.

## Development

Requires [uv](https://docs.astral.sh/uv/). Dependencies are locked with hashes in `uv.lock`, and
resolution ignores releases newer than the `exclude-newer` date in `pyproject.toml` (a
supply-chain cooldown, moved forward deliberately).

```sh
uv sync --locked --all-extras                    # the gateway's extra too, as CI does
uv run pytest                                    # tests, including property tests
uv run ruff check src tests examples/toolkits    # lint, the paths CI lints
uv run ruff format src tests examples/toolkits   # format
uv run mypy                                      # strict type checks
uv run zoeymcp check --config examples/policy.yaml
```

Security-relevant behavior is covered by effect tests (a refused request really reaches
nothing), acceptance tests per service shape over real TLS (`tests/acceptance`, using the
shipped `profiles/`), the portal's effect tests over real sockets (`tests/portal`), library
contract tests for the MCP SDK and what the portal relies on (`tests/sdk`), a by-hand browser
checklist ([docs/manual-checks.md](docs/manual-checks.md)), an image smoke test of both
deployment tiers (`scripts/smoke-image.sh`), and mutation testing of the security-critical
modules in CI (`.github/workflows/mutation.yml`, gated at 95% overall and 95% for each module M5 added).

## License

[Apache License 2.0](LICENSE)
