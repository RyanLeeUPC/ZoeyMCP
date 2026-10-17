# ZoeyMCP

A self-hosted proxy that lets AI agents use outside APIs and MCP servers **without ever holding a
real credential**, and that asks a human to approve the **exact arguments** of every consequential
action.

> Status: design phase. Nothing is built yet. See [docs/design.md](docs/design.md).

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
- **Bridge:** runs a stdio-only MCP server in its own container and exposes it over HTTP.
- **Admin portal:** passkey login.
  - Write-only secret entry: values go in and are never shown again.
  - OAuth and MCP server onboarding in the browser, with discovery, client registration and PKCE,
    and tokens stored straight into the encrypted store.
  - Tool review, with a diff when an upstream tool changes, plus credential health and an
    approval ledger.
- **Two deployment tiers:** a single container to get started, and a hardened compose, where the
  gateway has no internet access at all, for anything that moves money, sends mail or touches
  personal data.

Built for one operator running a few agents. Multi-tenant features and SSO are non-goals.

## Development

Requires [uv](https://docs.astral.sh/uv/). Dependencies are locked with hashes in `uv.lock`, and
resolution ignores releases newer than the `exclude-newer` date in `pyproject.toml` (a
supply-chain cooldown, moved forward deliberately).

```sh
uv sync --locked
uv run pytest                    # tests, including property tests
uv run ruff check src tests      # lint
uv run ruff format src tests     # format
uv run mypy                      # strict type checks
uv run zoeymcp check --config examples/policy.yaml
```

Security-relevant behavior is covered by effect tests (a refused request really reaches
nothing), acceptance tests per service shape over real TLS (`tests/acceptance`, using the
shipped `profiles/`), and mutation testing of the security-critical modules in CI
(`.github/workflows/mutation.yml`, gated at 89%).

## License

[Apache License 2.0](LICENSE)
