# A stdio MCP server behind a bridge

`zoeymcp bridge` serves a stdio-only MCP server as one Streamable HTTP endpoint, and to the rest
of ZoeyMCP it is one more upstream: a vault route to the bridge, with the bridge's token as the
route's header credential, and a `kind: remote` server on that route
(`profiles/stdio-bridge.yaml`). This directory builds an image for one such server and runs it in
either tier. `docs/operations.md` §33 is the how-to, and §32 the bridge's reference.

| File | What it is |
| --- | --- |
| `Dockerfile` | the official image plus one layer: the server in `/opt/stdio-server`, installed in a build stage from wheels locked by hash |
| `lock.sh` | builds the example server's wheel and writes `requirements.lock` (generated, never committed) |
| `verify.sh --bridge` | proves the image is the official one plus that prefix and nothing else |
| `server/` | the example server, `fetch-server`: standard library only, with `echo`, `fetch` and `wait` |
| `compose.bridge.yaml` | the hardened tier's override: the bridge in a container of its own, on networks of its own |
| `compose.standard.yaml` | the standard tier's override: the bridge as a child of the launcher, **unconfined** |

## Build and verify

```sh
OFFICIAL=zoeymcp:local   # in production: <registry>/zoeymcp@sha256:<release digest>
examples/bridge/lock.sh
docker build -f examples/bridge/Dockerfile \
    --build-context server=examples/bridge/server/dist \
    --build-arg OFFICIAL="$OFFICIAL" -t zoeymcp-bridge-fetch:local examples/bridge
examples/bridge/verify.sh --bridge "$OFFICIAL" zoeymcp-bridge-fetch:local
```

The build installs wheels only, so no package's build code runs as root (a server published only
as an sdist is built into a wheel elsewhere and locked by hash), into a prefix of its own, never
the vault's or the gateway's environment. `verify.sh --bridge` checks, without running anything
it added: the official layers in order plus exactly one; the same `User`, `Entrypoint`, `Cmd`,
`Env` and `WorkingDir`; an added layer that touches only `/opt/stdio-server`; both zoeymcp
environments byte for byte the official ones; nothing setuid, setgid or world-writable; emSign
ECC Root CA - G3 absent from the Debian store; the official `io.zoeymcp.source-tree` label and
`io.zoeymcp.bridge.command` naming the server. For a Node server, copy a pinned Node runtime into
`/opt/node` (the Dockerfile's comment) and verify with `--bridge --node`. Keep any package
registry out of the program's egress list, and turn off its update checks and telemetry where it
has a switch (the example has neither).

To run your own server, replace `server/` (or the lock with your server's wheels and their
dependencies, each hashed), the command in both overrides and the `io.zoeymcp.bridge.command`
label.

## The hardened tier: `compose.bridge.yaml`

```sh
docker compose -f deploy/compose.hardened.yaml -f examples/bridge/compose.bridge.yaml \
  --profile egress-proxy up -d
```

The bridge runs as uid 10005, read-only, with no capability, `no-new-privileges` and an init as
PID 1. It is on two internal networks: `bridge-fetch`, with the vault alone, where it listens as
`bridge-fetch-mcp:9000` (an alias on that network only), and `egress-fetch`, with the egress role
alone, through which its program reaches only the route's `program.egress` list. The override
restates the role's whole command with both listeners, and makes the vault depend on the bridge
(`service_started`), so compose stops the gateway, then the vault, then the bridge.

From a cold start:

1. Build and verify the image (above).
2. Commit the route (`upstream: http://bridge-fetch-mcp:9000`, `allow_insecure_upstream: true`,
   the `program` block), its header credential and the remote server (the profile) **without**
   this override, and reload.
3. `zoeymcp secret set bridge-fetch-token --generate` in the vault's container; set
   `ZOEYMCP_BRIDGE_FETCH_TOKEN_SHA256` to the `sha256:` line it prints.
4. For a program with egress: print the role's key (`zoeymcp egress-key`), set
   `ZOEYMCP_EGRESS_KEY` and start the role with `--profile egress-proxy`.
5. Add this override: `up -d bridge-fetch`, then `up -d vault`.
6. Review the server (`zoeymcp review fetch`) and commit its pins.

Until its hash is set the bridge refuses to start and compose keeps restarting it; the vault
starts regardless.

## The standard tier: `compose.standard.yaml`

> **Unconfined.** In the standard tier the program shares the container's network with the vault
> and the gateway: it can reach every TCP listener there, your network and the internet, and it
> can ignore proxy settings. Nothing in this tier limits where it connects. Use the hardened tier
> for a program you need to confine.
>
> It also shares the container's memory, processes and CPU, and every process there can read its
> arguments, so no secret goes in `ZOEYMCP_BRIDGE_FETCH_ARGS`. The vault runs from this image, so
> it must pass `verify.sh --bridge`.

```sh
docker compose -f deploy/compose.yaml -f examples/bridge/compose.standard.yaml up -d
```

The launcher starts bridge `fetch` (`--bridge fetch`) as uid 10100 after the vault and the
gateway, with its arguments from `ZOEYMCP_BRIDGE_FETCH_ARGS`, its token's hash from
`ZOEYMCP_BRIDGE_FETCH_TOKEN_SHA256`, and each `ZOEYMCP_BRIDGE_FETCH_ENV_<VAR>` as `<VAR>`. It
listens on `/run/zoeymcp-bridge-fetch/mcp.sock`, in a tmpfs the override mounts with
`mode=0750,uid=10100,gid=10001`: only the vault can connect, and only the bridge can create a
socket there. The route's upstream is that socket:

```yaml
upstream: unix:/run/zoeymcp-bridge-fetch/mcp.sock   # no allow_insecure_upstream, no program.egress
```

From a cold start: build and verify the image; commit the route with that upstream, its
credential and the server; run `zoeymcp secret set bridge-fetch-token --generate` in the
container and set `ZOEYMCP_BRIDGE_FETCH_TOKEN_SHA256`; add this override and recreate the
container; review as above. A second bridge is one more `--bridge NAME` with its own variables and
a tmpfs `/run/zoeymcp-bridge-NAME` for uid `10100 + its place in the list`. A bridge that exits
stays down, its route answering 502, until the container restarts.

## A remote bridge

On another host, `zoeymcp bridge --listen 127.0.0.1:9000 --era legacy -- <command>` behind your
own TLS front, and a route with `upstream: https://<that host>`, the token made in the vault and
its hash in that bridge's environment. Nothing here confines its program but that host.
