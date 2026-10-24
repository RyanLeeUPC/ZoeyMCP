# ZoeyMCP in an existing stack

A stack that already runs agents, an egress proxy and networks of its own takes ZoeyMCP's hardened
tier as three services: the gateway beside the agents, the vault behind the stack's proxy, and a
small relay that publishes the portal. Neither the vault nor the gateway gets a route out; the
relay's own published network is the only non-internal one, and it holds the relay alone.
[operations.md §29](../../docs/operations.md#29-fitting-zoeymcp-into-an-existing-stack) explains
the shape; this directory is that shape as files, and the image's smoke test runs it.

- `compose.yaml`: the vault, the gateway and `portal-relay`, with the vault's policy inline.
- `zoeymcp-squid.conf`: the Squid snippet `check --emit-egress-allowlist` prints for that policy,
  for the stack's proxy to include. A unit test fails when it no longer matches the policy.

## The networks

| Network | Internal | Who is on it |
| --- | --- | --- |
| `internal` (ZoeyMCP's) | yes | the vault (alias `zoeymcp-vault`) and the gateway |
| `stack-agents` (the stack's, external) | **must be** | the gateway (alias `zoeymcp-gateway`) and the agents |
| `stack-proxy` (the stack's, external) | **must be** | the vault and the stack's proxy |
| `portal` (ZoeyMCP's) | yes | the vault (alias `vault-portal`) and the relay |
| `portal-pub` (ZoeyMCP's) | no | the relay alone, publishing `127.0.0.1:8081` |

**The stack's agent network must be `internal: true`.** If it isn't, the gateway, and the toolkits
that run inside it, have a route out beside the proxy. **So must the proxy's network**, or the
vault has a direct route out and the allowlist confines nothing; the proxy reaches the internet on
a network of its own. Compose can't see how an external network was created, so the file can't
promise either: the probe below checks both on the running containers.

Set `ZOEYMCP_STACK_AGENTS` and `ZOEYMCP_STACK_PROXY` to the two networks' Docker names (they
default to `stack-agents` and `stack-proxy`), and change `egress_proxy` in the policy to the proxy's
name and port on its network.

**ZoeyMCP is reached by aliases only it uses**, never by its bare service names: the gateway
reaches the vault as `zoeymcp-vault`, and agents reach the gateway as `zoeymcp-gateway`. A
service name is resolved on every network the caller is on, and the stack's networks may hold a
`vault` or a `gateway` of their own (a HashiCorp Vault, an API gateway) that would then be sent
the gateway key or a client token. The other way round, the services' names `vault` and
`gateway` join the stack's networks too: if the stack already uses either name there, rename its
service or ZoeyMCP's before starting this.

The vault's own listener (port 8080) answers on every network it joins, so the stack's proxy and
the relay can reach it; like any caller without the gateway key or a route's placeholder, they get
403. Keep other services off the proxy's network all the same.

## Running it

```sh
ZOEYMCP_MASTER_KEY=... ZOEYMCP_GATEWAY_KEY=... \
  docker compose -f examples/existing-stack/compose.yaml up -d
```

`zoeymcp keygen` prints both keys. Secrets, reviews and setup codes work as in the hardened tier,
with this file's `-f` (and the keys in the environment, as every compose command here needs):

```sh
c="docker compose -f examples/existing-stack/compose.yaml"
printf '%s' "$VALUE" | $c exec -T vault zoeymcp secret set notes-key
$c exec gateway zoeymcp review notes
$c exec vault zoeymcp setup-code
```

Agents on the stack's agent network use `http://zoeymcp-gateway:8090/s/<server>/mcp` with
`Authorization: Bearer <client token>` (operations.md §10), and their runtime's own approval
setting for that server at its least-prompting level, so the gateway's approval is the one prompt.

## The proxy

The snippet allows the vault's `CONNECT` to each destination the policy names, and nothing else.
The stack's `squid.conf` defines what its header names, includes it, and denies the rest:

```text
acl CONNECT method CONNECT
# The vault's network: stack-proxy's subnet.
acl stack_vault_net src 172.30.5.0/24
# Emitted; never edited by hand.
include /etc/squid/zoeymcp-squid.conf
# Onboarding lines only; empty otherwise.
include /etc/squid/zoeymcp-onboarding.conf
http_access deny all
```

Squid takes `#` as a comment only at the start of a line, so each comment has a line of its own.

`egress_proxy_acls` in the policy names that `src` ACL, so every command prints the same lines.
After a policy change, regenerate the snippet and reload the proxy:

```sh
$c run --rm --no-deps -T vault check --emit-egress-allowlist --allowlist-format squid \
    > examples/existing-stack/zoeymcp-squid.conf
```

operations.md §28 has the rest: what goes through the proxy, how the snippet's rules work, and
onboarding through it.

**Bridges and the egress role.** A stdio server behind a hardened bridge (operations.md §33) gets
networks of its own here too, never one of the stack's: one it shares with the vault alone and,
when its program has an egress list, one it shares with the stack's proxy alone. The snippet then
gives the bridge's route a source of its own, whose `src` ACL is the bridge's address on that
network (operations.md §29). ZoeyMCP's own egress role (operations.md §31) is for a stack without
a proxy; here the policy leaves `egress_proxy_kind` unset, so the vault takes `egress_proxy` for
the stack's proxy.

## The portal

Docker publishes a port only through a non-internal network, so a vault on internal networks alone
can't publish the portal itself. `portal-relay` does it from networks of its own: `portal`, an
internal network it shares with the vault alone, and `portal-pub`, which publishes
`127.0.0.1:8081` and holds the relay alone. Open `http://localhost:8081` on the host, or tunnel
the same port number to it (`ssh -N -L 8081:127.0.0.1:8081 host`).

The relay is Caddy, the image `deploy/compose.hardened.yaml` pins, as uid 10007, read-only, with
every capability dropped but `NET_BIND_SERVICE` (the binary carries that file capability and won't
start without it; it listens on 8081 and never uses it), and tmpfs for its `/config` and `/data`.
It passes `Host`, `Origin` and the `Sec-Fetch-*` headers unchanged, so the vault's own checks
decide every request, as they do without it. It holds no secret and keeps no access log. Its
Caddyfile also turns off Caddy's error log and its proxy handler's log, which would otherwise
record a request's URI and headers on a 502 while the vault is down: the OAuth callback's query
and the `X-ZoeyMCP-Session` header among them (Caddy redacts neither). It does see what a browser
sends the portal, as any proxy in front of it does (operations.md §26).

The alternatives, best first after the relay:

- **The stack's own reverse proxy** joins the `portal` network instead of the relay, and follows
  §26's rules for a proxy in front of the portal (pass `Host` unchanged, expect the `X-Forwarded-*`
  headers it adds to be ignored, keep the callback's query and the session header out of its log,
  its error log included).
- **A separate non-internal network** for the vault's portal, with a host firewall rule that drops
  that network's outbound traffic. The weakest: the vault then has a route out, and only a rule
  outside Docker's view stops it.
- **No portal:** remove the `admin` block and the `portal-relay` service. Everything the portal
  does, the CLI does too.

## Verify probes

None of these changes anything. The last loop fails if the vault or the gateway is on a network
with a route out, which is how a stack network created without `--internal` shows up:

```sh
c="docker compose -f examples/existing-stack/compose.yaml"
$c run --rm --no-deps -T -v "$PWD/examples/existing-stack:/p:ro" vault \
    check --emit-egress-allowlist --allowlist-format squid --check /p/zoeymcp-squid.conf
$c exec -T gateway zoeymcp review notes            # exit 0 once it lists no tool nobody reviewed (include or decline each)
$c exec -T vault zoeymcp health --json --strict > /dev/null
$c exec -T gateway zoeymcp gateway-status
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: wrong.example' http://127.0.0.1:8081/   # 421
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Sec-Fetch-Site: cross-site' \
  -H 'Origin: https://evil.example' http://localhost:8081/api/logout                   # 403
for service in vault gateway; do
  id="$($c ps -q "$service")"
  for net in $(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' "$id"); do
    [ "$(docker network inspect -f '{{.Internal}}' "$net")" = true ] \
      || { echo "$service is on $net, which isn't internal"; exit 1; }
  done
done
```

The two `curl` lines are the portal's own posture probes (operations.md §26, "Checks for a verify
script"), answered by the vault through the relay.
