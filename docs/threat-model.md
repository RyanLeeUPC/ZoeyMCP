# ZoeyMCP threat model

Who might attack a deployment, what each can reach, and the most each can gain once everything
built so far (M1 to M3) holds. The mechanisms are in [design.md](design.md); the invariants the
tests hold the gateway to are G1 to G21 there (§8.2).

## Actors

| # | Actor | Has | Wants |
| --- | --- | --- | --- |
| T1 | **A compromised agent** (or its runtime, or its code sandbox) | its own client token; every byte it sends (headers, `_meta`, arguments, session ids, `Origin`); reach to the gateway, and maybe to a vault TCP listener | tools or servers it isn't assigned; the upstream around the filter; another agent's session or state; a real credential; to exhaust the gateway |
| T2 | **A hostile upstream MCP server** | the credential the vault injects for it (it is the legitimate recipient); full control of its definitions, results, errors, notifications, server → client requests, pagination, timing, redirects and session ids; it may show different definitions per session, and a clean set to `review` | to inject instructions; to change a tool after review; to get sampling, elicitation or roots; to steer the gateway to another vault route; to leak its credential to the agent; denial of service; terminal injection in `review` |
| T3 | **Another host on the LAN** | reach to published ports; a browser the operator uses (DNS rebinding, cross-site requests); passive sniffing | to use the gateway without a token; to read tokens on the wire |
| T4 | **A compromised gateway process** | the gateway's identity; agents' requests as they arrive (client tokens in transit); its view of the policy; egress in the standard tier | to read secrets, the master key or the store; to widen policy; to revive a retired gateway key |
| T5 | A compromised vault | everything | out of scope: the vault is the trust root (design §3.1) |

## What each can gain at most

- **T1** can call its own client's tools, with arguments the pinned schema accepts, within
  limits. It never sees the upstream credential, the gateway key or other clients' servers, and
  it can't use another client's legacy session. On a **modern stateful** upstream it may reach
  handles minted for another client, because every client shares one credential there (design
  §5.0.1). To isolate state, give each client its own server entry, route and credential.
- **T2** can return wrong or hostile *results* for reviewed tools. Changed definitions are
  hidden, and stay hidden after a flip back until the operator clears them. Its text reaches the
  model only inside results, with hidden characters made visible. It can't ask the agent
  anything, redirect the gateway, or get an echo of its credential past the vault in common
  encodings. It can still disclose the credential deliberately in a disguised form (split across
  events, rot13, in pieces): the defenses there are least-privilege credentials bound to their
  origin and, in the hardened tier, no agent egress except through the gateway. A silent change
  between two drift checks is caught at the next one (300 s by default).
- **T3** needs a 256-bit client token. The `lan` profile carries it over TLS; the standard tier
  publishes the gateway on loopback only. DNS rebinding fails on the `Host` and `Origin` checks.
  The `lan` proxy terminates TLS, so it sees client tokens, and holds no other secret.
- **T4** can call any route bound to `caller: gateway`, inside that route's policy, until
  vault-enforced approvals (M8). It can't read a secret, the store, the master key or the vault's
  environment, and it can't write policy. Recovery: restart (standard tier), or rotate the
  gateway key (hardened), then rotate client tokens. In the standard tier it shares the vault's
  network namespace, so it has egress; the hardened tier has none.

## The confused deputy

ZoeyMCP issues no OAuth tokens to agents and has no dynamic client registration on the agent's
side: client tokens are static and set by the operator. So the MCP specification's
confused-deputy precondition (a proxy that lets MCP clients register dynamically) doesn't hold.
Later milestones must keep it that way, or add per-client consent first.

## Accepted limits

- **Silent drift** between timer checks, as above.
- **Modern stateful servers** see one principal for every client.
- **Deliberate disclosure** of a credential by the server that was given it.
- **Standard-tier egress:** a compromised gateway can send what it sees anywhere.
- **A restore of the whole state volume** from an older backup is not detected (the gateway-key
  ratchet and managed policy versions both assume the volume moves forward).
- **Review findings are heuristics.** Reading the definition is the control.
