# Clients

This page is about the MCP clients your agents run: how to connect one to the gateway, what an
agent runtime can reach without the gateway, and what to check in a client before it answers
approvals. The commands behind each step are in [operations.md](operations.md).

## Connecting a client

### What a client needs

An agent's MCP client needs three things, and nothing else of ZoeyMCP's:

- **One URL per server**, `/s/<server>/mcp` on the gateway. The client sees each as an MCP server
  of its own, with its own tools, unprefixed. Where the gateway is depends on where the agent runs:
  - on the gateway's host, in the standard tier: `http://localhost:8090/s/<server>/mcp`, published
    on loopback only ([operations.md](operations.md) §9);
  - in a container on the hardened tier's `agents` network: `http://gateway:8090/s/<server>/mcp`
    (operations.md §9);
  - on another host: `https://<ZOEYMCP_LAN_HOST>:8443/s/<server>/mcp`, through the `lan` profile's
    TLS proxy (operations.md §15). A token sent over plain http is readable on the network, so
    never reach the gateway from another host without TLS.
- **Its client token**, sent on every request as `Authorization: Bearer zgc1-...`. Each agent has
  its own, made with `zoeymcp client-token`; the policy holds only its hash and the servers it may
  use (operations.md §10). Never give one agent's token to another: the token is the client's
  identity, in the gateway's log, its limits and its approvals.
- **Trust in the TLS certificate**, where the `lan` proxy is in front: install its CA's
  `zoeymcp-lan-root.crt` as trusted on the client's machine (for Node-based clients,
  `NODE_EXTRA_CA_CERTS=./zoeymcp-lan-root.crt`), or give the proxy a certificate your clients
  already trust (operations.md §15).

The gateway also checks the name the client uses: the `Host` it sends must be in `gateway.hosts`
(a 421 says it isn't), so a name other than the shipped ones (another host name, or a service name
on a container network) is added there first, in managed mode by an import (operations.md §15). A
client that sends an `Origin` header, as one running in a browser does, needs that origin in
`gateway.origins` (a 403 says it isn't). The gateway offers no OAuth sign-in: it answers a missing
or wrong token with a 401 and no sign-in metadata, so a client that tries to sign in by itself
finds nothing to sign in to, and must be given the header. What each refusal means is in
operations.md §18.

### A client configured from a file

Most clients read their MCP servers from a JSON file. The keys differ between clients (what they
call the HTTP transport, where headers go), but the shape is the same, one entry per server:

```json
{"mcpServers": {"notes": {"type": "http", "url": "http://localhost:8090/s/notes/mcp",
                          "headers": {"Authorization": "Bearer zgc1-..."}}}}
```

### A client configured from a command line

Some clients add a server with a command instead (an "add an MCP server" subcommand). Give it the
same three things: the HTTP transport, the server's URL and the `Authorization` header. Then look
at where the command wrote them:

- A token on a command line can stay in the shell's history and shows in the process list while
  the command runs. Prefer a way to give the header that the client reads from a file or its own
  configuration; otherwise run the command where nobody else sees the process list, and remove it
  from the shell's history afterwards.
- Check which file the client wrote, and its scope. A configuration kept with a project can be
  committed to a repository or read by the agent working in that project: keep the token in the
  client's own per-user configuration, which the agent can't read (below).

### Keeping the token out of the agent's reach

Anyone holding a client's token can call every server the client may use, and answer its
approval prompts (below, "The client token is the approval credential"). Keep it in the client's
own configuration, never in an environment, file or repository the agent's code or sandbox can
read. Where the gateway sees the client directly, pin the client's source address too
(`sources:`, operations.md §10). If a token leaks, cut it off: in managed mode, take every server
from the client in the portal, then import its removal; in declarative mode, remove it and reload
(operations.md §35).

### A client that can't send an Authorization header

The gateway reads the token from the `Authorization` header only: never from the query string, a
cookie or another header. A URL with the token in it is refused like one with no token, and
logged as `auth_refused` with `reason` `no_token`. There is no setting that changes this, since a
token in a URL ends up in logs and histories.

Such a client can still use the gateway through a small local adapter: an MCP server the client
starts on its own machine (over stdio, which needs no header), which forwards each message to the
gateway's URL with the header added. The adapter then holds the token, so it needs the token's
custody: run it outside the agent's sandbox, with the token in its own configuration rather than
on its command line, and check that it sends the header on every request, `GET` and `DELETE`
included. Don't put the token in a proxy that adds it for whoever connects: that makes an
endpoint with no token at all.

### Per-client notes

Not written yet. The steps for particular clients are recorded here when each is checked against a
real gateway, together with the approval checks below; until then, use the general shape above
and your client's own documentation for where the URL and the header go.

## What reaches servers without the gateway

Agent runtimes and MCP clients increasingly have their own ways to reach MCP servers and other
services: a built-in connector directory, an "install an MCP server" command, a marketplace, or
connectors set up in the vendor's account and synced to every client signed in to it. A server
reached that way is reached directly, by the runtime or by the vendor's own service, not through
the gateway: nothing is pinned, reviewed, sanitized or approved, no credential stays in the vault,
and ZoeyMCP logs nothing of it. ZoeyMCP can't see or stop it. For every client and runtime you
connect:

- turn those features off, or restrict them in the client's own settings or policy, so the
  gateway is the only path to MCP servers;
- after setup and after each update, check the client's list of MCP servers (and the connectors
  in the vendor's account): it should hold only the gateway's `/s/<server>/mcp` entries;
- check that the runtime adds no tools of its own beside each server's that reach the same
  services.

Network confinement helps only in part: an agent container whose only network is the hardened
tier's `agents` network has no route out, so a server installed inside it can't reach the
internet, but a connector that runs in the vendor's service doesn't go through that container at
all.

## Waking an agent on a change, before feeds

ZoeyMCP has no feeds yet: plain HTTP endpoints an agent runtime could poll to learn that something
changed (new mail, say) without calling a tool. They are planned with the first toolkit that reads
a mailbox. Until then, a runtime that wakes its agent on a change can use a small monitor script:

- Run it as part of the agent runtime itself (its own scripts, on its host or in its own
  container), not inside the agent's sandbox, where the agent's code could change what it does.
- Give it a vault route of its own instead of the real credential: the route holds the credential,
  and the script holds only a placeholder, a long random value the route lists under `callers`,
  with rules allowing only the `GET` paths the check needs (the `stats` route in
  [deploy/compose.hardened.yaml](../deploy/compose.hardened.yaml) has this shape). In the hardened
  tier the script's container joins the opt-in `direct` network to reach the vault. Such a route
  is a plain API route: the vault injects the credential and applies the route's rules, but
  nothing on it is pinned, reviewed or approved, and its answers reach the script without the
  gateway's sanitizing.
- Have it print only stable lines that carry nothing from the upstream: a count or a fixed "new
  mail" line, never a subject, a sender or a body, since whatever it prints reaches the agent's
  context unsanitized. The agent then reads the content through the gateway's tools, whose
  results are sanitized and whose approvals apply as for any other call.

## Approvals in the client

An `approve` tool asks the human through the agent's own MCP client (an elicitation, in form
mode), so whether a prompt is safe to answer depends on that client. This section lists what to
check in a client before marking it `attended`, and what has been checked so far.

ZoeyMCP renders every prompt itself and refuses any text that could hide or disguise content
(hidden characters, wide runs of spaces, stacked combining marks, and, for clients that render
Markdown, code fences, HTML and links). It never cuts a prompt: one over the budget is refused,
and the agent is told why. What it can't control is how the client shows the text and what the
client lets the human or its own settings do with it.

A client you can't check, or one nobody watches, can be asked out of band instead: mark it
`approvals: {out_of_band: true}` and its prompts go to the vault's approvers (a Telegram bot, the
portal's Approvals queue), not to the client ([operations.md](operations.md) §19, §36). A tool
marked `vault_approval` is asked there for any client that is attended or out of band (any other
client is refused). What an out-of-band approval trusts in place of the
client (the chat service, your chat account, the portal page) is in operations.md §36.6.

### What to check

For each client, and each version you deploy:

| Check | Why it matters | Policy setting it informs |
| --- | --- | --- |
| Shows the whole message, and up to what length | a client that truncates shows less than was approved | `approvals.budget_chars` (per client, lower only) |
| Shows plain text or renders Markdown | Markdown can hide text or fake structure | `approvals.renders`: `plain` only if it never renders |
| Renders URLs as links | a link's target can differ from its text, and a fetched preview tells a server the prompt was shown | `renders: markdown` refuses `](`; a bare `http(s)://` URL isn't refused for any `renders` value, so check whether the client makes one a link. The vault's approvers change no byte either: Telegram gets the whole text in one monospaced block with link previews off, and the portal shows it as text |
| Can auto-accept (by default, or through hooks or settings) | an auto-accepting client approves anything; the prompt protects nothing | don't mark such a client `attended`; `confirm_code: true` stops blind hooks only |
| Offers a persistent "always allow" for elicitations | one click would approve every later call | as above |
| Merges identical prompts | two calls could share one answer | each prompt carries its own ref; check the footer |
| Declines when there is no way to answer | no answer must mean no call | the gateway times out and records `timeout` |
| Honours `notifications/cancelled` | a cancelled call's prompt should go away | the gateway withdraws on cancel either way |
| Protocol eras it speaks | modern clients answer through retries; legacy ones on the call's stream | both are served |
| Has its own connectors or MCP-install features | a server reached that way bypasses the gateway, its pins and its approvals | none: turn them off ("What reaches servers without the gateway", above) |
| Its tool-call and idle timeouts | a prompt can't outlive the client's tool call | `approvals.timeout` below the client's tool-call timeout; for out-of-band waits, `approvers.block_seconds` below it too: past it the call answers `pending <ref>` and the agent collects the result with `check_approval`. Progress notifications are sent while a call blocks, and never relied on to keep a client waiting |

How to check one: run the gateway with the example policy and a test `approve` tool, make a
call, and look at the prompt as the client shows it: the first line (`Approval request <ref>`)
and the last (`End of approval request <ref>`) must both be visible, and the ref must match.
Then decline, let one time out, cancel one, and look for any setting that answers for you.

### Checked

| Client | Version | Date | Result |
| --- | --- | --- | --- |
| MCP Python SDK `Client` (the acceptance tests' agent) | 2.3.0 | 2026-10 | shows the message whole to its callback; no auto-accept unless the callback does; answers in both eras; honours cancellation. `renders` is the caller's choice. |

### Reported, not checked

Every other client is unchecked. Treat each as able to truncate, render Markdown and auto-accept
until you have checked it as above, and record what you find here with the client's version and
the date. A client that can auto-accept without a human must not be marked `attended`.

### Known deviation: the pending answer

A call that waits out of band past `approvers.block_seconds` answers `pending <ref>` as a tool
error (`isError: true`) with no `structuredContent`, even for a tool with an `outputSchema`. The
MCP specification says such a tool returns conforming structured results, with no exception for
errors; the reference SDKs skip output validation when `isError` is set, and ZoeyMCP relies on
that. A client that validates error results too would reject the pending answer: check it, and
keep `block_seconds` long enough for its calls not to reach it, or don't hold its tools.

### The client token is the approval credential

Anyone holding an attended client's token can make calls and answer their prompts, with or
without `confirm_code`. Keep the token out of the agent's sandbox (in the client's own
configuration, not an environment the agent can read), and pin the client's source network
where the gateway sees the client directly (the hardened `agents` network, loopback). Behind the
`lan` proxy the gateway sees only the proxy, so a source pin means nothing there. A prompt asked
out of band isn't the token's to answer: mark the client `out_of_band`, or the tool
`vault_approval`.
