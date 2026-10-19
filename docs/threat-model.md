# ZoeyMCP threat model

Who might attack a deployment, what each can reach, and the most each can gain once everything
built so far (M1 to M4) holds. The mechanisms are in [design.md](design.md); the invariants the
tests hold the gateway to are G1 to G21 (M3) and H1 to H16 (M4) there (§8.2).

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

## Approvals, mail and toolkits (M4)

M4 sharpens T1 and adds four actors.

| # | Actor | Controls | Wants |
| --- | --- | --- | --- |
| T1 | **A prompt-injected or compromised agent** | every argument, call timing and retries; `inputResponses`, `requestState`, `_meta`; maybe its own client token, if its sandbox can read it | a consequential call without informed consent: approve its own call, pre-answer, replay an accept, swap arguments between ask and run, flood or merge prompts, word arguments to mislead, reach a send route from a routine tool |
| T1a | **A client that answers by itself** (an auto-accept hook, an LLM-backed callback, a remembered "always") | the answer | the same as T1 |
| T6 | **A compromised toolkit or toolkit dependency** | code in the gateway process | send without approval, send other content, widen recipients, exfiltrate |
| T7 | **A curious reader** of logs or the ledger | shipped logs, the ledger file | contents, recipients, argument values, prompt text |
| T8 | **The mail path**: the egress proxy, a man in the middle, a hostile SMTP server | bytes on the path | the SMTP password, a downgraded session, a false outcome |
| T9 | **A careless approver** | a phone and little time | to understand a prompt at a glance |

At most:

- **T1** can only *cause a prompt* for an `approve` tool: one at a time per client, within the
  hourly cap, with a cooldown after each decline. It can't answer on a channel it doesn't own,
  reuse an answer, or change the arguments after the human saw them, and its words reach the
  human only as JSON-escaped values or inside a toolkit's declared layout, under the text rules.
  **If it holds the token of an attended client, it can make the call and answer its own prompt**,
  with or without `confirm_code`: the prompt goes back to whoever made the call. Keep the token
  out of the sandbox and pin the client's source where the gateway sees it directly
  ([clients.md](clients.md)); M8's out-of-band approver closes this.
- **T1a** is a client that isn't attended, so it must not be marked `attended`. If it is, the
  confirmation code defeats a blind hook, but not an LLM that reads the message.
- **T2** gains nothing new: its text never enters a prompt, and its own elicitation or
  `input_required` is refused during an approved call too.
- **T6 is T4.** Code in the gateway process can skip the gateway's approvals and call
  gateway-bound routes; toolkits aren't isolated from each other. What still holds is in the
  vault: fixed sender and recipients, the expected-recipient check, the rolling limit, `paused`,
  route allowlists, and the send journal, which the gateway can't edit. In the standard tier a
  toolkit dependency also has the gateway's egress. The derived-image recipe lowers the chance of
  T6; M8's vault-side approvals close the gap.
- **T7** sees names, refs, outcomes, counts and keyed digests; never argument values, prompt
  text, subjects, bodies, recipients, handles or secrets.
- **T8** sees TLS only: certificates are verified against certifi's roots, AUTH never goes out
  before TLS, and a break after the final dot is recorded as `unknown`, never retried.
- **T9** sees a short fixed frame, plain text, a ref and a deadline. Keep routine calls in
  `allow`, so prompts stay rare enough to read.



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
- **A client can auto-accept**, and a holder of an attended client's token can approve its own
  calls (above). The gateway can't tell a human's answer from software's.
- **A compromised gateway or toolkit can skip gateway approvals** until M8.
- **Markdown clients** might render something the markup guard doesn't anticipate; `renders:
  markdown`, the default, refuses the known constructs.

