# ZoeyMCP threat model

Who might attack a deployment, what each can reach, and the most each can gain once everything
built so far (M1 to M5) holds. The mechanisms are in [design.md](design.md); the invariants the
tests hold the gateway to are G1 to G21 (M3) and H1 to H16 (M4) there, and the portal's are P1 to
P22 (M5) (§8.2).

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

## The admin portal (M5)

The portal is the vault's own listener, on only when the policy has an `admin` block. It restates
T1, T3 (the browser it names), T4 and T7 for the portal and adds eight actors.

| # | Actor | Has | Wants |
| --- | --- | --- | --- |
| T1 | **A compromised agent or sandbox** | as above; in the hardened tier a sandbox on `direct`; in the standard tier an agent container joined to the compose network to reach the gateway | to sign in, redeem or guess a setup code, exhaust the portal |
| T3 | **A hostile page in the operator's browser** (any site) | cross-site requests, top-level navigations (to the OAuth callback too, with any query), frames, DNS rebinding of a name to `127.0.0.1` | cross-site request forgery, clickjacking, reading API answers, phishing a setup code, slipping a grant for its own account into the operator's connect |
| T4 | **A compromised gateway** | as above, plus the ledger report path; in the standard tier it shares the vault's network namespace and can connect to the portal | to rewrite or evict the vault's copy of its ledger, hide sends, fill the vault's disk, talk to the portal as a non-browser client |
| T7 | **A curious reader** of logs, the ledger, the vault's copy or a portal page | shipped logs, files, a screenshot, a page left open | values, prompt text, codes, tokens, recipients |
| T10 | **A stolen session**: one or both halves of a live session | whatever they allow until the session ends | to write secrets, connect a grant to the attacker's account, change passkeys |
| T11 | **Another server on the operator's machine** (another `localhost` port, a dev server, a local tool) | every cookie for `localhost` (cookies ignore ports); it can set cookies there, ask the browser for a `localhost` passkey assertion, and hold the portal's local port while a tunnel is down | to read or plant a session, get an assertion the vault accepts, relay a setup code |
| T12 | **A non-browser peer of the admin listener**: the gateway and sibling containers in the standard tier (the `lan` proxy, agents joined to reach the gateway); another user of the host on the published loopback port | any bytes, headers, connections and timing | to sign in without a passkey, redeem a relayed setup code, exhaust the portal, learn whether passkeys exist |
| T13 | **A hostile OAuth provider answer, a crafted pasted address or a crafted callback** | `error` and its description, scopes, `iss`, the query; sometimes a leaked authorization URL and a code the attacker got for it with its own account | to inject a grant for the attacker's account, mix up two authorization servers, hide text in what the portal shows |
| T14 | **Text someone else controls, shown in the portal** | provider text, ledger fields, store metadata, journal rows, policy names, passkey names | to run script, fake a line of the page, hide or spoof characters |
| T15 | **A passkey thief**: a lost or stolen authenticator, or a taken-over passkey provider account | a working passkey for one host name | a session and step-up on that origin |
| T16 | **A writer of `/state` without the master key**: a tampered or restored backup, another container mounting the volume | every file in `/state` | to add a passkey, plant a setup code, roll back a removal, edit what the portal shows |
| T17 | **The operator's own TLS proxy** in front of an `https` origin | the plaintext of every portal request, the callback's `code` and `state` included | secrets typed into the portal, both session halves |

At most:

- **T1** gains nothing in the hardened tier: the portal listens only on the vault's `egress`
  address, which no agent network reaches. In the standard tier an agent container on the compose
  network is a T12.
- **T3** can't read an API answer (no CORS, preflights refused) and can't make a change: the API
  needs `Sec-Fetch-Site: same-origin`, an `Origin` equal to the portal's, and the session's
  header token, and each refuses it alone. It can't frame the portal. **DNS rebinding** fails on
  the exact `Host` check: the attacker's name stays in `Host`, and only listed origins are
  answered. A fetch, frame or image aimed at the OAuth callback is refused before any sign-in is
  looked at. A top-level navigation to the callback carries the flow's binding cookie, so what
  protects a sign-in from T3 is its `state`, 256 random bits that only the owning session's page
  sees. **With a leaked authorization URL**, T3 can make the operator's browser deliver a code
  for its own account before the operator's approval comes back: the portal holds it and stores
  nothing until the operator confirms with a passkey; the operator's own answer then differs,
  and two different answers end the sign-in with nothing stored. Only an operator who confirms
  before finishing their own approval stores the attacker's grant; the confirmation says not to.
  **It can phish a setup code:** a look-alike page can ask for one and relay it, and anything
  that reaches the listener can redeem it (T12). A code works once, for 15 minutes, and the
  enrolment it allows is logged at `warning` and listed with its origin by `zoeymcp passkeys`. A
  passkey assertion can't be phished: it names its own origin.
- **T4** as a reporter can write false records from the moment of compromise, and no further
  back: a report that doesn't extend the copy's held head is refused, and keeps being refused
  until the operator restarts the chain with a passkey or from the host; the held head is also in
  the vault's logs. It can't evict what the vault received in the last 30 days, and a flood only
  stops further reports, visibly. It can't claim a record the vault wrote, and writes nothing but
  the copy. The orphan check on the Ledger page doesn't bound T4: the gateway picks each send's
  reference and writes the records, so it can cover a send of its own with a fabricated record.
  The check catches a send by a caller that can't write the gateway's ledger. As a peer of the
  standard tier's listener it is a T12.
- **T7** sees names, refs, decisions, outcomes, counts, bindings and health in the portal: never
  a value, a token, a recipient address, an SMTP username, a keyed digest or a Message-ID. The
  vault's copy files hold the gateway's keyed digests, as the gateway's ledger does. Logs gain no
  secret: no setup code, session half, challenge, `state`, pasted address or passkey name.
- **T10** with **both** halves can read what the portal shows, start an OAuth sign-in (a
  nuisance: it replaces a pending one), and end other sessions. It **can't** write or delete a
  secret, complete a connect, reset a credential, change a passkey or restart the ledger chain:
  each needs a fresh passkey assertion bound to that change. With one half it gets nothing.
  Sessions end after 15 idle minutes or 4 hours, at sign-out, at restart, by "end other
  sessions", and when their passkey is removed.
- **T11** receives the cookie half but not the header half, which the page keeps in the tab's
  `sessionStorage`. A cookie it plants pairs with no session. An assertion it gets for
  `localhost` names its own origin and is refused. It can deny the portal: enough planted cookies
  push ours out of the four the vault tries, or overflow the request head; clearing the
  browser's `localhost` cookies ends that. **The honest limit:** a process holding the portal's
  own `localhost` port *is* the origin: it can relay a live sign-in and read a typed setup code.
  Code on the operator's machine is outside what a web origin can defend.
- **T12** reaches only the static files, sign-in, setup-code redemption and the OAuth callback;
  every other route answers 401 before reading a body. It can't sign in without a passkey or
  guess a 120-bit code. It **can** redeem a relayed code (T3's case), and with continuous traffic
  it can deny the portal (the unauthenticated rate, the sign-in table, the unauthenticated
  request slots). Requests with a valid session have slots of their own, and the CLI keeps
  working. Answers are alike whether or not passkeys exist.
- **T13** can't inject a grant without the sign-in's `state`, and the callback also needs the
  flow's binding cookie, set in the browser that started it, so a callback from any other
  browser touches nothing. Through the operator's own browser it is T3's leaked-URL case. Each
  credential has its own callback address, so an honest server's answer reaches only the flow it
  was registered for; a paste is checked against the flow it names. A crafted error answer can
  end a sign-in and show its cleaned, capped text, labelled as the provider's. Extra scopes are
  stored and flagged.
- **T14** gets plain text, hidden characters shown as `[U+XXXX]`, within a cap, set with
  `textContent` only. No script runs: the CSP allows only the portal's own files, Trusted Types
  refuse every HTML sink where the browser supports it, and the files hold none.
- **T15** gets a session and step-up on that passkey's host name, as the operator would.
  Recovery is `zoeymcp setup-code --reset`, which removes every passkey and ends every session.
- **T16** can't add a passkey, plant a setup code or change a counter: both files are MAC'd under
  a key derived from the master key, and a bad MAC turns portal sign-in off while the proxy keeps
  serving. It **can** put back an older, validly sealed passkey file, bringing back a passkey
  removed since (below). It can edit the store's display metadata and the reported copy, which
  are shown labelled and never decide anything.
- **T17** sees what it carries, as the `lan` proxy sees client tokens. Its access log keeps the
  callback's `code` and `state` unless told not to (operations.md has a log format that drops
  them); the code is single use and useless without the vault's PKCE verifier, and the `state`
  without the binding cookie. The `localhost` and SSH-tunnel paths have no proxy.

## The confused deputy

ZoeyMCP issues no OAuth tokens to agents and has no dynamic client registration on the agent's
side: client tokens are static and set by the operator. So the MCP specification's
confused-deputy precondition (a proxy that lets MCP clients register dynamically) doesn't hold.
The portal's OAuth connect is the operator's, for the vault's own credentials, and a test checks
that neither the proxy listener nor the portal serves authorization-server metadata, a
registration endpoint or a token endpoint. Later milestones must keep it that way, or add
per-client consent first.

## Accepted limits

- **Silent drift** between timer checks, as above.
- **Modern stateful servers** see one principal for every client.
- **Deliberate disclosure** of a credential by the server that was given it.
- **Standard-tier egress:** a compromised gateway can send what it sees anywhere.
- **A restore of the whole state volume** from an older backup is not detected (the gateway-key
  ratchet and, from M6, managed policy versions both assume the volume moves forward). For the
  portal it brings back every passkey removed since the backup, with its older counter: a removed
  passkey that was lost or stolen works again. The vault logs the passkey file's `generation` at
  start (`passkeys_loaded`), so a lower number shows a restore. **After any restore, run
  `zoeymcp passkeys` and remove what shouldn't be there**, or `zoeymcp setup-code --reset`. The
  vault's copy of the gateway's ledger goes back too: the gateway refills it, or it refuses with
  a `gap` if the gateway pruned records meanwhile.
- **Review findings are heuristics.** Reading the definition is the control.
- **A client can auto-accept**, and a holder of an attended client's token can approve its own
  calls (above). The gateway can't tell a human's answer from software's.
- **A compromised gateway or toolkit can skip gateway approvals** until M8.
- **Markdown clients** might render something the markup guard doesn't anticipate; `renders:
  markdown`, the default, refuses the known constructs.
- **The portal (M5):**
  - **The authenticator shows nothing about the change.** A step-up confirms the summary the page
    shows; script controlling the page could show one change and ask for another. The CSP,
    Trusted Types and text-only rendering keep script off the page.
  - **The operator's machine is trusted** (T11): a process holding the portal's own `localhost`
    port can relay a sign-in and read a typed setup code. An `https` origin with a real
    certificate narrows this.
  - **Standard tier:** the gateway and sibling containers reach the admin listener (T12), so only
    passkeys and single-use setup codes protect it there, and they can deny it with continuous
    traffic. The hardened tier publishes it on the host's loopback only. Ports published on
    `127.0.0.1` stay off the LAN only on Docker Engine 28.0 or later, which ZoeyMCP can't check.
  - **Setup codes can be relayed** (T3, T12): a code typed into the wrong page works for whoever
    redeems it first, within 15 minutes. `setup-code --wait`, the `warning` log line and
    `zoeymcp passkeys` make it visible; they don't prevent it.
  - **The reported ledger is trust on first use,** and again after every chain restart.
  - **Synced passkeys** are as strong as the provider account that syncs them (T15). The passkey
    list marks them.
  - **Store metadata and the reported copy** are display-only, and a writer of `/state` can edit
    them (T16).
  - **A leaked sign-in link and a page in the operator's browser** can deliver a code for the
    attacker's account first (T3). An operator who confirms it before finishing their own approval
    stores that grant; paste is always available instead.
  - **A TLS proxy** in front of an `https` origin sees every secret typed into the portal (T17).
  - **The callback's address bar.** A refused callback answers in place, so its `code` and `state`
    stay in that tab's address and history; both are useless without the vault's verifier and the
    binding cookie.
  - **uvicorn's own answers** (a malformed request line, two `Host` headers, a head over 16 KiB)
    come without the portal's headers.
  - **Browsers below the floor** (Chrome or Edge 85, Firefox 119, Safari 16.4) are refused: they
    don't send the Fetch metadata headers the portal requires. Trusted Types is enforced only by
    browsers that support it.
