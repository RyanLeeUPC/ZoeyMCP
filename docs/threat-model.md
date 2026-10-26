# ZoeyMCP threat model

Who might attack a deployment, what each can reach, and the most each can gain once everything
built so far (M1 to M7) holds. The mechanisms are in [design.md](design.md); the invariants the
tests hold the gateway to are G1 to G21 (M3) and H1 to H16 (M4) there, the portal's are P1 to
P22 (M5), onboarding's, the egress role's and the bridge's are X1 to X24 (M7), and managed
policy's, drift review's and prompts' and resources' are Y1 to Y29 (M6) (§8.2).

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
  environment, and it can't write policy, in either mode (M6, below). Recovery: restart
  (standard tier), or rotate the gateway key (hardened), then rotate client tokens. In the
  standard tier it shares the vault's network namespace, so it has egress; the hardened tier has
  none.

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
  toolkit dependency also has the gateway's egress, which M7's egress role doesn't confine: it
  confines hardened bridges only. The derived-image recipe lowers the chance of
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

## Onboarding, the egress role and bridges (M7)

M7 lets the vault fetch and register at servers the operator names by URL, adds a review path
between the gateway and the vault, ZoeyMCP's own egress proxy, and bridges that run third-party
stdio programs. It restates T2, T4, T7, T10, T13 and T14 for these surfaces and adds six actors.
A bridge runs in one of three placements: **A**, the hardened tier, a container of its own;
**B**, the standard tier, a process of the one container with a uid of its own, listening on a
Unix socket; **C**, another host, reached over https.

| # | Actor | Has | Wants |
| --- | --- | --- | --- |
| T2 | **A hostile upstream MCP server, after review** (restated) | as before, plus its own DNS: it can make its committed host name resolve anywhere at any time | to turn the vault's route into a request to the vault's networks (the host's LAN, `internal`, `direct`, cloud metadata), carrying its own credential and the gateway's body |
| T18 | **A hostile MCP server met at onboarding** | the probe's answer (status, `WWW-Authenticate`), its protected-resource metadata, its DNS, redirects, documents of any size and type, timing | to make the vault fetch or post to an internal address; to name an authorization server it controls; to inject YAML into a fragment; to hide text on the review screen; to be onboarded with a wider audience than its own URL |
| T19 | **A hostile authorization server met at onboarding**, or an honest one impersonated by T18's metadata | its metadata (issuer, endpoints, flags), its registration answer (client ID, secret, redirect addresses, authentication method, grant types, error text), its authorization answers (`iss`, `error`, `code`), its DNS | to get a code or refresh token meant for another authorization server (mix-up); to make the vault send a client secret or code to an internal service; to plant hostile strings in the committed policy; to downgrade PKCE or the flow |
| T20 | **Third-party code in a bridge**, possibly holding a real secret, in any placement | code execution as the bridge's uid: the program and, through same-uid tracing and `/proc`, the bridge process; the bridge's environment. **A**: whatever its container's networks reach. **B**: the standard container's network namespace (every TCP listener there, the host's network and the internet, with proxy settings it may ignore), not other uids' memory, files or sockets, every other bridge's socket included. **C**: whatever its host gives it | to call another bridge's tools around the gateway's include lists, pins and approvals; to reach the gateway, the portal, the vault's other routes or the internet beyond its list; to exhaust the bridge or the vault; to leak its secret |
| T21 | **A compromised egress role** | the egress key (read-only allowlists), every tunnel's TLS bytes, each listener's network | to read secrets, misroute or deny tunnels, reach the vault's other paths or a bridge's MCP listener |
| T22 | **A hostile resolver path**: DNS rebinding by anyone who controls a name the vault or the role resolves | answers that change between lookups; mixes of public and private addresses | to pass a check with one address and connect to another |
| T23 | **A peer that can reach a bridge's listener**: **A**, anything put on a bridge's networks by mistake; **B**, any other process in the standard container (the gateway's uid, a toolkit, another bridge's program); **C**, anything on the remote host's network path | any bytes to the listener; in B, any socket call its own uid allows | to call the bridge's tools without the gateway; to tunnel out as that bridge; in B, to stand in for the bridge and receive the vault's requests with its token |
| T4 | **A compromised gateway** (restated) | as before, plus the review-job poll and the review report path | to show the operator one definition and pin another; to hide findings; to flood the vault with reports |
| T10 | **A stolen portal session** (restated) | as before | to make the vault fetch arbitrary URLs, register clients at arbitrary servers, read review reports |
| T13 | **A hostile authorization answer, paste or callback** (restated) | `iss`, `error`, `error_description` | to have provider text shown from an answer that came from the wrong authorization server |
| T14 | **Text someone else controls** (restated) | tool definitions, metadata strings, registration error text | to run script, fake a line on the review screen or in the CLI, smuggle a line into a fragment |
| T7 | **A curious reader** (restated) | logs, CLI output, fragments | a client secret, a registration token, a code, a verifier, the egress key, a bridge token |

At most:

- **T2** gains no new reach: every vault connection (routes, tokens, revocation, discovery,
  registration) made without an egress proxy resolves the name once, refuses if any address is
  loopback, private, CGNAT, link-local, multicast, reserved or unspecified, or an IPv4-mapped,
  IPv4-compatible, 6to4, Teredo or NAT64 form of one, unless the policy lists that exact
  `host:port` in `egress_private` (or it is a local MCP route's upstream), and connects only to
  the addresses it checked, each in turn within one deadline. With an egress proxy, the address
  check is the proxy's (see the accepted limits). It still holds its own credential.
- **T18** can make the vault send, before the operator confirms anything, at most two fixed POSTs
  to the URL the operator typed (the probe and, on a 400, one legacy `initialize` probe) and GETs
  of well-known, challenge-named or issuer-derived metadata URLs, nine requests in all within
  30 s, each over https to a global address with a public-looking name, with no redirect followed,
  no cookie kept, nothing secret sent and at most 64 KiB read. It can make onboarding fail, with a
  reason. It can't name an authorization server the operator doesn't see: every issuer, endpoint
  and host is in the plan, and a second authorization server is refused until the operator names
  one. It can't widen the audience: the `resource` sent is the one its metadata published, which
  must equal the URL (or origin) it was fetched for. Its strings reach the operator only with
  hidden characters revealed, and reach a fragment only as validated URLs and scope tokens.
- **T19** can refuse or misanswer registration, and onboarding stops with its cleaned, capped
  error. It can't downgrade: no S256, no `code` flow, a non-https endpoint, an issuer that differs
  by one byte, an authentication method the vault doesn't speak, or a redirect address changed in
  the answer each refuse it, and a client ID that reads as a secret reference (`store:`, `env:`)
  is refused. It can't steer an honest server's answer into its own flow when that server sends
  `iss`: the answer is refused before its `error` is read. Without `iss`, mix-up stays possible
  (below); each registration's own redirect address then narrows it to an attacker who can also
  register at the honest server with that address. The first request that carries a code,
  verifier, client secret or token goes only to a token endpoint written in the committed, loaded
  policy, through the same address guard; a client secret is stored at registration under the
  binding the plan predicts, and a committed policy that derives another can't use it.
- **T20** in every placement can lie in every answer, which the gateway treats as it treats any
  hostile upstream (pins, schemas, sanitizing, approvals), and can take over its own bridge
  process (same uid), which gives it little: the bridge holds only a hash of its token, but every
  request carries the token, so the program can read its own bridge's token from memory. That
  token reaches nothing but its own bridge, since `check` requires a store secret no other route
  or connector uses; it holds no other bridge's token, gateway key or client token. **In A** it
  reaches only its own networks: the vault's listener on `bridge-<name>`, where it has no identity,
  and, through the egress role, the `host:port` entries of its route's own egress list. It can't
  reach another bridge, the gateway or the portal. **In B** it is unconfined: it reaches every TCP
  listener in the container and the internet, but each listener still asks what it asks of anyone
  (the gateway a client token, the portal a passkey session, a vault TCP listener a placeholder),
  and its own uid keeps it out of the vault's and the gateway's memory, files and Unix sockets. It
  can't reach or stand in for another bridge: each bridge's socket sits in a directory only that
  bridge's uid may write and only the vault's group may enter, and the vault accepts on it only a
  peer running as that bridge's uid. It shares the container's memory, processes and CPU, so it can
  starve the vault and the gateway. **In C** it has what its host gives it; ZoeyMCP's reach to it is
  the route alone. Holding a real secret, it can send it to its own egress hosts (A) or anywhere
  (B, C); `check` warns and names them.
- **T21** can deny or misroute (a tunnel to the right name but an address it chose, which the
  endpoint's TLS check then refuses) and can see which hosts each source uses. It can't read TLS,
  can't present the gateway's or any route's identity (its key is accepted on one path only), and
  shares no network with a bridge's MCP listener or with the vault's plaintext hop to a bridge.
- **T22** gets nothing: one lookup, every answer checked, a refusal if any address fails, a connect
  only to the checked addresses (each in turn, within one deadline) and no second lookup, in the
  vault and in the role.
- **T23** needs the bridge's token, which only the vault holds, in every placement: an
  unauthenticated call is refused before any byte reaches the program. In A the role's listener it
  reached gives it at most that source's egress list. In C the token is the only barrier, and
  `check` refuses plain http beyond a loopback or private address, so the token never crosses a
  public network in clear. In B file permissions come first: the socket's directory is a tmpfs of
  the bridge's own (its uid, the vault's group, mode 0750), so the kernel refuses every other uid's
  connect, and only the bridge's uid can create a socket there, whether the bridge runs, was
  refused or has exited. The bridge also cuts any peer that isn't the vault's uid, and the vault any
  peer that isn't that bridge's uid, so a directory the bridge's own program loosens lets no other
  uid call it or stand in for it. A route to a loopback TCP address there, which any process could
  answer, is a health error.
- **T4** can report false listings for a review the operator asked for, but the vault recomputes
  every pin from the definition beside it, so the operator approves what they read. It can omit
  findings (they are heuristics; reading the definition is the control). It reaches only the new
  paths' caps: one waiting poll, two jobs, a report capped by the gateway's limits. It still can't
  write policy.
- **T10** can start discovery of any public URL, which the address guard and the fetch caps bound,
  and read review reports. A discovery that lifts the guard for a private server, a registration
  and a client secret's write each need a fresh passkey prompt, so a stolen session can't probe
  the vault's networks, register a client, store a secret or change policy.
- **T13** sees no provider text from an answer whose `iss` doesn't match.
- **T14** reaches the page only as text, the CLI only with hidden characters revealed, and a
  fragment only as validated values: every scalar is a double-quoted string of printable ASCII
  that passed its schema check, a `$` from the network is refused, and the compose form writes
  every `$` as `$$`.
- **T7** sees in logs and output no client secret, registration token or address, code,
  verifier, `state`, egress key, bridge token, registration answer body or URL query; a bridge's
  program's stderr is logged as text only when the operator asks for it (and it may then print
  the program's environment values).

## Managed policy, drift review, prompts and resources (M6)

M6 lets the vault write policy in **managed mode**: sealed revisions under the vault's state
volume, changed through stepped-up portal saves or by the host over the admin socket (an export,
an edit and `zoeymcp policy import`, or the offline `--state` forms). Declarative mode is
unchanged: no portal or socket route writes policy there. M6 also adds the gateway's status
report and restore witness, drift review in the portal, and prompts, resources and completions a
server may enable. It restates T2, T4, T10, T14, T15 and T16 and adds seven actors.

| # | Actor | Has | Wants |
| --- | --- | --- | --- |
| T15 | **A passkey holder** (restated: a thief of the authenticator or of the passkey provider's account, or anyone with a session and one fresh assertion) | step-up on one origin, now including **policy saves** in managed mode | to give an agent of theirs access (a client token, a placeholder caller, another server for an admitted client); to move tools to `allow`; to send an `env:` secret to a host they control; to lower a key generation; to roll back to a revision that revives a revoked agent or a re-pinned definition; to lock the operator out (remove `admin` or its origin); to clear drift marks |
| T10 | **A stolen session** (restated) | as before | everything in T15's list without a passkey: to prepare saves and read their plans (which show what a save would change), to read history and diffs, to queue fresh reviews |
| T16 | **A writer of `/state` without the master key** (restated) | every file in `/state`, now `/state/policy/` and `/state/policy-anchor.json` too | to replay an older revision or head, delete the newest revisions, delete the whole store so the vault seeds again from an older `ZOEYMCP_CONFIG`, restore `/state/policy` alone from a backup, mix files from two backups, or plant a revision from another deployment that shares the master key |
| T24 | **A reader of `/state` or of a backup of it, without the master key** | every byte of the volume, at rest | placeholders, connector account details, `token_headers` and forced query values, client token hashes, the history of every policy the deployment ran |
| T25 | **A crafted policy document** handed to `policy import` (a shared example, an export someone else edited, an attacker's file), parsed by the host's command | any bytes up to the cap | YAML that means something other than it looks (tags, NEL line breaks, deep nesting that crashes the parser); an `env:` reference to a `ZOEYMCP_` variable; a new client, caller or `admin` origin hidden in a long document; a lowered key generation; a pin set back to a retired definition |
| T26 | **A thief of an export file** | the export at rest (the operator's disk, a git repository, a chat paste) | placeholders and token hashes (the agents' route credentials, the clients' identities), connector account details |
| T27 | **A hostile upstream's other surfaces** (T2 restated for prompts, resources and completions) | prompt and resource-template definitions, prompt messages (user and assistant roles), resource contents and the URIs they name, completion values, list changes timed around a review | to inject instructions in the user's or the assistant's voice; to smuggle unreviewed resources inside a read of a reviewed one; to probe unreviewed names through completions; to change a prompt after review; to hide text in a definition |
| T28 | **Hostile text in a drift diff or a plan** (T14 restated) | both sides of a drift diff, every policy name in a plan, imported strings | to run script on the review screen or the Policy page, fake a line of the plan the operator confirms, hide a character that changes what is pinned |
| T4 | **A compromised gateway** (restated) | as before, plus the status report path and the witness | to hide drift from the portal, report a false status, claim a revision it never saw (a false restore alarm), stay silent about one it did see, show a false old definition |
| T29 | **A concurrent writer** (not an adversary: a second portal session, the socket, a stale tab) | a save prepared against an older revision | to overwrite a newer revision it never read |
| T30 | **The operator's own mistake** (not an adversary) | a save, rollback or import that removes the portal's origin, moves `admin.listen`, raises a key generation without giving the new key, or breaks a binding | an outage or a lockout with no way back |

At most:

- **T15** gains, in managed mode, exactly the portal's edit set: it can include, re-pin and
  classify tools of servers already in the policy (a re-pin only to a definition the vault itself
  verified in a review of the running policy), move tools from `approve` to `allow` (one from a
  server's page, or
  any number in one review save, each a sentence of its own in the plan the assertion confirms
  and each logged `tool_allowed`), decline tools, onboard a new server whose route accepts only
  the gateway and whose credential is a new store or OAuth secret, open egress to a private
  address for that onboarded server (after a stepped-up private discovery; it takes effect at
  once), give an existing client an existing server (one client per prompt, a logged weakening),
  pause or limit a connector, clear marks the gateway agrees are clean, and roll back to a
  revision that is narrower or neutral (which may remove what was added since). It **can't** add
  a client token or a placeholder caller, name a new `env:` variable or send an existing one to a
  new origin, change `admin`, lower a key generation, restore a retired pin, revive a removed
  client, move a tool to `allow` without that move's own row in the plan (a re-include as `allow`
  of a definition once classified `approve` is a move too), widen anything through a rollback,
  or change approvals settings, `gateway.limits`, the egress proxy settings or a connector's bound
  constraints (its host, port, sender and recipients stay the host's, changed by an import). So
  it can widen what *the agents already admitted* may call without a prompt, and what an
  onboarded server may reach on the private network; it can't admit a new agent or move a
  secret. Recovery stays `setup-code --reset`, then a host rollback to a revision before the
  theft.
- **T10** can read plans, history and diffs, which show only what the policy view shows, and
  queue reviews; it changes nothing without a passkey.
- **T16** can't forge a revision, the head or the anchor (each is MAC'd under a key derived from
  the master key) and can't decrypt a revision. An older revision replayed below the head fails
  the chain and is quarantined (history shows the gap); a head behind the anchor is refused at
  start; `/state/policy` deleted beside the anchor, or the anchor beside the store, refuses the
  start, and both deleted on a used volume refuse to seed until the host says so; `/state/policy`
  restored alone is behind the anchor and refused. A revision from another deployment fails on
  its deployment ID even under a shared master key, and once a master-key rotation is recorded, a
  file under the retired key is refused even while the old key is still set. What the volume
  can't catch is in the limits below; the gateway's witness catches most of it.
- **T24** reads only ciphertext for every revision's policy and ratchet; the headers it can read
  hold revision numbers, times, kinds, salted digests (which confirm no guessed policy) and the
  passkey fingerprint of each save.
- **T25** meets the strict loader first: a tag, an NEL or line or paragraph separator, a key that
  isn't a string, nesting deeper than 64, an integer of 33 digits or more, or any parser failure
  is a refusal with a reason. What loads goes through `check` with the vault's own environment,
  so a `ZOEYMCP_` reference is refused; the plan then shows every changed path through the policy
  view, widenings first (a new client, caller or origin is a widening row); bringing back what the
  store retired, or a new `env:` name or reach, is refused unless the host names it
  (`--allow-revive`, `--allow-env`); dropping a passkey origin or moving `admin.listen` asks for
  the origin typed; and `--yes` refuses any plan that widens unless `--accept-widening` is given
  too, so a script that pipes in someone else's edit can't admit a new agent by accident. A new
  client, caller or origin needs no named grant: reading the plan, or `--accept-widening`, is the
  host's confirmation.
- **T26** gets placeholders and token hashes, never a secret value (the policy holds none), the
  master key or a store entry. The export's first lines say so, and operations.md says to keep it
  like a secret.
- **T27** reaches an agent only through a server that enables the kind, for an included and
  pinned definition served exactly as pinned. Prompt messages pass the text rules with hidden
  characters revealed; an assistant-role message is refused unless the operator listed that
  prompt; an embedded resource is dropped unless its URI is allowed; a read answers only for an
  allowed URI, and contents naming another URI are dropped; a completion must name an included,
  pinned prompt or template. With `on_drift: fail`, a drift in any kind blocks the whole server.
  It can still write a
  pinned prompt whose output changes with its arguments (below).
- **T28** reaches the page only as text, with hidden characters shown, and the plan only as rows
  the vault built, through the policy view's hiding rules.
- **T4** can hide or invent status, drift marks, the policy mode and witness claims, which only
  ever raise warnings or a CLI refusal, never a vault decision: a witness revision is bounded, and
  an acknowledgment asks the host to type the target number, so a false claim can't make the vault
  jump its counter by itself; a hostile upstream's names can't blind the report, since the
  gateway sends only valid names and counts the rest, and the vault drops a bad entry, not the
  report. It can't show a false old definition (the vault recomputes its pin) or a false new
  one, and it still can't write policy.
- **T29** is refused at the plan or at the write (`policy_moved`): every save names the revision
  it was planned on, and the write checks it again in one section with nothing in between. Its
  own retry after a lost answer is recognized as already saved.
- **T30** can't lock the portal out from the portal (no portal save changes `admin`) and always
  has the socket and the offline `--state` forms; every restart, redeploy or broken binding a
  write causes is in its plan before the passkey or the `[y/N]`.

What doesn't change: **declarative mode** keeps every earlier statement (the operator's commit is
the guard, and no route writes policy); **T1, T4 and T6 stay open until M8**: moving a tool to
`allow` closes no approval gap, and a compromised gateway or toolkit can still skip the gateway's
approvals.

## The confused deputy

ZoeyMCP issues no OAuth tokens to agents and has no dynamic client registration on the agent's
side: client tokens are static and set by the operator. So the MCP specification's
confused-deputy precondition (a proxy that lets MCP clients register dynamically) doesn't hold.
The portal's OAuth connect is the operator's, for the vault's own credentials, and a test checks
that no listener (the proxy, the portal, the gateway, a bridge or the egress role) serves
authorization-server metadata, a registration endpoint or a token endpoint; the vault drops an
upstream's `WWW-Authenticate` before the gateway sees it, so no agent is ever pointed at one. M7's
dynamic client registration is the other way round: the vault registers itself at a server's
authorization server, from an operator's action, for the vault's own credential, and agents still
get only their static tokens. Later milestones must keep it that way, or add per-client consent
first.

## Accepted limits

- **Silent drift** between timer checks, as above.
- **Modern stateful servers** see one principal for every client.
- **Deliberate disclosure** of a credential by the server that was given it.
- **Standard-tier egress:** a compromised gateway can send what it sees anywhere, and so can a
  toolkit or its dependencies: they run in the gateway, which shares the vault's network
  namespace there. The egress role doesn't change that; the hardened tier, where the gateway has
  no route out, does.
- **A restore of the whole state volume** from an older backup is not refused: the gateway-key
  ratchet and managed policy's revisions both assume the volume moves forward. In managed mode
  the gateway's witness flags it (M6, below); otherwise nothing does. For the
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
- **Onboarding by URL and the egress role (M7):**
  - **An authorization server that doesn't send `iss`** can't be defended against mix-up by
    `iss`. Each registration's own redirect address leaves an attacker needing a registration at
    the honest server with that address, which open registration allows. The plan says when `iss`
    isn't advertised.
  - **Discovery and registration reach public hosts the server chooses.** The address guard
    keeps them off the vault's networks; it doesn't stop a hostile server from making the vault
    contact a public host of its choice once the operator starts onboarding it.
  - **With your own egress proxy, the address check is the proxy's.** The vault can't resolve
    names behind an internal-only network; the emitted Squid snippet carries the
    private-destination rule, rendered from the vault's own tables. An IPv6 answer under the NAT64
    prefix that embeds a private IPv4 address isn't caught by a Squid `dst` rule; the egress role
    catches it.
  - **The egress role confines hardened bridges, not the vault.** The vault keeps its direct
    route out on `egress` for the portal, so sending it through the role adds the allowlist and an
    address check at connect time, not confinement. The role confines nothing in the standard tier:
    not the gateway, toolkits or a bridge there, which all share the vault's network namespace.
  - **Domain fronting** through an allowlisted shared host: the role and the emitted snippet match
    the CONNECT `host:port`, not the name inside TLS.
  - **SMTP connections aren't address-guarded by the vault** without an egress proxy; the guard
    covers HTTP.
  - **A server on your network whose authorization server is also private** can't be onboarded by
    URL, since metadata hosts never get the private exception; write its policy by hand.
  - **Registrations left behind:** an abandoned onboarding, or a lost store, leaves its client
    registered at the provider (the vault keeps no registration token, so it can't delete it), and
    a restored volume brings back older client secrets.
  - **A compromised gateway can fake a review report** with consistent pins, and hide findings.
  - **A leaked sign-in link** works against a callback flow that onboarding set up as it does
    against any (the portal's limit above); standard-tier siblings reach the portal as before; and
    the approval-bypass gaps stay open until M8.
- **Bridges (M7):**
  - **A bridge and its program are one trust domain** (the same uid). The bridge defends the vault
    and the gateway from the program, not itself; a program that ignores proxy settings or skips
    certificate checks is held only by its networks.
  - **A standard-tier bridge is unconfined.** Its program shares the container's network namespace
    with the vault and the gateway: it can reach every TCP listener there (the gateway's port, the
    portal, a vault TCP listener; not another bridge's socket), the host's network and the
    internet, and it can ignore proxy settings, so nothing limits where it sends what it holds. It
    has the trust of a toolkit there: its own uid keeps it out of the vault's and the gateway's
    memory, files and sockets, and every listener still asks for its token, session or key. It
    shares the container's memory, processes and CPU and can starve the vault and the gateway; its
    own process limit, a kernel OOM preference that picks it first, its own work tmpfs and the
    container's process limit bound some of that, but no memory or CPU cap per bridge exists in
    that tier. Every process in the container can read its command line, so a secret never goes in
    its arguments. Its image is a derived one, so the program's install-time code would join the
    vault's trusted base unless the image passes `verify.sh --bridge`, which this placement
    requires. A program that outlives its bridge (same uid) could listen on the bridge's socket in
    its place and receive the vault's requests with the token, which it could read from the
    bridge's memory anyway. Use the hardened tier for a program you need to confine.
  - **A remote bridge** is as confined as its host makes it; ZoeyMCP sees only the route.
  - **A third-party stdio-to-HTTP wrapper** behind a route has whatever admission it has. It must
    check the route's bearer token; `check` can't tell whether it does, since the route sends the
    token either way, so one that ignores it leaves the hop unauthenticated without a warning.
  - **A bridge holding a real secret** can send it to any host on its own egress list (hardened)
    or anywhere (standard, remote); `check` warns and names them.
  - **One modern bridge program serves every client,** as a modern remote server sees one
    principal.
- **Managed policy, drift review, prompts and resources (M6):**
  - **A passkey widens what admitted agents may do.** In managed mode one assertion can include a
    tool, move it to `allow`, onboard a server (with, after a stepped-up private discovery,
    egress to a private address that takes effect at once) or give an admitted client another
    server, which is more than a declarative deployment's passkey can do. It can't admit a new
    agent, move a secret or lock the operator out. **One passkey covers every approve->allow move
    a review save lists:** each is its own row in the plan, with its sentence and the pinned
    definition, and each is logged `tool_allowed`, but whoever holds the passkey can make every
    included tool unprompted in one save, as they could in several. M8's vault-enforced approvals
    don't change this (a passkey could switch them off too); the hardened tier and the passkey's
    own protection are the answer.
  - **A relayed setup code now yields a passkey that can save policy** (T3, T12): in the standard
    tier the gateway and sibling containers still reach the portal's unauthenticated routes, and a
    code redeemed by one of them enrols a passkey that passes step-up for managed saves, within the
    portal's edit set above. This stays accepted: the hardened tier, which publishes the portal on
    the host's loopback only, is the answer.
  - **The authenticator shows nothing about the plan.** WebAuthn shows no transaction text: a
    save's plan, however long (every changed field, restart and binding, a rollback's whole
    difference), is rendered by the portal from the action it holds, so script running in the
    portal's origin could show one plan and confirm another. The CSP, Trusted Types and
    text-only rendering keep script off the page.
  - **Who sets what, per mode.** In declarative mode the file's author sets everything, as
    before. In managed mode the settings the earlier limits leave to that author (a client's
    `renders` and the other approvals settings, `drift_check_interval`, a connector's host and
    recipients) are the host's, changed by an import; a passkey holder chooses a connector's
    limits and pause, never its hosts.
  - **The volume is its own witness only partly.** The anchor refuses a head behind it and a
    store or anchor deleted or restored alone. A head and the anchor restored together by exactly
    one revision look like a crash and drop the newest revision; `head.json` and the anchor put
    back together by any number of revisions, with the revision files above that head deleted,
    are accepted, and the older policy runs with its older record of what may only move forward,
    so removed clients and retired pins come back; a whole `/state` restored is accepted; a whole
    `/state` deleted seeds again from `ZOEYMCP_CONFIG` under a new deployment, bringing back
    everything removed since the seed. The gateway's witness catches each of these when the
    gateway's volume wasn't restored with it (`policy_behind_witness`,
    `policy_deployment_changed`); restoring both volumes from one snapshot hides it. An older copy
    of the anchor put back after a declarative period undoes the park, so the next managed start
    runs the parked head instead of resuming from the file; `policy_seed_ignored` then says so.
    Back up and restore the vault's volume on its own, and compare the head with your latest
    export after any restore (operations.md §34).
  - **A compromised gateway can stay silent** about drift, new tools and the witness, or raise
    false alarms; it can't make the vault accept a false definition, pin or policy.
  - **Prompt output depends on its arguments,** so a pinned prompt can still produce new text
    later; it is sanitized, not pinned. Content pins for prompts without arguments aren't built.
  - **An export is a sensitive file:** it holds placeholders and token hashes, and the vault
    can't protect a copy once it leaves the socket.
  - **Windows has no state lock and no directory fsync:** two vaults could fork the revisions,
    and a crash right after a save may lose it. Windows hosts are for development only.
  - **The ratchet is bounded** (10,000 entries): a deployment that re-pins and removes that much
    is refused `ratchet_full`, and the only way on is a reseed with `--new-ratchet`, which drops
    the old record and prints every entry it forgets: the host's explicit act.
  - **A retired master key stays dangerous until its rotation is recorded.** While
    `ZOEYMCP_MASTER_KEY_PREVIOUS` is set, a `/state` writer holding the old key could plant files
    under it for the vault to seal again; once a rotation finishes, the anchor records the old key
    as retired and files under it are refused or quarantined even with the variable still set.
    Remove `ZOEYMCP_MASTER_KEY_PREVIOUS` right after the rotation (operations.md §34).
  - **A save blocks the vault for its few writes and fsyncs,** a few milliseconds on a local disk,
    longer on a slow one, so that saves are serial with no second locking scheme.
  - **Host access is total,** as before: anyone who can run the admin socket or the offline form
    can write any policy `check` accepts, flags included.
