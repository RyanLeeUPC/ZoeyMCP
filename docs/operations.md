# Operating ZoeyMCP

How to run what is built so far: the vault (M1), OAuth in the vault (M2), the gateway for
remote MCP servers in both deployment tiers (M3, §9 onwards), and approvals, the SMTP connector
and toolkits (M4, §19 onwards). The design and the reasons behind
it are in [design.md](design.md); this page is the how-to.

Admin commands run **inside the container** and talk to the vault or the gateway over its admin
socket (`/run/zoeymcp/admin.sock` for the vault, `/run/zoeymcp-gateway/admin.sock` for the
gateway, or `--socket`):

```sh
# hardened tier: one container per role
docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp oauth status
docker compose -f deploy/compose.hardened.yaml exec gateway zoeymcp review
# standard tier: one container; the CLI becomes the socket's owner by itself
docker compose -f deploy/compose.yaml exec zoeymcp zoeymcp oauth status
```

The examples below shorten that to `zoeymcp ...`. `docker compose exec` gives the command a
terminal, which the hidden prompts need. Add `-T` to pipe a value in instead.

## 1. The state volume

The vault keeps its state in one directory (`/state`, the `vault-state` volume):

- `store.json`: the encrypted secrets, written atomically (a temporary file, then a rename);
- `vault.lock`: held with `flock` while the vault runs;
- `setup.json`: the pending portal setup code.

**One vault per state volume.** A second vault on the same directory refuses to start ("another
vault is using this state directory"). Network filesystems are unsupported: without `flock` the
vault refuses to start, and a lock that isn't shared between hosts protects nothing.

**When the store can't be written** (a full or read-only volume), nothing is lost while the vault
runs: the new value stays in memory and is used. The vault says so:

- `secret set` and `secret delete` answer "kept in memory, not written to disk; check the state
  volume" (an HTTP 500, exit code 1);
- `zoeymcp login` prints "kept in memory, not on disk; fix the state volume; zoeymcp oauth status
  shows when it is saved" and exits 1;
- `oauth status` shows `degraded (not persisted): the store can't be written; check the state
  volume` under every credential;
- the log has `oauth_persist_failed` (level `critical` for a credential with `rotates: true`,
  `error` otherwise).

Fix the volume. The next write then saves everything: the vault retries before every refresh and
when it stops, and logs `oauth_persist_recovered`. **Don't restart the vault while it is
degraded:** a crash or restart before a successful write loses the change, and for a rotating
refresh token that means a new `zoeymcp login`.

**Stopping.** The vault waits up to 45 s for refreshes in flight, so a new refresh token is saved
before it exits. The hardened compose sets `stop_grace_period: 50s` for this. Docker's default
is 10 s, so when running the image some other way, give it the same time (`docker stop -t 50`).

## 2. Logging in

`zoeymcp login <credential>` consents to an OAuth credential and stores its refresh token. It
needs the credential's `authorize_url`, a route that uses the credential, and, for a
confidential client, the client secret stored first (`zoeymcp secret set <name>`). Register the
credential's `redirect_uri` with the provider exactly as written; the default is
`http://127.0.0.1/callback`, with no port.

```text
$ zoeymcp login spotify
Credential   spotify (public client, PKCE S256, rotating refresh tokens)
Binding      token endpoint https://accounts.spotify.com:443
             access tokens to https://api.spotify.com:443
Scopes       user-read-currently-playing user-top-read

Open this URL in a browser and approve:
  https://accounts.spotify.com/authorize?response_type=code&client_id=...

Your browser will then try to open http://127.0.0.1/callback?... and fail to load. That is
expected. Copy the full address from the address bar and paste it here (input hidden, 10 minutes):
>
Stored the refresh token for spotify as spotify-refresh.
Granted: user-read-currently-playing user-top-read
The grant ends at 2027-04-15T09:00:00Z; run login again before then.
```

- Open the URL in any browser, on any machine: the redirect goes to the browser's own machine and
  never has to reach the vault. Paste the whole address, including `?code=...&state=...`.
- The address is read from a hidden prompt (or one line of stdin), never from the command line,
  and never echoed or logged. Ctrl-C, an empty line or the end of input cancels the login.
- A login lasts 10 minutes and works once: after any failure, run `login` again. Starting a new
  login for a credential replaces its pending one; at most 8 can be pending.
- Scopes outside the expected set are stored and flagged: `UNEXPECTED: ...` on stderr, exit
  code 0, and a warning in `oauth status`. Missing ones print `missing: ...`.
- For an `env:`-seeded credential, login stores the token in `oauth.<credential>.live` and says
  what happens to the seed: "The env seed VAR is now ignored (reseed: never). You may remove
  it."
- Exit codes: 0 when stored (warnings or not), 1 on any failure or when the store couldn't be
  written.

**In two steps,** for example from a script or when the vault and the browser are far apart:

```text
$ zoeymcp login spotify --start
...
Then, within 10 minutes, run: zoeymcp login spotify --flow=<ID>
and give it the address your browser was sent to.
$ zoeymcp login spotify --flow=<ID>
```

The second command reads the address the same way (a hidden prompt, or one line piped in with
`exec -T`). Keep the `=`: a flow ID can start with a dash.

**`--rebind`.** A login is refused when the policy now binds the grant differently from the
stored one, for example after a route moved to a new upstream origin. The CLI prints the old and
the new binding; run the login again with `--rebind` to accept the new one.

**`client_credentials`.** There is nothing to consent to: `login` makes one token call, prints
"The client credentials of <name> work: ...", stores nothing, and clears the credential's failure
state.

**Timeouts.** The CLI waits up to 76 s for a login answer (the 20 s code exchange, up to 41 s for
a refresh of the same slot that is already running, and 15 s to spare), up to 56 s for
`secret set` and `secret delete` (a secret an OAuth credential uses waits for a refresh in
flight), and 10 s for everything else. After a timeout, check `oauth status` before
trying again: the vault may have finished.

**Why a login is refused.** The CLI prints a message; the admin answer also carries one of
these `reason` codes:

| Reason | Meaning | What to do |
| --- | --- | --- |
| `not_oauth` | no `oauth2` credential has that name, or it no longer uses the refresh grant | check the name and the policy |
| `no_authorize_url` | the credential has no `authorize_url` | add one, or give the refresh token another way (the message says how) |
| `no_route` | no route uses the credential, so there is nothing to bind its tokens to | add a route |
| `authorize_misconfigured` | the authorization URL can't be built: a `client_id` ref, or an `authorize_params` name the vault sets (`check` reports both) | fix the policy and run `check` |
| `client_id_unavailable`, `client_secret_unavailable` | the client ID ref or client secret isn't set, or isn't bound to the token endpoint | `zoeymcp secret set <name>`, or set the env var and restart (the message says which) |
| `not_configured` | the token manager doesn't know the credential; it shouldn't happen | reload the policy (§7) or restart the vault |
| `binding_changed` | the stored grant is bound differently from what the policy now derives | `--rebind` |
| `too_many_flows` | 8 logins are pending | finish one, or wait 10 minutes |
| `flow_unknown` | the flow expired, was used, or belongs to another credential | run `login` again |
| `redirect_mismatch` | the pasted address isn't under `redirect_uri`, can't be read, or has the answer in the fragment | paste the full address from the address bar |
| `state_mismatch` | the address is from a different login | use the URL of the latest login |
| `duplicate_param`, `no_code` | the address has a parameter twice, or no usable code | run `login` again |
| `iss_mismatch` | the answer names a different issuer than `issuer` | check `issuer` against the provider's metadata |
| `provider_error` | the provider refused (for example, consent was denied); its description is shown, never logged | act on the description |
| `exchange_failed:<code>` | the token endpoint refused the code; `<code>` is one of §4's codes | for `invalid_grant`, the code expired or was used: run `login` again |
| `no_refresh_token` | the provider issued no refresh token | Google: keep `access_type: offline` and `prompt: consent`; other providers may need an `offline_access` scope |

## 3. Credential health: `health`, `oauth status` and `oauth reset`

**`zoeymcp health`** lists what needs you, per credential, connector and store entry, with what
to do about each. It reads metadata only: nothing is decrypted and no request is sent.

```text
$ zoeymcp health
notes (header): ok
calendar (oauth2): warning
  warning idle: unused for 171 days; the provider drops unused grants after 180 (from stored metadata)
          run: zoeymcp login calendar
connector mail: ok (3 of 20 sends in 24 h)
store: info (4 entries)
  info    unreferenced: nothing in the policy uses store:old-key
          run: zoeymcp secret delete old-key
health: ok (0 error(s), 1 warning(s), 1 info)
```

It exits 0 with no error (with `--strict`, no warning either), 1 otherwise, and 2 when the vault
can't be asked. `--json` prints the whole report, with a `summary` of counts per level and each
finding's `code`, `level`, `advisory`, `text` and `action` (a `kind` such as `connect`, `reset`,
`set_secret`, `restart`, `delete_secret`, `fix_policy`, `wait`, `check_volume` or
`check_mailbox`, and the name it applies to). For a deployment's verify script:

```sh
docker compose -f deploy/compose.yaml exec -T zoeymcp zoeymcp health --json --strict > /dev/null
```

There is no unauthenticated health endpoint: health is the admin socket's `GET /health`.

| Code | Level | When |
| --- | --- | --- |
| `missing` | error | a `store:` reference has no entry |
| `env_unset` | error | an `env:` reference's variable wasn't set when the vault loaded the policy (an env seed only while there is no live token) |
| `binding_changed` | error | the entry's binding doesn't cover a use the policy makes now (a route added, another connector constraint or token endpoint): the vault refuses that use until you enter it again |
| `binding_wider` | info | the binding covers every use and more (an explicit `--origin`, or a route removed since): it works |
| `no_route`, `binding_conflict` | error | the policy can't bind the name, as `secret set` would refuse it: fix the policy |
| `seed_ignored` | info | an env seed is set while the live token is used (§5) |
| `unreferenced`, `orphan_slot` | info | an entry nothing in the policy uses; a live slot no credential keeps its token in |
| `degraded` | error | the store can't be written (§1) |
| `terminal`, `backoff` | error, warning | as `oauth status` shows them, with the hint's action |
| `reconsent_due`, `unexpected_scopes`, `missing_scopes` | warning | as `oauth status` shows them |
| `insufficient_scope` | warning | an upstream said the token lacks a scope, **since the vault started**: a restart forgets it |
| `last_failure` | warning | no failure in memory, but the last attempt failed after the last success: a restart forgets failures, the store's metadata doesn't |
| `idle` | warning | `idle_expiry_days` is set, and the last success is older than it less 14 days. Refresh happens only on demand, so an unused grant can reach a provider's idle expiry |
| `paused`, `near_limit`, `unknown_sends` | info, warning, warning | a paused connector; 80% of `max_per_day` used in the last 24 hours; a send in the last 24 hours with an unknown outcome |

Findings marked `(from stored metadata)` (`advisory` in JSON) come from the store's clear
metadata, which anyone with the state file can edit: they are shown, and nothing the vault
decides reads them.

**`zoeymcp oauth status`** shows each OAuth credential in more detail:

```text
$ zoeymcp oauth status
google-calendar: terminal oauth_reconsent_needed
  hint: run: zoeymcp login google-calendar
  last success 3 days ago
spotify: ok
  access token expires in 52 min
  last success 8 min ago
  WARNING re-consent due by 2027-04-15T09:00:00Z
```

Each credential gets a line with its state, then details. Nothing in it is a secret.

- **States:** `ok` (an access token is cached), `idle` (none is cached: not needed yet, or
  expired), `backoff` (a transient failure; `retry in ...` says when the next request may try),
  `terminal` (no token calls until you act). `(refreshing)` means a refresh is running.
- `hint:` what to do about the code (below).
- `last success ... ago`: from the store's display metadata. Google drops a refresh token unused
  for 6 months.
- `WARNING re-consent due by ...`: the grant ends within 14 days, by `consented_at` plus
  `grant_lifetime_days`, or by the refresh token's own expiry.
- `UNEXPECTED scopes: ...` / `missing scopes: ...`: the last granted scopes against the expected
  ones.
- `WARNING an upstream said upstream_insufficient_scope at ...`: an upstream answered that the
  token lacks a scope. A new token won't fix that; log in with more scopes, or narrow the rules.
  Kept in memory since the vault started.
- `WARNING last attempt failed: <code> at ... (from stored metadata)`: after a restart the state
  is `idle`, but the last token call failed after the last success. `oauth reset` or the next
  request tries again.
- `WARNING unused for N days; ... (from stored metadata)`: see `idle` above.
- `degraded (not persisted)`: see §1.

**Hints.** The hint depends on why the credential failed, then on its code:

| When | Hint |
| --- | --- |
| reason `client_id_unavailable` / `client_secret_unavailable` | "enter the client ID (or secret) with zoeymcp secret set NAME" or "set the client ID (or secret) in env VAR and restart the vault", then "then run: zoeymcp oauth reset NAME" |
| reason `no_route` | "no route uses NAME; fix the policy" |
| `oauth_reconsent_needed`, `oauth_rotation_lost`, `credential_unavailable` | with `authorize_url`: "run: zoeymcp login NAME". Without one, how to give a new refresh token: "enter the refresh token with zoeymcp secret set ENTRY", or for an env seed "put a new refresh token in env VAR and restart the vault (reseed: on-change)" or "put a new refresh token in env VAR, delete oauth.NAME.live with zoeymcp secret delete (reseed: never keeps it), and restart the vault". For `client_credentials`: "check the client ID and secret, then run: zoeymcp oauth reset NAME" |
| `oauth_client_rejected` | "check the client ID and secret, then run: zoeymcp oauth reset NAME" |
| `oauth_misconfigured` | "fix the policy, then run: zoeymcp oauth reset NAME" |
| `oauth_unsupported` | "the provider's tokens aren't Bearer tokens the vault can use" |
| `oauth_unavailable` | "the token endpoint is unavailable; a request after the backoff tries again" |

**`zoeymcp oauth reset <credential>`** clears the failure state, so the next request that needs a
token tries once. Use it after fixing something the vault can't see: a client re-enabled at the
provider, a corrected policy, or a spurious `invalid_grant` during a provider outage. Fixing the
cause through the vault (a login, `secret set` or `secret delete` of a secret the credential uses,
a reload that changes the credential) clears the state by itself. So does a restart, since
failure states live in memory.

The `reason` behind a failure is in the admin answer's `reason` field and in the `oauth_refresh`
log line's `failure_reason`: `provider_error` and `http_status` (the token endpoint refused),
`no_response` and `pre_send` (no answer), `unparseable_body`, `not_ok`, `bad_access_token`,
`token_type` and `unusable_refresh_token` (an answer the vault can't use), `internal_error`, and,
before any call, `no_token`, `live_unusable`, `seed_unusable`, `no_route`, `request` (the policy
can't build the request), `client_id_unavailable` and `client_secret_unavailable`.

## 4. Codes

After a caller is identified and a rule matched, a route that can't get its credential answers
502 `{"error": "upstream unavailable", "code": "<code>"}`. The codes are stable, and each needs a
different action:

| Code | Meaning | Action |
| --- | --- | --- |
| `credential_unavailable` | no usable secret: none stored, a refused or tampered entry, an unset env var, or a route outside the grant's resources | set the secret, or log in; `oauth status` has the hint |
| `oauth_reconsent_needed` | the provider refused the refresh token (`invalid_grant`): revoked, expired, or retired | `zoeymcp login <credential>` |
| `oauth_rotation_lost` | as above, right after a replay: the successor of a rotating token was probably lost in transit | `zoeymcp login <credential>` |
| `oauth_client_rejected` | the provider refused the client ID or secret | check them, `secret set` the secret, or `oauth reset` |
| `oauth_misconfigured` | the provider refused the request (`invalid_scope`, `invalid_request`, ...) | fix the policy (scope, `extra_params`, `client_auth`), reload, or `oauth reset` |
| `oauth_unsupported` | the provider's tokens can't be used (DPoP or another non-Bearer type), or it sent a malformed refresh token | not usable with this vault yet |
| `oauth_unavailable` | the token endpoint is down, rate limiting, or answered with nothing usable | none: the vault backs off and the next request after `Retry-After` tries again |

A 502 for an upstream that failed by itself carries no code. Identity failures stay a bare 403.

## 5. Seed vs live

A refresh token can be given three ways:

- `store:<name>`: entered with `zoeymcp login` or `zoeymcp secret set <name>`, and replaced in
  place on every rotation.
- `env:<VAR>`: a **seed**. On its first success the vault promotes it into the store entry
  `oauth.<credential>.live`, and uses that **live** token from then on. `check` says so for every
  seeded credential.
- `client_credentials` has no refresh token at all.

With the default `reseed: never`, a changed env value is ignored once a live token exists.
With `reseed: on-change`, a value different from the one last seeded (or the one set at the last
login) replaces the live token. Every `oauth_refresh` log line says which token was used
(`token_source`: `store`, `live` or `seed`) and why (`reason`, design §4.3).

**To re-seed,** in order of preference:

1. `zoeymcp login <credential>`: no redeploy. The seed is then superseded, and login says so.
2. `zoeymcp secret delete oauth.<credential>.live`: the next refresh presents the env seed and
   promotes it.
3. `reseed: on-change`, a new env value, and a restart.

**A rotating seed works once. Never roll an env seed back.** With `rotates: true` the provider
retires the seed on its first use. Presenting an old one again (an earlier env value, with
`reseed: on-change`) fails, and providers with reuse detection revoke the whole grant when they
see it.

A seed env var that is unset is only a warning in `check`: the vault uses the live token, so the
seed may be removed once it has been promoted.

## 6. Recovery per kind

| Credential | Lost master key or state volume | Lost rotation |
| --- | --- | --- |
| `header`, `query`, `path`, `basic` | `secret set` again | — |
| OAuth refresh token in `store:` | `zoeymcp login` | `zoeymcp login` |
| OAuth env seed, not rotating | automatic: the seed is promoted again | — |
| OAuth env seed, rotating | `zoeymcp login` | `zoeymcp login` |
| `client_credentials` | `secret set` the client secret | — |

A rotation is lost when the vault never saved the newest refresh token: a crash between the
token answer and the write, a store that couldn't be written followed by a restart, or an answer
lost in transit by a provider without a grace window (`oauth_rotation_lost`).

## 7. Reloading the policy

```sh
docker compose -f deploy/compose.hardened.yaml kill -s HUP vault
docker compose -f deploy/compose.yaml kill -s HUP zoeymcp      # standard tier: both roles
```

On `SIGHUP` the vault loads and checks its policy file again, and the gateway sees the result
within a second or two (it long-polls its view, §9). In the standard tier the launcher passes
`HUP` on to both. The vault:

- A policy that fails is refused (`reload_refused` in the log), and the running one stays.
- On success the log has `reload_ok`, with `oauth_reset` listing the OAuth credentials whose
  settings or route origins changed. Their cached access tokens are dropped and their failure
  states cleared. A refresh in flight still saves its new refresh token.
- A changed `egress_proxy` needs a restart (`egress_proxy_change_needs_restart`).
- A route moved to a new upstream origin can't use its stored grant until
  `zoeymcp login <credential> --rebind`.
- The environment is read once, at startup: a new env value (a seed, a client secret) needs a
  restart. An inline policy in `ZOEYMCP_CONFIG` is part of the environment too, so changing it
  means recreating the container.

## 8. Provider notes

**Google** (`profiles/google-oauth.yaml`):

- Register a **Desktop app** client: it accepts the loopback redirect.
- Keep `authorize_params: {access_type: offline, prompt: consent}`, or no refresh token is
  issued.
- While the consent screen is in **Testing** status, a grant lasts 7 days.
- At most 100 refresh tokens per account and client ID; another login retires the oldest.
- A refresh token unused for 6 months stops working.
- `invalid_grant` with `error_subtype: invalid_rapt` means a Workspace re-authentication policy
  wants the user to sign in again: `zoeymcp login`.

**Spotify** (`profiles/spotify-pkce.yaml`):

- Register the redirect URI `http://127.0.0.1/callback` exactly: no port, never `localhost`.
- Refresh tokens rotate on every use (`rotates: true`).
- The grant ends 6 months after consent. The profile sets `grant_lifetime_days: 180`, so
  `oauth status` warns 14 days before.

## 9. Running the gateway

The gateway is the MCP server agents connect to: one endpoint per server, `/s/<server>/mcp`. It
holds no secret. Everything upstream goes through a vault route that accepts only the gateway,
and the vault serves the gateway its view of the policy (design §4.6): one policy, kept in the
vault.

**Standard tier** (`deploy/compose.yaml`): one container, started as root with
`cap_drop: [ALL]`, `cap_add: [SETUID, SETGID]` and `no-new-privileges`. Its launcher refuses to
start otherwise, and says which setting is missing. It runs the vault as uid 10001 and the
gateway as uid 10002, linked by a Unix socket only the gateway's uid may use, then drops to uid
10003 with an empty environment. The gateway is published on `127.0.0.1:8090` only: a client
token sent without TLS is readable on the network.

```sh
export ZOEYMCP_MASTER_KEY=...        # zoeymcp keygen; keep it as a deployment secret
docker compose -f deploy/compose.yaml up -d
curl -s http://127.0.0.1:8090/healthz # ok, once the gateway has its view
```

**Hardened tier** (`deploy/compose.hardened.yaml`): the gateway in its own container, on the
`internal` network (to the vault) and the `agents` network, both without a route out, so it has
no egress at all. It authenticates to the vault with the gateway key:

```sh
docker run --rm zoeymcp:local keygen  # prints ZOEYMCP_MASTER_KEY and ZOEYMCP_GATEWAY_KEY
export ZOEYMCP_MASTER_KEY=... ZOEYMCP_GATEWAY_KEY=...
docker compose -f deploy/compose.hardened.yaml up -d
```

Agents' containers join the `agents` network and use `http://gateway:8090/s/<server>/mcp`. For
agents on other hosts, use the `lan` profile (§15).

**What stops the gateway starting** (it prints one line and exits 2): the master key,
`ZOEYMCP_MASTER_KEY_PREVIOUS` or `ZOEYMCP_CONFIG` in its environment; running as root; an
`http://` link without `ZOEYMCP_GATEWAY_KEY` or `ZOEYMCP_GATEWAY_KEY_FILE`; a state directory
open to other users; a drift-marks file it can't read (move it aside to start over, which forgets
the marks).

**Until it has a view**, and whenever it has had no answer from the vault for
`gateway.limits.policy_max_stale` (300 s), `/healthz` and every agent request answer 503, and
upstream connections close (`policy_stale`): a revoked client can't keep working while the vault
is unreachable.

**Stopping.** Calls in flight get 10 s. The standard tier's launcher gives both roles 50 s, so
compose sets `stop_grace_period: 60s`.

## 10. Client tokens

Each agent gets its own client token. The policy holds only its hash:

```text
$ zoeymcp client-token
client_token: zgc1-...
token_sha256: sha256:3b1f0c...
```

```yaml
gateway:
  clients:
    agent1:
      token_sha256: sha256:3b1f0c...
      servers: [notes]
```

Configure the agent's MCP client with the server's URL and the token as a bearer header. For an
agent that reads a JSON MCP config, typically:

```json
{"mcpServers": {"notes": {"type": "http", "url": "http://localhost:8090/s/notes/mcp",
                          "headers": {"Authorization": "Bearer zgc1-..."}}}}
```

- Every request is authenticated, `GET` and `DELETE` included; a session id never stands in for
  the token. Tokens are never read from the query string.
- **Revoking:** remove the client (or its `token_sha256`, or a server from its list) and reload
  the policy. The gateway refuses it from its next request, stops its calls and streams in
  flight there (`requests_stopped` in the log; the upstream calls are cancelled), and closes its
  sessions and upstream connections.
- A literal `token:` in the policy still works, with a `check` warning: anyone who reads the
  policy can act as that client.
- Source pins (`sources:`) match the direct peer address only. Behind the `lan` proxy the peer is
  the proxy, so pins can't tell agents apart there; tokens do.

## 11. Adding a remote MCP server

1. **The route and credential,** for the gateway only (`profiles/remote-mcp-static-key.yaml` is
   the shape): `callers: [gateway]`, `stream: true`, an `https` upstream, and rules for `POST`,
   `GET` and `DELETE` on the server's path. `check` refuses anything less.
2. **The server entry,** with nothing included yet, assigned to the clients that should see it:

   ```yaml
   gateway:
     servers:
       notes: {kind: remote, route: notes-mcp, path: /mcp}
   ```

3. **The secret:** `printf '%s' "$KEY" | zoeymcp secret set notes-key` (in the vault's
   container).
4. **Reload** the policy (§7).
5. **Review it** in the gateway's container. The running gateway lists the server on a fresh
   connection of its own; the server needn't be assigned to anyone yet:

   ```text
   $ zoeymcp review notes --add get_note --add search_notes
   server notes  (remote, vault path /notes/mcp, modern 2026-07-28)
     get_note      unreviewed  sha256:71d2a3b4c5d6...  not included
     search_notes  unreviewed  sha256:0c4e1f2a3b4c...  not included
   findings (heuristics; reading the definition is the control):
     search_notes: note /annotations: suggested by the server: allow (readOnlyHint=true)

   # YAML to commit (declarative mode). Review the changes above first.
   gateway:
     servers:
       notes:
         era: modern
         tools:
           include: [get_note, search_notes]
           allow: []
           approve: []
           # get_note: put it in allow or approve; nothing is implied
           # search_notes: put it in allow or approve; nothing is implied
         review:
           get_note: sha256:71d2...  # ADDED
           search_notes: sha256:0c4e...  # ADDED
   ```

   Read each definition (`--show TOOL`, or `--all`) before you add it. Findings are heuristics:
   instruction-like text, URLs, long base64 runs, nested-quantifier patterns, arguments that
   travel in HTTP headers, and the server's suggested classification. Hidden characters are
   shown as `[U+XXXX]`. A tool with an error finding (hidden characters, an unsafe schema) gets no
   pin line at all.
6. **Classify and commit:** put each added tool under `allow` or `approve`. `check` fails until
   you do: there is no implicit default. An `approve` tool asks a human before each call (§19).
7. **Reload** again. Agents see the tools at once (their clients are told the list changed).

`review` exits 0 when every included tool matches its pin and nothing is marked, 1 when
something needs you, and 2 when it couldn't run (the gateway is down, the server is unknown or
not a remote one, the vault refused, the upstream failed or a listing limit was hit). The
message says which. `--format json` prints the same, with the snippet as a list of lines.

## 12. Drift

When an included tool's definition changes, the gateway hides it from every client of the
server, logs `tool_drift` (with the members that changed), and marks it. The mark holds even if
the server changes the tool back: a server that changed a tool once can do it again.

```text
$ zoeymcp review notes
  get_note      ok          sha256:71d2a3b4c5d6...
  search_notes  DRIFT       changed: description    hidden, marked
diff search_notes:
  --- reviewed
  +++ listed
  ...
```

- **Accept the change:** read the diff, then `zoeymcp review notes --repin search_notes` and
  commit the snippet: the new pin replaces the old, and a changed pin clears the mark.
- **The server changed it back:** the line says `MARKED`. Once every included tool matches again,
  `zoeymcp review notes --clear` clears the server's marks. It lists fresh first and refuses
  (exit 1, saying which tools don't match) unless every included tool matches.
- **`on_drift: fail`** hides the whole server instead (`server_blocked`); its tools show
  `BLOCKED`.
- A tool the server no longer lists is `MISSING`. It comes back when it is listed again.

The gateway checks for drift when the server says its list changed, when a session changes or
reconnects, and every `drift_check_interval` (300 s) regardless, since a hostile server won't
announce its changes. A silent change between two checks is caught at the next one.

## 13. `gateway-status`

```text
$ zoeymcp gateway-status
view sha256:5c1d...  fresh
notes  remote  ready  era modern  connections 1  exposed 2/2
  unreviewed: export_all
  last listing 42 s ago
```

`zoeymcp review` with no server prints one line per server from the same data, and exits 1 if
anything is drifted, marked, missing or invalid. Neither makes an upstream call, and neither
shows definitions or token hashes. `--format json` for both.

## 14. Rotating the gateway key (hardened tier)

1. Raise `gateway_key_generation` in the policy (the shipped compose takes it from
   `ZOEYMCP_GATEWAY_KEY_GENERATION`) and reload or recreate the vault. The old key now works for
   at most 5 more minutes.
2. `zoeymcp gateway-key` in the vault prints the new key. While the old one is still accepted, it
   also prints `rotation pending: generation N-1 accepted until <time>` on stderr.
3. Give the gateway the new key and recreate it (with a key file, `kill -s HUP gateway` is
   enough). Its first request with the new key retires the old one (`gateway_key_retired` in the
   vault's log).

For a suspected leak, run `zoeymcp gateway-key --retire-previous` right after step 1. The gateway
is then down until step 3. If step 3 misses the 5 minutes, the gateway logs
`policy_fetch_failed` with `status: 403`, and answers 503 until it has the new key.

A bump is written to `/state/gateway-key.json` before the new policy is used, and a vault restart
doesn't revive a retired key. A generation lower than the current one is refused. The standard
tier has no gateway key at all: the link socket's peer uid is the identity.

## 15. The `lan` profile

For agents on other hosts, add a TLS reverse proxy (Caddy, pinned by digest):

```sh
export ZOEYMCP_LAN_HOST=zoeymcp.lan.example   # the name agents use; the default
docker compose -f deploy/compose.yaml --profile lan up -d
docker compose -f deploy/compose.yaml cp \
  lan:/data/caddy/pki/authorities/local/root.crt ./zoeymcp-lan-root.crt
```

- Agents use `https://<ZOEYMCP_LAN_HOST>:8443/s/<server>/mcp`. Install `zoeymcp-lan-root.crt`
  as trusted on each client (`NODE_EXTRA_CA_CERTS=./zoeymcp-lan-root.crt` for Node-based ones).
  The CA lives in the `lan-data` volume, so it survives restarts.
- `gateway.hosts` must list the name: the shipped policies list `zoeymcp.lan.example`. A 421
  from the gateway means it isn't listed.
- `ZOEYMCP_LAN_BIND` (default `0.0.0.0`) picks the host address to publish on.
- Caddy sees client tokens (it terminates TLS) and holds no other secret.

## 16. Limits

Under `gateway.limits`, all with defaults: request bodies (1 MiB), arguments (256 KiB), results
(4 MiB), one upstream message (8 MiB), concurrent requests (8), streams (4) and legacy sessions
(16) per client, upstream sessions (64), idle timeouts (1800 s for agents' sessions, 600 s
upstream), the call and listing deadlines (300 s, 30 s), listing pages (32), tools (512) and
bytes (4 MiB), schema size (64 KiB), depth (32) and subschemas (512), and `policy_max_stale`
(300 s). A server's `call_timeout` overrides the call deadline. Changing the body limit or the
session idle timeout takes a gateway restart (`limits_change_needs_restart`).

## 17. What the gateway can't do

- **Silent drift** between two checks is caught at the next check, not at the next call.
- **Modern stateful servers** see one principal for every client (one credential): a handle
  minted for one agent works for another. To keep agents' state apart, give each its own server
  entry, route and credential. On legacy servers sessions are per client unless
  `shared_session: true`, which `check` warns about.
- **Deliberate disclosure:** a server can always leak the credential it was given in a form the
  vault doesn't recognize. Bind credentials narrowly; in the hardened tier agents have no other
  way out.
- **Standard-tier egress:** the gateway shares the vault's network namespace. For anything that
  moves money, sends mail or touches personal data, use the hardened tier.

## 18. Troubleshooting the gateway

| An agent sees | Likely cause | Look at |
| --- | --- | --- |
| 401 | a wrong or missing token, a source pin | `auth_refused` with `reason` `no_token`, `bad_token` or `source` |
| 404 | the server isn't assigned to the client, doesn't exist, or isn't remote; another client's session | the policy; `auth_refused` with `reason` `unassigned` or `session` |
| 421 / 403 | `Host` not in `gateway.hosts` / `Origin` not in `gateway.origins` | `auth_refused` with `reason` `host` or `origin` |
| 429 | too many requests, streams or sessions for the client | `auth_refused` with `reason` `limit`; `gateway.limits` |
| 503 | no view yet, or a stale one | `policy_stale`; `policy_fetch_failed` (`status: 403` is a refused gateway key) |
| `-32602 Unknown tool` | not included, unpinned, drifted, marked or invalid | `zoeymcp review <server>` |
| `-32603 upstream unavailable (ref ...)` | the listing failed, the vault refused (its `code` says why, e.g. `credential_unavailable`), or the upstream is down | grep the ref; `server_list_failed`, `vault_refused` |
| `isError` with `(ref ...)` | an upstream error, a timeout, a lost connection, a result refused | grep the ref |
| `arguments refused: at ...` | the arguments don't match the pinned schema | the tool's definition (`review --show`) |

Every log line is JSON with `role` (`vault`, `gateway` or `launcher`). No client token or hash,
gateway key, session id, argument value, result content or upstream error text is ever logged.

## 19. Approvals

An `approve` tool asks a human before each call, through the agent's own MCP client (an
elicitation in form mode; see [clients.md](clients.md) for what to check in a client). Only a
client whose policy entry has `approvals: {attended: true}` is ever asked; every other client's
`approve` calls are refused at once ("refused: no approver for this client").

What the human sees, rendered by the gateway and nothing else:

```text
Approval request 3f9a2c41d07e8b15
Client: agent1
Tool: broker-trade → place_order
Answer by 14:05 UTC. Accept runs this one call, exactly as shown.

{
  "quantity": 10,
  "symbol": "ACME"
}
End of approval request 3f9a2c41d07e8b15
```

The ref heads and ends every prompt, is in the agent's answer and in the ledger, so one call can
be followed from end to end. A toolkit shows a plan of exact writes instead of arguments (the
mail toolkit: From, To, Subject, then the body as it will be sent).

- **Accept** runs exactly the call shown, once. Anything else (decline, dismiss, no answer before
  the deadline, the agent cancelling, the client losing the stream, a policy change, a stop)
  sends nothing, and the agent is told which.
- **Busy:** while one call of a tool waits or runs, a second call of the same tool by the same
  client is refused with the first one's ref and when it frees. A client has at most
  `max_pending_per_client` prompts waiting (1), at most `max_prompts_per_hour` (30), and a
  `cooldown` (15 s) after a decline before the same tool may ask again.
- **Timeouts:** `gateway.approvals.timeout` (300 s) must stay below the client's own tool-call
  timeout, or the client gives up before the human answers; a client's `approvals.timeout` may
  only lower it. `check` refuses more than 600 s.
- **Nothing hidden:** a prompt holding hidden characters, wide runs of spaces, stacked combining
  marks, or (for a client that renders Markdown, `renders: markdown`, the default) code fences,
  HTML or links, is refused before anyone is asked, as is one over `budget_chars` (3000; a
  client's may only be lower). It is never cut. Set `renders: plain` only for a client you have
  checked shows prompts as plain text.
- **`confirm_code: true`** adds a short code the human must type. It stops a blind auto-accept
  hook, not software that reads the message, and not a holder of the client's token.
- **Approve only what you read.** Keep routine calls in `allow`, so prompts stay rare enough to
  read.

## 20. Stopping with approved calls running

A stop waits for approved calls that are already running: their outcome is recorded before the
gateway exits. The gateway stops first, then the vault, so a send the gateway waits on isn't cut.
The shipped windows cover a 300 s `call_timeout`: the standard container's `stop_grace_period` is
420 s (the gateway gets 330 s, then the vault 75 s); in the hardened compose the gateway has 330 s
and the vault 75 s. If an `approve` tool's `call_timeout` is longer, `check` warns: raise the
stop windows to match. A new approval asked during a stop is refused ("the gateway is stopping").

## 21. The approval ledger

Every approval is in `/state-gateway/ledger/`: `asked`, `decided`, then exactly one `outcome`,
each record hash-chained to the one before and holding only names, refs, decisions and keyed
digests (an HMAC under `/state-gateway/ledger.key`) of the arguments and the prompt, never their
values. A record is on disk before the next step: the accept before the call goes out. If the
ledger can't be written, nothing is asked.

```sh
zoeymcp ledger --since 1d                 # recent calls: ref, client, tool, decision, outcome
zoeymcp ledger --verify                   # walk the hash chain
zoeymcp ledger check <ref> args.json      # were these the arguments that call was shown with?
```

After a crash, the next start closes every call left open: a prompt that was waiting gets
`decided abandoned` and `outcome not_sent`; an accepted call whose result never came back gets
`outcome unknown`, since it may have run. A torn last
line is moved aside. To anchor the chain, copy the head hash `--verify` prints somewhere the
gateway can't write.

## 22. The SMTP connector

The vault sends mail itself, with an app password only it holds, from a fixed sender to fixed
recipients (`profiles/smtp-implicit-tls.yaml`, `profiles/smtp-starttls.yaml`). The route accepts
only the gateway, and only `GET /config` and `POST /send`.

- **`zoeymcp secret set mail-pass`** binds the password to the connector's host, port, sender
  and recipients. Change any of them and sends answer `credential_unavailable` until you enter it
  again: a changed recipient list needs your say-so. Use one app password per connector.
- **TLS is verified before AUTH**, against the mail server's name, implicit or with STARTTLS;
  STARTTLS is required, never optional. With `egress_proxy` set, the vault connects through it
  with CONNECT.
- **The rolling limit:** `max_per_day` attempts in any 24 hours, failures included, rebuilt from
  the journal at start.
- **Every attempt is journaled** under `/state/connectors/<connector>/` before connecting, keyed
  by the caller's `Idempotency-Key` (a toolkit uses its call's ref). A key is sent at most once:
  a repeat answers with the first result. A send cut after the final dot (or by a crash) is
  recorded `unknown` and never retried: check the recipient's mailbox before sending again.
- **Kill switches**, fastest first: `paused: true` and reload (sends refused at once, no password
  needed to resume); drop the tool from the toolkit's `include`; revoke the app password at the
  provider.

| Code | Meaning |
| --- | --- |
| `connector_paused` | `paused: true` |
| `daily_limit` | the rolling limit; `Retry-After` says when |
| `credential_unavailable` | the password is missing, or its binding no longer matches: `secret set` |
| `connector_constraints_differ` | the request expected another sender or recipient list |
| `proxy_refused`, `smtp_unreachable`, `smtp_tls_failed`, `smtp_auth_failed`, `smtp_auth_unsupported`, `smtp_refused` | not sent |
| `smtp_outcome_unknown` | the connection dropped after the message was handed over: it may have arrived |

## 23. Toolkits

A toolkit is Python running inside the gateway. It holds no credential or address: it declares
named slots, and the policy maps each to a vault route and lists the methods and paths it may use
there (`profiles/toolkit-mail.yaml`, `profiles/toolkit-records.yaml`). A consequential tool shows
the human a plan of exact writes and may send only those, once. **A toolkit is as trusted as the
gateway**: code in the gateway process can skip the gateway's approvals.

- **Writing one:** `examples/toolkits` and `zoeymcp.toolkit` (`Toolkit`, `@toolkit.tool`,
  `Text`, `Range`, `Batch`, `Plan`, `Write`, `Show`); test it with `zoeymcp.toolkit.testing.run`,
  which applies the gateway's own checks and texts.
- **Registering:** an entry point in the `zoeymcp.toolkits` group of your distribution. The
  gateway imports only registered modules, never `zoeymcp` itself, and only from files inside its
  environment that its uid can't write.
- **Installing:** build a derived image (`examples/derived-image`: `lock.sh`, `docker build`,
  `verify.sh`) and run its gateway, in the hardened tier with `ZOEYMCP_GATEWAY_IMAGE`.
- **Reviewing:** `zoeymcp review <server>` prints each tool's definition, its classification
  from the code and its pin; `--add TOOL` puts a tool the code declares consequential into
  `approve`. A tool the code marks consequential can't be put in `allow`: it is hidden.
- **`pinning: off`** serves the definitions the image holds, without pins: a rebuilt image can
  change a tool without review (`check` warns; `toolkit_loaded` logs each tool's pin). Fine for a
  toolkit you build yourself; keep `required` otherwise.
- **Configuration** comes only from the policy (slots and rules) and what the vault answers: the
  standard tier's launcher passes the gateway no other environment.

## 24. What approvals can't do

- **A client can auto-accept.** The gateway can't tell a human's answer from software's: check
  each client ([clients.md](clients.md)) before marking it `attended`.
- **A holder of an attended client's token can approve its own calls**, with or without a
  confirmation code. Keep the token out of the agent's sandbox, and pin a source network where
  the gateway sees the client directly; behind the `lan` proxy it sees only the proxy.
- **A compromised gateway or toolkit can skip gateway approvals** until M8's out-of-band
  approver. What the vault enforces still holds: fixed recipients, the limit, the pause, the
  route allowlists, the send journal.
- **The standard tier shares egress** between the vault and the gateway (and so toolkits): use
  the hardened tier for toolkits with third-party dependencies.
- **One gateway process:** approvals, locks and committed calls aren't shared between replicas.

## 25. Troubleshooting approvals

| The agent sees | Likely cause | Look at |
| --- | --- | --- |
| `refused: no approver for this client` | the client isn't `attended` | the client's `approvals` |
| `refused: this client can't show approvals` | the client declared no form-mode elicitation, or has no back channel | the client's capabilities; [clients.md](clients.md) |
| `refused: another call to this tool is waiting or running (ref ..., frees within N s)` | the same tool is already asking or running for this client | the first ref in the ledger |
| `refused: an approval is already waiting for this client`, `... too many approval requests this hour`, `... declined moments ago` | `max_pending_per_client`, `max_prompts_per_hour`, `cooldown` | `gateway.approvals` |
| `refused: ...` naming a rule (`markup`, `over budget`, ...) | the prompt would hide text, or is too long | the arguments; the client's `renders` and `budget_chars` |
| `declined by operator`, `no answer in time` | the human's answer, or none | the ledger |
| `refused: the approval ledger can't be written` | the ledger directory or disk | `ledger_write_failed` |
| `refused: the tool or policy changed while waiting for approval` | a pin, policy or freshness change between ask and accept | `approval_decided`, the view |
| `toolkit unavailable (ref ...)` | the module isn't registered, failed to import, or its slots don't match | `toolkit_unavailable` with `reason` |
| `toolkit error: vault answered 403 blocked_<reason>` | the toolkit tried something its slots don't allow | `toolkit_vault_blocked` |
