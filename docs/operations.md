# Operating ZoeyMCP

How to run what is built so far: the vault (M1), OAuth in the vault (M2), the gateway for
remote MCP servers in both deployment tiers (M3, §9 onwards), approvals, the SMTP connector
and toolkits (M4, §19 onwards), and the admin portal as far as it is built (M5, §26). The design
and the reasons behind it are in [design.md](design.md); this page is the how-to.

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
- `setup.json`: the pending portal setup code, as a hash with its expiry, MAC'd under a key
  derived from the master key (the code itself is never stored);
- `portal/passkeys.json`: the portal's passkeys, MAC'd the same way, and any
  `portal/passkeys.rejected-<ms>.json` a `--reset` enrolment moved aside;
- `ledger-reported/`: the vault's copy of the gateway's approval ledger (§21).

**Setup codes.** `zoeymcp setup-code` prints a one-time code that enrols a passkey in the portal.
It works once, for 15 minutes, and a new one replaces the last. Enrolling with it adds a passkey;
with `--reset` it removes every other passkey and ends every session (for a lost or stolen
passkey, or a passkey file that can't be verified). Its stderr names the origins to open, and says
what enrolling will do. **If the portal refuses a code you haven't used, someone else used it
first:** run `zoeymcp passkeys` to see what they enrolled, then `zoeymcp setup-code --reset`.
`--wait` keeps the command running until a passkey is enrolled with the code, then prints that
passkey's fingerprint, origin, name and time, to compare with what the portal showed you. The
code is never logged; `setup_code_issued` records only its expiry and `reset`.

`zoeymcp passkeys` lists every passkey with its fingerprint, how and where it was enrolled
(`via` is `setup_code`, `setup_code_reset` or `portal`) and when it was last used;
`zoeymcp passkeys --remove FINGERPRINT` removes one, the last one too. `zoeymcp sessions` lists
the portal's sessions and `--end-all` ends them. None of these need a passkey: host access is the
recovery path.

On a host without the admin socket (Windows, or `--admin-socket none`),
`zoeymcp setup-code --state DIR [--reset]` writes the code into the state directory itself. It
needs the vault's `ZOEYMCP_MASTER_KEY` in its environment, and refuses to run as root, which would
leave a file the vault's uid can't read. A running vault reads the file at the next redemption.

**Backups.** Back up `store.json`, `gateway-key.json` and `portal/passkeys.json` together: they
are all sealed under the same master key, and none is any use without it. A backup restored with
an older passkey file brings back passkeys removed since, so after any restore run
`zoeymcp passkeys` and remove what shouldn't be there. Safe to drop: `setup.json` (issue a new
code), `portal/passkeys.rejected-*.json`, and the `torn-*.bin` files the reported copy keeps
aside. Drop with care: `ledger-reported/` (the gateway refills what it still holds; older history
is lost) and the connectors' send journals (the daily limit and the record of what was sent).
Back up the gateway's `/state-gateway` separately; restoring one volume and not the other shows
as a fork in the reported copy (§21).

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

**In the portal.** **Connect**, on the Credentials page (§26), is the same login from a
browser, and pasting is its primary path too. The dialog shows the scopes asked for and expected,
where the tokens will go, and a link that opens the provider's sign-in page in a new tab. After
you approve, that tab is sent to the credential's `redirect_uri` and fails to load, as above:
copy its whole address from that tab's address bar and paste it into the dialog, within the
login's 10 minutes. The vault checks the paste at once, before any passkey prompt: a mistyped or
wrong address is refused with its reason and can be pasted again, while a provider's refusal
ends the login and shows the description the answer carried. Then it shows what it will store
(the binding, the one it replaces, the scopes), and exchanges the code only after you confirm
with your passkey; the exchange can take up to 76 s. **Connect and rebind** is `--rebind`. For
`client_credentials` the button is **Test it**, the test fetch; one that works clears the
credential's failure state, as `oauth reset` would. **Try again** is `oauth reset`, after a
passkey prompt.

**The portal's callback.** A credential can skip the paste when its `redirect_uri` is its own
callback address on a listed origin: the origin, `/oauth/callback/`, and the credential's name,
exactly, such as `https://vault.example.net/oauth/callback/calendar` for a credential named
`calendar` with `https://vault.example.net` in `admin.origins`. Each credential has its own
address. A trailing slash, a query, a default port written out or another credential's name is
paste only, and `check` warns with the exact form. The one `localhost` address allowed is
`http://localhost:<port>/oauth/callback/<credential>`, and only when `http://localhost:<port>`
is listed and the name is the credential's own; otherwise the policy doesn't load. The port is
the browser's, the origin's: the published or tunnelled one. The default
`http://127.0.0.1/callback`, and any `127.0.0.1` address, stays paste only.

Register the exact address with the provider. At Google that needs a **Web application**
client: an `https://<name>` origin is the durable route; a `localhost` address suits a testing
or unverified client, since Google offers local addresses on a web client "for testing" and its
verification may ask for them to go. If the provider refuses the address, keep the default and
paste. The shipped `profiles/google-oauth.yaml` uses a Desktop client and pastes.

Approve in the same browser that started **Connect**, from a session on the callback address's
own origin: the start sets a binding cookie there, and the callback takes the sign-in only
with it. The provider sends the tab to `/oauth/callback/<credential>`, which holds the code and
moves the tab to a page saying so; the dialog notices within a few seconds and asks for your
passkey, with "Confirm only if you have just finished approving in the provider's tab; if you
haven't, cancel." Nothing is stored before that confirm. Approving in another browser or on
another machine lands on a page saying "The portal didn't take this sign-in": copy that tab's
address and paste it into the dialog, as without the callback. "Two different answers came back
for this sign-in. Nothing was stored. Connect again." means what it says: something other than
your approval answered too. A login started with `zoeymcp login` never takes the callback; for a
callback address it prints "Your browser will land on the portal's callback, which doesn't take
a command-line login: copy the full address from that tab's address bar and paste it here".
Logs: `portal_request` for the callback's answer, with the route `/oauth/callback/{credential}`
and never the query; `oauth_callback_returned{credential}`;
`oauth_callback_failed{credential, reason, error}`; and for a refused callback
`oauth_callback_refused{reason, count}`, at most once per 10 seconds per reason.

Logins are owned: one started in the portal can't be completed or cancelled from the CLI or from
another session, nor one started in the CLI from the portal; each gets `flow_unknown`, as an
unknown login would. A credential still has one pending login, whoever started it: a new start
replaces it and says so (the CLI prints "Replaced a login pending in the portal."; the portal's
dialog says where the replaced one was pending). A portal session that ends cancels its logins.

**`--rebind`.** A login is refused when the policy now binds the grant differently from the
stored one, for example after a route moved to a new upstream origin. The CLI prints the old and
the new binding; run the login again with `--rebind` to accept the new one. The portal checks the
binding again when it checks the paste, so a policy reloaded meanwhile is refused there, before
the code is spent.

**`client_credentials`.** There is nothing to consent to: `login` makes one token call, prints
"The client credentials of <name> work: ...", stores nothing, and clears the credential's failure
state.

**Timeouts.** The CLI waits up to 76 s for a login answer (the 20 s code exchange, up to 41 s for
a refresh of the same slot that is already running, and 15 s to spare), up to 56 s for
`secret set` and `secret delete` (a secret an OAuth credential uses waits for a refresh in
flight), and 10 s for everything else. After a timeout, check `oauth status` before
trying again: the vault may have finished.

**Why a login is refused.** The CLI prints a message; the admin answer also carries one of
these `reason` codes, and the portal answers with the same reason and status, in its own words
(the table at the end of §26):

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

In the portal only, after the callback: `flow_returned` (409) means the callback already holds
the answer you pasted, so confirm that one; `flow_conflict` (409) means two different answers
came back for one sign-in and the login ended with nothing stored: connect again.

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
`set_secret`, `restart`, `delete_secret`, `fix_policy`, `wait`, `check_volume`,
`check_mailbox`, `check_gateway` or `read_ledger`, and the name it applies to). For a
deployment's verify script:

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
| `ledger_copy_none`, `ledger_copy_stale` | info, warning | (with a `gateway` section) the gateway hasn't reported to the vault's copy of its ledger yet; it hasn't asked or reported for 5 minutes, since the vault started (§21) |
| `ledger_copy_refused`, `ledger_copy_broken`, `ledger_copy_unavailable` | error | the copy refuses reports after a fork, gap or full; its files stop chaining at a seq; its directory can't be read (§21) |

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
- A reload that fails in some other way logs `reload_failed` with the error's type, and the
  running policy stays. The launcher's `TERM` after it still stops the process.
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
- To skip the paste in the portal, register a **Web application** client with the credential's
  exact callback address instead, and set `redirect_uri` to it (§2, "The portal's callback").
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

**The vault's copy.** The gateway pushes each record, once it is on disk, to the vault over the
link it already uses, and the vault keeps an append-only copy in `/state/ledger-reported/`, where
the gateway can't write: a held head the gateway can't rewrite afterwards, and in the vault's own
logs (`ledger_report_accepted` carries `head_seq` and `head_hash`). The gateway asks for the
copy's head at least once a minute, and as soon as a record is written, and sends what the copy
lacks, at most 256 records per report. While the copy refuses reports (below) it asks every 5
minutes; while the vault can't be reached it retries, backing off up to 5 minutes. The gateway
logs `ledger_report_failed` with a `reason` (a vault code such as `unavailable` or `fork`, or the
error's type) at most once per 5 minutes. Approvals never wait for a report. Read the copy in the
vault, or on the portal's Ledger page (§26):

```sh
zoeymcp ledger --vault                    # the copy's state, then the newest 200 calls with their sends
zoeymcp ledger --vault --before 980       # older ones
zoeymcp ledger --vault --format json
```

Every row is as the gateway reported it. A send in a connector's journal whose call the copy
doesn't hold is listed as an orphan: `no_ledger_record` once the copy has received a report since
that send began (a caller other than the gateway, or a gateway that didn't record it), else
`not_yet_reported`. No keyed digests are shown: check arguments with `zoeymcp ledger check` in the
gateway. The command exits 1 when the copy isn't `ok` or its files don't chain.

The first report after an empty copy is taken on trust; after that every report must extend the
held head, and a resend of records the copy holds is trimmed. Otherwise the copy **refuses every
report until you restart its chain**, logged once at `critical` (`ledger_report_refused`) and shown
by `zoeymcp health` (`ledger_copy_refused`):

| State | What happened | What to check |
| --- | --- | --- |
| `fork` | the gateway's ledger no longer extends the copy: its volume was lost or restored from a backup, or its ledger was rewritten | why the gateway's history changed. Approvals keep working |
| `gap` | the gateway skipped records the copy doesn't hold: the vault's volume was restored, and the gateway pruned those records since | whether the vault's volume was restored |
| `full` | the copy holds 64 MiB, and nothing received more than 30 days ago (by the vault's clock) can be pruned | a gateway sending more than an honest one would |

Once you have decided why:

```sh
zoeymcp ledger --vault --restart-chain
```

or **Restart the chain** on the portal's Ledger page, confirmed with a passkey. Either shows what
happens and asks first: the live chain moves to `archive-<ms>/` (still on disk, and readable on
the Ledger page), and if the archives would pass 64 MiB, the oldest are deleted, each listed with
its seq range, when it was received and its size. A deleted epoch's head seq and hash stay in `head.json` and in the
`ledger_reported_restarted` log line as anchors. The next report starts a new chain, on trust. If
the copy changed between the plan and your answer, nothing is done: run it again.

At start, before it listens, the vault recovers the copy: a torn last line is moved to
`torn-<ms>.bin` (`ledger_reported_repaired`), and a `head.json` that disagrees with the lines is
rebuilt from them. A break inside the files (damage, or an edit) is logged at `critical`
(`ledger_reported_broken`) and shown at its seq. A copy directory the vault can't read makes the
copy unavailable (`ledger_reported_unavailable`): reports are refused with 503 and the proxy runs
as before. Losing `ledger-reported/` loses the copy's history and its anchor; the gateway refills
what it still holds, on trust.

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

## 26. The portal

A draft, filled in as the portal is built: signing in, setup, sessions, passkeys, step-up,
secrets, health, OAuth connect, the ledger and the policy so far. Everything here can also be done with the CLI (§1).

**Before the first start.** The portal is on only when the policy has an `admin` block:

```yaml
admin:
  listen: 127.0.0.1:8081
  origins: [http://localhost:8081]
```

`listen` is where the vault binds its own listener for the portal (never a `--listen` address of
the proxy); `origins` lists every exact address a browser will use. A passkey belongs to the
origin's host name (its RP ID): one enrolled on `http://localhost:8081` also works on
`http://localhost:9000` if that is listed, since `localhost` has no port, but not on
`https://zoeymcp.tailnet.example`. Plain HTTP works only on `localhost`; anything else needs
HTTPS with a certificate the browser trusts, since browsers refuse passkeys elsewhere.

**The first start.** The log has `portal_listening` with the address, then, while no passkey can
sign in, `setup_pending` ("run zoeymcp setup-code in the vault's container", or with `--reset`
when the passkey file can't be verified). No code exists until you issue one. Without an `admin`
block the log has `portal_disabled`.

**Reaching it.** Open one of the listed origins exactly as written. An IP address such as
`http://127.0.0.1:8081/` is sent on to `http://localhost:8081/` when that origin is listed;
any other address gets 421. Through an SSH tunnel, forward the same port number
(`ssh -N -L 8081:127.0.0.1:8081 host`): the browser's address must be a listed origin, port
included, so another local port (`-L 9000:...`, `http://localhost:9000`) must be added to
`admin.origins`; it takes the same passkeys and needs no new setup code.

Both compose files turn the portal on and publish it on the host's loopback only, at
`http://localhost:8081`; set `ZOEYMCP_ADMIN_PORT` to publish it on another port, and the
compose file's origin follows. Remove the `admin` block for no portal.

- **Standard tier:** the vault listens on `0.0.0.0:8081` inside the container (a container's
  loopback can't be published). The gateway shares that network namespace, and any container on
  the compose project's network (the `lan` proxy, an agent joined to reach port 8090) can reach
  the listener too. Without a session they can only load the page and try to sign in or redeem
  a setup code: passkeys and single-use setup codes are what protect it there.
- **Hardened tier:** `admin.listen` is `vault-portal:8081`, a network alias the vault has on
  `egress` only, and the vault refuses to start unless it resolves to exactly one address. Only
  the host's loopback reaches it: not the gateway, nor anything on `internal`, `direct` or
  `agents`. Keep `egress` to the vault alone, since whatever joins it reaches the portal (an
  egress proxy gets a network of its own). If `egress` must become an internal network to your
  own proxy, nothing can be published: give the vault a separate non-internal network with its
  own alias for the portal, or run without one.

A port published on `127.0.0.1` stays off the LAN only on Docker Engine 28.0 or later; older
engines let hosts on the same network segment reach it. For a browser on another machine, use
the SSH tunnel above, or an HTTPS reverse proxy of your own with a certificate that machine
trusts: list its `https://<name>` origin, and have it pass `Host` unchanged, port included
(nginx's `$host` drops the port: use `$http_host`). The vault ignores `X-Forwarded-*`, and the
proxy sees every secret typed into the portal.

Such a proxy must also keep the OAuth callback's query out of its access log: the address
`/oauth/callback/<credential>?code=...&state=...` carries the provider's code and the login's
`state`. nginx's default log format logs `$request`, query included; for the portal use a format
that logs `$uri`, the path alone:

```nginx
log_format portal '$remote_addr [$time_local] "$request_method $uri $server_protocol" $status';
access_log /var/log/nginx/portal.log portal;
```

Caddy writes no access log unless the site has a `log` directive. If you enable one, keep the
query of `/oauth/callback/` paths out of it; check how your Caddy version filters fields before
relying on it.

**The first passkey.**

1. Run `zoeymcp setup-code` (add `--wait` to see the enrolment from the host).
2. Open the portal, choose **I have a setup code**, and type the code. Case, spaces and dashes
   don't matter. The code is spent at once: if anything fails from here, issue a new one.
3. Name the passkey (the device it is on, say) and choose **Create the passkey**. The browser
   asks your authenticator; the vault requires user verification (a PIN or biometrics).
4. The page shows the new passkey's fingerprint, then signs in with it, so you leave setup with
   a passkey that is proven to work. Compare the fingerprint with `zoeymcp passkeys`, or with
   the line `--wait` prints.

A phone's passkey provider may report an error even when the enrolment or the sign-in worked: if
the portal shows the new passkey's fingerprint, or signs you in, it worked.

A setup session lasts 10 minutes and enrols one passkey. A code relayed to someone else works for
whoever uses it first, so watch for it: `passkey_enrolled` with `via: setup_code` (or
`setup_code_reset`) is logged at level `warning`, and `--wait` prints the passkey's
fingerprint, origin and name. A portal that refuses a code you haven't used means someone else
used it: see §1.

**Daily use.** **Sign in with a passkey** asks for any passkey of this address; the browser
offers the ones it holds. A session has two halves: an `HttpOnly` cookie whose name carries the
port, and a token the page keeps in the tab's `sessionStorage`. Neither works alone. A session
ends after 15 minutes without use, 4 hours after sign-in, at **Sign out**, when the vault
restarts, and when the passkey that made it is removed. Closing the tab doesn't end it: browsers
restore a closed tab with its session, so sign out on a shared machine. Signing out also clears
the page's storage (`Clear-Site-Data: "storage"`).

**One signed-in tab per browser.** Each tab has its own token, but the browser holds one cookie
for the portal, so signing in from a second tab (or redeeming a setup code there) signs the first
tab out: its session ends at once, logged `portal_session_ended` with `why: replaced`, and the
first tab is told it is signed out at its next request. Signing in there again signs the second
tab out in turn. Only the browser holding a session's cookie can end it this way; other browsers'
sessions stay.

**Sessions.** The Sessions page lists every signed-in browser, by fingerprint, with its origin,
the passkey it signed in with, and when it was made and last used; **End the other sessions**
ends every one but yours. `zoeymcp sessions` lists the same from the host, and
`zoeymcp sessions --end-all` ends them all. At most 8 sessions are kept; a ninth sign-in ends the
one used least recently.

**Passkeys.** The Passkeys page lists every passkey that can sign in, by name and fingerprint:
the host name it works on (its RP ID), its key type, whether it is synced (a passkey provider
copies it between devices) or device-bound, how and on which origin it was enrolled, when, and
the day it was last used; the one this session signed in with is marked. **Enrol a passkey**
adds one from a signed-in session (after the step-up below, the browser asks the new
authenticator to create it; an authenticator that already holds one of this address's passkeys
is refused by the browser). **Rename** and **Remove** act on one. Removing a passkey ends every
session it signed in, yours too if it was the one; the portal never removes the last passkey
(enrol another first, or use `zoeymcp passkeys --remove` or `zoeymcp setup-code --reset` from
the host). `zoeymcp passkeys` lists the same from the host.

**Step-up.** Every change in the portal asks for a passkey first, in two steps. The vault checks
the change and shows what it will do (for a removal, which passkey and how many sessions end)
before any prompt, so a mistake shows there. **Confirm with your passkey** answers a prompt that
is bound to that one change, from this session and this address; the vault then runs exactly
what it showed. It holds a prepared change for 5 minutes, one per session; **Close** drops it.
If something it showed changed in between (another session renamed the same passkey, say), it
refuses with what it finds now, and you prepare again. Logs: `step_up_confirmed` (the kind and
the passkey that confirmed it), `step_up_refused` (the reason), `action_changed`,
`passkey_renamed` and `passkey_removed`; names are never logged.

**Secrets.** The Secrets page lists every secret in the store by name: what it may be used for
(the origins it is sent to; for an OAuth secret, its token endpoint and where its access tokens
go; for an SMTP password, the server, sender and recipients), when it was set and last
replaced, the master key it is encrypted under, and its health: `ok`, or what `zoeymcp health`
finds about it (`binding_changed` when a use the policy makes now would be refused,
`unreferenced` when nothing uses it, `orphan_slot` for a live token no credential keeps). It
never shows a value, its length or a hash of one, and no portal answer carries one. **Set the
secret** writes one: give the name
(the `NAME` of `store:NAME` in the policy) and the value, which the page empties as soon as it
is sent, whatever the answer. The value field is masked where the browser supports it, and
isn't offered to password managers. The vault checks it and shows, before the
passkey prompt, the binding it will be stored with and what it replaces (and the binding until
now, when that changes); the checks and bindings are exactly `zoeymcp secret set`'s. A name no
route or connector uses needs **Origins** (the https addresses it may be sent to); an OAuth
secret (a client ID, client secret or refresh token in the policy) always takes the policy's
binding and refuses origins. **Replace** fills in the name for a new value; **Delete** removes
one. Names starting `oauth.` are the vault's own (a credential's live tokens): the portal
neither writes nor deletes them (Connect does, on the Credentials page; `zoeymcp secret delete`
can from the host). If the policy is reloaded between the summary and the passkey prompt and
the binding moves, the vault refuses with what it finds now. A write the state volume refuses is
kept in memory and said so, as with the CLI. Logs: `secret_set` and `secret_deleted` with `via:
"portal"` (or `"socket"`), never the value.

**Home and health.** Home is the checklist of what needs you: every finding `zoeymcp health`
reports (§3), errors first, then warnings, then information, each with what to do: a button
where the portal can do it (**Connect**, **Try again**, **Set it on the Secrets page**, **Add a
passkey**), or the words for what only the host can do (restart with an environment variable
set, fix the policy, check the state volume). With no error or warning it says "Everything is
ready". Findings marked "(from stored metadata)" come from the store file's clear metadata,
which anyone with the file can edit: they are shown, never acted on. Every page shows the counts
of errors and warnings beside the session, and a banner while there is an error. Health is read
from metadata only, as `zoeymcp health` reads it: nothing is decrypted and no request is sent.

**Credentials.** The Credentials page lists every credential in the policy with the routes that
use it, its health findings, and for an OAuth credential its state (`ok`, `idle`, `backoff`,
`terminal`), its failure code, when it last worked, the scopes it asks for and where its tokens
go. **Connect** signs in with the provider by paste (§2); **Test it**, for a `client_credentials`
credential, makes one token call and, if it works, clears the failure state. **Try again** clears
a failure state after a passkey prompt, as `zoeymcp oauth reset` does, so the next request that
needs a token tries once. A credential whose refresh token is given another way (an `env:` seed,
or a store entry set on the Secrets page) has no Connect: its findings say how to renew it.
The Credentials page never shows a token, a code or a client secret, and neither does any portal
answer: the authorization link holds the login's `state` and the PKCE challenge, useless without
the verifier the vault keeps. Logs: `oauth_login_started`, `oauth_login_completed` or
`oauth_login_failed` (the reason), `oauth_flow_replaced`, `step_up_confirmed` with the action
`oauth.complete` or `oauth.reset`, and `oauth_cache_reset`; never a pasted address, a flow ID or
a provider's description.

**Ledger.** The Ledger page is the vault's copy of the gateway's approval ledger (§21), newest
first, 200 rows a page (**Older rows** for more). Each call shows when it was asked, its client,
server and tool, the decision, the outcome and how many writes it asked for and sent, and under
it each of its sends from the SMTP connectors' journals: the state, the SMTP code and the time,
never the Message-ID or the message's digest. Every row is as the gateway reported it; a record
the vault wrote itself (from M8) says so. A client or server the current policy doesn't name is
marked "Not in the current policy". Below the rows are the sends whose call the copy doesn't
hold: `no_ledger_record` once the copy has had a report since the send began (a caller other
than the gateway, or a gateway that didn't record it), else `not_yet_reported`. No keyed digest
of a call's arguments or prompt is shown: check arguments with `zoeymcp ledger check REF FILE` in
the gateway's container. The state line says where the copy's head is, when it last moved, and
whether its files stop chaining. While the copy refuses reports (`fork`, `gap` or `full`, §21),
every page has a banner, and **Restart the chain** shows, before the passkey prompt, the state
it lifts, the live chain it archives and every archived chain it deletes to stay within 64 MiB,
each with its seq range, when it was received and its size; it does what `zoeymcp ledger --vault
--restart-chain` does. If the copy changes between the summary and the prompt (a restart from the
host, say), the vault refuses with what it finds now. Archived chains are listed at the bottom,
each with **Show its rows**; a deleted one keeps only its head, as an anchor. A copy the vault
can't read is shown as such, and can't be restarted until the state volume is fixed. Logs:
`step_up_confirmed` with the action `ledger.restart`, then `ledger_reported_restarted`.

**Policy.** The Policy page shows the running policy, read-only: this deployment's policy is
declarative, so change it in its source (the file given with `--config`, `ZOEYMCP_CONFIG`, or
standard input) and reload (§7); the page shows the reloaded policy at once. It is built field by
field from a list of what may be shown, so a field a later version adds stays out until that
version decides. Shown only as `(set)`, and listed by where they are: a client's token or token
hash, every placeholder, a basic credential's username, a connector's username and sender (its
recipients as a count), and the values of an OAuth credential's `token_headers` and of a route's
forced query parameters, which could hold a literal credential. Secret references (`store:x`,
`env:X`) show as written; the policy never holds a secret value.

**A second origin.** Add it to `admin.origins` and reload (§7): it is served at once, and
removing one ends its sessions. Another `http://localhost` port takes the passkeys you have. A
different host name has its own: issue a setup code and redeem it **on the new origin**.

**Recovery.** One passkey lost while another works: sign in with the other and remove the lost
one on the Passkeys page (or `zoeymcp passkeys --remove FINGERPRINT` from the host).
Every passkey lost: `zoeymcp setup-code` adds one, or `--reset` replaces them all. A passkey or
device that may be stolen, or a passkey file reported tampered (`passkey_store_tampered`, and
the portal answering "can't be verified"): `zoeymcp setup-code --reset`. A reset enrolment
removes every other passkey and ends every session; the old authenticator may be the one you
enrol again.

**What a stolen session can do.** A session is the cookie and the tab's token together; a page
on another `localhost` port receives the cookie (cookies ignore ports) but not the token, and
gets 401. Someone holding both halves, within the session's limits, can read what the portal
shows and end other sessions; every change needs a fresh passkey prompt bound to that change.

**When something fails.** The portal shows the vault's own sentence for every refusal; the
reason is in the vault's log line `portal_request` (or `portal_refused`, at most once per 10
seconds per reason). What the browser itself refuses (an IP address, a page that isn't a secure
context, no passkey support, a cancelled prompt) is worded by the page.

<!-- refusals: generated from portal/refusals.py; tests/unit/test_refusal_doc.py -->
| Status | Reason | What the portal says |
| --- | --- | --- |
| 421 | `wrong_host` | This portal doesn't answer to that address. Use one listed in admin.origins; behind a proxy, pass the original Host header. |
| 405 | `method` | The portal doesn't answer that method. |
| 404 | `not_found` | Nothing by that name exists here. |
| 403 | `cross_site` | Refused: this request didn't come from the portal's own page. |
| 403 | `bad_origin` | Refused: this request didn't come from the portal's own page. |
| 415 | `content_type` | The request wasn't JSON. |
| 411 | `length_required` | The request didn't say how long its body is. |
| 413 | `too_large` | The request was too large. |
| 503 | `busy` | Too many requests right now. Wait a moment and try again. |
| 429 | `rate_limited` | Too many requests right now. Wait a moment and try again. |
| 401 | `no_session` | You're signed out (the session ended, or the vault restarted). Sign in again. |
| 403 | `scope` | A setup session can only enrol a passkey. Sign in with your passkey first. |
| 408 | `too_slow` | The request was too slow. |
| 400 | `bad_json` | The request wasn't valid JSON. |
| 400 | `bad_body` | The request didn't have the expected fields. |
| 401 | `setup_code_refused` | That setup code isn't valid. Codes work once, for 15 minutes. If you haven't used it, someone else may have: run zoeymcp setup-code --reset. |
| 401 | `passkey_refused` | That passkey wasn't accepted here. Passkeys belong to one address: use the one you enrolled it on, or a setup code. |
| 401 | `step_up_refused` | The passkey didn't confirm this. Nothing changed; prepare it again. |
| 503 | `unavailable` | The passkey file can't be verified (edited, or written under another master key). Run zoeymcp setup-code --reset with host access. |
| 409 | `changed` | Something changed since you prepared this (shown below). Check it and prepare it again. |
| 404 | `action_unknown` | That confirmation, login or passkey prompt expired or was already used. Start again. |
| 404 | `ceremony_unknown` | That confirmation, login or passkey prompt expired or was already used. Start again. |
| 409 | `last_passkey` | This is the only passkey. Enrol another first, or use zoeymcp setup-code --reset. |
| 409 | `ambiguous_fingerprint` | More than one passkey has that fingerprint, so nothing changed. Run zoeymcp setup-code --reset with host access. |
| 400 | `bad_name` | A passkey name is 1 to 64 characters on one line, with no hidden characters. |
| 500 | `not_written` | Not written to disk; nothing changed; check the state volume. |
| 500 | `internal` | The portal failed to answer that; the vault's log has the cause. |
| 400 | `invalid_name` | Names are lower case letters, digits and _ . -, up to 128, starting with a letter or a digit. |
| 409 | `vault_managed` | Tokens for this credential come from Connect, on the Credentials page. |
| 400 | `empty_value` | Enter a value. |
| 400 | `bad_value` | The value has line breaks, control or invisible characters. |
| 409 | `value_too_large` | A secret can't be larger than 65536 bytes. |
| 400 | `origins_type` | Origins are a list of https URLs. |
| 409 | `origins_on_oauth` | OAuth secrets take the policy's binding. |
| 409 | `bad_origins` | That origin can't be used: `<detail>`. |
| 409 | `unbound` | No route or connector uses store:`<name>`, so give the origins it may be sent to. |
| 409 | `no_route` | The policy can't bind it: `<detail>`. Fix the policy. |
| 409 | `orphan_slot` | The policy can't bind it: `<detail>`. Fix the policy. |
| 409 | `binding_conflict` | The policy can't bind it: `<detail>`. Fix the policy. |
| 404 | `not_oauth` | That isn't an OAuth credential in the policy. |
| 404 | `flow_unknown` | That confirmation, login or passkey prompt expired or was already used. Start again. |
| 409 | `no_authorize_url` | This credential has no authorize_url, so it can't connect in a browser. |
| 409 | `authorize_misconfigured` | The policy's authorization settings can't make a sign-in link. Fix the policy. |
| 409 | `binding_changed` | The policy now binds this grant differently (shown below). Connect again and accept the new binding. |
| 409 | `client_id_unavailable` | The client ID isn't set, or isn't bound to the token endpoint. Set it on the Secrets page. |
| 409 | `client_secret_unavailable` | The client secret isn't set, or isn't bound to the token endpoint. Set it on the Secrets page. |
| 400 | `not_configured` | The vault has no token settings for this credential. |
| 429 | `too_many_flows` | Too many sign-ins are pending. Finish or cancel one, or wait 10 minutes. |
| 400 | `redirect_mismatch` | That isn't the address the provider sent you to; it starts with `<redirect_uri>`. |
| 400 | `state_mismatch` | That address belongs to another login; use the tab this login opened. |
| 400 | `duplicate_param` | That address has a parameter twice. Copy it again from the address bar. |
| 400 | `provider_error` | The answer said the provider refused: `<error>` |
| 400 | `iss_mismatch` | The answer came from a different issuer; nothing was stored. Connect again. |
| 400 | `no_code` | The provider's answer had no usable code. Connect again. |
| 400 | `exchange_failed` | The provider's token endpoint didn't take the sign-in (`<code>`). Connect again. |
| 400 | `no_refresh_token` | The provider issued no refresh token. For Google keep access_type: offline and prompt: consent; some providers need an offline_access scope. |
| 409 | `flow_returned` | The provider already sent this sign-in back to the portal; confirm it here. |
| 409 | `flow_conflict` | Two different answers came back for this sign-in. Nothing was stored. Connect again. |
| 400 | `callback_not_taken` | The portal didn't take this sign-in. Copy this tab's address and paste it into the portal's Connect dialog, or into zoeymcp login if you started it there. |
| 403 | `not_navigation` | The portal didn't take this sign-in. Copy this tab's address and paste it into the portal's Connect dialog, or into zoeymcp login if you started it there. |
| 400 | `bad_query` | The portal didn't take this sign-in. Copy this tab's address and paste it into the portal's Connect dialog, or into zoeymcp login if you started it there. |
| 409 | `not_restartable` | The reported ledger isn't stuck, so there's nothing to restart. |
| 503 | `copy_unavailable` | The vault's copy of the gateway's ledger can't be read: check the state volume. The proxy runs as before. |
| 400 | `too_large` (enrolling a passkey) | The passkey's answer was too large. |
| 400 | `bad_field` (enrolling a passkey) | The browser's answer didn't have the passkey fields expected. Try another browser. |
| 400 | `client_data` (enrolling a passkey) | The browser's passkey data couldn't be read. Try another browser. |
| 400 | `wrong_type` (enrolling a passkey) | The browser answered a different kind of passkey prompt. Start again. |
| 400 | `wrong_challenge` (enrolling a passkey) | That passkey answer was for another prompt. Start again. |
| 400 | `wrong_origin` (enrolling a passkey) | The passkey answer names another address. Use the portal at the address you opened. |
| 400 | `cross_origin` (enrolling a passkey) | The passkey prompt ran inside another page. Open the portal directly. |
| 400 | `top_origin` (enrolling a passkey) | The passkey prompt ran inside another page. Open the portal directly. |
| 400 | `no_attested_data` (enrolling a passkey) | The authenticator didn't give a new key. Try again, or another authenticator. |
| 400 | `wrong_rp` (enrolling a passkey) | The passkey was made for another address. Use the one you enrolled it on. |
| 400 | `not_present` (enrolling a passkey) | The authenticator didn't confirm you were there. Try again. |
| 400 | `not_verified` (enrolling a passkey) | The passkey didn't verify you with a PIN or biometrics; the vault requires it. |
| 400 | `backup_flags` (enrolling a passkey) | The authenticator's backup flags contradict each other. Try another authenticator. |
| 400 | `credential_id` (enrolling a passkey) | The authenticator's credential ID can't be used. Try another authenticator. |
| 400 | `raw_id_mismatch` (enrolling a passkey) | The browser's credential ID doesn't match the authenticator's. Try another browser. |
| 400 | `key_encoding` (enrolling a passkey) | This authenticator's key encoding isn't supported. |
| 400 | `algorithm` (enrolling a passkey) | The browser reported another key type than the authenticator made. Try another browser. |
| 400 | `public_key` (enrolling a passkey) | The authenticator's key can't be used (ES256, Ed25519, or RSA of 2048 to 4096 bits). |
| 400 | `key_mismatch` (enrolling a passkey) | The browser's copy of the new key doesn't match the authenticator's. Try another browser. |
| 409 | `duplicate_credential` (enrolling a passkey) | This passkey is already enrolled. |
| 409 | `too_many_passkeys` (enrolling a passkey) | There are 32 passkeys already. Remove one first. |
| 400 | `not_allowed` (enrolling a passkey) | That passkey isn't one this prompt asked for. |
| 400 | `unknown_credential` (enrolling a passkey) | That passkey isn't enrolled here. |
| 400 | `user_handle` (enrolling a passkey) | That passkey belongs to another account. |
| 400 | `at_flag` (enrolling a passkey) | The authenticator's answer carried key data it shouldn't. Try again. |
| 400 | `trailing_bytes` (enrolling a passkey) | The authenticator's answer had bytes it shouldn't. Try again. |
| 400 | `backup_eligibility_changed` (enrolling a passkey) | This passkey's backup setting changed since it was enrolled. Enrol it again. |
| 400 | `signature` (enrolling a passkey) | The passkey's signature didn't verify. |
<!-- end of refusals -->
