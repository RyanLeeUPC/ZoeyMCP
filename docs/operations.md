# Operating ZoeyMCP

How to run what is built so far: the vault (M1), OAuth in the vault (M2), the gateway for
remote MCP servers in both deployment tiers (M3, §9 onwards), approvals, the SMTP connector
and toolkits (M4, §19 onwards), and the admin portal (M5, §26). §27 says which hosts are
supported. M7's so far: onboarding a remote MCP server by URL (§11), your own egress proxy
(§28), and fitting ZoeyMCP into a stack that already has one (§29). The design and the reasons
behind it are in [design.md](design.md); this page is the how-to.

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
- `gateway-key.json`: the gateway key's generations and when the previous one retires (hardened
  tier, §14), MAC'd;
- `connectors/<connector>/`: each SMTP connector's send journal (§22);
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
| `client_id_unavailable`, `client_secret_unavailable` | the client ID ref or client secret isn't set, or the client ID isn't bound to the token endpoint (a stored client secret bound otherwise is `client_secret_binding_changed`) | `zoeymcp secret set <name>`, or set the env var and restart (the message says which) |
| `not_configured` | the token manager doesn't know the credential; it shouldn't happen | reload the policy (§7) or restart the vault |
| `binding_changed` | the stored grant is bound differently from what the policy now derives | `--rebind` |
| `client_secret_binding_changed` | the client secret in the store is bound to another token endpoint origin or other server origins than the policy now derives. An onboarded client's secret is stored for the endpoints its fragment named; one you set yourself, for the token endpoint and the routes its credential had then, so adding or removing a route of a credential with a stored client secret, or naming the secret from a second credential, also needs it entered again (`zoeymcp health` doesn't report this yet) | revert the edit, onboard again, or enter the secret again with `zoeymcp secret set <name>`; `--rebind` doesn't apply |
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
`check_mailbox`, `check_gateway`, `read_ledger`, `add_passkey`, `review_passkeys` or
`reset_passkeys`, and the name it applies to). For a
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
| `passkeys_unavailable` | error | (with an `admin` block) the passkey file can't be verified, so portal sign-in is off: `zoeymcp setup-code --reset` (§26) |
| `passkey_counter`, `passkey_single` | warning, info | a passkey's signature counter went back in the last 30 days (the authenticator may have been copied: check `zoeymcp passkeys`); only one passkey is enrolled, so losing it means a reset |

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

**Adopting a grant another tool holds** (a refresh token issued to another client of yours):
there must be one holder at a time, or a rotating token is used twice and the provider may revoke
the whole grant. In order: commit the credential with that tool's client ID (onboarded with `login
--mcp URL --client-id ID`, §11, or written by hand); stop the old holder's refreshes; seed the
token, `printf '%s' "$RT" | zoeymcp secret set <credential>-refresh` (or an `env:` seed); and only
then let the vault refresh it. `login --mcp URL --no-connect` then compares the committed
credential with the server's metadata without signing in, and a second run never signs in over a
token the credential already holds.

## 6. Recovery per kind

Where the table says `secret set` or `zoeymcp login`, the portal's **Set the secret** (Secrets
page) or **Connect** (Credentials page) does the same (§26).

| Credential | Lost master key or state volume | Lost rotation |
| --- | --- | --- |
| `header`, `query`, `path`, `basic` | `secret set` again | — |
| OAuth refresh token in `store:` | `zoeymcp login` | `zoeymcp login` |
| OAuth env seed, not rotating | automatic: the seed is promoted again | — |
| OAuth env seed, rotating | `zoeymcp login` | `zoeymcp login` |
| `client_credentials` | `secret set` the client secret | — |
| SMTP connector | a new app password at the provider, then `secret set` it; after a change of recipient, host, port or From, `secret set` again (the old binding no longer matches) | — |

The portal's own state recovers from the host, never from the portal:

| What happened | Recovery |
| --- | --- |
| one passkey lost, another still works | sign in with the other and remove the lost one (or `zoeymcp passkeys --remove FINGERPRINT`) |
| every passkey lost | `zoeymcp setup-code` adds one; `--reset` replaces them all |
| a passkey or its device may be stolen | `zoeymcp setup-code --reset`: its enrolment removes every other passkey and ends every session |
| the passkey file can't be verified (`passkey_store_tampered`, `passkeys_unavailable`) | `zoeymcp setup-code --reset`: the file is moved aside as `portal/passkeys.rejected-<ms>.json`, never overwritten |
| the state volume lost | the store's recovery above, then `zoeymcp setup-code` for a first passkey |
| the master key lost (or replaced without `ZOEYMCP_MASTER_KEY_PREVIOUS`), the volume kept | the store's recovery above, then `zoeymcp setup-code --reset`: the passkey file can't be verified under another key |
| the state volume restored from a backup | `zoeymcp passkeys`, and remove every passkey that shouldn't be there: the backup brings back passkeys removed since (§1) |

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
- A changed `egress_proxy` needs a restart: every HTTP client and the SMTP connectors keep the
  proxy the vault started with until then. A reload whose `egress_proxy` differs from the one the
  vault started with logs `egress_proxy_change_needs_restart`, on every reload until the restart.
- A changed, added or removed `admin.listen` needs a restart (`admin_listen_change_needs_restart`):
  the portal stays where it listens. A changed `admin.origins` takes effect at once, and the
  sessions of a removed origin end. Removing the whole `admin` block keeps the portal on its old
  origins until the restart.
- A route moved to a new upstream origin can't use its stored grant until
  `zoeymcp login <credential> --rebind`.
- The environment is read once, at startup: a new env value (a seed, a client secret) needs a
  restart. An inline policy in `ZOEYMCP_CONFIG` is part of the environment too, so changing it
  means recreating the container.

**Upgrading to M7.** A URL field that ends in a bare `?` or a bare `#`
(`https://auth.example/token?`, `http://127.0.0.1/callback#`) loaded before and is now refused, at
start and on reload. Delete the character: the address is the same without it. A `token_url` or
`authorize_url` longer than 2,048 characters is now refused too. `check` gives two new warnings
on a policy that loaded before: an oauth2 credential behind a gateway server's route that sends no
`resource` in `extra_params` (set it to the server's URL), and, with `egress_proxy` set, a
credential-less `allow_insecure_upstream` route over plain http, which a CONNECT-only proxy
refuses.

## 8. Provider notes

**Any provider.** A `token_url` or `authorize_url` may carry a query, such as a tenant or a
policy name (`https://login.example/oauth2/token?p=B2C_1_signin`). RFC 6749 says it must be kept,
so the vault sends it exactly as written and puts its own parameters after it. The query holds
letters, digits, `%HH` escapes and `-._~!()*+,=&:@/?` only: at most 16 `name=value` pairs, each
name written without escapes and given once, and none that the vault sets on that request
(`client_id`, `redirect_uri`, `state`, `scope`, `resource` and the rest) or that the credential's
`extra_params` or `authorize_params` sets. Either URL is at most 2,048 characters. Every other URL
in a policy still takes no query.

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

**Keep the tool list small.** Every tool an agent is given takes room in the model's context, on
every turn. Include only the tools each agent needs, and assign each agent only the servers it
uses. Where a client can load tools lazily (a tool search that fetches a definition only when the
model asks for it), turn that on: the gateway serves the same pinned definitions either way, and
tells clients when a list changes, so a lazy client fetches the new one.

### Onboarding by URL

`zoeymcp login --mcp URL` (M7) adds an OAuth-protected MCP server from its URL, beside the manual
path above. It takes two commits: fragment 1 adds the credential, its route and the server with
no tools; once it is committed, the same command again signs in, and the review (steps 5 to 7
above) gives the tools to commit. Until the vault registers clients itself (later in M7), it
needs a client the provider registered for you: its client ID, and its secret if it has one.
Without one the plan stops at `registration_unavailable`.

It runs in the vault's container, over the admin socket:

```sh
# hardened tier
docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp login \
  --mcp https://mcp.notes.example/mcp --name notes --client-id my-client > onboard-notes-1.yaml
# standard tier
docker compose -f deploy/compose.yaml exec zoeymcp zoeymcp login \
  --mcp https://mcp.notes.example/mcp --name notes --client-id my-client > onboard-notes-1.yaml
```

The vault probes the URL once, reads the server's protected-resource metadata and its
authorization server's metadata through its guarded client, and the plan goes to stderr: every
host it contacted or will contact, the endpoints, the issuer, whether `iss` is required, the
scopes and where they came from, the names, the client and its redirect address, and `check`'s
findings with the server merged (an error there stops it before anything is stored). Every string
from the network is shown with hidden characters made visible. Confirm (`--yes` doesn't ask), and
fragment 1 goes to stdout and a `Next:` list to stderr: each command to run, as you type it on the
host.

- **The shipped `notes` example.** The compose files carry a `notes` server with a static key
  (credential `notes-key`, route `notes-mcp`) at `https://mcp.notes.example/mcp`. A URL a server
  already reaches with a credential that isn't oauth2 is refused `already_configured`: remove that
  server, its route and its credential first.
- **Names.** `--name` names the credential, the route and the server; `--credential`, `--route`
  and `--server` name each. Without them, the host's first label that says something (not `mcp`,
  `api`, `www`, `app` or `server`), with `-2` and on when it is taken. A name you give that the
  policy, the store or another onboarding has is refused `name_taken`.
- **A public client** (`--client-id` alone): nothing is sent past discovery and nothing is stored;
  the fragment holds only what you typed.
- **A confidential client**: `--client-secret`, with `--issuer` (the authorization server that
  issued the client: a discovered one that differs, byte for byte, is refused `as_unknown`) and
  `--client-auth basic|post` (default `basic`). Show the plan first with `--plan-only`, then pipe
  the secret in with `exec -T` and `--yes`: the question can't be read from the stdin the secret
  comes on, and a secret typed into an `exec` whose stdout is redirected would be echoed. On a
  terminal without `--yes`, it is read from a hidden prompt once you confirm. Never on the command
  line.

  ```sh
  docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp login \
    --mcp https://mcp.notes.example/mcp --name notes --issuer https://auth.notes.example \
    --client-id existing-client --plan-only
  printf '%s' "$CLIENT_SECRET" | docker compose -f deploy/compose.hardened.yaml exec -T vault \
    zoeymcp login --mcp https://mcp.notes.example/mcp --name notes \
    --issuer https://auth.notes.example --client-id existing-client --client-secret \
    --client-auth basic --redirect-uri http://127.0.0.1:8765/callback --yes > onboard-notes-1.yaml
  ```

  The secret is stored at once as `<credential>-client-secret`, bound to the token endpoint and
  the server's origin that fragment 1 names: it works once that fragment is committed, and only
  while those stay (`client_secret_binding_changed` otherwise). The fragment holds `client_secret:
  "store:<credential>-client-secret"`, never the value.
- **The redirect address**: `--redirect-uri` is the one the provider has on record for the
  client; without it, the shared `http://127.0.0.1/callback`. The plan says when the address isn't
  the credential's own, which turns off a backstop against pasting an answer meant for another
  sign-in.
- **`--plan-only`** discovers and prints the plan, then stops. The same command (the same URL,
  names and options) within 30 minutes carries on from that plan.
- **A server that publishes no protected-resource metadata** (an older pattern): the plan says
  so, and where the authorization server was found: the issuer you named (`--issuer`, MCP's
  "pre-configured values"), the server's origin (MCP 2025-03-26's rule), or the server's own URL as
  an issuer, which the plan marks as a ZoeyMCP heuristic and no MCP rule. Check that one before you
  confirm.
- **Several authorization servers**: the plan stops at `as_choice_needed`, listing them; name one
  with `--issuer`.
- **More options**: `--scope "a b"` requests your scopes instead of the server's; `--allow-private`
  lets the typed server's own `host:port` resolve to a private address (fragment 1 then adds it to
  `egress_private`); `--client-name` is the name a provider may show for the client; `--indent N`
  or `--for compose` lays fragment 1 out for an inline policy; `--format json` prints the vault's
  answers as one JSON document on stdout instead.

**Committing fragment 1.** The `Next:` list gives the commands for the policy's source: `check
--with` proves the fragment merges and says what it adds, then you merge it, prove the edited
policy with `check`, and reload. For the inline `ZOEYMCP_CONFIG` of the compose files:

```sh
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps -v "$PWD:/w:ro" vault \
  check --with /w/onboard-notes-1.yaml
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps vault check
docker compose -f deploy/compose.hardened.yaml up -d vault
```

Merge it under `ZOEYMCP_CONFIG` in the compose form (`--for compose`: indented 8, every `$`
written `$$`), or replace the whole block with `check --with FRAGMENT --print-merged --for
compose`. Check the edited file before `up -d`: a bad merge stops the vault from starting, and
the portal with it. For a policy file the commands are `zoeymcp check --config FILE --with
FRAGMENT` and `zoeymcp check --config FILE`, then SIGHUP (§7); for a policy on stdin, `--config
-`, then a restart.

**The second run.** Once the policy names the credential, the same `login --mcp` command doesn't
onboard again. It rediscovers (the probe and GETs; nothing is registered or stored), compares
what it finds with the committed credential, route and server, and signs in with `zoeymcp
login`'s paste flow (§2; `--rebind` passes through). A difference is refused
`onboarding_mismatch`, naming each field that differs, never its value: revert the edit, or
register a new client with `--reregister`. A stored client secret's binding is checked too
(`client_secret_binding_changed`). Then the `Next:` list says to review the server in the
gateway's container (`zoeymcp review <server>`, steps 5 to 7 above); later in M7 the vault queues
the review itself.

**Adopting a grant another tool holds.** Onboard with that tool's client
(`login --mcp URL --client-id ID ...`) and commit fragment 1; stop the old holder's refreshes;
seed its refresh token with `printf '%s' "$RT" | ... exec -T vault zoeymcp secret set
<credential>-refresh`; then run `login --mcp URL --no-connect`, which compares and doesn't sign
in. The second run skips signing in by itself whenever the credential already holds a refresh
token, and says so. Keep that order for a rotating token (§5).

**Re-registering** (`login --mcp URL --reregister`): a new client for the committed credential,
under its own names. Discovery runs again, the new client's secret replaces the stored one, and
fragment 1 replaces `credentials.<credential>` whole: its header line says so, and a comment names
each field that changed. What you set beyond the client and the endpoints (the scopes unless you
give `--scope`, lifetimes, the refresh token's ref) is kept; `rotates` follows the new client
when it authenticates differently. A credential with `token_headers`, or with a list in
`extra_params` or `authorize_params`, can't be written into a fragment, so it is refused
`reregister_by_hand` before anything is asked or stored: edit that credential by hand. If
anything fails after the new client's secret is stored, the vault puts the committed secret back
and the answer says `secret_restored`. After the commit, sign in again with `zoeymcp login
<credential> --rebind`: the old grant belongs to the old client, and `--rebind` accepts its new
binding when the token endpoint moved.

**Through your own proxy** (§28): a host the proxy refuses stops the onboarding at
`proxy_refused`, naming every host it needs with the Squid lines to add for the vault
(`--squid-src vault=ACL` names its source ACL there), and the same command to run again, which
carries on where it stopped. Keep the onboarding lines in a separate included file, so `--check`
on the emitted file stays clean. After the commit, the `Next:` list says to emit the allowlist
again, reload the proxy and remove the onboarding lines.

**Your own compose command.** The printed commands start with `ZOEYMCP_COMPOSE_CMD` and name the
services in `ZOEYMCP_EXEC_SERVICE` and `ZOEYMCP_REVIEW_SERVICE`, which the shipped compose files
set. If you run compose with override files, a project directory or a project name, set
`ZOEYMCP_COMPOSE_CMD` in `.env` to the command you type (`docker compose -f
deploy/compose.hardened.yaml -f my-override.yaml`), or every printed command names the shipped
file alone.

| When | What happens, and what to do |
| --- | --- |
| The vault restarts before you confirm | the onboarding is gone: run the same command again |
| It restarts after a client secret was stored, before the commit | the secret stays (health reports it `unreferenced` until fragment 1 is committed): commit the fragment you were shown, or run the same command to see fragment 1 again, which stores nothing |
| The commit recreates the vault (inline `ZOEYMCP_CONFIG`) | nothing is lost: run `login --mcp` again to sign in |
| It restarts during the sign-in | the sign-in is lost (§2): run it again; a stored client secret stays |
| The store is lost | the client secret with it: onboard again with a new client (`--reregister` once the policy names the credential); the old client stays registered at the provider |

The admin socket's routes behind it (M7 design M.1): `POST /onboard/discover` answers the plan,
or the second run's comparison (`stage: committed`); `POST /onboard/<onboarding>/register` stores
a given client's secret and answers fragment 1; `POST /onboard/<onboarding>/fragment` answers
fragment 1 for a client with no secret (or again, at another indent); `DELETE
/onboard/<onboarding>` cancels. A vault restart ends every onboarding, but a client secret it
stored stays; the same discovery again finds it, checks its binding against a fresh discovery,
and answers the onboarding registered, so `/fragment` shows fragment 1 again without storing
anything. If the binding differs, its names stay taken: delete the entry or choose other names.
If anything fails after register stored the secret, the vault deletes it again and the answer says
`secret_deleted`; a re-registration's puts back the secret it replaced, and says
`secret_restored`. Its log lines:

| Event | Fields |
| --- | --- |
| `onboard_started` | `owner` (`cli` or `portal`), `host` (the server's), `allow_private` |
| `discovery_fetch` | `fetch_kind` (`probe`, `prm`, `as`, `register`), `host`, `port`, `status`, `bytes`, `ms`, `via` (`direct` or `proxy`) |
| `onboard_planned` | `host`, `issuer` (its host), `require_iss`, `registration`, `auth`, `scopes` (how many) |
| `onboard_refused` | `reason`, `host` (the server's) |
| `onboard_registered` | `credential`, `issuer` (its host), `auth`, `secret_stored` |
| `onboard_blocked` | `host` and `port` your proxy refused, `needed` (how many hosts it must allow) |
| `onboard_ended` | `why`: `registered` (the policy names its credential now), `cancelled`, `expired`, `owner_gone`, or `compared` (a second run's comparison found nothing changed) |
| `address_refused` | `purpose` (`discovery`), `host`, `port`, `verdict` |

None holds an onboarding's ID, a secret, a URL's path or query, or a body; a stored client
secret logs `secret_set` with `via` and its binding, as any secret does.

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
- The `lan` proxy forwards only `/s/*` to the gateway: it doesn't front the portal (§26).

**Your own certificate.** Instead of Caddy's CA, give it a certificate your clients already trust
(from your own CA, or a tailnet's). Replace the Caddyfile in a compose override file, with the
certificate and key as compose secrets, and run with both files
(`docker compose -f deploy/compose.yaml -f lan-cert.yaml --profile lan up -d`):

```yaml
# lan-cert.yaml
services:
  lan:
    secrets: [lan-cert, lan-key]
    environment:
      ZOEYMCP_CADDYFILE: |
        {
          admin off
          auto_https disable_redirects
        }
        https://${ZOEYMCP_LAN_HOST:-zoeymcp.lan.example}:8443 {
          tls /run/secrets/lan-cert /run/secrets/lan-key
          request_body {
            max_size 16MB
          }
          @mcp path /s/*
          handle @mcp {
            reverse_proxy ${ZOEYMCP_LAN_UPSTREAM:-zoeymcp:8090} {
              flush_interval -1
            }
          }
          handle {
            respond 404
          }
        }
secrets:
  lan-cert: {file: ./zoeymcp-lan.crt}   # the certificate, then any intermediates
  lan-key: {file: ./zoeymcp-lan.key}
```

This is the shipped Caddyfile with `tls internal` replaced; with `compose.hardened.yaml`, write
`gateway:8090` as the upstream's default. Outside Swarm, compose mounts a file secret as it is on
the host, so the key file must be readable by Caddy's uid, 10004, and by nobody else who
shouldn't have it. Clients then need no `zoeymcp-lan-root.crt`.

**ACME** (a certificate from a public CA such as Let's Encrypt) needs a name in public DNS, and a
challenge the CA can complete: Caddy answers the HTTP and TLS-ALPN challenges on ports 80 and 443,
which the profile doesn't publish, and the DNS challenge needs a Caddy build with your DNS
provider's module, which the pinned image doesn't have. Where both hold, the same override
without the `tls` line (and without the secrets) makes Caddy obtain and renew one, kept in the
`lan-data` volume. For a host on a private network, your own certificate is the simpler path.

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
doesn't hold is listed as an orphan. The copy here is the live chain and every archived chain a
restart kept (below), so a send whose call was archived is no orphan. Each orphan has a flag:

| Flag | What it means |
| --- | --- |
| `not_yet_reported` | no report has reached the live chain since the send began: look again after the next one |
| `older_than_copy` | the send began before the earliest record the copy still holds (the files holding its call were pruned after 30 days, or a restart deleted its archived chain), so it can't be checked |
| `no_ledger_record` | the copy has had a report since the send began, covers its time, and holds no record of its call: a caller other than the gateway, or a gateway that didn't record it. However old the send, this stands |

The journal keeps sends for 400 days and the copy may keep less, so `older_than_copy` is
expected for old sends. No keyed digests are shown: check arguments with `zoeymcp ledger check` in the gateway.
The command exits 1 when the copy isn't `ok` or its files don't chain.

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

The admin portal is the vault's own web page for what needs a person: the first passkey,
secrets, OAuth connect, health, the ledger and the policy, in that order below. Everything here
can also be done with the CLI (§1, §2, §3, §21), and recovery is done only from the host.

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
  own proxy, nothing can be published through it. A separate non-internal network with its own
  alias for the portal would publish it, but **it gives the vault a direct route out beside your
  proxy**, which only a host firewall rule outside Docker's view could then stop. Publish it
  through a relay on networks of its own instead, as `examples/existing-stack/` does (§29), or
  run without a portal.

A port published on `127.0.0.1` stays off the LAN only on Docker Engine 28.0 or later; older
engines let hosts on the same network segment reach it (§27).

**From another machine,** use the SSH tunnel above, or an HTTPS reverse proxy of your own with a
certificate that machine's browser trusts (a public CA's, a tailnet's, or your own CA installed
on that machine): browsers refuse passkeys on a page with a certificate error. List its origin,
`https://<name>`, in `admin.origins`. The proxy must:

- **pass `Host` unchanged**, port included: Caddy does by default; nginx's `$host` drops the
  port, so use `$http_host`. A 421 means the `Host` the vault got isn't a listed origin;
- **expect `X-Forwarded-*` to be ignored:** the vault never reads them, nor `Forwarded`;
- **keep the OAuth callback's query out of its access log:** the address
  `/oauth/callback/<credential>?code=...&state=...` carries the provider's code and the
  login's `state`;
- **keep the session's header half out of its log** too, if it logs request headers: the page
  sends it as `X-ZoeyMCP-Session`.

The proxy sees every secret typed into the portal and both halves of every session: run it on a
machine you trust as much as the vault's host. The `localhost` and SSH-tunnel paths have none.

nginx, whose default log format logs `$request`, query included, and no request headers but the
referrer and user agent:

```nginx
log_format portal '$remote_addr [$time_local] "$request_method $uri $server_protocol" $status';

server {
    listen 443 ssl;
    server_name zoeymcp.example.com;
    ssl_certificate     /etc/nginx/tls/zoeymcp.crt;
    ssl_certificate_key /etc/nginx/tls/zoeymcp.key;
    access_log /var/log/nginx/portal.log portal;    # $uri: the path alone, no query

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $http_host;          # not $host, which drops a port
    }
}
```

Caddy, which writes no access log unless the site has a `log` directive, and then logs the full
URI and every request header (the values of `Cookie` and `Authorization` redacted, other
headers not), so the filter removes both secrets:

```caddyfile
zoeymcp.example.com {
	reverse_proxy 127.0.0.1:8081
	log {
		output file /var/log/caddy/portal.log
		format filter {
			request>uri query {
				delete code
				delete state
			}
			request>headers>X-Zoeymcp-Session delete
		}
	}
}
```

With a public name Caddy obtains the certificate itself; for your own, add
`tls /path/to/cert.pem /path/to/key.pem` to the site. Caddy writes header names as
`X-Zoeymcp-Session`, the form the filter names. The `filter` syntax is that of Caddy's current
documentation: check it against your version's, and look at a log line before relying on it.

Both snippets assume the proxy runs on the vault's host and reaches the published port. With
`admin.origins` set to `[http://localhost:8081, https://zoeymcp.example.com]`, both addresses
work, each with its own passkeys.

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
go. **Connect** signs in with the provider by paste, or through the portal's callback for a
credential registered with its own callback address (§2); **Test it**, for a `client_credentials`
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
marked "Not in the current policy". Below the rows, on the first page, are the sends whose
call neither the live chain nor a kept archived chain holds, each flagged in words (§21's
table): "no ledger record" when the copy has had a report since the send began and covers its
time (a caller other than the gateway, or a gateway that didn't record it), "not reported yet"
when no report has reached it since, and "older than the ledger copy: can't be checked" when the
send began before the earliest record the copy still holds. To judge them, the first page reads
every kept archived chain too, at most 64 MiB. No keyed digest
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
enrol again. After restoring the state volume from a backup, check `zoeymcp passkeys`: a passkey
removed since the backup is back, and works (§1, §6).

**What a stolen session can and can't do.** A session is the cookie and the tab's token
together; a page on another `localhost` port receives the cookie (cookies ignore ports) but not
the token, and gets 401. Someone holding both halves, within the session's limits, can read what
the portal shows (names, bindings, health, the policy view, the ledger, the passkey and session
lists), start an OAuth sign-in, and end other sessions. They can't write or delete a secret,
complete a connect, reset a credential, enrol, rename or remove a passkey, or restart the ledger
chain: each needs a fresh passkey prompt bound to that change. If you think a session was taken,
**End the other sessions** (or `zoeymcp sessions --end-all` from the host); the threat model
([threat-model.md](threat-model.md)) has the rest.

**Checks for a verify script.** None of these changes anything:

```sh
docker compose -f deploy/compose.yaml exec -T zoeymcp zoeymcp health --json --strict > /dev/null
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: wrong.example' http://127.0.0.1:8081/   # 421
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'Sec-Fetch-Site: cross-site' \
  -H 'Origin: https://evil.example' http://localhost:8081/api/logout                   # 403
```

The first exits non-zero on any error or warning (§3). The second shows that a name the policy
doesn't list (a DNS-rebinding page's) gets nothing. The third shows that a cross-origin request
is refused before any session is looked at.

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
| 409 | `client_secret_binding_changed` | The committed token endpoint or server origin differs from the ones this client was registered with. Onboard again, or set the secret with zoeymcp secret set. |
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
| 400 | `url_invalid` | That address can't be onboarded (`<detail>`). Use an https URL without a query; a private host needs allow private. |
| 502 | `endpoint_invalid` | The server's `<field>` can't be used (`<detail>`), so nothing was sent to it. |
| 502 | `url_dollar` | The server's `<field>` holds a $, which compose would read as a variable in the policy, so it isn't used. |
| 502 | `challenge_ambiguous` | The server's sign-in challenges name two different metadata addresses, so neither is used. |
| 502 | `scope_invalid` | The server names a scope a policy can't hold (a $, a quote, a backslash or a space in it, or too many), so nothing was registered. |
| 409 | `not_protected` | The server answered without asking for a sign-in and publishes no OAuth metadata. Add it to the policy by hand. |
| 502 | `prm_not_found` | The server publishes no protected-resource metadata, and no authorization server was found without it. Give its issuer, or add the server by hand. |
| 502 | `prm_invalid` | The server's protected-resource metadata can't be used (`<detail>`). |
| 502 | `prm_resource_mismatch` | The server's metadata is for `<resource>`, not `<expected>`, so it isn't used (RFC 9728). |
| 502 | `dpop_required` | The server requires DPoP-bound tokens: the provider's tokens aren't Bearer tokens the vault can use. |
| 409 | `as_choice_needed` | The server names more than one authorization server. Choose one of `<issuers>`. |
| 400 | `as_unknown` | That issuer isn't one the server names. Choose one of `<issuers>`. |
| 502 | `as_metadata_not_found` | No metadata was found for the authorization server at the addresses tried. |
| 502 | `as_metadata_invalid` | The authorization server's metadata can't be used (`<detail>`). |
| 502 | `as_issuer_mismatch` | The authorization server's metadata names another issuer than the one it was fetched for, so it isn't used (RFC 8414). |
| 502 | `pkce_unsupported` | The authorization server doesn't advertise PKCE with S256, which MCP requires. |
| 502 | `code_flow_unsupported` | The authorization server doesn't advertise the authorization code flow. |
| 409 | `name_taken` | The policy, the vault's store or another onboarding already has `<name>`. Choose another name. |
| 422 | `diff_invalid` | The running policy with this change merged fails check (`<detail>`), so no fragment is shown. |
| 404 | `onboarding_unknown` | That onboarding isn't in progress: it finished, expired or was started elsewhere. Start it again. |
| 429 | `onboarding_busy` | At most 4 onboardings can be in progress. Finish or cancel one, or wait for one to expire (30 minutes). |
| 409 | `onboarding_options_changed` | The onboarding in progress for this URL and these names stopped at your proxy and was started with other options. Run it with the same options to carry on, or start again once it expires (30 minutes). |
| 409 | `registration_unavailable` | Register a client at `<host>` and run again with its client ID. |
| 502 | `proxy_refused` | Your egress proxy refused the vault's connection to `<host>`. Allow the hosts listed here in it for the vault, then run the same command again. |
| 409 | `already_configured` | The server `<server>` already reaches this URL, with a credential of kind `<kind>`, not oauth2. Remove it, its route and that credential from the policy and reload first. |
| 409 | `onboarding_mismatch` | The committed policy differs from what the server publishes now, at `<fields>`. Revert the edit, or register a new client with zoeymcp login --mcp URL --reregister. |
| 409 | `reregister_by_hand` | The credential `<credential>` sets `<field>`, which a re-registration's fragment can't carry (`<why>`). Re-register by hand: edit the credential in the policy. |
| 502 | `address_refused` | The vault doesn't connect to `<host>`: its name resolves to a private, loopback or reserved address. Nothing was sent to it. |
| 502 | `resolve_failed` | The name `<host>` didn't resolve, so nothing was sent to it. |
| 502 | `fetch_failed` | The host `<host>` didn't answer as needed (`<detail>`). |
| 502 | `fetch_redirect` | The host `<host>` answered with a redirect, which the vault doesn't follow. |
| 502 | `fetch_too_large` | The answer from `<host>` is larger than the vault reads, so it isn't used. |
| 502 | `fetch_not_json` | The answer from `<host>` isn't one JSON object, so it isn't used. |
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

## 27. Supported platforms

**Deployments run in Linux containers**, from the official image, on Docker Engine 28.0 or later
in both tiers. Older engines let other hosts on the same network segment reach ports published
on `127.0.0.1`, and connect to a container's published ports directly, which would put the
portal and the standard tier's gateway on the LAN. The image smoke test refuses an older engine,
but ZoeyMCP can't check the host's engine at run time: check `docker version` yourself.

**Windows and macOS hosts are for development and tests only.** Running the vault or the gateway
outside a container there works for trying things out, with these differences:

| On | What differs |
| --- | --- |
| Windows | no admin socket, so no admin CLI against a running vault: issue a setup code with `zoeymcp setup-code --state DIR` (§1), and use the portal for the rest |
| Windows | no state lock (`state_lock_unavailable` in the log): nothing stops two vaults sharing a state directory |
| Windows | toolkits are refused (`no_ownership_on_this_platform`): file ownership can't be checked |
| Windows | no `SIGTERM`, `SIGINT` or `SIGHUP` handlers: stop with Ctrl-C, and restart to reload the policy |
| Windows | when a browser drops a connection, Python's event loop may print `ConnectionResetError` tracebacks to stderr, outside the JSON log; they are noise |
| Windows, macOS | the standard tier's launcher (`zoeymcp standard`) refuses to run: it needs a Linux container |
| Windows, macOS | the link socket's peer check needs Linux: the gateway uses a gateway key over TCP |

On a development host, `localhost` may resolve to `::1` first; bind the portal to
`127.0.0.1:8081` and browsers fall back to it.

## 28. Your own egress proxy

With `egress_proxy` set, the vault sends what it sends out through your proxy, and the proxy's
allowlist decides where that may go. `zoeymcp check --emit-egress-allowlist` prints that
allowlist from the policy, as a Squid snippet or as plain lists, and compares a file with it, so
a verify script notices when the proxy's configuration and the policy part.

**What goes through it.** Every HTTP request the vault makes: each route's upstream (so every
`tools/list`, `tools/call` and the rest that the gateway sends to a remote server, and every call
on a direct route), and every OAuth token request (`zoeymcp login`, the portal's connect, and each
refresh). Each SMTP connector connects through it too, with `CONNECT host:port`. As M7's
onboarding by URL lands, its discovery and registration requests, and the revocation of a deleted
credential's grant, go the same way. The vault ignores `HTTP_PROXY`, `HTTPS_PROXY` and the rest:
only `egress_proxy` counts. Nothing inbound goes through it: agents, the gateway's link and the
portal reach the vault directly.

**Setting it.** `egress_proxy` is `http://host:port`, with no path:

```yaml policy
version: 1
mode: declarative
# Every vault connection goes to your proxy, as CONNECT host:port.
egress_proxy: http://proxy.stack.example:3128
# The src ACL your squid.conf defines for the vault's address.
egress_proxy_acls: {vault: stack_vault_net}
# A destination on your own network: it may resolve to a private address.
egress_private: ["files.lan.example:443"]
credentials:
  notes-key: {kind: header, header: X-API-Key, format: "{secret}", secret: "store:notes-key"}
  files-key: {kind: header, header: Authorization, format: "Bearer {secret}", secret: "store:files-key"}
routes:
  - name: notes-mcp
    prefix: /notes
    upstream: https://mcp.notes.example
    credential: notes-key
    callers: [gateway]
    stream: true
    rules: [{methods: [POST, GET, DELETE], paths: [/mcp]}]
  - name: files
    prefix: /files
    upstream: https://files.lan.example
    credential: files-key
    callers: [{placeholder: ph-files-replace-me-with-a-long-random-value}]
    rules: [{methods: [GET], paths: [/v1/**]}]
```

- **CONNECT-only means https-only.** An `https` upstream is a `CONNECT` tunnel; a plain `http`
  one goes to the proxy as a forwarded request, which a CONNECT-only proxy (the snippet below
  allows nothing else) refuses. The text form marks such a destination, and `check` warns about a
  credential-less `allow_insecure_upstream` route over plain http when `egress_proxy` is set.
- **Changing it needs a restart.** `egress_proxy` is read when the vault starts, and every vault
  connection (routes, token requests, onboarding and SMTP sends) keeps that proxy. A reload whose
  `egress_proxy` differs from the one the vault started with logs
  `egress_proxy_change_needs_restart`, again on every reload until the restart: recreate the vault
  right after changing it (§7).

**Emitting the allowlist.** Run the image, which reads the service's own inline policy (add
`--config FILE` for a policy file). The policy is checked first: its findings go to stderr, the
allowlist to stdout, and a policy with errors prints no allowlist and exits 1.

```sh
# hardened tier
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps -T vault \
    check --emit-egress-allowlist --allowlist-format squid > proxy/zoeymcp.conf
# standard tier
docker compose -f deploy/compose.yaml run --rm --no-deps -T zoeymcp \
    check --emit-egress-allowlist --allowlist-format squid > proxy/zoeymcp.conf
```

**Comparing.** `--check FILE` compares FILE with what would be emitted, line endings aside: exit 0
when they match, 1 with each difference listed (`missing:`, `unexpected:`, or `order:` for the
first line out of place), 2 when FILE can't be read. Put it in your verify script:

```sh
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps -T -v "$PWD/proxy:/p:ro" vault \
    check --emit-egress-allowlist --allowlist-format squid --check /p/zoeymcp.conf \
  || echo "proxy configuration is out of date"
```

The standard tier's form swaps the prefix, as above. Each form's header names a digest of the
lists alone (hosts, ports and which are private), so an edit that changes no destination changes
no output, and `--check` stays clean.

**The forms** (`--allowlist-format`, default `text`):

- `text`: the header, then one `source host:port` line per destination, sorted by source, host
  and port. For the policy above:

  ```text
  # zoeymcp egress allowlist, lists sha256:2a54ff25a28967d36d1138d58af2ed4689f06e9aefcf3e07e730af498181f314
  vault files.lan.example:443
  vault mcp.notes.example:443
  ```

  The vault's source is `vault`; a plain-http destination's line ends with
  `# plain http: refused by a CONNECT-only proxy`.
- `json`: `{"v": 1, "digest": ..., "sources": {"vault": [{"host", "port", "private"}, ...]}}`.
- `squid`: a snippet to `include` from your `squid.conf`:

  ```text
  # zoeymcp egress allowlist, lists sha256:2a54ff25a28967d36d1138d58af2ed4689f06e9aefcf3e07e730af498181f314; regenerate with zoeymcp check --emit-egress-allowlist; keep your own final deny
  # expects your squid.conf to define: acl CONNECT method CONNECT, and acl stack_vault_net src <the vault's network>
  acl zoeymcp_private_dst dst 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 ::/96 64:ff9b:1::/48 100::/64 2001::/32 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 fec0::/10 ff00::/8
  acl zoeymcp_port_443 port 443
  acl zoeymcp_vault_1 dstdomain -n files.lan.example
  http_access allow stack_vault_net CONNECT zoeymcp_vault_1 zoeymcp_port_443
  acl zoeymcp_vault_2 dstdomain -n mcp.notes.example
  http_access allow stack_vault_net CONNECT zoeymcp_vault_2 zoeymcp_port_443 !zoeymcp_private_dst
  ```

**What the snippet expects of your `squid.conf`.** It defines none of the ACLs its header names,
and it never ends with a deny: your file defines `acl CONNECT method CONNECT` and one `src` ACL
for the vault's address, includes the snippet, and denies everything else after it. Squid stops
at an ACL that isn't defined, so a missing one shows on `squid -k parse`:

```text
http_port 3128
acl CONNECT method CONNECT
# The network the vault reaches the proxy on.
acl stack_vault_net src 172.30.5.0/24
# Emitted; never edited by hand.
include /etc/squid/zoeymcp.conf
# Onboarding lines only; empty otherwise.
include /etc/squid/zoeymcp-onboarding.conf
http_access deny all
```

Squid takes `#` as a comment only at the start of a line, so each comment has a line of its own.

The `src` ACL's name comes from the policy's `egress_proxy_acls` (`{vault: stack_vault_net}`), so
every command and the portal print the same lines; `--squid-src vault=NAME` overrides it for one
run, and with neither the snippet uses `zoeymcp_src_vault`. A name is 1 to 64 letters, digits or
underscores.

**How the snippet's rules work.** Each destination gets its own rule, so a host and its port
stay paired. The rule tests the source, `CONNECT`, the exact name (`dstdomain -n`, so a subdomain
doesn't match; an IP-literal destination uses `dst -n`) and the port first. With `-n` Squid looks
nothing up for that test: a name the policy doesn't list is refused by your final deny before any
DNS lookup, and a `CONNECT` to an address is never matched through its reverse (PTR) name, which
whoever controls that address chooses. Only after a name matched does
`!zoeymcp_private_dst` make Squid resolve it, and if any address in the answer is private,
loopback, link-local or otherwise non-global, the tunnel is refused, a mixed answer included. That
rule is rendered from the vault's own address tables, so keep it, and regenerate rather than edit.
A destination in `egress_private` has no private-destination test: it is on your network by
design. Squid holds an IPv4 address in its IPv4-mapped form (`::ffff:a.b.c.d`), so the rule
leaves out the mapped range itself, which would refuse every IPv4 destination; an AAAA answer of
`::ffff:10.0.0.1` still meets `10.0.0.0/8`. The image's smoke test runs a pinned Squid against an
emitted snippet: it parses it, refuses a listed name answering `10.x`, `::ffff:127.0.0.1` or a mix
of public and private, and an address whose PTR name is listed, and lets a listed public name
through.

**Onboarding through it.** With onboarding by URL (`zoeymcp login --mcp`, as M7 lands), the
proxy refuses the hosts the policy doesn't name yet. The vault then stops and answers
`proxy_refused` with every host it has learned so far and the Squid lines that allow them, in
the snippet's shape, reusing its `zoeymcp_private_dst` and its `zoeymcp_port_<n>` ACLs (a port
the emitted file has no ACL for, such as an authorization server on 8443, gets its `acl` line
among them); run the same command again after adding them and the vault runs discovery again
under the same onboarding, with its names and its 30 minutes. Usually two rounds suffice: the
server's host, then its authorization server's. Keep
those lines in their own included file (`zoeymcp-onboarding.conf` above), so `--check` on the
emitted file stays clean meanwhile. Once the policy names the credential and the route, the
emitted list covers the hosts the vault needs from then on: regenerate it, reload the proxy, and
empty the onboarding file.

**What it doesn't do.**

- **A NAT64 answer slips through.** A Squid `dst` ACL can't see the IPv4 address inside a NAT64
  answer (`64:ff9b::/96`), so where your resolver synthesizes them, a listed name can steer the
  proxy to a private IPv4 address that way. Only a proxy that judges the address it connects to
  catches it, as ZoeyMCP's own egress role (hardened tier, later in M7) does; Squid doesn't.
- **It doesn't confine the gateway or toolkits in the standard tier.** They share the vault's
  network namespace there and don't use `egress_proxy`: the standard tier shares egress (§24).
  Neither your proxy nor ZoeyMCP's own egress role changes that; the hardened tier, whose gateway
  has no route out, does.

## 29. Fitting ZoeyMCP into an existing stack

A stack that already runs agents, an egress proxy and its own networks takes ZoeyMCP's hardened
tier as two more services: the gateway beside the agents, the vault behind the stack's proxy,
and no new route out for either. `examples/existing-stack/` is this shape as a compose file of its
own, with the portal relay below, the policy inline and the emitted Squid snippet; its README has
the steps, a unit test pins the file's networks, and the image's smoke test runs it. This is the
shape.

- **The gateway** joins the stack's agent network in place of `agents`, plus `internal` to the
  vault, and nothing else; no `lan` profile. **The agent network must be `internal: true`**: if it
  isn't, the gateway, and the toolkits that run inside it, have a route out beside the proxy.
- **Aliases only ZoeyMCP uses:** the gateway reaches the vault as `zoeymcp-vault` (an alias on
  `internal`), and agents reach the gateway as `zoeymcp-gateway` (an alias on the agent network),
  never by the bare service names. A name is resolved on every network the caller is on, and the
  stack's networks may hold a `vault` or `gateway` of their own that would be sent the gateway
  key or a client token.
- **The vault** is on `internal` and on one network it shares with the stack's proxy, and, with
  the portal, the relay's internal `portal` network (below), and no other.
  **That network must be `internal: true`** too, so the proxy is the vault's only way out (the
  proxy reaches the internet on a network of its own): if it isn't, the vault has a direct route
  out beside the proxy, and the allowlist confines nothing. `egress_proxy` names the proxy's
  address on that network, and the emitted snippet (§28) goes into the proxy's configuration,
  with the vault's address on that network as its `src` ACL.
- **The agents** get one entry per server in the runtime's configuration: the URL
  `http://zoeymcp-gateway:8090/s/<server>/mcp`, the header
  `Authorization: Bearer <client token>` (§10), and the runtime's own approval setting for that
  server at its least-prompting level, so the gateway's approval (§19) is the one prompt.
- **Your own compose files.** The commands onboarding by URL prints (§11) start with
  `ZOEYMCP_COMPOSE_CMD`, which `examples/existing-stack/compose.yaml` sets to its own file. Set it
  in `.env` to your stack's command (its `-f` files, `--project-directory` or `-p`), or they name
  that file alone.

The vault's policy, inline in its `ZOEYMCP_CONFIG` as in `deploy/compose.hardened.yaml`, here
with no portal (no `admin` block: see "The portal" below for adding one):

```yaml policy
version: 1
mode: declarative
egress_proxy: http://stack-proxy:3128
egress_proxy_acls: {vault: stack_vault_net}
credentials:
  notes-key: {kind: header, header: X-API-Key, format: "{secret}", secret: "store:notes-key"}
routes:
  - name: notes-mcp
    prefix: /notes
    upstream: https://mcp.notes.example
    credential: notes-key
    callers: [gateway]
    stream: true
    rules: [{methods: [POST, GET, DELETE], paths: [/mcp]}]
gateway:
  hosts: [zoeymcp-gateway]
  clients:
    agent1:
      token_sha256: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
      servers: [notes]
  servers:
    notes:
      kind: remote
      route: notes-mcp
      path: /mcp
      tools: {include: [], allow: [], approve: []}
      review: {}
```

An override beside the stack's own compose files moves both services onto those networks with
their aliases (`!override` replaces a list instead of adding to it, and `!reset` empties one;
Compose 2.24.4 or later), points the gateway at `zoeymcp-vault`, and sets the vault's
`ZOEYMCP_CONFIG` to the policy above:

```yaml
# compose.zoeymcp.yaml
networks:
  stack-agents: {external: true}      # the stack's agent network, internal: true
  stack-proxy: {external: true}       # the network the stack's proxy listens on, internal: true
services:
  vault:
    networks: !override
      internal: {aliases: [zoeymcp-vault]}
      stack-proxy: {}
    ports: !reset []                  # nothing to publish through: see "The portal" below
    environment:
      ZOEYMCP_CONFIG: |
        # the policy above
  gateway:
    command: [gateway, --vault, "http://zoeymcp-vault:8080", --listen, "0.0.0.0:8090"]
    networks: !override
      internal: {}
      stack-agents: {aliases: [zoeymcp-gateway]}
```

**The portal.** Docker publishes a port only through a non-internal network, so a vault with
none can't publish the portal, and giving it one (§26's paragraph on an internal `egress`) also
gives it a direct route out beside the proxy. The answers, best first:

- **A relay on networks of its own:** a small reverse proxy on an internal network shared with
  the vault alone (the vault's `vault-portal` alias is there) and on a second network that
  publishes `127.0.0.1:8081`. The vault keeps no non-internal network; the relay holds no secret
  and keeps no access log, nor an error log that would record a request's URI and headers.
  `examples/existing-stack/` ships this as its `portal-relay` service:
  Caddy, passing `Host`, `Origin` and `Sec-Fetch-*` unchanged, so the vault's own checks answer
  through it as they do without it.
- **The stack's own reverse proxy** joins that internal network instead, and follows §26's rules
  for a proxy in front of the portal.
- **A separate non-internal network** for the vault's portal, with a host firewall rule that drops
  that network's outbound traffic. The weakest: the route out exists, and only a rule outside
  Docker's view stops it.
- **No portal:** leave the `admin` block out. Everything the portal does, the CLI does too.

**Verify probes** for the stack's verify script, none of which changes anything (`$c` is your
stack's compose command):

```sh
c="docker compose -f deploy/compose.hardened.yaml -f compose.zoeymcp.yaml"
$c run --rm --no-deps -T -v "$PWD/proxy:/p:ro" vault \
    check --emit-egress-allowlist --allowlist-format squid --check /p/zoeymcp.conf
$c exec -T gateway zoeymcp review notes            # exit 0 for each server
$c exec -T vault zoeymcp health --json --strict > /dev/null
$c exec -T gateway zoeymcp gateway-status
# Neither the vault nor the gateway has a network with a route out.
for service in vault gateway; do
  id="$($c ps -q "$service")"
  for net in $(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' "$id"); do
    [ "$(docker network inspect -f '{{.Internal}}' "$net")" = true ] \
      || { echo "$service is on $net, which isn't internal"; exit 1; }
  done
done
```

Add the portal's probes from §26 ("Checks for a verify script") against the address you publish
it on, if you do.
