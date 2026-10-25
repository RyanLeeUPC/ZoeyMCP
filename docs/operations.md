# Operating ZoeyMCP

How to run what is built so far: the vault (M1), OAuth in the vault (M2), the gateway for
remote MCP servers in both deployment tiers (M3, §9 onwards), approvals, the SMTP connector
and toolkits (M4, §19 onwards), the admin portal (M5, §26), and M7: onboarding a remote MCP
server by URL (§11), your own egress proxy (§28), fitting ZoeyMCP into a stack that already has
one (§29), a first hardened deployment end to end (§30), the egress role (§31), the bridge
(§32) and a stdio server behind one in each placement (§33). M6, in progress: drift review in
the portal (§12) and managed policy (§34), the vault keeping the policy as revisions. §27 says
which hosts are supported. The design and the reasons behind it are in [design.md](design.md); this page is
the how-to.

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
- `ledger-reported/`: the vault's copy of the gateway's approval ledger (§21);
- in managed mode, `policy/` (the policy's revisions, encrypted and MAC'd) and
  `policy-anchor.json` beside it (the highest revision committed), §34.

Onboarding by URL (§11) keeps its client in the store too, under names it reserves for the
credential: `<credential>-client-secret` (a confidential client's secret, given or registered,
bound to the token endpoint and the server's origin like any OAuth secret) and
`<credential>-client-id` (a public client the vault registered, kept only until the second run).
Their metadata says where they came from and, for a registered secret, when the provider says it
expires (§3). Nothing else from an onboarding is written: onboardings, review jobs and bridge
sessions live in memory, and a restart drops them.

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
are all sealed under the same master key, and none is any use without it. In managed mode
`policy/` and `policy-anchor.json` belong with them: back up the vault's volume whole, at one
moment, since a `policy/` restored without its anchor, or from another backup than it, refuses
the start (§34). Keep a policy export too (`zoeymcp policy export`): it is the way back when the
store itself is lost. A backup restored with
an older passkey file brings back passkeys removed since, so after any restore run
`zoeymcp passkeys` and remove what shouldn't be there. Safe to drop: `setup.json` (issue a new
code), `portal/passkeys.rejected-*.json`, and the `torn-*.bin` files the reported copy keeps
aside. Drop with care: `ledger-reported/` (the gateway refills what it still holds; older history
is lost) and the connectors' send journals (the daily limit and the record of what was sent).
Back up the gateway's `/state-gateway` separately; restoring one volume and not the other shows
as a fork in the reported copy (§21).

**Restoring an older backup** isn't detected: the vault takes the volume as it finds it. (In
managed mode the anchor catches a `/state/policy` restored on its own; the whole volume restored
from one backup brings back the policy of its day, as every other file here.) Besides
the passkeys above, a restored `store.json` holds the client secrets of its day. A client the
vault registered since the backup is gone from the store, but stays registered at the provider
(remove it in the provider's own console), and its credential needs a new one (`login --mcp URL
--reregister`, §11); a client re-registered since is back to its old secret, which the provider
may no longer take (`oauth_client_rejected`, §4): register again the same way. A rotating refresh
token that rotated since the backup is spent: sign in again (§6).

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
before it exits, and for the revocations of deleted grants (§2). The hardened compose sets
`stop_grace_period: 50s` for this. Docker's default is 10 s, so when running the image some
other way, give it the same time (`docker stop -t 50`).

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

**Deleting a grant revokes it.** `zoeymcp secret delete` (or the portal's **Delete**) of a
credential's refresh token, the entry its `refresh_token` names or its live slot
`oauth.<credential>.live`, also revokes that token (RFC 7009) when the credential has a
`revocation_url`: onboarding writes it from the provider's `revocation_endpoint`, or you set it
by hand, on the token endpoint's origin (`check` refuses another, and the vault sends nothing
there). The token revoked is the one deleted: a refresh running at the time finishes first, and
if it rotated the token, the new one is revoked. The request carries the client authentication
the token endpoint gets; it is sent once, after the delete is saved, waits at most 10 s and
follows no redirect. The delete's answer never waits for it, and says `revocation: "requested"`,
or `"none"` when nothing is sent. A failure changes nothing: the entry is gone either way, and the
provider may keep the grant until it expires (end it in the provider's settings if it must end
now); a stop or restart waits for it (within those 10 s), but a crash or a kill within those
10 s skips it. Nothing is revoked when you replace a secret, log in again or reset a credential,
nor for a client ID or client secret. Deleting a live slot to reseed (§5) revokes the token it
held, so an env seed of that same grant (a provider that doesn't rotate) is revoked with it. The
revocation endpoint is a vault destination like the token endpoint: it goes through
`egress_proxy` when that is set, and otherwise a host whose name resolves to a private address
needs its `host:port` in `egress_private`. Logs: `oauth_revoked` (the table at the end of §11),
and `discovery_fetch` with `fetch_kind: revoke` for the request.

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
| `binding_changed` | the stored grant is bound differently from what the policy now derives; or, for a pasted answer or a code the portal's callback holds, a reload since the login started changed the credential's `issuer` or turned `require_iss` off (`old` and `new` show both) | `--rebind`; for the issuer, run `login` again |
| `client_secret_binding_changed` | the client secret in the store is bound to another token endpoint origin or other server origins than the policy now derives. An onboarded client's secret is stored for the endpoints its fragment named; one you set yourself, for the token endpoint and the routes its credential had then, so adding or removing a route of a credential with a stored client secret, or naming the secret from a second credential, also needs it entered again (`zoeymcp health` reports it by this code, §3) | revert the edit, onboard again, or enter the secret again with `zoeymcp secret set <name>`; `--rebind` doesn't apply |
| `too_many_flows` | 8 logins are pending | finish one, or wait 10 minutes |
| `flow_unknown` | the flow expired, was used, or belongs to another credential | run `login` again |
| `redirect_mismatch` | the pasted address isn't under `redirect_uri`, can't be read, or has the answer in the fragment | paste the full address from the address bar |
| `state_mismatch` | the address is from a different login | use the URL of the latest login |
| `duplicate_param`, `no_code` | the address has a parameter twice, or no usable code | run `login` again |
| `iss_mismatch` | the answer names a different issuer than the `issuer` the login started with; nothing else in it is read, so a provider's error isn't shown | check `issuer` against the provider's metadata |
| `iss_missing` | the credential has `require_iss: true` and the answer has no `iss`; nothing else in it is read | check that the provider sends `iss` (its `authorization_response_iss_parameter_supported`) |
| `provider_error` | the provider refused (for example, consent was denied); its description is shown, never logged | act on the description |
| `exchange_failed:<code>` | the token endpoint refused the code; `<code>` is one of §4's codes | for `invalid_grant`, the code expired or was used: run `login` again |
| `no_refresh_token` | the provider issued no refresh token | Google: keep `access_type: offline` and `prompt: consent`; other providers may need an `offline_access` scope |

In the portal only, after the callback: `flow_returned` (409) means the callback already holds
the answer you pasted, so confirm that one; `flow_conflict` (409) means two different answers
came back for one sign-in and the login ended with nothing stored: connect again.

## 3. Credential health: `health`, `oauth status` and `oauth reset`

**`zoeymcp health`** lists what needs you, per credential, connector and store entry, with what
to do about each, and under `egress` each route with no credential whose upstream the vault
refused to connect to. It reads metadata only: nothing is decrypted and no request is sent.

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
`check_mailbox`, `check_gateway`, `read_ledger`, `add_passkey`, `review_passkeys`,
`reset_passkeys`, `onboard_again` (with the `command`, `login --mcp URL --reregister`),
`widen_scope` (with the `scope` and the `fragment` that sets it), `check_egress_role` or `review`
(with the `server`: `zoeymcp review <server>`), and the name it applies to). For a deployment's
verify script:

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
| `client_secret_binding_changed` | error | a `store:` client secret of a credential you log in to isn't bound exactly as the policy now derives (§2's login refusal of that name): the token endpoint, or the routes of every credential naming it, differ from when it was stored. Onboard again (the action's command, for a credential onboarding wrote, when every route using the secret still goes to that server's origin) or enter it again with `secret set` |
| `no_route`, `binding_conflict` | error | the policy can't bind the name, as `secret set` would refuse it: fix the policy |
| `seed_ignored` | info | an env seed is set while the live token is used (§5) |
| `unreferenced`, `orphan_slot` | info | an entry nothing in the policy uses; a live slot no credential keeps its token in. An onboarding's client secret or client ID stored before its fragment 1 was committed says it is waiting for its credential (from stored metadata, §11) |
| `degraded` | error | the store can't be written (§1) |
| `terminal`, `backoff` | error, warning | as `oauth status` shows them, with the hint's action |
| `reconsent_due`, `unexpected_scopes`, `missing_scopes` | warning | as `oauth status` shows them |
| `insufficient_scope` | warning | an upstream said the token lacks a scope, **since the vault started**: a restart forgets it. When its challenge named a `scope`, the text lists it, and if that adds to the credential's own the action is `widen_scope`: merge the fragment (`--json` holds it; it sets `credentials.<c>.scope` to the union and keeps the rest), check and reload, then `zoeymcp login <c>`. The vault never widens a scope itself |
| `client_secret_expiring`, `client_secret_expired` | warning, error | a client the vault registered has a `client_secret_expires_at` (from stored metadata) within 14 days, or past: register a new client with `login --mcp URL --reregister` (the action's command), or for a credential without the server's URL as its `resource`, enter the new secret with `secret set`. The wall clock judges it |
| `resource_metadata_changed` | warning | a 401 on the credential's route named other protected-resource metadata than its `resource_metadata`, **since the vault started**: the server may have moved its authorization. Onboard again (`login --mcp URL --reregister`); the vault never registers again by itself |
| `address_refused` | error | the vault refused to connect to the credential's token endpoint, its revocation endpoint or a route's upstream **since the vault started**, because the name resolved to a private, loopback or otherwise non-global address (§7's upgrade note): list its `host:port` in `egress_private` if it is meant to be private, and reload. A reload that lists it, or moves the endpoint, ends the finding. A route with no credential has no credential section: its refusal is the `egress` section's, with the route's name (`fix_policy`). The log has each refusal too (`address_refused`, §11) |
| `egress_allowlist_stale` | warning | the egress role (§31) hasn't fetched its allowlists for more than 300 s: its lists are stale, so it refuses every new tunnel. A role whose key the vault refuses (a wrong key, or the old one after a generation bump) counts from its first request. With `egress_proxy_kind: role` the role is expected, so one that hasn't asked since the vault started counts from the vault's start. Check that it runs, reaches the vault, and has the key `zoeymcp egress-key` prints (`check_egress_role`). In the `egress` section; with your own proxy or none, a vault no role has asked since it started has no such finding |
| `program_unconfined` | info | (standard tier) a route has a `program` block, a `unix:` upstream, or is a bridge's route to a loopback address (a literal, `localhost` or a name under it): nothing in the standard tier confines that program, which can reach every listener in the container, the host's network and the internet (§32). In the `egress` section, naming the route; nothing to do but know it, or move the program to the hardened tier |
| `loopback_bridge_route` | error | (standard tier) a bridge's route (a gateway server's route over plain http with `allow_insecure_upstream`) goes to a loopback address over TCP: any process in the container can listen there first and receive the route's token. A bridge under the launcher listens on `unix:/run/zoeymcp-bridge-<name>/mcp.sock`; use that as the upstream (`fix_policy`) |
| `bridge_socket_unknown` | error | a route's upstream is `unix:/run/zoeymcp-bridge-<name>/mcp.sock` and the launcher started no bridge `<name>` (`--bridge`; none in the hardened tier): the route answers 502. Fix the name, or start the bridge (`fix_policy`) |
| `program_secret_unflagged` | warning | (standard tier) a bridge's `ZOEYMCP_BRIDGE_<NAME>_ARGS` hold `--secret-env`, and the route to its socket has no `program: {holds_secret: true}`, so `check` can't warn about the secret it holds (`fix_policy`) |
| `last_failure` | warning | no failure in memory, but the last attempt failed after the last success: a restart forgets failures, the store's metadata doesn't |
| `idle` | warning | `idle_expiry_days` is set, and the last success is older than it less 14 days. Refresh happens only on demand, so an unused grant can reach a provider's idle expiry |
| `paused`, `near_limit`, `unknown_sends` | info, warning, warning | a paused connector; 80% of `max_per_day` used in the last 24 hours; a send in the last 24 hours with an unknown outcome |
| `ledger_copy_none`, `ledger_copy_stale` | info, warning | (with a `gateway` section) the gateway hasn't reported to the vault's copy of its ledger yet; it hasn't asked or reported for 5 minutes, since the vault started (§21) |
| `ledger_copy_refused`, `ledger_copy_broken`, `ledger_copy_unavailable` | error | the copy refuses reports after a fork, gap or full; its files stop chaining at a seq; its directory can't be read (§21) |
| `passkeys_unavailable` | error | (with an `admin` block) the passkey file can't be verified, so portal sign-in is off: `zoeymcp setup-code --reset` (§26) |
| `passkey_counter`, `passkey_single` | warning, info | a passkey's signature counter went back in the last 30 days (the authenticator may have been copied: check `zoeymcp passkeys`); only one passkey is enrolled, so losing it means a reset |
| `tools_unreviewed` | warning | (with a `gateway` section; from the gateway's status report, §13) the server lists tools nobody reviewed: new ones, and declined ones whose definition changed, counted here and named by `zoeymcp review <server>`. Review the server, and include or decline each (§11) |
| `drift_marked` | warning | (§13) included tools that changed since the review, that a drift mark hides, or that the server no longer lists (§12): review the server |
| `server_blocked` | warning | (§13) the gateway reports that `on_drift: fail` blocked the server (a tool drifted, a drift mark held, or an included tool listed invalid): none of its tools is served until it is reviewed (§12) |
| `server_listing_invalid` | warning | (§13) the server lists tools the gateway can't serve, or whose names aren't valid, counted and not named; or the vault couldn't read the gateway's status for that server |
| `gateway_status_stale` | info | (§13) the gateway hasn't pushed its status for 3 minutes (it does at least every minute): the `gateway` section's other findings are that old. Check that the gateway runs and reaches the vault |
| `gateway_view_behind` | info | (managed mode, §34) the gateway still reports another revision's view than the head's 30 s after a save: it usually takes a new view within seconds. Check that the gateway runs and reaches the vault |

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
| reason `address_refused` | "the vault doesn't connect to the token endpoint: list HOST:PORT in egress_private if this destination is meant to be private; then run: zoeymcp oauth reset NAME" |
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
`no_response` and `pre_send` (no answer), `address_refused` (nothing was sent: the token
endpoint's name resolves to a non-global address `egress_private` doesn't list), `unparseable_body`, `not_ok`, `bad_access_token`,
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
| `address_refused` | the route's upstream name resolves to a private, loopback or otherwise non-global address that `egress_private` doesn't list; nothing was sent. On a local MCP route (a bridge's plain-http route) its name resolved beyond a loopback or private address, which `egress_private` can't change; on a `unix:` route no bridge of that name was started, or another uid listens on its socket (the log's `verdict` says which) | list its `host:port` in `egress_private` if it is meant to be private, and reload (§7); for a bridge, check its name, its address or that it runs |

A 502 for an upstream that failed by itself carries no code. Identity failures stay a bare 403.
An upstream's `WWW-Authenticate` is never passed to the gateway (the vault reads it first, for
health); a placeholder caller still gets it.

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
| a client secret you gave `login --mcp` (`<credential>-client-secret`) | `secret set` it again, then `zoeymcp login` | — |
| a client the vault registered (`<credential>-client-secret`, or none for a public client) | `login --mcp URL --reregister` (§11), commit the fragment, then `zoeymcp login`; remove the old client in the provider's own console | — |
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
| the state volume restored from a backup | `zoeymcp passkeys`, and remove every passkey that shouldn't be there: the backup brings back passkeys removed since; then check the clients onboarding registered since (§1) |

In managed mode the policy recovers from the host too (§34): keep an export, since a reseed
starts from it.

| What happened | Recovery |
| --- | --- |
| the state volume lost | reseed from your latest export (`policy import --state /state --reseed`), then the recoveries above |
| the master key lost, or replaced without `ZOEYMCP_MASTER_KEY_PREVIOUS` | the store refuses the start (`key_unknown`): reseed from your latest export |
| the head, a revision's file or the anchor fails to verify | the head and the anchor refuse the start, naming the file: restore `/state` from one backup, or reseed; an older revision is moved to `quarantine/` and the start goes on |
| `/state/policy` or the anchor deleted, or restored on its own | refused (`policy_store_missing`, `policy_anchor_missing`, `policy_head_behind`): restore the whole of `/state` from one backup |

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
`HUP` on to both. This is declarative mode. In managed mode (§34) a `SIGHUP` never applies the
file: it verifies the store again and installs its newest revision if that isn't the one running,
which is how a saved change that couldn't be applied is retried, and it logs `reload_ok
source=head`. In either mode the mode itself is chosen at start: a declarative vault's reload of a
file that now says `mode: managed` is refused. The vault, in declarative mode:

- A policy that fails is refused (`reload_refused` in the log), and the running one stays.
  So is a policy whose `egress_key_generation` is below the running policy's: the lower
  generation's key was retired (§31).
- A reload that fails in some other way logs `reload_failed` with the error's type, and the
  running policy stays. The launcher's `TERM` after it still stops the process.
- On success the log has `reload_ok`, with `oauth_reset` listing the OAuth credentials whose
  settings or route origins changed. Their cached access tokens are dropped and their failure
  states cleared. A refresh in flight still saves its new refresh token.
- A changed `egress_proxy` or `egress_proxy_kind` needs a restart: every HTTP client and the SMTP
  connectors keep the proxy the vault started with until then, and onboarding keeps whether it
  is the egress role. A reload whose `egress_proxy` or `egress_proxy_kind` differs from the one
  the vault started with logs `egress_proxy_change_needs_restart`, on every reload until the
  restart.
- A changed `egress_private` takes effect at once: the vault reads it at each new connection, so
  the next request to a destination a reload lists goes through, and a connection already open to
  one it removes isn't cut.
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

**Upgrading to M7: the address guard.** Without `egress_proxy`, the vault now refuses to connect
to any destination whose name resolves to a private, loopback, link-local or otherwise non-global
address, for every route's upstream, every token endpoint and every revocation endpoint, as it
already did for onboarding, unless `egress_private` lists its `host:port`. It resolves the name
once per connection and connects to the address it checked, so a name can't be pointed at the
vault's own networks after you added it. A route on your own network then answers 502
`address_refused` (§4) and a login or refresh fails with the reason `address_refused` (§3), each
logged as `address_refused` with the destination (§11), and `health` reports it. Add one line per
such destination and reload; no restart is needed:

```yaml
egress_private: ["files.lan.example:443", "auth.lan.example:8443"]
```

The entry is the host as the URL writes it, in lower case and without a trailing dot (an
internationalized name in its `xn--` form, as the hint writes it), and the port (443 for https and
80 for http when the URL has none). With `egress_proxy` set nothing changes: the proxy resolves the
names and its allowlist judges the address (§28).

**Upgrading to M7: no bridge kind.** A gateway server written `kind: bridge` never ran (no version
served one; `check` warned "not served by this version" on a client assigned one); it now stops the
policy loading, at start and on reload, with an error at `gateway.servers.<name>.kind` that says
what to write instead. A bridge is an upstream: a `kind: remote` server behind a vault route, the
same as any other. The old `url` splits in two: its scheme, host and port become the route's
`upstream` and its path the server's `path` (the vault joins the two, so an upstream that kept
`/mcp` would send `/mcp/mcp`). The route has `callers: [gateway]`, `stream: true`, rules allowing
`POST`, `GET` and `DELETE` on that path, and a `header` credential holding the bridge's token; the
old `egress` list moves to the route's `program.egress`. See §33, A stdio server behind a bridge.

**Upgrading to M6: check.** An `env:` reference that names one of ZoeyMCP's own variables
(any name that starts with `ZOEYMCP_`, such as `ZOEYMCP_MASTER_KEY` or `ZOEYMCP_GATEWAY_KEY`) is
now an error in every mode, at start and on reload: keep that secret in the store, or under a
variable of its own name. No shipped policy has one. `check` now reads `mode` for two findings:
`mode: managed` is a warning that the vault seeds its first revision from the document and
ignores it afterwards, and without an `admin` block it is also an error ("managed mode is edited
in the portal"). A managed start, and switching a deployment to it, is §34's. A policy with
`mode: declarative` checks as before.

**Upgrading to M6: review.** A tool a server lists that the policy neither includes nor declines
is one nobody reviewed, and `zoeymcp review` now exits 1 for it, naming it ("3 listed that nobody
reviewed: ..."), where it exited 0 before. Record the tools you leave out once, with `review
<server> --decline-rest` (§11) or `decline` lines in a choices file, and commit the snippet. A
policy with a `declined` block needs the gateway on M6 too: recreate the vault first, then the
gateway.

**Upgrading to M6: clearing marks.** An M6 gateway's review polls say which job kinds it runs
(`kinds=review,clear`), and an M7 vault refuses that query: the gateway's polls back off and
retry until the vault is on M6, so recreate the vault first, then the gateway. Until the gateway
is on M6 too, it runs review jobs only, and clearing marks through the vault (the portal's
**Clear the marks**, or `review --via vault --clear`) is refused `clear_unsupported`: run
`zoeymcp review <server> --clear` in the gateway's container instead.

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

**The egress role** runs in its own container, in the hardened tier only: the `egress-proxy`
profile (§31), ZoeyMCP's own CONNECT-only proxy, held to the allowlists the vault derives from
the policy. The standard tier has no role: nothing in its one container could make a program
use it.

**Bridges** (a stdio MCP server behind `zoeymcp bridge`, §33) run in either tier, and only the
hardened tier confines them: there each bridge has a container and networks of its own and
reaches out only through the role; in the standard tier a bridge is one more process in the one
container, unconfined.

**What stops the gateway starting** (it prints one line and exits 2): the master key,
`ZOEYMCP_MASTER_KEY_PREVIOUS` or `ZOEYMCP_CONFIG` in its environment; running as root; an
`http://` link without `ZOEYMCP_GATEWAY_KEY` or `ZOEYMCP_GATEWAY_KEY_FILE`; a state directory
open to other users; a drift-marks file it can't read (move it aside to start over, which forgets
the marks).

**Until it has a view**, and whenever it has had no answer from the vault for
`gateway.limits.policy_max_stale` (300 s), `/healthz` and every agent request answer 503, and
upstream connections close (`policy_stale`): a revoked client can't keep working while the vault
is unreachable.

**Stopping.** Calls in flight get 10 s, but an approved call already running finishes (§20). The
standard tier's launcher stops the gateway first and gives it up to 330 s, then the vault up to
75 s, then each bridge 10 s, so a call in flight through the vault or a bridge finishes first:
at most 415 s, inside the `stop_grace_period: 420s` compose sets. In the hardened tier compose
stops the gateway (330 s), then the vault (75 s), then each bridge (§33).

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

**In managed mode** (§34) the policy isn't a file you commit, so this section's fragments don't
apply: add the route, the credential and the server, and choose the server's tools, in the portal,
which saves each change, or export the policy, edit it and import it on the host (§34, "Importing
a change"). The CLI knows which mode runs and prints no fragment for a managed deployment: `review`
with `--add`, `--allow`, `--approve`, `--allow-read-only`, `--repin`, `--decline`,
`--decline-rest` or `--choices`, and `login --mcp`, refuse (exit 2) and name the way instead:

```text
$ zoeymcp review notes --add search_notes
zoeymcp review: this deployment is managed: save it in the portal, or export, edit and import
Next:
  Save the change in the portal
  Or export the policy (in the vault's container):
    zoeymcp policy export > policy.yaml
  Edit policy.yaml, then import it (in the vault's container); it shows the plan, and the same with --yes writes it:
    zoeymcp policy import - < policy.yaml
```

Through the vault's socket (`--via vault`, and `login --mcp`) the CLI asks the vault's mode
(`GET /policy`) before anything else, and the commands it names carry the compose prefix. In the
gateway's container, which has no vault socket, the gateway's answer names the mode: the vault
states it beside every view it serves (the `x-zoeymcp-policy-mode` header, outside the view and
its digest, so a mode alone changes no view), and the gateway passes on the last one it saw as
`policy_mode`, in its status (§13) and on every review answer of its socket. Until the gateway has
its first view the mode is `unknown`, and the same options refuse: "the gateway hasn't received
the policy from the vault yet: try again". A review that only reads (`review`, `review <server>`
with `--show`, `--all`, `--choose` or `--clear`) works in either mode. In managed mode it prints
no YAML snippet to commit: a plain review (text or JSON) ends with the way on instead, which is
that save or import (through the vault, the vault's own `next`, below); `--choose` prints the
file alone, and a clear that goes through has no next step. The JSON of a review never carries
`policy_mode`: the mode is beside the review, not part of it.

`check` (with `--with` or `--emit-egress-allowlist` too) and `selftest` run in a throwaway
container with no socket, so they read the document you give them, never the running revision.
Given a managed document, they say so on stderr: "checking this document, not the running
revision: to check what runs, pipe zoeymcp policy export into this command with --config -":

```sh
# hardened tier
docker compose -f deploy/compose.hardened.yaml exec -T vault zoeymcp policy export \
  | docker compose -f deploy/compose.hardened.yaml run --rm --no-deps -T vault check --config -
# standard tier
docker compose -f deploy/compose.yaml exec -T zoeymcp zoeymcp policy export \
  | docker compose -f deploy/compose.yaml run --rm --no-deps -T zoeymcp check --config -
```

**Onboarding by URL in the portal, in managed mode,** ends in saves, not commits. It takes five
passkey prompts, each for a different thing (§26, "MCP servers"):

1. **Add a server by URL**, the plan, then **Register its client** (or **Store the secret**, for a
   client you registered with a secret): `onboard.register`, as in declarative mode. The client
   secret, if any, is stored at once under the binding the plan predicts. No fragment is shown;
   the row reads `needs_save`.
2. **Save** on that row: the vault plans the server's credential, route and server (the change
   fragment 1 would carry, the route called by the gateway alone) on the head and shows the plan,
   "Revision 2, from 1 (...)", one row per thing it adds; one passkey writes it (`policy.save`),
   and the vault applies it itself. The row is `needs_connect` at once. A public client you
   registered (`--client-id` alone) needs no registration: **Save** is its one step.
3. **Connect** (§2); the page queues the review.
4. The review screen's **Save** (`policy.save`), each tool newly allowed on its own row first. Its
   answer ends with "Then give notes to each client that should reach it": nothing reaches the
   server yet.
5. **Give to clients** on the server's row (every server's row has it, so a server can be taken
   from a client at any time): a box per client, ticked where it reaches the server, and **Save** (`client.servers`, one save per client whose box changed): "agents holding
   client agent1's token can call notes's 12 included tools".

Adding a client, changing its token, or the server's route or credential once saved are host
imports (§34). The CLI's `login --mcp` refuses in managed mode (above), so this walk is the
portal's; `zoeymcp login <credential>` still signs in from the host.

The rest of this section is declarative mode.

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
   $ zoeymcp review notes --allow search_notes --approve get_note
   server notes  (remote, vault path /notes/mcp, modern 2026-07-28)
     get_note      unreviewed  sha256:71d2a3b4c5d6...  not included
     search_notes  unreviewed  sha256:0c4e1f2a3b4c...  not included
   findings (heuristics; reading the definition is the control):
     search_notes: note /annotations: suggested by the server: allow (readOnlyHint=true)

   # YAML to commit (declarative mode). Review the changes above first.
   # zoeymcp: review of notes. Replace the tools: and review: blocks of gateway.servers.notes.
   # zoeymcp replace: gateway.servers.notes.tools gateway.servers.notes.review
   # added: search_notes (allow)
   # added: get_note (approve)
   gateway:
     servers:
       "notes":
         era: "modern"
         tools:
           include: ["search_notes", "get_note"]
           allow: ["search_notes"]
           approve: ["get_note"]
         review:
           "get_note": "sha256:71d2..."
           "search_notes": "sha256:0c4e..."
   ```

   Read each definition (`--show TOOL`, or `--all`) before you include it. Findings are
   heuristics: instruction-like text, URLs, long base64 runs, nested-quantifier patterns,
   arguments that travel in HTTP headers, and the server's suggested classification. Hidden
   characters are shown as `[U+XXXX]`. A tool with an error finding (hidden characters, an unsafe
   schema) gets no pin line at all.

   The snippet is a fragment, written as onboarding's are: its header says it replaces the
   server's `tools:` and `review:` blocks whole, so a tool you leave out loses its pin too. Prove
   it with `check --with` (below) and merge it, or paste those two blocks over the server's. Its
   comments are of fixed kinds and carry no text from the server: `added` (and why), `changed` (a
   re-pin, with the old pin), `kept` (a drifted, missing or unpinnable tool keeps its old pin and
   stays hidden), `not included` (with its pin and the server's suggestion), `can't be included`
   (an error finding), `suggested` (the server's suggestion for a tool `--add` leaves to you) and
   `merge` (a toolkit with `pinning: off`, which keeps no pins).
6. **Classify and commit:** `--allow TOOL` and `--approve TOOL` include a tool and classify it.
   `--allow-read-only` includes as `allow` every tool the server marks read-only and not
   destructive (`readOnlyHint: true` without `destructiveHint: true`); that is the server's own
   claim, not a judgement by ZoeyMCP, and no option includes an unannotated tool in bulk. `--add
   TOOL` includes a tool and leaves it to you: `check` fails until it is under `allow` or
   `approve`, since there is no implicit default. An `approve` tool asks a human before each call
   (§19). For many tools, use the choices file (below).
7. **Reload** again. Agents see the tools at once (their clients are told the list changed).

**Declined tools.** A tool the server lists that the policy neither includes nor declines is one
nobody reviewed: `review` names it ("3 listed that nobody reviewed: export_all, purge, share"),
and the summary (`review` with no server) prints the same line under the server's row.
`--decline TOOL` records a tool you leave out under the server's `declined`, at the pin listed,
and `--decline-rest` every listed tool the snippet doesn't include; a declined tool is hidden, as
an unreviewed one is, and logs nothing. Once the server has a `declined` block, or the options
decline a tool, the snippet replaces that block whole too (an included tool leaves it). If the
server later changes a declined tool's definition, its pin no longer matches and it counts again.

`review` exits 0 when every included tool matches its pin, nothing is marked and every listed tool
is included or declined, 1 when something needs you, and 2 when it couldn't run (the gateway is down, the server is unknown, the
vault refused, the upstream failed or a listing limit was hit) or an option
doesn't fit what it found. The message says which. `--format json` prints the same, with the
snippet as a list of lines.

**Keep the tool list small.** Every tool an agent is given takes room in the model's context, on
every turn. Include only the tools each agent needs, and assign each agent only the servers it
uses. Where a client can load tools lazily (a tool search that fetches a definition only when the
model asks for it), turn that on: the gateway serves the same pinned definitions either way, and
tells clients when a list changes, so a lazy client fetches the new one.

**Reading pinned schemas.** A pin covers a tool's input schema, and the gateway checks every call's
arguments against the pinned one. JSON Schema's `pattern` is written for ECMA-262 (JavaScript's
regular expressions); the gateway runs it on Python's `regex` module, and the two differ in places,
so read a pattern for what the gateway will enforce:

- `\d` and `\w` match ASCII only, as in ECMA-262 (the `ASCII` flag), and so does `\s`, where
  ECMA-262's also matches Unicode spaces and line separators.
- `$` also matches before a final newline in Python, and not in ECMA-262. So that a value can't
  slip a trailing `\n` past a pattern meant to end there, a pattern with an unescaped `$` refuses
  every string that ends in `\n`.
- `\A` and `\Z` are anchors here (the start and the very end of the string); in ECMA-262 they are
  the letters `A` and `Z`, or an error with the `u` flag.
- `\p{...}` (a Unicode property) matches ASCII characters only here, under the same flag: `\p{L}`
  refuses `é`, and `\P{L}` accepts it. In ECMA-262 it needs the `u` flag and then covers all of
  Unicode; without the flag, `\p{L}` is the text `p{L}`.
- Possessive quantifiers (`a*+`) and atomic groups (`(?>...)`) work here and never backtrack;
  ECMA-262 has neither, so a schema that uses them wasn't written for it.
- Lookbehind (`(?<=...)`, `(?<!...)`) works here at any length, as in current ECMA-262.

What a reviewer can hit: a pattern the `regex` module can't compile, an unsupported `$schema`, a
`$ref` that isn't a local pointer, or `$id` and the dynamic keywords are error findings (the tool
can't be pinned); a pattern with a nested quantifier is a warning (it can backtrack for a long
time); and every pattern gets a note saying it is checked this way. At call time a match over
50 ms, or a call over its time budget, refuses the call (`arguments refused`), never passes it.

### Many tools: the choices file

Per-tool options don't scale to a hundred tools. `review <server> --choose` prints a choices
file, one line per tool the server lists, and `--choices FILE` (`-` for stdin) reads the edited
file back and prints the fragment, the same one the options would make. Both run in either
container; in the vault's they go through the review job path (below), so `--choose` and
`--choices` read the one report within 30 minutes, at the same policy:

```sh
# hardened tier
docker compose -f deploy/compose.hardened.yaml exec vault \
  zoeymcp review notes --choose --suggest > notes.choices
# edit notes.choices: skip, allow, approve or decline on each line, then:
docker compose -f deploy/compose.hardened.yaml exec -T vault \
  zoeymcp review notes --choices - < notes.choices > onboard-notes-2.yaml
# standard tier
docker compose -f deploy/compose.yaml exec zoeymcp \
  zoeymcp review notes --choose --suggest > notes.choices
docker compose -f deploy/compose.yaml exec -T zoeymcp \
  zoeymcp review notes --choices - < notes.choices > onboard-notes-2.yaml
```

```text
# zoeymcp review notes: 96 tools. Keep "skip", or write "allow", "approve" or "decline", on each line.
# report 3f9c... sha256:aa41... policy sha256:5e07...
# allow: agents call it with no prompt. approve: every call asks you first.
# The suggestions are the server's own annotations, not a judgement by ZoeyMCP.
# bad_tool can't be included: error finding (...); review notes --show bad_tool
skip     delete_note  sha256:0b7d...   # not annotated: approve suggested if you include it
allow    list_notes   sha256:6c1e...   # read-only (the server's suggestion)
```

- **Each line** is a word (`skip`, `allow`, `approve` or `decline`), the tool's name and its full
  pin, then a comment; `#` lines are comments, and a line you delete counts as no change. Write the
  word you want; leave the rest alone. `decline` leaves the tool out and records it declined at the
  line's pin (taking it out first if it is included); a tool the policy declined at that pin says
  `decline`, and `skip` on it takes it out of `declined`.
- **Without `--suggest`** every tool not yet included says `skip`. With it, a tool the server
  marks read-only and not destructive says `allow`, and every other line stays `skip` with the
  server's suggestion in its comment (`approve` for an unannotated or destructive tool), so an
  unedited file never includes one. A tool the policy already includes says its classification,
  so an unedited file changes nothing; `skip` on it takes it out.
- **No line**: a tool with an error finding (it can't be pinned), and an included tool that has
  drifted, is missing or no longer pins; it stays as the policy has it (`review <server> --repin
  TOOL` takes a drifted tool's new pin).
- **Comments** show the server's text cut to 100 characters, with every line break and hidden
  character made visible, so a description can't start a line of its own. A file saved with
  CRLF line endings or a byte order mark (as Windows editors and PowerShell 5.1 save it) reads the
  same.
- **The header** names the report: its job (`-` for a review over the gateway's socket), its
  digest, and the digest of the server's `include`, `allow` and `approve` in the policy, and its
  `declined` once it has one. If the
  policy's tools for the server changed since `--choose` (you included, took out or reclassified
  one), `--choices` refuses the file `choices_stale`: its `skip` lines would take out what you
  included since. Write the file again. `--choices` checks every `allow` and `approve` line's pin against the report it reads
  then, the same one or a newer listing, and emits exactly the pins in the file. A tool whose
  definition changed since `--choose` refuses the whole file `choices_stale`, naming each such
  tool: read it again (`--show`) and write the file again. Anything else wrong (an unknown word,
  an unknown or repeated tool, a missing or edited pin, `allow` or `approve` for a tool that can't
  be pinned, a tool a toolkit declares consequential in `allow`, a file for another server)
  refuses it `choices_invalid`, naming the line. Both exit 2 with nothing on stdout.
- **Fragment 2** goes to stdout and a line saying what it includes to stderr. Commit it as
  fragment 1 is (**Committing fragment 1**, below: `check --with`, merge, `check`, reload). It
  never assigns the server to clients: add `notes` by hand to the
  `gateway.clients.<client>.servers` list of each client that should have it.

### Onboarding by URL

`zoeymcp login --mcp URL` (M7) adds an OAuth-protected MCP server from its URL, beside the manual
path above. It takes two commits: fragment 1 adds the credential, its route and the server with
no tools; once it is committed, the same command again signs in and queues the review (steps 5
to 7 above), which gives the tools to commit. Without `--client-id`, the vault registers a client itself
(dynamic client registration, RFC 7591) when the authorization server offers it; with one, it
uses the client the provider registered for you. A server that offers neither stops the plan at
`registration_unavailable` (or `cimd_only`, for one that registers clients by metadata document
alone, which ZoeyMCP doesn't support yet): register a client there and give its client ID.

It runs in the vault's container, over the admin socket:

```sh
# hardened tier
docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp login \
  --mcp https://mcp.notes.example/mcp --name notes > onboard-notes-1.yaml
# standard tier, with a client the provider registered for you
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
- **A client the vault registers** (no `--client-id`): once you confirm "Register a client at
  <issuer host>?", the vault sends one request to the server's `registration_endpoint`, with
  public metadata only: the client's name (`--client-name`, default `ZoeyMCP (<server>)`), its
  redirect address, the authorization code and refresh token grants, and the scopes. It asks
  for a public client (`token_endpoint_auth_method: none`) when the server allows one, else a
  client secret (`client_secret_basic`, else `client_secret_post`); `dcr_auth_unsupported`
  otherwise, before anything is sent. The answer is checked, not trusted: a client ID a policy
  can't hold (`dcr_bad_client_id`), another redirect address than the one asked for
  (`dcr_redirect_changed`), an authentication the vault doesn't speak, a secret where none
  belongs or none where one does (`dcr_bad_secret`), grants without the authorization code and
  the refresh token (`dcr_grant_missing`) or a malformed expiry (`dcr_answer_invalid`) are
  refused, and so is a server's refusal (`dcr_refused`, with its error code and, for you alone,
  its description) or any other answer (`dcr_failed`). A refused or timed-out registration may
  have left a client at the provider (`dcr_failed` says so): the next run registers a new one.
  The answer's registration access token and URI are never kept, so the vault never updates or
  deletes the client at the provider: remove an unused one in the provider's own console.

  A confidential client's secret is stored at once as `<credential>-client-secret`, as for a
  secret you give (below); a public client's ID is stored as `<credential>-client-id`, only so
  that a vault restart before the commit can show fragment 1 again, and the second run deletes
  it. When the provider sets `client_secret_expires_at`, `zoeymcp health` warns 14 days before
  it (`client_secret_expiring`) and errors after it (`client_secret_expired`): register a new
  client with `--reregister`.
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
  client; without it, a given client uses the shared `http://127.0.0.1/callback`, and a client
  the vault registers gets the credential's own, `http://127.0.0.1/callback/<credential>`
  (paste), or with `--callback-origin ORIGIN`, one of `admin.origins`, that portal's
  `ORIGIN/oauth/callback/<credential>`. A loopback or `localhost` address registers the client
  as `native`, any other as `web`. The plan says when the address isn't the credential's own,
  which turns off a backstop against pasting an answer meant for another sign-in.
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
  `egress_private`), and that one `host:port` alone: a registration endpoint on a private address
  passes discovery's checks when the policy lists its host in `egress_private`, but the
  registration is refused at the connection (`address_refused`, purpose `registration`), since
  the vault makes no exception for a registration host; register the client in the provider's
  console and give its client ID instead. `--client-name` is the name a provider may show for
  the client; `--indent N` or `--for compose` lays fragment 1 out for an inline policy; `--format
  json` prints the vault's answers as one JSON document on stdout instead.

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
(`client_secret_binding_changed`). Then it queues the server's review through the vault (the
review job path, below), waits up to 2 minutes for the gateway's report, and prints its counts:

```text
Reviewing through the gateway: 96 tools (64 the server marks read-only, 32 not annotated, 1 with an error finding).
Next:
  Choose its tools:
    docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp review notes --via vault --choose --suggest > notes.choices
  Edit notes.choices (skip, allow, approve or decline on each line; decline the tools you leave out), then make fragment 2:
    docker compose -f deploy/compose.hardened.yaml exec -T vault zoeymcp review notes --via vault --choices - < notes.choices > onboard-notes-2.yaml
```

The counts are the server's own annotations, not a judgement by ZoeyMCP. The two commands are
the choices file (above): both read that same review without listing the server again, since
within 30 minutes and at the same policy every run reads the one report (`--fresh` reviews
again). Commit fragment 2 as fragment 1 was. `zoeymcp review notes --via vault`, in the vault's
container, prints the review itself (steps 5 to 7 above: the tools, their findings and the YAML
snippet, with `--allow`, `--show` and the rest). A review that fails or isn't done in time says so, and the run exits 1;
the same `review` command then tells you more. With `--no-connect` and no token yet there is
nothing to review with, so no review is queued.

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

**Through the egress role** (§31): nothing to edit. With `egress_proxy_kind: role` the vault
takes `egress_proxy` to be the role (it never guesses: without that setting the proxy is your
own, even while a role fetches the vault's lists): each host joins the onboarding's allowance in
the vault's list before the vault connects to it, the role's long poll is answered at once, and
the vault waits up to 5 s for the role to fetch the widened list (a role still starting up, or
back after a vault restart, is waited for the same way). An allowance is gone once the
onboarding has its fragment 1, is cancelled or expires (30 minutes). A CONNECT the role refuses
all the same (a role that isn't running or stopped polling, one with an old key, or a host whose
address it refuses or can't reach) is `egress_refused`, naming the host and the role's status:
during discovery it ends the onboarding; at registration the onboarding is kept. The role's
`egress_refused` log line names the reason; for a role that hadn't fetched, run the same command
again.
"This server is on my network" (`--allow-private`) is refused `private_needs_direct` through the
role, which can't tell one vault request from another and would give every vault connection to
that host the exception: onboard such a server with `egress_proxy` unset, or write its fragment
by hand.

**Your own compose command.** The printed commands start with `ZOEYMCP_COMPOSE_CMD` and name the
service in `ZOEYMCP_EXEC_SERVICE`, which the shipped compose files set. If you run compose with
override files, a project directory or a project name, set
`ZOEYMCP_COMPOSE_CMD` in `.env` to the command you type (`docker compose -f
deploy/compose.hardened.yaml -f my-override.yaml`), or every printed command names the shipped
file alone.

| When | What happens, and what to do |
| --- | --- |
| The vault restarts before you confirm | the onboarding is gone: run the same command again |
| It restarts after a client secret was stored, before the commit | the secret stays (health reports it `unreferenced` until fragment 1 is committed): commit the fragment you were shown, or run the same command to see fragment 1 again, which stores nothing |
| It restarts after it registered a public client, before the commit | its `<credential>-client-id` entry stays, likewise: commit the fragment, or run the same command to see fragment 1 again, which registers nothing |
| A registration times out | `dcr_failed`: the provider may hold a client nobody uses; the same command registers a new one |
| The commit recreates the vault (inline `ZOEYMCP_CONFIG`) | nothing is lost: run `login --mcp` again to sign in |
| It restarts during the sign-in | the sign-in is lost (§2): run it again; a stored client secret stays |
| The store is lost | the client secret with it: onboard again with a new client (`--reregister` once the policy names the credential); the old client stays registered at the provider |

The admin socket's routes behind it: `POST /onboard/discover` answers the plan,
or the second run's comparison (`stage: committed`); `POST /onboard/<onboarding>/register` stores
a given client's secret, or registers a client for an onboarding with no client ID, and answers
fragment 1 (with the registered `client_id` and its secret's `client_secret_expires_at`);
`POST /onboard/<onboarding>/fragment` answers fragment 1 for a client with no secret (or again,
at another indent); `DELETE /onboard/<onboarding>` cancels. A vault restart ends every
onboarding, but a client secret it stored stays; the same discovery again finds it, checks its
binding against a fresh discovery, and answers the onboarding registered, so `/fragment` shows
fragment 1 again without storing anything. If the binding differs, its names stay taken: delete
the entry or choose other names.
If anything fails after register stored the secret, the vault deletes it again and the answer says
`secret_deleted`; a re-registration's puts back the secret it replaced, and says
`secret_restored`. Its log lines:

| Event | Fields |
| --- | --- |
| `onboard_started` | `owner` (`cli` or `portal`), `host` (the server's), `allow_private` |
| `discovery_fetch` | `fetch_kind` (`probe`, `prm`, `as`, `register`, or `revoke` for a deleted grant's revocation, §2), `host`, `port`, `status`, `bytes`, `ms`, `via` (`direct` or `proxy`) |
| `onboard_planned` | `host`, `issuer` (its host), `require_iss`, `registration`, `auth`, `scopes` (how many) |
| `onboard_refused` | `reason`, `host` (the server's) |
| `onboard_registered` | `credential`, `issuer` (its host), `auth`, `secret_stored` |
| `onboard_blocked` | `host` and `port` your proxy refused, `needed` (how many hosts it must allow) |
| `onboard_ended` | `why`: `registered` (the policy names its credential now), `cancelled`, `expired`, `owner_gone`, or `compared` (a second run's comparison found nothing changed) |
| `address_refused` | `purpose` (`discovery`, `registration`, `revocation`, `route` or `token`), `host`, `port`, `verdict`; for a `unix:` route, `bridge` (its name) instead of `host` and `port`, and `verdict` `unknown_socket` (no bridge of that name was started) or `peer_uid` with the `uid` that listens there |
| `oauth_revoked` | `credential`, `outcome` (`ok`; `refused`: nothing was sent, because the endpoint isn't on the token endpoint's origin, its address was refused, or the client can't be authenticated; `failed`, with the `status` when there was an answer; `timeout`), `status`: a deleted grant's revocation (§2) |

None holds an onboarding's ID, a secret, a registration access token or URI, a URL's path or
query, or a body; a stored client secret (or a registered public client's ID) logs `secret_set`
with `via` and its binding, as any secret does.

### The review job path

A review can also run through the vault: the vault queues a job, and the gateway,
which asks the vault for work and never takes a connection from it, runs the same review as
`zoeymcp review` and posts its result back: `zoeymcp review <server> --via vault` in the vault's
container (both tiers: `docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp review
notes --via vault`, or `docker compose -f deploy/compose.yaml exec zoeymcp zoeymcp review notes
--via vault`), and the second `login --mcp`. `--via auto`, the default, takes the gateway's admin
socket when the container has it, as the standard tier's does, else the vault's; `--via gateway`
is the review over the gateway's socket as before, and the summary (`review` with no server) is
only that. `review <server> --via vault --clear` queues a clear job: the gateway lists the server
again and clears its drift marks only if every included tool matches its pin, as `--clear` on its
own socket does, and otherwise refuses `clear_not_clean`, naming the tools, with the review that
found them (exit 1). One review runs at a time in the gateway, a job's or the socket's.
Behind it are the admin socket's routes: `POST /review/<server>` queues a review of a remote or
toolkit server in the running policy, or answers the CLI's finished review of it at the current
policy view again (send `{"fresh": true}` for a new one); `POST /review/<server>/clear` queues a
clear of its marks, always a new job; `GET /review/jobs/<job>?wait=N` (at most 30 s) answers the
job's state, and its report once it is done; `POST /review/jobs/<job>/diff` makes fragment 2 from
`{"include": [...], "allow": [...], "approve": [...]}` (and `"indent"`, 0 to 16 or `"compose"`),
as the portal's review screen does, saving nothing, or refuses `review_stale` when the server's
tools, pins or declines in the running policy changed since the review. A finished job's answer
and every refusal carry `next`, the way on: after a review, choosing its tools (in managed mode,
the portal's save or the host's export and import, §11); after a refusal that a fresh review
answers, `zoeymcp review <server> --via vault --fresh`. `review <server> --via vault` prints it
on stderr, after the review (in its JSON as `next`; not after `--choose`, `--choices` or an
option that makes fragment 2, which are that way already) and after a refusal. A clear job
goes only to a gateway whose polls say it runs one (`kinds=review,clear`); while an older
gateway polls, a clear is refused `clear_unsupported`, and its review jobs work as before. At
most two reviews are under way at once, one per server. A queue call is refused
`review_unavailable` while the gateway isn't polling (no poll waiting, no review it took still
running, and no poll or result in the last 15 s); in the first 45 s after the vault starts it waits
for the gateway's first poll instead. A job the gateway doesn't take within 60 s, because it holds
another version of the policy, fails `review_stale`; one it took and didn't answer within 2 minutes
fails `review_timeout`. A finished review is kept for 30 minutes, in memory only: a vault restart
forgets every job. The vault reads a report under the gateway's limits and recomputes every pin from
the definition beside it: one pin that isn't its definition's refuses the whole report
(`pin_mismatch`, logged at `critical`: the gateway's own review never reports that). A report larger
than the cap the gateway's limits give (`max_tools_per_server` x 16 KiB, within 8 and 64 MiB) isn't
read at all, and the review fails `review_too_large`, naming the cap. Its log lines:

| Event | Fields |
| --- | --- |
| `review_requested` | `server`, `job` (the first 8 hex digits of the job ID's SHA-256), `owner` (`cli` or `portal`), `reused` (a finished review handed back); `clear: true` for a clear job |
| `review_reported` | `server`, `job`, `tools` (how many the report lists); or, when the gateway couldn't review it, `reason` (`review_failed`, or `review_too_large` when the vault refused its report as too large) and the gateway's `code`; `clear: true` for a clear job, and `reason` `clear_not_clean`, with `tools`, when the gateway refused the clear and posted the review that found the tools |
| `review_refused` | `reason` (`job_unknown`, `review_invalid` or `pin_mismatch`), with `server` and `job` for a known job, and `tools` (how many pins differ) for `pin_mismatch` |
| `review_unavailable` | `server`: a queue call refused because the gateway isn't polling, or the vault is stopping |
| `review_stale` | `server`, `job`: the gateway didn't take it within 60 s |
| `review_timeout` | `server`, `job`: the gateway took it and sent no result within 2 minutes |

The gateway's side: it polls with the digest of the policy view it holds, so a job queued at
another view waits for it to catch up (or fails `review_stale`). A poll at the vault's view ends
as soon as a reload changes that view, so a review asked for right after a reload starts at once;
a poll at an older view waits as before. The gateway posts the report fitted to
the vault's caps (an odd tool's long text or oversized definition is cut and marked, never a
reason to refuse the server's report). A report over the vault's cap isn't sent: the job fails
`review_too_large`. A post that fails is tried twice more within the 2 minutes, then dropped; a
poll that fails backs off from 1 s up to 30 s. Its log lines:

| Event | Fields |
| --- | --- |
| `review_job_started` | `server`, `job` |
| `review_job_done` | `server`, `job`, `outcome`: `done`, or `failed` (the gateway's review couldn't run, and its error was posted; or it refused a clear job and posted the review that found the tools, which the vault failed `clear_not_clean`), or `review_invalid` or `pin_mismatch` (the vault refused the report, logged at `error`) |
| `review_job_post_failed` | `server`, `job`, `outcome`: `job_unknown` (the vault restarted, or the job ended), or why the last try failed |
| `review_poll_failed` | `reason`: why a poll failed, at most once a minute |

None holds a job's ID, a tool's name or definition, or anything else from a report.

## 12. Drift

When an included tool's definition changes, the gateway hides it from every client of the
server, logs `tool_drift` (with the members that changed), and marks it. The mark holds even if
the server changes the tool back: a server that changed a tool once can do it again. Marks that
go log `drift_cleared`, with `server`, `tools` (the marks cleared) and `by`: `review` (`--clear`
on the gateway's socket), `portal` (a clear job through the vault: the portal's **Clear the
marks**, or `review --via vault --clear`), or `policy` (a reload that changed the pin).

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

**In the portal** (declarative mode). Home says "notes changed 1 included tool since the review",
and the server's row on **MCP servers** says what the gateway reports, above **Review again**,
which asks for a fresh review, never the finished one handed back, since a server changes a tool
without the policy changing (so does **Review again** under the review screen's tools). On the review screen the tool's row is `drift`, with two columns: **Reviewed**,
the definition the policy pinned, which the vault checked against the pin, and **Now**, the one
the server lists, which the vault pinned itself, each whole in marked chunks, and under them the
vault's line diff between the two. When the gateway no longer holds the reviewed copy (it keeps
it in memory, so not across its restart) the row says so and the new definition is shown whole.
Each finding names the field it is about ("warning at /inputSchema/properties/q/description:
..."; "(definition)" for the whole definition). Tick **Accept the new definition** to take the
new pin: the tool keeps its classification, except that an `allow` tool whose new definition the
server no longer marks read-only says approve is proposed, and ticking the box chooses approve on
its row; choose allow there to keep it, and the fragment says you kept it (`# kept: <tool> (allow: ...)`), as `--repin` does.
**Generate** gives fragment 2 with the new pin and a `# changed:` line; commit it and reload, and
the mark clears when the pin changes. A tool that flipped back to its reviewed definition reads
`marked`, and its mark stays until it is cleared: **Clear the marks** under the tools (enabled
once every included tool matches its pin), on the server's row, or on Home's item, asks for your
passkey, then the gateway lists the server again and clears the marks only if every included tool
still matches (else the portal names those that don't: `clear_not_clean`), as `review --clear`
does.

**Allow without asking** (declarative mode). Each server row has a button per included `approve`
tool. It opens the review screen with that tool moved to `allow` on its row; Generate's fragment
says so (`# changed: <tool> (approve -> allow: calls to <tool> will run with no prompt)`), and
the move takes effect once you commit it and reload. **Select suggested** never moves a tool.

**Declined tools in the portal.** **Decline** on a tool's row leaves it out and records it under
the server's `declined` at the definition shown; **Record the rest as declined** (ticked by
default) does that for every listed tool you don't include, as `--decline-rest` does (§11), so
a server reviewed once ends quiet. A declined tool you include later leaves `declined`.
Generate is refused `review_stale` when the policy's tools, pins or declines for the server
changed since the review (another fragment committed meanwhile, which this one would undo):
review again.

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
anything is drifted, marked, missing or invalid, or listed and nobody reviewed it. Neither makes
an upstream call, and neither shows definitions or token hashes. `--format json` for both; its
`policy_mode` is the mode the vault last stated beside the view, `managed` or `declarative`, or
`unknown` before the gateway's first view (§11).

**The status in the portal and in `health`.** The vault never connects to the gateway, so the
gateway pushes a summary of the same data to the vault: per server its kind, state, era,
whether it is blocked, and counts, the mode it last saw, the highest revision it has seen of each
deployment of a managed vault (its restore witness, §34), and the names its attention decision sorts out (the tools that drifted, that a drift
mark hides, that it no longer lists, and the tools nobody reviewed with the pin each is listed
at), never a definition, a token hash or a client name. It pushes when that changes, at most
once every 5 seconds, and at least once a minute; the vault keeps the latest in memory only, so
after a vault restart the next push, within a minute, fills it again. Nothing the vault decides
reads it: it is shown, labelled as what the gateway reports.

- **`zoeymcp health`** shows it as the `gateway` section (`tools_unreviewed`, `drift_marked`,
  `server_blocked`, `server_listing_invalid`, `gateway_status_stale`; §3), each with
  `run: zoeymcp review <server>`. `review`'s exit code, these findings and the portal's list
  come from the one decision, so a server `review <server>` exits 1 for has a finding here.
- **The portal's Home page** lists the same, per server, under the checklist: drifted, missing
  and marked tools, the tools nobody reviewed, a blocked server, and a bridge's state while it
  isn't ready, each with **Review**, which opens the MCP servers page, or, for marked tools,
  **Clear the marks** (§12) (at most 64 items; the rest are in `zoeymcp health`).
- The upstream reports a tool it can't serve under the name it lists, which often isn't a tool
  name: those are counted, not named. A report the vault can't read for one server leaves that
  server out (`server_listing_invalid`) and keeps the rest.

The vault takes the report on its own path, `POST /_zoeymcp/gateway/v1/report/status`, the
gateway's alone (its key on the TCP listener, or the link socket): at most 256 KiB, one at a
time, and at most one accepted every 5 seconds (429 sooner). Its log lines:

| Event | Fields |
| --- | --- |
| `status_received` | `servers` (how many the report names), `bytes`: at most once a minute |
| `status_refused` | `reason`: `too_soon` (429), `too_large` (413), `witness_range` (a witness revision above 9,999,999,999), or `invalid` (anything else the vault couldn't read): at most once a minute |

The gateway's side logs `status_push_failed` with the `reason` (a vault code, a status, or the
error's type), at most once a minute; it backs off from 1 s up to 30 s, and waits 5 s after a
429. None of these holds a tool's name or anything else from the report.

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
`policy_fetch_failed` with `status: 403` (and `vault_refused` with `status: 403` for a call in
flight; there is no other event for a refused key), and answers 503 until it has the new key.

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
(300 s). A server's `call_timeout` overrides the call deadline. The body limit and the session
idle timeout are the two the gateway's session manager keeps from its start: a lower value
applies at once, since the gateway's own checks follow every policy, but a higher one takes a
gateway restart. The gateway logs `limits_change_needs_restart` when either differs from the
value it started with.

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
- **Identical calls at once:** the gateway lets a `tools/call` out only for a call it validated,
  counted by tool and arguments. If two calls with the same tool and arguments run at once and
  one fails after it was sent, its withdrawal can take the other's place in that count, and the
  other is then refused at the gateway's egress check and fails. It fails closed: call again.
- **Bridges** (§33) relay the protocol and nothing else: a program behind one gets no roots,
  sampling or elicitation from the gateway (the bridge answers its `ping` and refuses every other
  request it makes), so give it its directories on its command line. Under `shared_session: true`
  every client shares one legacy child, and a modern bridge always runs one child, which every
  client shares. A legacy bridge's restart is caught at the gateway's next request (it gets 404, opens a
  new session, lists and compares the pins); a modern bridge's when the listen stream the gateway
  keeps open through it ends: the gateway lists and compares the pins then, and again once it has
  opened the stream again, about 5 seconds later (listings of one connection are at least 5 s
  apart), as for any modern server. A standard-tier bridge is unconfined; only the hardened tier
  limits where a bridge's program connects.

## 18. Troubleshooting the gateway

| An agent sees | Likely cause | Look at |
| --- | --- | --- |
| 401 | a wrong or missing token, a source pin | `auth_refused` with `reason` `no_token`, `bad_token` or `source` |
| 404 | the server isn't assigned to the client or doesn't exist; another client's session | the policy; `auth_refused` with `reason` `unassigned` or `session` |
| 421 / 403 | `Host` not in `gateway.hosts` / `Origin` not in `gateway.origins` | `auth_refused` with `reason` `host` or `origin` |
| 429 | too many requests, streams or sessions for the client | `auth_refused` with `reason` `limit`; `gateway.limits` |
| 503 | no view yet, or a stale one | `policy_stale`; `policy_fetch_failed` (`status: 403` is a refused gateway key, the one sign of it besides `vault_refused`) |
| `-32602 Unknown tool` | not included, unpinned, drifted, marked or invalid | `zoeymcp review <server>` |
| `-32603 upstream unavailable (ref ...)` | the listing failed, the vault refused (its `code` says why, e.g. `credential_unavailable`), or the upstream is down | grep the ref; `server_list_failed`, `vault_refused` |
| `isError` with `(ref ...)` | an upstream error, a timeout, a lost connection, a result refused | grep the ref |
| `arguments refused: at ...` | the arguments don't match the pinned schema | the tool's definition (`review --show`) |

Every log line is JSON with `role` (`vault`, `gateway`, `launcher` or `egress`). No client
token or hash, gateway key, session id, argument value, result content or upstream error text is
ever logged.

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
- **In managed mode** (§34) the Policy page lists each connector with whether it sends and its
  three limits. **Pause** (and **Resume**) and **Save limits** (`max_per_day`,
  `max_subject_chars`, `max_body_chars`) are saves of their own, `connector.limits`, each with
  one passkey: a pause is the first kill switch there, and needs no password to undo. The
  dialog marks what widens: "sends can go out again" for a resume, "20 -> 50: raised" for a
  raised limit. The host, port, sender and recipients the password is bound to are never the
  portal's: change them with `zoeymcp policy import`, whose plan says the password stops
  matching (set it again after it).

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

**A change while a prompt waits.** A save, an import or a reload can land while a prompt is
still waiting. What the waiting call gets depends on the change, and on whether the client speaks
a legacy protocol version (2025-11-25, 2025-06-18: the prompt waits on the call's own stream) or
the modern one (2026-07-28: the client answers by retrying the call with the prompt's handle):

- **The tool changed upstream, or was re-pinned** (`tool.repin`): nothing is sent, since the call
  was shown under the old definition. A legacy accept is refused `refused: the tool or policy
  changed while waiting for approval`. A modern retry meets the change itself: `refused: this
  approval belongs to a different call` after a re-pin, or `Unknown tool` while the tool is
  hidden.
- **The tool moved from `approve` to `allow`** (**Allow without asking**, or a review save that
  moves it): the prompt is withdrawn, as it is when the tool goes, and nothing is sent for the
  waiting call, whatever the human answers. A legacy call is answered `refused: the policy
  changed; call the tool again`. A modern answer comes back as a retry of what is now an `allow`
  tool, and is refused `refused: approval expired or already used` (a handle is good only for an
  `approve` tool). The ledger records the prompt as `withdrawn` straight away, so it no longer
  holds the client's pending slot or the tool's lock, and the agent's next call to the moved tool
  runs with no prompt.
- **The tool, the client's assignment or its attendance went:** the prompt is withdrawn either
  way. A legacy call is answered `refused: the policy changed; call the tool again`. A modern
  retry is answered `refused: approval expired or already used`, or `Unknown tool` if the tool is
  no longer listed for the client.

## 26. The portal

The admin portal is the vault's own web page for what needs a person: the first passkey,
secrets, OAuth connect, health, the MCP servers page and its review screen (§11, §12), the
ledger and the policy, in that order below. Everything here can also be done with the CLI (§1,
§2, §3, §11, §21, §34), and recovery is done only from the host. In managed mode (§34) the page
says so where a declarative page says to commit or reload, and the review screen saves.

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
one, and revokes a refresh token as `zoeymcp secret delete` does (§2). Names starting `oauth.`
are the vault's own (a credential's live tokens): the portal neither writes nor deletes them
(Connect does, on the Credentials page; `zoeymcp secret delete` can from the host). If the
policy is reloaded between the summary and the passkey prompt and the binding moves, the vault
refuses with what it finds now. A write the state volume refuses is kept in memory and said so,
as with the CLI. Logs: `secret_set` and `secret_deleted` with `via: "portal"` (or `"socket"`),
never the value.

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

**MCP servers.** The MCP servers page is §11's onboarding by URL and review, in the browser (M7).
It lists every remote and toolkit server in the policy (a toolkit says so; a bridge is a remote
server), and the server you are adding, each with its state and one button for what comes next;
the steps after it are written out, each command as you run it in the vault's container (put your
compose command in front, `docker compose -f deploy/compose.hardened.yaml exec vault` or
`docker compose -f deploy/compose.yaml exec zoeymcp`). The states:

- `needs_register`: discovered, nothing sent or stored yet. **Register and make the YAML** (the
  vault registers a client), **Store the secret and make the YAML** (a client you registered,
  with its secret) or **Make the YAML** (a public client you registered). In managed mode
  **Register its client**, **Store the secret**, or for a public client you registered **Save**
  at once (below).
- `needs_commit`: fragment 1 is made but the running policy doesn't name its credential yet.
  **Show fragment 1** makes it again, at any indent, until the commit or for 30 minutes.
- `needs_save` (managed mode, in place of `needs_commit`): registered, its credential, route and
  server not saved yet. **Save** plans them on the head and asks for your passkey (below), for
  30 minutes.
- `needs_connect`: in the policy, with no refresh token yet. **Connect** opens the Credentials
  page's dialog (§2); once it completes, the page queues the server's review by itself.
- `needs_review`: connected, and the policy includes none of its tools. **Review tools**.
- `reviewed`: **Review again**; the tools it serves and the clients it is assigned to; for a
  server whose credential names its resource, as onboarding by URL writes it, **Register a new
  client** is `zoeymcp login --mcp URL --reregister` (§11), which the portal doesn't run.
- `blocked`: your own egress proxy refused the vault (§28). **Show the hosts to allow** lists
  them with the Squid lines; allow them, then **Try again**: it puts the onboarding's own URL and
  names back in the form and discovers again (with the form's other options), so the onboarding
  carries on where it stopped.

In managed mode every server's row, `needs_connect`, `needs_review` or `reviewed`, has **Give to
clients** (below).

**Add a server by URL** takes the URL; **More options** holds the names (empty, the vault picks
free ones from the server's host name and fills them in; typing another URL empties them), a
client ID you registered with its
client authentication, secret and redirect address, a client name, an issuer (required with a
secret) and scopes. The secret field is write-only, as on the Secrets page: it is sent once, when
you prepare the registration, and the page empties it then and when you leave the page. **This
server is on my network** lets the vault reach a private address for this server alone, so the
discovery itself asks for your passkey first. **Discover** shows what the vault found: every row
of the plan, the authorization server's host in large type (compare it with the provider you
expect), the hosts the built-in egress role allows for it, `check`'s findings with the server
merged, and the button worded for the case. Registering a client or storing a secret asks for
your passkey, showing first the issuer's host, where the client is registered, the redirect
address and the name and binding a secret is stored under; a public client you registered needs
no passkey, since nothing is sent or stored. Fragment 1 then shows with what was stored (for a
client the vault registered, when its secret expires and any note on its answer), **Copy**
(the exact text shown), the indent (plain, indented 2, 4 or 8 spaces, or the compose form for
`ZOEYMCP_CONFIG`) and the steps that apply it:
`check --with` for your policy's source, the merge, `check` of the edited policy, the commit and
the reload. The page reads the rows again while a server waits on its commit, so it moves on by
itself once the vault sees the commit; after a recreate, sign in and it is there. A server that
names several authorization servers asks you to choose one (a button for each). **Cancel** drops
an onboarding in progress; signing out drops it too.

**Onboarding and Give to clients, in managed mode.** In managed mode (§34) onboarding by URL ends
in saves (§11's five prompts): after **Register its client** the page shows no fragment, and the
row's **Save** asks the vault to plan the server's credential, route and server as one change on
the head; the dialog lists what it adds ("Revision 2, from 1 (...)", then `credentials.notes`,
`routes.notes` and `gateway.servers.notes`, each added, and whether a restart is needed), and one
passkey writes it as `policy.save`. The vault holds that change for 5 minutes, as a review's
(`draft_unknown`: press **Save** again). The route it adds is called by the gateway alone and uses
the credential the same save adds; nothing in it can take an `env:` reference. A given public
client's plan has **Save** as its one button. A server's **Give to clients**, reviewed or not,
shows a box per client in the policy, ticked where the client reaches the server at the revision
the page read; **Save** writes each client whose box changed as a save of its own
(`client.servers`, one passkey each), its servers given whole and planned on that revision, so a
change written since (another session's, a host import) is `policy_moved`: the boxes are drawn
again at the head, and **Save** plans on it. Giving a server is a weakening,
its row first: "agents holding client agent1's token can call notes's 12 included tools"; taking
one away is a narrowing. Saving nothing changed is `no_change`; a change to a second client in the
same save is `kind_mismatch`. A client is added, or its token changed, only by a host import
(§34, §10). A review saved for a server no client reaches says to give it to them.

**The review screen.** **Review tools** (or **Review again**) queues a fresh review for the
gateway's poll (§11, "The review job path"), never a finished one handed back, since a server can
change a tool without the policy changing (§12), and shows it once the gateway reports: the
server's own name
and instructions, the counts ("96 tools: 64 the server marks read-only, 32 not annotated, ..."),
three chips (suggested read-only, not annotated, with findings: a tool shows when it matches any
chip ticked) and a filter on the name and title. "With findings" is a warning, as in the counts (a
tool with an error finding is counted apart); the first two chips read the server's own
annotations, as the counts do, so a toolkit's consequential tool shows under them by its
annotations though it is suggested approve. Each tool has its state, the server's suggestion
and why, its description, its findings (each naming the field it is about) and **Show
definition**, the pinned definition as JSON with every character outside ASCII escaped and
nothing cut (a long line wraps onto marked lines under it); a drifted tool has its two
definitions and their diff (§12). Nothing is included by default: tick **Include** on a tool, and
its allow or approve choice starts at the policy's classification for a tool the policy includes,
else at the server's suggestion, labelled as the server's (allow: agents call it with no prompt;
approve: every call asks you first). A tool that can't be pinned has no box, and says why.
**Select suggested** includes every unticked, pinnable tool the server marks read-only and not
destructive, each where its own box starts: as allow for a new tool, at its classification for
one the policy includes, so **Clear** then **Select suggested** gives each tool back its
classification and never moves one from approve to allow; it is the only bulk allow. **Clear**
takes every tool out. Tools the policy includes already start included, at their classification,
so generating unchanged keeps them; taking one out drops it. **Decline** and **Record the rest as
declined** record what you leave out (§12). **Generate (n tools: a allow, b approve)** makes fragment 2, with
**Copy**, the indent and its steps, ending with the `gateway.clients.<client>.servers` line to
add yourself: fragment 2 assigns no client. Nothing is saved.

**Saving a review, in managed mode.** In managed mode (§34) the review screen has **Save** where
it has **Generate**. The vault builds the change from your choices (the same change fragment 2
would carry), plans it on the policy's head and holds it for 5 minutes, one per session (a
second **Save** replaces it), then asks for your passkey with the plan: "Revision 18, from 17 (by
you, `<when>`: 17 is the head)", then every move to allow first, each on its own row with its
sentence ("approve -> allow. Calls to `<tool>` will run with no prompt"; "`<tool>` was approve in
an earlier revision: calls will run with no prompt"; a re-pinned allow tool whose new definition
the server no longer marks read-only, kept allow: "`<tool>`'s new definition isn't marked
read-only and stays allow") and every line of the definition it allows below it, nothing cut;
then the other changes (a re-pin shows both pins: "re-pinned: you read both definitions"), and
whether a restart is needed. The vault, not the page, decides the save's kind from the change,
and the passkey confirms that kind (the log's `step_up_confirmed` names it): a save whose only
change is re-pins is `tool.repin`, one whose only change is one included approve tool moved to
allow is `tool.allow`, and anything else is `policy.save` (a review that learns the server's era
for the first time writes it too, so that first save is a `policy.save`). One passkey writes the
revision; the answer names it, says the gateway takes the new view within seconds (health says
`gateway_view_behind` if it hasn't after 30 s, §3) and whether a restart is needed, with each
step's command and where it runs (the vault's own restart is your compose command's `restart` of
the vault's service, §34). **Select suggested** never moves a tool to allow: a tool the policy
includes, or one it once had as approve, starts at approve; a move is always your choice on its
row. **Allow without asking** on the MCP servers page is `tool.allow` for that one tool, with the
definition pinned for it from a review the vault still holds (reviews are kept 30 minutes; for a
tool that drifted, the reviewed definition, not the one the server lists now; on a `pinning: off`
toolkit the listed one, followed by "pinning is off for `<server>`: the image can change this
definition with no review"); with none, the page reviews the server again first, then opens the
dialog. A tool the policy no longer has as approve at the pin the page showed is `changed`: open
the server's page again. A definition too long for the dialog (more than 400 rows) is
`summary_too_large`: make that move on the host (`zoeymcp policy export`, edit, `zoeymcp policy
import`). Nothing moves to allow for a tool the gateway marks drifted, or a toolkit's
consequential tool. If the policy moved between the plan and your passkey (another session
saved, or the host imported), the dialog shows "The policy moved to revision 19, saved `<when>`
by `<who>` since you planned this: press Save again to plan it on revision 19", then the plan
**Save** would make on revision 19, and nothing is written; any other change the vault finds at
that moment shows in the dialog the same way, its first row the reason. If the vault writes the
revision but can't apply it, the answer is `saved_not_running` (send SIGHUP to the vault or
restart it), and every save waits for that. A change older than 5 minutes is `draft_unknown`
("press Save again"). A save that would leave a stored secret
unused lists it first: delete it on the Secrets page before the save, while it can still be
revoked at the provider. Logs: `step_up_confirmed` with the kind, then `policy_saved`, and
`tool_allowed` (with `kept: true` for a kept allow) and `tool_repinned` per tool (§34).

When a review doesn't come back: `review_unavailable` means the gateway isn't polling the vault
(check that it runs and reaches it, then review again); `review_stale` means the policy was
reloaded since (the gateway didn't take the job within 60 s, or the server's tools changed since
its report): review again once the gateway has the new policy; `job_unknown` means the report
expired (30 minutes), the vault restarted or it was already used: review again. Logs:
`onboard_started` (`owner: portal`), `onboard_planned`, `onboard_refused`, `onboard_registered`,
`onboard_blocked` and `onboard_ended` (§11), `step_up_confirmed` with the action
`onboard.register` or `onboard.discover_private` (in managed mode `policy.save` and
`client.servers` too, each then `policy_saved`), and `review_requested` with `owner: portal`;
never a client secret, a fragment or a tool's definition.

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

**The Policy page, in managed mode.** In managed mode (§34) the page shows the head (the revision
it shows, when and by whom it was saved), which revision the gateway runs (or that it hasn't taken
the head yet, or hasn't reported since the vault started), a revision saved and not running, and
the host's `zoeymcp policy export` command, as you run it in the vault's container. **History**
lists the kept revisions, newest first, 50 a page (**Older revisions** for more): each with when
and by whom it was saved (a passkey's fingerprint, the host and how, or the seed), what made it (a
save, a re-pin, a move to allow, a rollback with its target, an import, the seed, ...) and the
host's reason, as `zoeymcp policy history` shows them (§34); a revision in quarantine shows as a
gap. **Show the changes** lists what a revision changed from the one before it, one row per field
with its direction (wider, narrower or neutral), rendered as the policy view is, so a hidden field
shows only as `(set)`, `(changed)` or `(removed)`, and text from the policy with every hidden
character revealed. **Roll back to revision N**, on any kept revision but the head (also one whose
changes can't be shown because the revision before it is no longer kept or is in quarantine),
plans a new revision with N's content, keeping from the head its key generations, its `admin`
block and the pin of every tool both have, and the declines less what N includes (§34, "Rolling
back"); the dialog lists every change, the store entries it leaves unused first ("delete it on the
Secrets page, then roll back again": after the rollback a removed credential's secret can't be
revoked at the provider), and one passkey writes it. The portal rolls back only when every change
is narrower or neutral, so it can undo an onboarding, a tool's inclusion, a move to allow or a
raised limit. A rollback that would bring back a client or a caller a later revision removed is
refused `rollback_revives`, naming it and the revision that removed it; anything wider (a dropped
`sources` pin, a re-pointed server, a raised timeout, `wrap_results` turned off, a tool moved to
allow, ...) is refused `portal_widens`, naming each path: both before any passkey prompt, and both
are the host's to do, with `zoeymcp policy rollback N` and its flags (§34). A revision in
quarantine or no longer kept is `revision_unreadable` or `revision_unknown`; if it goes to
quarantine between the plan and your passkey, the dialog says so and nothing is written, as it
does when the policy moved meanwhile (`policy_moved`: the page is drawn again at the new head, so
press **Roll back** again to plan it there). Logs: `step_up_confirmed` with the action
`policy.rollback`, then `policy_rolled_back` with its `target` (§34).

**Connectors, in managed mode.** The managed Policy page lists each SMTP connector with whether
it sends and its three limits, each in a field (§22). **Pause** refuses every send at once and
**Resume** lets them go out again; **Save limits** writes the three fields. Each is
`connector.limits`, planned on the head the page shows and confirmed with a passkey: a pause or a
lowered limit is narrower, a resume ("sends can go out again") and a raised limit ("20 -> 50:
raised") are weakenings. A value outside the schema's range is `bad_body`, the same values again
`no_change`. If the policy moved since the page showed it, the page is drawn again first ("press
the connector's button again"). Its recipients, mail server and sender are bound to its password
and are the host's to change (§34, "Importing a change"). Logs: `step_up_confirmed` with the
action `connector.limits`, then `policy_saved` with `write_kind: connector.limits`.

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

**What a stolen session can and can't do.** A session is the cookie and the tab's token together; a
page on another `localhost` port receives the cookie (cookies ignore ports) but not the token, and
gets 401. Someone holding both halves, within the session's limits, can read what the portal shows
(names, bindings, health, the policy view and, in managed mode, its history and diffs, the
ledger, the passkey and session lists, review reports), start an OAuth sign-in, start onboarding
a server by URL (the vault then fetches that server's public metadata, through its address
guard), queue a review, plan a review save (managed mode: the plan is held, nothing is written),
and end other sessions. They can't write or delete
a secret, complete a connect, reset a credential, register a client, discover a server on your
own network, enrol, rename or remove a passkey, restart the ledger chain, or, in managed mode,
save a review or an onboarding's server, re-pin a tool, move one to allow, give a server to a
client or take it away, pause, resume or change a connector's limits, or roll back the policy:
each needs a fresh passkey prompt bound to that change. If you think a session was taken, **End the other
sessions** (or `zoeymcp sessions --end-all` from the host); the threat model
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
A `binding_changed` for a pasted answer or a returned sign-in, when a reload changed the
credential's `issuer` or turned `require_iss` off since the sign-in started, says instead: "The
policy changed this credential's issuer since the sign-in started: it was `<old>`, it is now
`<new>`. Nothing was stored. Connect again."

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
| 409 | `generate_refused` | Only a header, query, path or basic credential's secret can be generated; enter an OAuth or connector secret as it was given. |
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
| 400 | `iss_missing` | The answer didn't name its issuer, which this provider always does; nothing was stored. Connect again. |
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
| 403 | `portal_env_ref` | A credential the portal adds or changes takes its secret from the store, not from env: (`<detail>`). Only the host can use an env: reference. |
| 403 | `route_reuses_credential` | A route the portal adds calls as the gateway alone, with a credential the same change adds; `<detail>` doesn't. Only the host can add it. |
| 404 | `onboarding_unknown` | That onboarding isn't in progress: it finished, expired or was started elsewhere. Start it again. |
| 429 | `onboarding_busy` | At most 4 onboardings can be in progress. Finish or cancel one, or wait for one to expire (30 minutes). |
| 409 | `onboarding_options_changed` | The onboarding in progress for this URL and these names stopped at your proxy and was started with other options. Run it with the same options to carry on, or start again once it expires (30 minutes). |
| 409 | `registration_unavailable` | Register a client at `<host>` and run again with its client ID. |
| 409 | `cimd_only` | This server registers clients by metadata document, which ZoeyMCP doesn't support yet. Register a client at `<host>` and run again with its client ID. |
| 502 | `dcr_refused` | The authorization server refused the registration (`<error>`), so no client was registered. |
| 502 | `dcr_failed` | The authorization server didn't answer the registration as needed (`<detail>`). It may have registered a client anyway; the next run registers a new one. |
| 502 | `dcr_redirect_changed` | The authorization server registered another redirect address than the one asked for, so its client isn't used. |
| 502 | `dcr_auth_unsupported` | The authorization server offers no client authentication the vault speaks (none, client_secret_basic or client_secret_post), so no client is used. |
| 502 | `dcr_bad_client_id` | The client ID the authorization server issued can't be written into a policy (1 to 255 printable characters, no space, quote, backslash or $, and no store: or env: reference), so it isn't used. |
| 502 | `dcr_bad_secret` | The authorization server's client secret doesn't fit the client's authentication (one missing, one too many, or one that can't be stored), so its client isn't used. |
| 502 | `dcr_grant_missing` | The authorization server registered the client without the authorization_code and refresh_token grants, so it isn't used. |
| 502 | `dcr_answer_invalid` | The authorization server's registration answer can't be used (`<detail>`). |
| 502 | `proxy_refused` | Your egress proxy refused the vault's connection to `<host>`. Allow the hosts listed here in it for the vault, then run the same command again. |
| 502 | `egress_refused` | The egress role refused the vault's connection to `<host>`: it hadn't fetched the onboarding's hosts yet, its key is out of date, or it refused or couldn't reach the host's address. Its egress_refused log line names which; if it hadn't fetched yet, run the same command again. |
| 409 | `private_needs_direct` | A server on your network can't be onboarded through the egress role, which can't keep its private exception to this onboarding. Onboard it with egress_proxy unset, or add it to the policy by hand. |
| 409 | `already_configured` | The server `<server>` already reaches this URL, with a credential of kind `<kind>`, not oauth2. Remove it, its route and that credential from the policy and reload first. |
| 409 | `onboarding_mismatch` | The committed policy differs from what the server publishes now, at `<fields>`. Revert the edit, or register a new client with zoeymcp login --mcp URL --reregister. |
| 409 | `reregister_by_hand` | The credential `<credential>` sets `<field>`, which a re-registration's fragment can't carry (`<why>`). Re-register by hand: edit the credential in the policy. |
| 502 | `address_refused` | The vault doesn't connect to `<host>`: its name resolves to a private, loopback or reserved address. Nothing was sent to it. |
| 502 | `resolve_failed` | The name `<host>` didn't resolve, so nothing was sent to it. |
| 502 | `fetch_failed` | The host `<host>` didn't answer as needed (`<detail>`). |
| 502 | `fetch_redirect` | The host `<host>` answered with a redirect, which the vault doesn't follow. |
| 502 | `fetch_too_large` | The answer from `<host>` is larger than the vault reads, so it isn't used. |
| 502 | `fetch_not_json` | The answer from `<host>` isn't one JSON object, so it isn't used. |
| 502 | `review_invalid` | The gateway's review report isn't in the form the vault reads (`<detail>`), so nothing from it is shown. Review again. |
| 502 | `pin_mismatch` | The gateway's review report gives a pin that isn't its definition's, for `<tools>`, so nothing from it is shown. The gateway's own review never reports that: check the gateway. |
| 413 | `review_too_large` | The gateway's review report is too large (`<detail>`), so it isn't read. |
| 404 | `review_unknown_server` | The running policy has no remote or toolkit server named `<server>`. Check the name, or reload the policy that adds it. |
| 409 | `review_busy` | A review of `<server>` is already under way. Wait for it (at most 3 minutes), then review again. |
| 429 | `review_jobs_full` | At most 2 reviews can be under way at once. Wait for one, then review again. |
| 503 | `review_unavailable` | The gateway isn't asking the vault for review jobs (`<detail>`), so nothing was queued. Check that the gateway is running and reaches the vault. |
| 409 | `job_unknown` | That review isn't known to the vault: it finished more than 30 minutes ago, the vault restarted, or its result came already. Review again. |
| 409 | `review_stale` | The policy changed since this review: the gateway didn't take it within 60 seconds, holding another version, or the server's tools changed since its report. Review again once the gateway has caught up. |
| 504 | `review_timeout` | The gateway took the review but sent no result within 2 minutes. Check the gateway's log, then review again. |
| 502 | `review_failed` | The gateway couldn't review the server (`<code>`). Its log says why; review again once that is fixed. |
| 409 | `clear_unsupported` | The gateway is older than the vault: run zoeymcp review `<server>` --clear in the gateway's container. |
| 409 | `clear_not_clean` | These still don't match their pins: `<tools>`. No mark was cleared; review the server again. |
| 400 | `kind_mismatch` | This change is `<detail>`. Prepare it again from the page. |
| 409 | `allow_needs_review` | There is no reviewed definition of `<detail>` at its pin to show you: review the server again, then allow it. |
| 409 | `allow_marked` | The gateway marks `<detail>` as drifted: its classification waits for its review. |
| 409 | `consequential_allow` | The toolkit declares `<detail>` consequential: it stays approve, never allow. |
| 400 | `generation_lowered` | The policy's `<detail>`: that would bring back a retired key. |
| 409 | `pin_retired` | This would put `<detail>` back on a definition it was re-pinned away from: review it. |
| 409 | `rollback_revives` | Rolling back to `<detail>`: only the host can, with zoeymcp policy rollback and --allow-revive. |
| 409 | `revives_client` | This brings back `<detail>`: refused without --allow-revive client:NAME for each. |
| 409 | `revives_caller` | This brings back `<detail>`: refused without --allow-revive caller:ROUTE/INDEX for each. |
| 403 | `env_name_new` | The reference env:`<detail>`: only the host can allow that, with zoeymcp policy import --allow-env. |
| 403 | `env_reach_grows` | The reference env:`<detail>`: only the host can allow that, with zoeymcp policy import --allow-env. |
| 409 | `ratchet_full` | The ratchet holds 10,000 retired entries: reseed with --new-ratchet on the host (operations.md section 34). |
| 403 | `portal_widens` | The portal can't `<detail>`: export, edit and import with zoeymcp policy import. |
| 403 | `generation_raise_from_portal` | A key rotation is done on the host: raise `<detail>` with zoeymcp policy import. |
| 413 | `summary_too_large` | This change is too long to confirm in the portal: `<detail>` (zoeymcp policy export, edit, zoeymcp policy import), where all of it is shown. |
| 400 | `no_change` | Nothing would change. |
| 500 | `policy_write_failed` | The revision couldn't be written; nothing changed. |
| 400 | `revision_out_of_range` | A revision can't go above 9,999,999,999. |
| 500 | `reseed_incomplete` | The reseed failed and couldn't put the old store back, so the vault won't start (`<detail>`). Put each file named back, then run the reseed again; if the old anchor can't be put back, run it with --new-ratchet. |
| 409 | `policy_not_running` | Revision `<revision>` is saved but not running: send SIGHUP to the vault or restart it, then save again. |
| 409 | `policy_moved` | Nothing was written: `<detail>`. For an import, export again and redo your edit; for a rollback, run it again. |
| 409 | `plan_changed` | The plan changed since you read it: plan the change again and read it first. |
| 400 | `import_refused` | The policy is refused: `<detail>`. |
| 404 | `draft_unknown` | That change expired: press Save again. |
| 422 | `save_invalid` | The running policy with this change fails check (`<detail>`), so it can't be saved. |
| 500 | `saved_not_running` | Saved as revision `<revision>`, but the vault couldn't apply it: send SIGHUP to the vault or restart it. |
| 400 | `state_as_root` | This command won't run as root: the vault's uid couldn't read what it writes. Run it as the vault's uid: add --user 10001:10001. |
| 409 | `state_locked` | The state directory is in use: stop the vault first (`<command>`), then run this again. |
| 400 | `seed_declarative` | The policy given says mode: declarative, and a seed is managed mode's first revision: set mode: managed, check it, then seed. |
| 400 | `import_declarative` | An import is a managed revision; to go declarative, put an export made with --mode declarative in ZOEYMCP_CONFIG. |
| 409 | `policy_store_present` | The state directory `<state>` already holds a policy store or its anchor: replace it with zoeymcp policy import --state `<state>` --reseed. |
| 409 | `reseed_needs_new_ratchet` | The old policy head doesn't verify (`<detail>`), so there is no ratchet to plan the reseed against: add --new-ratchet, which forgets what the old store retired. |
| 409 | `policy_not_managed` | This deployment's policy is declarative: commit a fragment instead. |
| 428 | `base_required` | Say which revision this change is planned on: pass --base N (the revision you exported; zoeymcp policy head shows the current one). |
| 400 | `export_other_deployment` | This export is from deployment `<detail>`, not this one: export from this deployment and redo your edit there. |
| 400 | `import_widens` | This plan widens the policy (`<detail>`): with --yes it needs --accept-widening too, or run it without --yes to read the plan and confirm it. |
| 400 | `lockout_unconfirmed` | This change `<detail>`: type the confirmation at the prompt, or pass --yes --lockout-ok. |
| 409 | `nothing_to_acknowledge` | There is nothing to record: `<detail>`. |
| 409 | `revision_unreadable` | Revision `<revision>` is in quarantine: it can't be read, so it can't be used. |
| 409 | `revision_unknown` | Revision `<revision>` is no longer kept, or never was. |
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

**Deployments run in Linux containers**, from the official image, on Docker Engine 28.0 or later in
both tiers; so do the egress role and every bridge, from the official or a derived image. Older
engines let other hosts on the same network segment reach ports published on `127.0.0.1`, and
connect to a container's published ports directly, which would put the portal and the standard
tier's gateway on the LAN. The image smoke test refuses an older engine, but ZoeyMCP can't check the
host's engine at run time: check `docker version` yourself.

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
| Windows | the bridge (§32) refuses to start: it needs a POSIX platform |
| Windows | the egress role (§31) has no `SIGTERM`, `SIGINT` or `SIGHUP` handlers, as above |
| Windows, macOS | a bridge can't listen on a Unix socket, and the vault refuses `--bridge` (both peer checks need Linux), so a route's `unix:` upstream answers 502: the standard tier's bridges need its launcher anyway |

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
- **Your own proxy or the egress role.** `egress_proxy_kind` says which `egress_proxy` is: `own`
  (the default) for your own proxy, as this section describes, where onboarding stops at
  `proxy_refused` with the Squid lines to add (§11); `role` for ZoeyMCP's egress role (§31),
  which takes its lists from the vault, so nothing is edited. `role` without `egress_proxy` is
  refused, and `check` warns about `egress_proxy_acls` with `role`: those names serve your own
  Squid only.
- **Changing it needs a restart.** `egress_proxy` and `egress_proxy_kind` are read when the vault
  starts, and every vault connection (routes, token requests, onboarding and SMTP sends) keeps
  that proxy. A reload whose `egress_proxy` or `egress_proxy_kind` differs from the one the vault
  started with logs `egress_proxy_change_needs_restart`, again on every reload until the restart,
  and only once the reload takes effect (a refused reload logs none): recreate the vault right
  after changing it (§7).
- **A policy change can outdate the allowlist.** A route upstream, token or revocation endpoint,
  connector or `egress_private` entry added, changed or removed changes the vault's list; a route
  program's `egress` or `egress_private` changes that program's list; and `egress_proxy_acls`
  changes the Squid form's names. The vault can't tell your proxy: after such a change, run
  `--check` (below) and regenerate the file if it differs. The egress role
  (`egress_proxy_kind: role`) takes its lists from the vault, so it needs none of this.

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
  `# plain http: refused by a CONNECT-only proxy`. A route whose `program.egress` lists something
  (a bridge's) is a source of its own, named by the route, and a local MCP route's own upstream
  is never in the vault's list: the vault reaches a bridge directly, never through a proxy.
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
underscores. A route program's source takes its own key, the route's name
(`{bridge-fetch: fetch_net}`), and defaults to `zoeymcp_src_<route>`. Unless `egress_proxy_kind`
is `role`, `check` refuses such a route named `src`, `src_...` or `port`, whose destination ACLs
(`zoeymcp_<route>_<n>`) would share a name with another ACL in the snippet, and a name that makes
an ACL name longer than Squid's 63 characters.

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

**Onboarding through it.** With onboarding by URL (`zoeymcp login --mcp`, §11), the
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
  catches it, as ZoeyMCP's own egress role (hardened tier, §31) does; Squid doesn't.
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
- **A hardened bridge** (§33) gets networks of its own here too, never one of the stack's:
  `bridge-<name>`, internal, which it shares with the vault alone, and, when its program has an
  egress list, an internal network it shares with the stack's proxy alone, through which the
  program goes out. The emitted snippet gives the bridge's route a source of its own
  (`zoeymcp_src_<route>`, so `zoeymcp_src_bridge-fetch` for the example's, unless
  `egress_proxy_acls` names your ACL), whose `src` is the
  bridge's address on that network, so the program reaches its own list and nothing on the
  vault's.
- **The egress role** (§31) is for a stack without a proxy of its own. Beside the stack's proxy,
  leave `egress_proxy_kind` unset (or `own`): the vault then takes `egress_proxy` for your
  proxy, and onboarding asks you to allow its hosts there (§11). A hardened bridge's program
  goes out through the stack's proxy too (above), not the role.
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

## 30. A first hardened deployment, end to end

The steps above in the order a first deployment takes them, in the hardened tier: the keys, a
client token, the policy, a secret, the reload, a remote MCP server onboarded by its URL, its
review, and an agent's container attached. Every command runs on the host, from the repository's
root; `c` is the compose command, which the commands ZoeyMCP prints start with too (§11):

```sh
c="docker compose -f deploy/compose.hardened.yaml"
docker build -t zoeymcp:local .
```

1. **The keys.** `docker run --rm zoeymcp:local keygen` prints `ZOEYMCP_MASTER_KEY` and
   `ZOEYMCP_GATEWAY_KEY`. Keep both as deployment secrets (an `.env` file only you can read, say):
   the master key opens the store, and a lost one means setting every secret and signing in
   again (§6).
2. **A client token** for each agent: `docker run --rm zoeymcp:local client-token` (§10). The
   agent gets `client_token`; the policy gets `token_sha256`.
3. **The policy.** The compose file's `ZOEYMCP_CONFIG` is the policy (or put it in a file, §7).
   Put the agent's `token_sha256` under `gateway.clients.agent1`, and give it no servers yet
   (`servers: []`). Remove the example `notes` server, its route `notes-mcp` and its credential
   `notes-key` before you onboard a server at that URL: `login --mcp` refuses a URL a server
   already reaches with another kind of credential (`already_configured`). Keep or remove the
   `stats` route; if you keep it, replace its placeholder with a long random value. Then prove the
   file: `$c run --rm --no-deps vault check`.
4. **Start**: `$c up -d`. `$c exec vault zoeymcp health` lists what still needs you, and
   `$c exec gateway zoeymcp gateway-status` shows the gateway's view, `fresh` once it has one.
5. **A secret** for a route that holds one, piped in, never typed on the command line:
   `printf '%s' "$KEY" | $c exec -T vault zoeymcp secret set music-stats`. No reload: the policy
   names the secret, never its value.
6. **The reload.** An inline policy is part of the vault's environment, so a changed one is
   applied by recreating the vault: `$c up -d vault`. The gateway carries on, and sees the new
   view once the vault is back (§9). Nothing the next step needs lives only in the vault's memory,
   so a recreate costs at most a portal sign-in. For a policy file, `$c kill -s HUP vault` (§7).
7. **A remote MCP server, by its URL** (§11, "Onboarding by URL"):

   ```sh
   $c exec vault zoeymcp login --mcp https://mcp.notes.example/mcp --name notes > onboard-notes-1.yaml
   $c run --rm --no-deps -v "$PWD:/w:ro" vault check --with /w/onboard-notes-1.yaml
   ```

   The plan and the `Next:` list go to the terminal, fragment 1 to the file. Merge fragment 1
   into `ZOEYMCP_CONFIG` (`check --with /w/onboard-notes-1.yaml --print-merged --for compose`
   prints the whole block to paste over it), prove the edited file with `$c run --rm --no-deps
   vault check`, and recreate the vault (step 6). Then run the same `login --mcp` command again,
   without the redirect: it compares the server with fragment 1, prints the sign-in link (open
   it, approve, paste back the address you land on), and queues the server's review, which the
   gateway runs. A server that offers neither a client you registered (`--client-id`) nor
   dynamic registration stops at `registration_unavailable`: register a client there first.
8. **The review.** The second run ends with the counts and two commands:

   ```sh
   $c exec vault zoeymcp review notes --via vault --choose --suggest > notes.choices
   # edit notes.choices: skip, allow, approve or decline on each line
   $c exec -T vault zoeymcp review notes --via vault --choices - < notes.choices > onboard-notes-2.yaml
   ```

   Read the definitions you include (`$c exec vault zoeymcp review notes --via vault --show
   TOOL`). Commit fragment 2 as fragment 1 (`check --with`, the merge, `check`, the recreate),
   then add `notes` to `gateway.clients.agent1.servers` and recreate once more: fragment 2 never
   assigns a server to a client. `$c exec gateway zoeymcp review notes` then exits 0.
9. **The agent's container** joins the `agents` network, `zoeymcp_agents` to Docker (the compose
   project is `zoeymcp`), and nothing else of ZoeyMCP's. In the agent's own compose file:

   ```yaml
   services:
     agent:
       networks: [zoeymcp]
   networks:
     zoeymcp:
       external: true
       name: zoeymcp_agents
   ```

   or `docker network connect zoeymcp_agents <container>` for one already running. Its MCP
   client takes `http://gateway:8090/s/notes/mcp` with the header `Authorization: Bearer
   <client_token>` (§10). The `agents` network has no route out, so an agent that needs the
   internet keeps a network of its own for that; it still reaches the server only through the
   gateway, and never holds the server's token.

**The same in the portal.** Steps 7 and 8 can run in the portal instead (§26): issue a code with
`$c exec vault zoeymcp setup-code`, open `http://localhost:8081`, and enrol a passkey. On **MCP
servers**, **Add a server by URL** discovers the server and shows the plan; **Register and make
the YAML** registers a client after your passkey (a client you registered yourself goes under
**More options**), and fragment 1 shows with **Copy** and its steps. After the commit and the
recreate, sign in again: the server's row says `needs_connect`, and **Connect** signs in with
your passkey at the end, then queues the review by itself. **Review tools** shows the tools with
the server's suggestions, **Generate** makes fragment 2, and the row says `reviewed` once it is
committed. Assigning the server to the agent is still yours (step 8).

Through your own egress proxy (§28), step 7 may stop at `proxy_refused`, naming the hosts to
allow and the same command to run again, which carries on where it stopped once they are allowed.
Through the egress role (§31: the `egress-proxy` profile, its key from `zoeymcp egress-key`, and
`egress_proxy` with `egress_proxy_kind: role` in the policy) there is nothing to allow by hand:
the vault widens its own list while the onboarding runs.

**A stdio server** joins behind a bridge, in §33's cold-start order: build the derived bridge
image; commit the bridge's route, its header credential and the server (step 6) without the
override yet; make its token with `$c exec vault zoeymcp secret set bridge-<name>-token
--generate` and set `ZOEYMCP_BRIDGE_<NAME>_TOKEN_SHA256` to the line it prints (without it the
bridge refuses to start, and compose keeps restarting it); then add
`examples/bridge/compose.bridge.yaml` beside the compose file (`c` then names both files, and so
should `ZOEYMCP_COMPOSE_CMD`), with the role running (§31) when its program needs egress, and run
`$c up -d bridge-<name>`, then `$c up -d vault`. Its program reaches only its own egress list,
through the role. Review it as in step 8 and assign it to the agent.

## 31. The egress role

`zoeymcp egress` is ZoeyMCP's own egress proxy for the hardened tier: CONNECT only, with one
listener per egress source, each allowing only that source's `host:port` list. The vault's
source is `vault`; a route's program is the source named by the route. It holds no policy and no
secret but its key, inspects no TLS and caches nothing.

```sh
zoeymcp egress --vault http://vault:8080 --listen vault=egress-vault:3128
```

- `--listen SOURCE=NAME:PORT` (repeatable) binds the role's address on that source's network.
  `NAME` is a host name or an IP address; it must resolve to exactly one address, and never to
  `0.0.0.0` or `::`, so a container on another source's network can't reach the listener. A name
  that resolves to no address or to several, or doesn't resolve within 5 s, leaves that listener
  unbound, which refuses its source's tunnels; the role logs it and tries again at each contact
  with the vault. A source the vault's lists don't name refuses every tunnel on its listener.
- The lists come from the vault: the role long-polls `GET /_zoeymcp/egress/v1/allowlists` with
  the egress key in `x-zoeymcp-egress`, from `ZOEYMCP_EGRESS_KEY` or the file
  `ZOEYMCP_EGRESS_KEY_FILE` names (re-read on `SIGHUP` and after a 403, at most once per 10 s).
  Without a key it refuses to start, naming `zoeymcp egress-key`. It opens no tunnel before its
  first list, and none once 300 s pass without an answer from the vault (fail closed); a list
  that doesn't parse is refused and the last good one kept, still going stale on time. A
  destination whose host no CONNECT could name (a route's name IDNA refuses) is skipped, and the
  rest of the list kept. After a failure it retries within 30 s; the held request sends TCP
  keepalives, so a vault that vanishes without closing it is noticed within 15 s.
- Per connection: one `CONNECT host:port` head (8 KiB, 10 s), the `host:port` exactly as listed
  (lower case; a non-ASCII name is never listed), one lookup (5 s) whose every address is global
  unless the entry is marked private, and a connect to the addresses it checked, never a
  second lookup: each in turn, in the resolver's order, until one connects, all within 10 s
  (an IPv6 address with no route is passed over for the next). Tunnels close after
  `--idle-timeout` (900 s) idle or `--max-tunnel-seconds` (86400) open, and at most
  `--max-tunnels` (256) run per listener, 1,024 in all. When the lists change, a tunnel whose
  destination left its source's list is closed.
- Every answer the role makes itself is empty, with `Content-Length: 0` and no
  `WWW-Authenticate` or `Proxy-Authenticate`. Any method but CONNECT is 405 with `Allow:
  CONNECT`, so plain http can't go through it.

| Reason | Status | Why |
| --- | --- | --- |
| `head_too_large`, `head_timeout`, `bad_request` | 431, 408, 400 | the head is over 8 KiB, took over 10 s, or isn't `CONNECT host:port HTTP/1.1` with at most 64 header lines |
| `not_connect` | 405 | another method |
| `list_stale` | 503 | no list yet, or none fetched in the last 300 s |
| `no_list`, `not_allowed` | 403 | the vault's lists don't name this listener's source, or don't list this `host:port` for it |
| `resolve_failed`, `address_refused` | 502, 403 | the name didn't resolve in 5 s, or resolved to a private, loopback or otherwise non-global address the entry isn't marked private for (`verdict` names its class) |
| `connect_failed` | 502 | no checked address connected within 10 s (`address` is the last one tried) |
| `busy` | 503 | the listener's, or the role's, tunnel cap |

Its log lines (`role: egress`):

| Event | Fields |
| --- | --- |
| `egress_started` | `vault` (its `host:port`), `listeners` (each source's bound address, or `null` when unbound), `max_tunnels` |
| `egress_listen_failed` | `source`, `listen`, `reason`: a listener left unbound, once per reason |
| `egress_listen_bound` | `source`, `address`: a listener bound at a later try |
| `egress_allowlist_applied` | `digest`, `sources` (how many destinations each source has), `skipped` (destinations no CONNECT could name): new lists |
| `egress_allowlist_failed` | `error_type`, or `status` and, for a document it refused, `reason`: a fetch that wasn't contact |
| `egress_allowlist_ended` | `error_type`: the long poll ended, which can't happen in a working role; the role stops |
| `egress_allowlist_stale` | `age_s`, `digest`: 300 s without contact, once until contact resumes |
| `egress_key_reloaded`, `egress_key_unreadable` | a changed key file read after `SIGHUP`; a key file that can't be read (`reason`), the old key kept |
| `egress_tunnel` | `source`, `host`, `port`, `address`, `result` (`closed`, `idle`, `timeout`, `removed` or `stopped`), `bytes_up`, `bytes_down`, `ms` |
| `egress_refused` | `source`, `reason` (the table above), and `host`, `port`, `verdict` and `address` where known |

None holds the key, a request's headers or anything a tunnel carries.

**The vault's side.** Name the role in the policy: `egress_proxy` is its `vault` listener
(`http://egress-vault:3128` for the command above) and `egress_proxy_kind: role` says it is the
role, which onboarding needs (§11, "Through the egress role"); both take a restart to change
(§7). `zoeymcp egress-key` (inside the vault's container) prints
`ZOEYMCP_EGRESS_KEY=...` for the policy's `egress_key_generation` (1 by default), and the
generation on stderr. The key reads the allowlists and nothing else: the vault refuses it on
every other path, and on the gateway's link socket, and the gateway's key on the allowlists.
To change it, raise `egress_key_generation` and reload; never lower it (a reload that lowers it
is refused, `reload_refused`). The old key is refused at once (there is no rotation window), so
the role refuses new tunnels within 300 s unless it is given the new key (update the file and
send it `SIGHUP`, or set the variable and recreate it). The vault's list
is the policy's destinations (`check --emit-egress-allowlist` shows the same), plus each
onboarding's allowance while it runs (§11, "Through the egress role"). `health` reports
`egress_allowlist_stale` (§3) when a role stops fetching, when its key is refused, or, with
`egress_proxy_kind: role`, when no role has asked within 300 s of the vault's start.
The vault's log line (`role: vault`):

| Event | Fields |
| --- | --- |
| `egress_allowlist_served` | `digest`, `waited_ms`: new lists answered to the role (a 304 isn't logged; each request is a `request` line with `endpoint: egress_allowlists`) |

**In the hardened tier: the `egress-proxy` profile.** `deploy/compose.hardened.yaml` runs the
role as the `egress-proxy` service, and only with `--profile egress-proxy`. The standard tier has
no role (§9). Start the vault, print the key it holds for the role, then start the role with it:

```sh
docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp egress-key
export ZOEYMCP_EGRESS_KEY=zeg1-...   # the line it printed
docker compose -f deploy/compose.hardened.yaml --profile egress-proxy up -d
```

- **Its container.** uid 10006 (the image's `egress` user, which owns no file), read-only, every
  capability dropped (it listens on 3128, so it needs no `NET_BIND_SERVICE`),
  `no-new-privileges`, no published port, and no ZoeyMCP setting but the key. Its command
  is the one above, `egress --vault http://vault:8080 --listen vault=egress-vault:3128`. The
  compose file reads `ZOEYMCP_EGRESS_KEY: ${ZOEYMCP_EGRESS_KEY:-}`, so compose commands with the
  profile off don't need the key; with the profile on and no key the role exits 2 naming
  `zoeymcp egress-key`, and compose keeps restarting it to no effect, since a restart keeps the
  environment the container was made with: set `ZOEYMCP_EGRESS_KEY` and run the `up -d` above
  again, which recreates it with the key. For a key in a file (a Docker
  secret, say), set `ZOEYMCP_EGRESS_KEY_FILE` in an override instead, and
  `docker compose kill -s HUP egress-proxy` after changing it.
- **Its networks.** `egress-ctl` is internal and holds the vault and the role: the role fetches
  the vault's lists there, and the vault reaches the role's one listener there, as
  `egress-vault`. `egress-out` is the role's way out and holds the role alone. The role never
  joins `egress`, the vault's own way out, since whatever joins it reaches the portal (§26); nor
  `internal`, `direct` or `agents`, so nothing there can reach its listener.
- **The vault through it.** The compose file's inline policy carries the two lines, commented;
  uncomment them and recreate the vault (`egress_proxy` and `egress_proxy_kind` are read at
  start, §7). `egress_proxy_kind: role` is what tells the vault the proxy is the role, so
  onboarding needs no proxy edit (§11); without it the vault takes `egress_proxy` for a proxy of
  your own. The SMTP profiles carry the same two lines, commented: with them the connector's
  CONNECT goes through the role's vault listener, which allows the connector's `host:port` since
  it is in the vault's list.

  ```yaml policy
  version: 1
  mode: declarative
  egress_proxy: http://egress-vault:3128
  egress_proxy_kind: role
  connectors:
    mail-out:
      kind: smtp
      host: smtp.mail.example
      port: 465
      tls: implicit
      username: agent@mail.example
      password: store:mail-pass
      from: "Agent <agent@mail.example>"
      to: [partner@mail.example]
  routes:
    - name: mail-send
      prefix: /mail
      connector: mail-out
      callers: [gateway]
      rules: [{methods: [GET], paths: [/config]}, {methods: [POST], paths: [/send]}]
  ```

  A destination on your own network (a mail server at a private address, say) needs its
  `egress_private` line, as without the role: the role reads the private mark from the vault's
  list, and refuses an unmarked name that resolves to a private address (`address_refused`).
- **What it protects, honestly.** The role is for programs that can't be trusted to keep their
  own limits: a hardened bridge (§33), confined to its own `host:port` list. For the
  vault it adds the allowlist and an address check at connect time behind a proxy, but the vault
  already guards its own connections (§7's upgrade note) and keeps its direct route on `egress`
  for the portal, so the role doesn't confine the vault: sending the vault through it stays
  optional. It confines nothing in the standard tier, and the hardened gateway and its toolkits
  need no role: they have no route out at all.
- **A restart** (a new image, `docker compose restart egress-proxy`, a crash) cuts the role's
  open tunnels: a vault request in flight fails 502, and a mail send cut after its final dot is
  `smtp_outcome_unknown`, journaled and never sent again (§22). The new role opens no tunnel until
  its first fetch from the vault: until then every CONNECT is 503 `list_stale`.
- **A new key.** After `egress_key_generation` is raised and the policy reloaded, run
  `zoeymcp egress-key` again, set the new `ZOEYMCP_EGRESS_KEY`, and run the `up -d` above again,
  which recreates the role with it.

## 32. The bridge

`zoeymcp bridge` serves one stdio MCP program as a Streamable HTTP endpoint, `/mcp`. To the rest
of ZoeyMCP it is one more upstream: a `kind: remote` server behind a vault route whose upstream
is the bridge and whose header credential holds the bridge's token. It relays JSON-RPC envelopes:
it rewrites ids and progress tokens so that clients can't collide, and otherwise passes the
program's bytes through; it parses no tool definition and imports no MCP SDK. This section is
its reference; §33 is the how-to, with the policy, the image and each placement.

```sh
zoeymcp bridge --listen unix:/run/zoeymcp-bridge-fetch/mcp.sock --peer-uid 10001 \
  --era legacy -- /opt/stdio-server/venv/bin/fetch-server
```

- **`--listen`** is a network alias `NAME:PORT` (it must resolve to exactly one address, never
  `0.0.0.0` or `::`), a loopback address such as `127.0.0.1:9000` (behind your own TLS front),
  or `unix:<path>`. With `unix:`, `--peer-uid` is required (and refused with any other form): the
  socket's directory must exist, be the bridge's own uid's, and give others no access and its
  group no write; a stale socket at the path is removed and anything else there refuses the
  start. Every connection on the socket whose peer isn't `--peer-uid` is cut before anything is
  read (`bridge_peer_refused`).
- **`--era legacy|modern`** is required: the MCP era it serves, which the server's `era` in the
  policy should assert. A legacy bridge runs a child per session (`--max-sessions`, 8; a session
  idle for `--idle-timeout`, 600 s, is stopped); a modern bridge runs one child, started again
  after it exits.
- **The child** is the command after `--`, fixed at start, in a session of its own, with
  `--work-dir` (`/tmp/zoeymcp-bridge` by default; created 0700, or accepted only as the bridge's
  own 0700 directory) holding its home, temporary and working directories. Its environment is
  built, not inherited: `PATH`, `HOME`, `TMPDIR`, `LANG`, `LC_ALL`, `TZ`, the proxy variables of
  `--egress-proxy http://host:port` (which confine only where the bridge has no other way out),
  then each `--env NAME` and `--secret-env NAME` (which must be set). No `ZOEYMCP_` variable
  reaches it. The bridge lowers its own `RLIMIT_NPROC` to `--max-procs` (64) and raises its
  `oom_score_adj` to 1000 before the first child, which inherits both. Stopping a child closes
  its stdin, then sends its process group `SIGTERM` after 2 s and `SIGKILL` 2 s later.
- **Lines** from the child are at most `--max-message-bytes` (8 MiB); a longer one, a line that
  isn't one JSON object, or a batch ends that child, and its calls in flight are answered 502. A
  request from the child is never relayed: `ping` is answered, everything else (sampling, roots,
  elicitation) refused with `-32601`. **stderr** is counted (lines and bytes per 10 s) and never
  shown, because programs print their configuration; `--stderr text` logs lines (2 KiB each, 50
  per 10 s) and may show `--env` values, and is refused beside `--secret-env`.
- **Readiness.** At start the bridge asks a child `initialize` (legacy) or `server/discover`
  (modern); until an answer within `--start-timeout` (60 s) it answers 503, and after it, it
  writes `<work-dir>/ready`, which `zoeymcp bridge --ready-check [--work-dir DIR]` tests (exit 0,
  or 1 before).
- **Answers** are SSE, one event per message as it arrives, with a `: keepalive` comment every
  `--keepalive` seconds (15) while a call is silent. In the modern era a client that leaves
  before the answer cancels the call; in the legacy era only its `notifications/cancelled` does,
  whether it comes before or after the client left.
- **Stopping.** `SIGTERM`, or with `--control-fd` a `TERM` line on that pipe (or its end), stops
  every child and the bridge; a `HUP` line is ignored.

**The token.** The bridge holds only the token's hash, `ZOEYMCP_BRIDGE_TOKEN_SHA256`, read before
its socket exists: unset or not `sha256:` and 64 lower-case hex digits, it refuses to start
(exit 2). Every request needs exactly one `Authorization: Bearer <token>` whose hash matches, and
no `Origin`. Make the token in the vault, once the policy names the route and its header
credential:

```sh
docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp secret set fetch-token --generate
docker compose -f deploy/compose.yaml exec zoeymcp zoeymcp secret set fetch-token --generate
```

`--generate` stores 32 random bytes under that name, bound as any header credential's secret
(to a `unix:` route's socket), and prints only the `sha256:` line to set as the bridge's
`ZOEYMCP_BRIDGE_TOKEN_SHA256`: the token never leaves the vault. Run it again for a new token.
It is refused for an OAuth secret or a connector's, with or without `--origin`
(`generate_refused`).

What it answers itself: 202 with no body (an accepted notification), 403 with no body (no token,
a wrong one, or an `Origin`), 404 (any path but `/mcp`, so no OAuth metadata, registration,
token or authorization path), 405, 411, 413, 415, 400 with a JSON-RPC error (`-32020` when a
modern request's headers disagree with its body, `-32600`, or a modern bridge's refusal of
`initialize` naming the versions it serves), 404 for an unknown or ended legacy session, 502
(the child exited, or didn't answer an `initialize` in time), and 503 (`not_ready`,
`bridge_busy` at 256 calls in flight, `sessions_full`).

Its log lines (`role: bridge`):

| Event | Fields |
| --- | --- |
| `bridge_started` | `era`, `listen`, `command` (its first word, never its arguments), `max_sessions`, `max_message_bytes`, `idle_timeout`, `start_timeout`, `keepalive`, `max_procs`, `stderr` |
| `bridge_ready`, `bridge_probe_failed` | the readiness probe passed; or `reason` (`spawn_failed`, `timeout`, `exited`, `error`), tried again 5 s later |
| `bridge_child_started`, `bridge_child_failed` | `pid`, `purpose` (`probe`, `session` or `shared`); or `purpose`, `error_type`: the command couldn't be run |
| `bridge_child_exited` | `pid`, `purpose`, `code` or `signal` |
| `bridge_child_violation` | `pid`, `reason` (`too_long`, `invalid_json`, `batch`, `not_object`): the line that ended the child |
| `bridge_session_started`, `bridge_session_ended` | `session` (8 hex digits of its id's SHA-256, never the id), `pid`; `reason` (`deleted`, `idle`, `child_exited`) |
| `bridge_stderr`, `bridge_stderr_suppressed` | `pid`, and `lines` and `bytes` (by default) or `text`; `count`: the lines left out of a window |
| `bridge_client_request_refused` | `pid`, `method` (cut to 64 characters): a request from the child, refused |
| `bridge_unmatched` | `pid`, `count`: answers to no request in flight, logged at the 1st, 2nd, 4th, 8th... |
| `bridge_refused` | `reason`, `status`: an answer the bridge made itself |
| `bridge_peer_refused` | `uid`: a connection to its socket from another uid, cut before anything was read |
| `bridge_stopped` | |
| `control_received`, `control_ignored`, `control_failed` | as the vault's and the gateway's, with `--control-fd` |

None holds the token or its hash, a session id, a request's or the child's content, an
environment value or the command's arguments.

### Under the standard launcher

In the standard tier, `zoeymcp standard --bridge NAME` (repeatable, at most 8; `NAME` is 1 to 16
lower-case letters or digits) starts bridge `NAME` as one more child of the launcher, after the
vault and the gateway. It is **unconfined**: it shares the container with the vault and the
gateway, can reach every listener there, the host's network and the internet, can ignore proxy
settings, and can use up the container's memory, processes and CPU. Health says so
(`program_unconfined`, §3).

- **Its uid** is 10100 plus its place in the `--bridge` list (10100 to 10107), group the same,
  with no other group: it can't signal or read the vault, the gateway or another bridge.
- **Its socket** is always `/run/zoeymcp-bridge-<name>/mcp.sock`, the route's
  `upstream: unix:/run/zoeymcp-bridge-<name>/mcp.sock`. The directory is a tmpfs of its own,
  owned by its uid, group 10001 (the vault's), mode 0750: only the vault can reach the socket,
  and only the bridge can create one there, whether it runs or not. Its work directory is
  `work/` beside the socket. Before starting any child the launcher checks each bridge's
  directory and refuses that bridge alone if it is missing or isn't exactly
  `<10100+i>:10001 0750` (a reordered `--bridge` list, a typo in the mount). The vault is told
  each bridge's name and uid (`--bridge NAME=UID`) and refuses a socket another uid listens on.
- **Its configuration** is the container's environment:
  `ZOEYMCP_BRIDGE_<NAME>_ARGS`, a JSON array of its `zoeymcp bridge` arguments, which must hold
  `--era` and `--` with a command, and may not hold `--listen`, `--peer-uid`, `--work-dir` or
  `--control-fd` (the launcher's) or `--egress-proxy` (nothing in the standard tier enforces
  egress), alone or as `--<option>=<value>`, before the `--`. Every process in the container can
  read these arguments, so **no secret goes in ARGS**. `ZOEYMCP_BRIDGE_<NAME>_TOKEN_SHA256` is
  handed to it as `ZOEYMCP_BRIDGE_TOKEN_SHA256`; and each `ZOEYMCP_BRIDGE_<NAME>_ENV_<VAR>` as
  `<VAR>`, for its `--env` and `--secret-env`: a process's environment is readable only by its
  own uid, so this is where a secret goes (with `program: {holds_secret: true}` on its route,
  or health warns `program_secret_unflagged`). It gets nothing else: no master key, no
  `ZOEYMCP_CONFIG`, no gateway key, no other bridge's variables.
- **A refused bridge** (its ARGS, an `ENV_` name that isn't a variable name or is a `ZOEYMCP_`
  one, its name, a ninth bridge, its directory) isn't started, and the vault and the gateway
  start as usual; its route answers 502. A bridge without its token hash is started and refuses
  to start itself (§32's token): on a cold start, run `secret set --generate`, set the hash and
  recreate the container.
- **A bridge that exits** isn't restarted, and the vault and the gateway keep serving: its route
  answers 502 at once, and no other process can listen in its place. Restarting the container
  brings it back. A bridge has nothing to reload, so `SIGHUP` reaches only the vault and the
  gateway.
- **Stopping**: the gateway first (up to 330 s), then the vault (up to 75 s), then each bridge
  (10 s), so a call in flight through a bridge finishes inside the vault's window; the launcher
  waits at most 415 s, inside compose's `stop_grace_period: 420s`.

The launcher's log lines (`role: launcher`) about bridges:

| Event | Fields |
| --- | --- |
| `child_started`, `child_exited` | `child` (`bridge:<name>`), `pid` and `uid`; `status` |
| `launcher_bridge_refused` | `name` (none for a malformed one), `reasons`: each names a variable, the directory, or for ARGS a position (`ZOEYMCP_BRIDGE_FETCH_ARGS[3]: --listen is the launcher's`), or why it couldn't be spawned (`it couldn't be started: Argument list too long`), never a value |
| `launcher_bridge_down` | `name`, `status`: after its `child_exited`, a bridge that exited on its own; it isn't restarted and the others keep running |

## 33. A stdio server behind a bridge

A stdio-only MCP server reaches the gateway through `zoeymcp bridge` (§32), which serves it as
one Streamable HTTP endpoint. **A bridge is an upstream**: in the policy it is a vault route whose
upstream is the bridge, with the bridge's token as the route's header credential, and a
`kind: remote` server on that route. The gateway lists, pins, reviews and approves its tools as
any remote server's. The policy is the same in every placement but the route's upstream, and
`profiles/stdio-bridge.yaml` (S11) is it; `examples/bridge/` holds the image recipe and both
tiers' compose overrides.

| | Hardened (A) | Standard (B) | Remote (C) |
| --- | --- | --- | --- |
| Where it runs | a container of its own (`compose.bridge.yaml`) | a child of the standard launcher, as a uid of its own (`compose.standard.yaml`) | another host, behind your TLS front |
| The route's upstream | `http://bridge-<name>-mcp:9000`, with `allow_insecure_upstream: true` | `unix:/run/zoeymcp-bridge-<name>/mcp.sock` | `https://<host>` (plus any prefix your front adds) |
| Who can reach it | the vault alone, on a network of their own | the vault alone, by file permissions and both ends' peer checks | whatever reaches that host |
| Where its program connects | only through the egress role, to its route's `program.egress` | **anywhere**: nothing confines it | wherever that host lets it |

Bridges work in both tiers; **only the hardened tier confines them**.

**The token, in every placement.** Every request to a bridge needs its token, which only the
vault holds: in the hardened tier a container put on the bridge's network by mistake reaches
nothing without it, in the standard tier it is the second barrier behind the socket's
permissions, and in front of a remote bridge it is the only one. Once the policy names the route
and its header credential, the vault makes the token:

```sh
# hardened tier
docker compose -f deploy/compose.hardened.yaml -f examples/bridge/compose.bridge.yaml \
  exec vault zoeymcp secret set bridge-fetch-token --generate
# standard tier
docker compose -f deploy/compose.yaml -f examples/bridge/compose.standard.yaml \
  exec zoeymcp zoeymcp secret set bridge-fetch-token --generate
```

It prints only the token's `sha256:` line, which the bridge gets as `ZOEYMCP_BRIDGE_TOKEN_SHA256`
(the examples read it from `ZOEYMCP_BRIDGE_FETCH_TOKEN_SHA256`); a hash is configuration, safe to
keep with your compose files. The token itself never leaves the vault, which adds it to every
request on the route as `Authorization: Bearer` and never shows it to the gateway. Run it again
for a new token, and give the bridge the new hash. With override files, set
`ZOEYMCP_COMPOSE_CMD` (§11) to the command you type, so the commands ZoeyMCP prints name them.

**The route.** `check` takes plain http on an MCP route only to a loopback or private address,
or a single-label name, with the route's header credential a secret no other credential uses
(a local MCP route); beyond that, https. A standard-tier bridge's `unix:` socket is the other
local MCP route, in the standard tier only. The vault reaches a local MCP route directly, never
through `egress_proxy`, and refuses a plain-http connection whose name resolves anywhere but a
loopback or private address. Assert the server's `era` (`legacy` or `modern`, the bridge's
`--era`); `auto` works too, at the cost of a probe.

```yaml policy
version: 1
mode: declarative
credentials:
  bridge-fetch: {kind: header, secret: "store:bridge-fetch-token"}   # Authorization: Bearer
routes:
  - name: bridge-fetch
    prefix: /bridge-fetch
    upstream: http://bridge-fetch-mcp:9000     # the bridge's alias, on its network alone
    allow_insecure_upstream: true              # plain http: a local target only
    credential: bridge-fetch
    callers: [gateway]
    stream: true
    rules: [{methods: [POST, GET, DELETE], paths: [/mcp]}]
    program:                                   # what the egress role lets the program reach
      egress: ["docs.example.org:443"]
gateway:
  servers:
    fetch: {kind: remote, route: bridge-fetch, path: /mcp, era: legacy}
```

### The image

`examples/bridge/Dockerfile` builds an image from the official one (by its digest, in production) plus one layer:
the server installed at build time, in a build stage, into its own prefix `/opt/stdio-server`,
from wheels only and locked by hash (`lock.sh`), so no package's build code runs as root. The
same image is the hardened tier's bridge container and the whole standard container.
`examples/bridge/verify.sh --bridge OFFICIAL IMAGE` proves it is the official image plus that
prefix and nothing else: the official layers in order plus one, the same `User`, `Entrypoint`,
`Cmd`, `Env` and `WorkingDir`, an added layer that touches only `/opt/stdio-server`, both
zoeymcp environments byte for byte the official ones, nothing setuid, setgid or world-writable,
the labels, and emSign ECC Root CA - G3 out of the Debian store (the official image drops it,
since a bridge's program may read that store). In the standard tier the vault runs from this
image, so it **must** pass. A Node server is built the same way (`npm ci --ignore-scripts` from a
lock with integrity hashes, in the build stage), with a pinned Node runtime copied into
`/opt/node`, which `verify.sh --bridge --node` allows. Keep any package registry out of the
program's egress list, and turn off its update checks and telemetry where it has a switch. See
`examples/bridge/README.md`.

### A: the hardened tier

**Confined.** The bridge runs in a container of its own, as uid 10005 (the image's
`bridge` user, which owns no file), read-only, with no capability, `no-new-privileges`, and
`init: true`, so PID 1 reaps the orphans a program leaves (an `npx`- or `uvx`-style grandchild).
`examples/bridge/compose.bridge.yaml` gives it two internal networks:

- `bridge-<name>`, which it shares with the vault alone. It listens on `bridge-<name>-mcp:9000`,
  an alias declared on that network only, so the name means nothing anywhere else; that is the
  route's upstream host.
- `egress-<name>`, which it shares with the egress role alone (§31), only when its program has an
  egress list. Its child's proxy variables (`--egress-proxy http://egress-<name>:3128`) point at
  the role's listener there, which allows only the route's `program.egress`. The network has no
  route out, so a program that ignores the variables reaches nothing: its requests then show no
  `egress_tunnel` line in the role's log, which is the symptom to look for.

It is on no other network: not `internal` (the gateway's), `agents`, `direct` or `egress` (the
portal's). The override also restates the role's whole `command` with both listeners, since an
override replaces a command whole, and gives the vault `depends_on: {bridge-<name>: {condition:
service_started}}`: never `service_healthy`, so the bridge's code never decides whether the vault
starts, and compose stops the gateway, then the vault, then the bridge, so a call in flight
through it finishes inside the vault's window. Each hardened bridge with egress takes two Docker
networks: Docker's default address pools hold about 30 networks per host, shared with every
other compose project, and the hardened tier itself uses up to seven, so widen them in the
daemon's configuration (`"default-address-pools": [{"base": "10.200.0.0/16", "size": 24}]` in
`/etc/docker/daemon.json` gives 256) before running many bridges.

From a cold start:

1. Build the image from `examples/bridge/` (its README) and verify it.
2. Commit the route (`upstream: http://bridge-fetch-mcp:9000`, `allow_insecure_upstream: true`,
   the `program` block if the program needs egress), its header credential and the remote
   server, **without** the override yet, and reload (§7).
3. Make the token (above) and set `ZOEYMCP_BRIDGE_FETCH_TOKEN_SHA256` to the line it prints.
4. For a program with egress: start the role (§31) with `--profile egress-proxy` and its key.
5. Add the override, then `up -d bridge-fetch`, then `up -d vault`:

   ```sh
   docker compose -f deploy/compose.hardened.yaml -f examples/bridge/compose.bridge.yaml \
     --profile egress-proxy up -d bridge-fetch
   docker compose -f deploy/compose.hardened.yaml -f examples/bridge/compose.bridge.yaml \
     --profile egress-proxy up -d vault
   ```

6. Review the server (`zoeymcp review fetch`, §11), commit its pins and reload.

A bridge started without its hash refuses to start, and compose keeps restarting it until the
hash is set; the vault starts regardless. The bridge answers 503 until its readiness probe has
passed (`zoeymcp bridge --ready-check` is its health check).

### B: the standard tier

> **Unconfined.** In the standard tier the program shares the container's network with the vault
> and the gateway: it can reach every TCP listener there, your network and the internet, and it
> can ignore proxy settings. Nothing in this tier limits where it connects. Use the hardened tier
> for a program you need to confine.
>
> It shares more than the network: the container's memory, processes and CPU, which it can use
> up (the bridge lowers its own process limit to `--max-procs` and makes itself the first to go
> when memory runs out, and the override sets the container's `pids_limit`, but nothing caps its
> memory or CPU here), and its arguments, which every process in the container can read. The
> program's code is installed in the vault's own container, so the image must pass
> `examples/bridge/verify.sh --bridge`.

`examples/bridge/compose.standard.yaml` runs the image as the standard container and adds
`--bridge fetch` to the launcher's command (repeat it for each bridge, at most 8). Bridge *i* in
`--bridge` order runs as uid 10100 + *i* with no other group, so it can't signal or read the
vault, the gateway or another bridge; health reports `program_unconfined` for its route (§3).
Its configuration (§32, "Under the standard launcher"):

- `ZOEYMCP_BRIDGE_<NAME>_ARGS`: a JSON array of its `zoeymcp bridge` arguments, with `--era` and
  the command after `--`. The launcher sets `--listen`, `--peer-uid`, `--work-dir` and
  `--control-fd` itself and refuses them here, and `--egress-proxy` (nothing here enforces it).
  **No secret goes in ARGS**: every process in the container can read a command line.
- `ZOEYMCP_BRIDGE_<NAME>_TOKEN_SHA256`: its token's hash.
- `ZOEYMCP_BRIDGE_<NAME>_ENV_<VAR>`: handed to it as `<VAR>`, for its `--env` and `--secret-env`.
  A process's environment is readable only by its own uid, so a placeholder or a secret goes
  here.
- Its socket directory: a tmpfs the override mounts at `/run/zoeymcp-bridge-<name>`, with exactly
  `size=64m,mode=0750,uid=<10100+i>,gid=10001`: owned by the bridge's uid, group the vault's,
  mode 0750. The bridge creates its socket `mcp.sock` there and its work directory `work/` (0700).
  Only the vault's group can search the directory, so only the vault can connect to the socket,
  and only the bridge's uid can write it, so no other process can create, replace or remove a
  socket there, whether the bridge runs, was refused, waits for its hash or has exited. Both ends
  check the other's uid as well (`SO_PEERCRED`): the bridge cuts any peer but the vault
  (`bridge_peer_refused`), and the vault refuses a socket another uid listens on
  (`address_refused`, verdict `peer_uid`), so even a directory its own program loosened lets no
  one else in or stand in. The launcher checks the directory before starting the bridge and
  refuses that bridge alone if it is missing or not exactly so (a reordered `--bridge` list
  changes its uid: fix the mount too).

The route's upstream is the socket, `unix:/run/zoeymcp-bridge-fetch/mcp.sock`, with no
`allow_insecure_upstream` and no `program.egress`. Not a loopback port: any process in the
container could listen on a free port first and take the route's token, so health reports a
bridge's route to a loopback address as `loopback_bridge_route` (an error).

```yaml policy
version: 1
mode: declarative
credentials:
  bridge-fetch: {kind: header, secret: "store:bridge-fetch-token"}
routes:
  - name: bridge-fetch
    prefix: /bridge-fetch
    upstream: unix:/run/zoeymcp-bridge-fetch/mcp.sock
    credential: bridge-fetch
    callers: [gateway]
    stream: true
    rules: [{methods: [POST, GET, DELETE], paths: [/mcp]}]
gateway:
  servers:
    fetch: {kind: remote, route: bridge-fetch, path: /mcp, era: legacy}
```

From a cold start: build and verify the image; commit the route, its credential and the
server, and recreate the container; make the token in it (above) and set
`ZOEYMCP_BRIDGE_FETCH_TOKEN_SHA256`; add the override and recreate the container:

```sh
docker compose -f deploy/compose.yaml -f examples/bridge/compose.standard.yaml up -d
```

Then review as in A. Until its hash is set the bridge refuses to start and stays down, and its
route answers 502.

**A bridge that exits on its own stays down**: the launcher logs `child_exited` and
`launcher_bridge_down` and doesn't restart it, since PID 1 holds no privilege to start a process
as another uid and third-party code must not be able to restart the trust root. The vault and
the gateway keep serving every other server. Its route answers 502 at once, with nothing sent,
and no other uid can create a socket in its directory to take its place. Restarting the
container brings it back: a fresh tmpfs, the launcher's checks, a new socket.

### C: a remote bridge

On another host, run `zoeymcp bridge --listen 127.0.0.1:9000 --era legacy -- <command>` behind
your own TLS front, which must pass `Authorization` through, add no `Origin` (the bridge refuses
every request that has one) and not buffer streamed answers (`flush_interval -1` in Caddy, as
the `lan` profile has it). The route's upstream is `https://<that host>` plus any prefix the
front adds (never `/mcp`, which is the server's `path`), with no `allow_insecure_upstream`; the
vault verifies the front's certificate against certifi like any upstream's, and a front at an
address the vault resolves non-globally needs its `host:port` in `egress_private` (§7). Plain
http to a bridge on your LAN at a private address passes `check` too, but the token then
crosses the LAN in clear: use https there as well. Make the token in the vault (above) and set
the hash in that bridge's environment. Its program's confinement, secrets and egress are that
host's: `program.egress` confines nothing there, and `check` says so.

### Secrets the program needs

Where the program takes a base URL for its API, give it a vault route with a placeholder
instead of the secret: its `--env` carries the placeholder and the base URL (in A,
`http://vault:8080/<prefix>` on the bridge's network; in B a `--vault-listen 127.0.0.1:<port>`
address; in C a vault listener that host can reach), and the vault injects the real credential
as for any placeholder caller. In B the placeholder goes in `ZOEYMCP_BRIDGE_<NAME>_ENV_<VAR>`,
never in ARGS. Otherwise the program holds the secret itself, R35's exception: pass it with
`--secret-env NAME` (in B from `ZOEYMCP_BRIDGE_<NAME>_ENV_NAME`) and mark the route
`program: {holds_secret: true}`. `check` then warns, naming where the program can send it:
through the role only to its egress list in A, and anywhere in B and C. A bridge with a
`--secret-env` logs its program's stderr as counts only. In B, health warns
`program_secret_unflagged` when a bridge's ARGS hold `--secret-env` and its route has no
`holds_secret`.

### What a bridge doesn't do

- It relays no request from the program to the gateway: it answers `ping` and refuses roots,
  sampling and elicitation (`-32601`), so pass the directories a program needs on its command
  line.
- In the legacy era each MCP session gets a child of its own, but under `shared_session: true`
  every client shares one; in the modern era every client always shares the one child.
- A legacy bridge's restart is noticed at the gateway's next request, which gets 404, opens a
  new session, lists and compares the pins: a changed tool is marked and hidden until
  `review --repin` (§12). A modern bridge's restart ends the listen stream the gateway keeps open
  through it, so it is noticed when the stream ends and again when the gateway opens it again,
  about 5 seconds later (listings of one connection are at least 5 s apart), and a changed tool
  is marked and hidden the same way.
- Its program's stderr is logged as line and byte counts by default, since programs commonly
  print their configuration. `--stderr text` logs the lines themselves and may show `--env`
  values: turn it on only to debug.
- The proxy variables confine only in the hardened tier, where the bridge's networks have no
  other way out; in B and C a program may ignore them.

### A third-party wrapper instead

Since a bridge is just an upstream, another stdio-to-HTTP wrapper may stand behind the route, in
A (its own container on the networks above) or C (another host), never in B: the standard
launcher starts only `zoeymcp bridge`, which listens in a directory of its own and checks its
peer, and a wrapper started there by other means would listen on a port any process could take
first. Check that it speaks one MCP era to the gateway; that it checks a bearer token, the
route's header credential, on every request (a wrapper that can't makes the route's token
authenticate nothing, and isn't a supported shape in any placement); that it runs only its
configured command, never one a request names; that it listens on its own network alias (A) or
on loopback behind your TLS front (C); and that it is installed at build time with hashes, as
the recipe above. What it may lack, which leaves the gateway's own defences (pins, schemas,
sanitizing, `max_upstream_message_bytes`, `call_timeout`) to carry the load alone: a cap on each
line, stderr counted rather than logged, the refusal of the program's own requests, ids and
progress tokens kept apart between clients, keepalives, readiness, and a built environment for
the program.

## 34. Managed policy

**In managed mode, every "edit the policy and reload" in this guide is an export, an edit and
`zoeymcp policy import`, or the portal's own change where there is one.** The policy's `mode` says
which of two ways the vault runs:

- `mode: declarative`: the policy is the file or `ZOEYMCP_CONFIG` you give it, read at start and
  on every `SIGHUP`, as in every section before this one;
- `mode: managed`: the vault keeps the policy itself, as numbered revisions (below). The file you
  give it seeds revision 1, once, and is ignored afterwards; changes are made in the portal or
  imported on the host.

The mode is chosen at start: a `SIGHUP` never changes it (a reload of a declarative vault whose
file now says `mode: managed` is refused, "the mode is chosen at start; restart to change it").

### Starting managed: the seed and its guard

On a fresh state volume (nothing in `/state` but `vault.lock`, or a `setup.json` from
`setup-code --state`), a vault started with `mode: managed` **seeds** revision 1 from the policy it
is given: it checks it, writes every client's literal `token` as its `token_sha256` (the literal
never reaches the store), writes the anchor, then revision 1, and runs it (`policy_seeded
revision=1 deployment=<8> tokens_hashed=<n> via=start`). This is the policy seed, not §5's OAuth
seed. A managed policy needs an `admin` block, since the portal is where it is changed:

```yaml policy
version: 1
mode: managed
admin:
  listen: 0.0.0.0:8081
  origins: [http://localhost:8081]
gateway:
  hosts: [localhost]
  clients:
    agent1:
      # From `zoeymcp client-token`: set it before the first start. No portal change can set a
      # client's token, so after the seed a new one is a host import.
      token_sha256: sha256:8ca973db011281c88e678afeb86d1955579aed24fd7deeae43155fe7aabb0f43
      servers: []
```

So set what you would otherwise edit later **before the first `up -d`**: each client's
`token_sha256`, your servers' URLs, `gateway.hosts` and the egress settings. After the seed each of
those is a host import.

**The guard.** A volume a vault already used (a `store.json`, `gateway-key.json`, `portal/`,
`ledger-reported/` or `connectors/`, or any name the vault doesn't know) with no revisions and no
anchor is never seeded by itself: a deleted `/state/policy` and anchor beside an intact store is
how someone would make the vault reseed from an older `ZOEYMCP_CONFIG`. The start is refused, with
the way on in your own commands (from `ZOEYMCP_COMPOSE_CMD`, §11; the standard tier adds
`--user 10001:10001`):

```text
refused to start: managed mode with no policy revisions, on a state volume that was used before
(gateway-key.json, store.json). If you are switching this deployment to managed mode, seed revision 1
from ZOEYMCP_CONFIG once:
  docker compose -f deploy/compose.hardened.yaml stop vault
  docker compose -f deploy/compose.hardened.yaml run --rm --no-deps vault policy seed --state /state
  docker compose -f deploy/compose.hardened.yaml up -d vault
If you didn't, /state/policy and /state/policy-anchor.json may have been deleted: restore /state from
one backup.
```

**At every managed start** the vault logs `policy_head revision=N digest=<8> deployment=<8>
write_kind=<kind>`, so logs kept off the host carry the revision. The head's policy is checked with
the vault's environment as a declarative policy is: a head that now fails (an `env:` variable this
container lacks) refuses the start, naming the path, and the store is left as it is.

### The policy you give after the seed

You may remove the policy from `ZOEYMCP_CONFIG` after the seed: a managed start runs the head. If
you leave it, every start and every `SIGHUP` compares it with the policy it seeded and with the
head. While it matches either, nothing is said; once it differs, doesn't load or fails `check`,
it is ignored, never applied: `policy_seed_ignored revision=N reason=changed|unreadable|fails_check`
(warning) and the health finding of the same name, "ZOEYMCP_CONFIG has changed since the policy
was seeded from it and is ignored: the policy is revision N". Remove it; or record it as it is,
without applying it, with `zoeymcp policy import --from-env --baseline-only`; or apply it with
`zoeymcp policy import --from-env` (its plan shows what it undoes).

### Back to declarative, and back again

A declarative start on a volume with revisions runs its file as before and **parks** the store: the
anchor records the head it parked (`policy_store_parked revision=N`, warning, once), and health
shows `policy_store_parked` (info) while it stays parked. A parked store is never read as policy.
If the file brings back what managed mode had removed (a client's token, a caller's placeholder, a
pin the store retired), the park says so at once: `policy_store_parked` is critical, with
`revived` and the `names`, and health raises `policy_declarative_revives` (warning) naming each,
while the file you run does. A store a declarative start can't verify is left as it is
(`policy_store_unverified`, warning, and in health): a return to managed will meet its refusal.

Coming back is the one-line change to `mode: managed`. The vault **resumes**: the file it is given
becomes the next revision (`origin: resume`), planned against the parked head and what may only
move forward, so nothing stale runs and the history is kept. What the declarative period brought
back that the store had retired (a client token, a pin, an `env:` name or where it may be sent) is
accepted, since the host ran it, and named once: `policy_resumed revision=N+1 parked_at=N
revived=<n>`, a warning with the `names` when `revived` is above 0. A key generation below the
highest the store ran, or below the gateway key generation the declarative period moved to,
still refuses the start, naming the field, with nothing written and the store still parked
(`resume_generation_lowered`). A managed start with no policy given, or one that doesn't load,
can't resume: `policy_resume_needs_source`.

### Reloading, and a change that couldn't be applied

In managed mode `SIGHUP` reads the store again, verifies it and checks the head with the vault's
environment, and installs the head if it isn't the one running. It never applies the policy you
gave it: it only compares it (above). It logs `reload_ok source=head revision=N installed=true|false`,
or `reload_refused` with the running policy kept (its `reason` is the store's refusal, or
`policy_store_parked` for a store parked under it). Stray names in `/state/policy` are logged at a
start only, not at each `SIGHUP`.

A change is saved first and then applied. If applying it fails (the gateway key state can't be
written), the revision stays saved and the previous one keeps running: `policy_not_installed`
(critical), the change's answer "saved as revision N, but the vault couldn't apply it", and health's
`policy_not_running` (error). Every later change is refused (`policy_not_running`) until a
`SIGHUP` or a restart applies it: fix the volume, then send `SIGHUP`. A change that needs a restart
(`egress_proxy`, `admin.listen`, a raised gateway limit) says so, and health keeps
`policy_restart_needed` until the restart; for a raised gateway limit, until the gateway's status
says it started after the change that raised it. The policy view names the revision that runs:
while a saved one isn't running, the one before it.

### When a start is refused

Every refusal names the file and the way on, as commands for your host. In short:

| Refused | What happened | Recovery |
| --- | --- | --- |
| `policy_seed_needs_host` | a used volume, no revisions and no anchor | switching to managed: `policy seed --state /state` once; otherwise restore `/state` |
| `policy_store_missing` | `/state/policy` is gone, the anchor names revisions | restore `/state` from one backup, or reseed from your latest export |
| `policy_anchor_missing` | the anchor beside `/state/policy` is gone | the same |
| `policy_head_behind`, `policy_anchor_behind` | the head or the anchor was restored from an older backup | restore the whole of `/state` from one backup |
| `tampered`, `policy_anchor_tampered`, `head_dangling`, `files_above_head`, `policy_deployment_mismatch` | a file changed, or put back, outside the vault | restore `/state`, or reseed from your latest export |
| `key_unknown`, `key_retired` | a file is sealed under another master key | after a rotation, set `ZOEYMCP_MASTER_KEY_PREVIOUS` to the old key and recreate the vault; otherwise restore or reseed |
| `fails_check` | the head fails `check` in this container | set what it names (an `env:` variable), then start again |
| `policy_resume_needs_source`, `resume_generation_lowered` | a parked store with no usable policy, or one that would lower a key generation | give the policy to resume from, with the generation at the floor or above |

The reseed is `policy import --state /state --reseed - < policy-export.yaml`, with the vault
stopped: keep an export (`zoeymcp policy export`) somewhere safe, since it holds your policy's
secrets as the store does. Its last resort, `--reseed --from-env`, takes your compose policy as it
is now, usually older than the head. The vault never falls back to the seed by itself.

### A restored volume: the gateway as witness

The anchor catches `/state/policy` restored or deleted on its own: the start is refused (above).
It can't catch the whole of `/state` put back from one backup, since the head and the anchor
then agree, nor `/state` wiped and seeded again from `ZOEYMCP_CONFIG`, which looks like a fresh
install. The gateway can: in managed mode every view answer states the vault's deployment and
the revision it runs (`x-zoeymcp-policy-revision`, outside the view), and the gateway keeps the
highest revision it has seen of each deployment in its own volume
(`/state-gateway/policy-seen.json`, at most 8 deployments). Its status report carries them, and
the vault compares them with its head. Nothing is refused on it: the gateway applies the view
either way, and the vault keeps running. Back up the vault's volume and the gateway's apart, so a
restore of one leaves the other to notice.

**The whole `/state` restored, the gateway's volume not.** The vault starts on revision 27, the
gateway has seen 31. Health (and a banner on every portal page) shows `policy_behind_witness`
(error): "the gateway has applied revision 31; this vault holds 27. Was the state volume
restored? Removed clients and moves back to approve since 27 are undone. Re-apply them (import
your latest export: it restores clients, classifications and declines, not pins), review again
each server Home lists as drifted, then acknowledge: docker compose -f
deploy/compose.hardened.yaml exec vault zoeymcp policy acknowledge-restore" (the command from
`ZOEYMCP_COMPOSE_CMD` and `ZOEYMCP_EXEC_SERVICE`). An import can't re-pin, so every tool re-pinned
after 27 is served as drift until you review it again; Home lists each.

**`/state` wiped whole, the gateway's volume kept.** The vault seeds revision 1 under a new
deployment; the gateway has seen revision 31 of the old one. Health shows
`policy_deployment_changed` (error): "the gateway has seen revision 31 of another deployment of
this vault, and this one starts at 1. Was /state deleted? Everything removed since
the seed is back. Restore /state from one backup, or import your latest export, then acknowledge:
...". It is raised while the other deployment's revision is 2 or more and at least this one's,
and this deployment was seen after it (or is still at revision 1).

**Acknowledging.** Once you have re-applied what the restore undid:

```text
$ docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp policy acknowledge-restore
Revision 27 jumps to 32: one above the gateway's claim of 31; the number comes from the gateway.
Type 32 to write it: 32
Planned on revision 27 (the head):
  Revision: 32, from 27, past 28-31, which are never written
Acknowledged the restore as revision 32.
Next:
  The gateway takes the new view within seconds
```

It writes a revision with the head's content (`policy.acknowledge`, `jumped_from` 27), numbered
one above the gateway's claim, so the counter passes it and the finding clears; the anchor moves
with it, and history shows 32 straight after 27. Since the number is only the gateway's claim,
you type it, or give it as `--to 32` (then `[y/N]`, or `--yes`; with `--yes`, `--to` is
required, and a `--to` other than the vault's number writes nothing). A claim above
9,999,999,999 is refused when the report arrives (`status_refused reason=witness_range`), and a
number past it, the vault's or one you give or type, is `revision_out_of_range`. With nothing to acknowledge the vault answers
`nothing_to_acknowledge`. The same command takes `--state /state` with the vault stopped, where
there is no claim to read: type the number health named, or give `--to`. It changes no policy:
it records that you saw the restore.

**What the witness can't see.** A restore of both volumes from one snapshot looks like nothing
happened. A compromised gateway can stay silent, or raise a false alarm; it can't make the vault
take a number you didn't type. The gateway's side logs:

| Event | Fields |
| --- | --- |
| `policy_revision_regressed` | `deployment` (8 characters), `seen` (the highest it recorded), `now` (the lower one stated): once per regression (critical) |
| `policy_deployment_seen` | `deployment` (8 characters): a deployment recorded for the first time; a warning beside others, info for the first |
| `policy_seen_not_written` | `error`: the record couldn't be written; it holds in memory, and the next change writes it whole (warning) |

### Seeding and reseeding with the vault stopped

Both commands run in a one-off container of the vault's service, with the vault stopped: they take
the lock a running vault holds, and while it runs they refuse with "The state directory is in use:
stop the vault first", naming the stop in your own commands. They need the vault's master key,
which the service has, and refuse to run as root, since the vault's uid couldn't read what they
wrote: in the standard tier add `--user 10001:10001` after `--no-deps`. Each checks the policy as
the vault would, with the service's environment, refuses a `gateway_key_generation` below the one
`gateway-key.json` holds before it writes anything, prints what it will write to stderr and asks
`[y/N]`, unless `--yes`. A policy piped on standard input leaves no answer to read: without `--yes`
the plan is printed and nothing is written, so run it once to read the plan, then again with
`--yes`:

```sh
docker compose -f deploy/compose.hardened.yaml stop vault
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps -T vault policy import --state /state --reseed - < policy-export.yaml
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps -T vault policy import --state /state --reseed --yes - < policy-export.yaml
docker compose -f deploy/compose.hardened.yaml up -d vault
```

**`policy seed --state /state [--config FILE|-]`** seeds revision 1 on a volume the vault won't seed
by itself (the guard above), from `ZOEYMCP_CONFIG` unless `--config` names another. It shows the
clients, routes and servers, the `env:` names the policy allows and how many literal client tokens
it writes as their hash, and records the host as the seed's author (`policy_seeded ...
via=offline`). With a store or its anchor present it refuses and names the reseed.

**`policy import --state /state --reseed FILE|-`** (or `--reseed --from-env`, your compose policy)
replaces the store:

- when the old head verifies, the reseed is planned against it and what it retired, as a host
  import: the plan names the revisions it undoes (`Undoes: revisions 13..24`), each key generation
  against its floor, and every change. Bringing back a client's token, a caller's placeholder or a
  pin the store retired, or a new `env:` name or a new place one is sent, is refused until you name
  it: `--allow-revive client:<name>` (or `caller:<route>/<index>`, `pin:<server>/<kind>/<name>`),
  `--allow-env <NAME>`. As for an import (below), with `--yes` a plan that widens needs
  `--accept-widening`, and a reseed that drops the origin a passkey was enrolled through or
  moves `admin.listen` asks you to type it, or needs `--lockout-ok`;
- `--new-ratchet` starts instead from the policy's own record of what may only move forward, and
  lists what it forgets. It is the only way when the old head doesn't verify, and the way out of
  `ratchet_full`. While the old head verifies, it never lowers a key generation below that head's
  floors; when it doesn't, only the gateway key generation is checked, against
  `gateway-key.json`.

The old head and every revision move to `/state/policy/quarantine/` (`head.reseeded.json`,
`<n>.reseeded.json`), never deleted, and the new revision is numbered one above any the volume
shows, so no number is used twice. The deployment ID is kept while the anchor verifies, and a new
one is made when it doesn't. `--reason TEXT` is kept with the revision. A reseed that fails before
its new head is written puts the old store back as it was; if even that fails, it says which files
are still in quarantine (`reseed_incomplete`).

### The head, history and diffs

Run these in the vault's container over its admin socket (`docker compose -f
deploy/compose.hardened.yaml exec vault zoeymcp policy ...`, or `exec zoeymcp` in the standard
tier); `--format json` prints the vault's answer instead:

- `zoeymcp policy` (or `policy head`): the mode and, in managed mode, the head: when, how and by
  whom it was written, its deployment and digest (8 characters each), the revision the
  gateway runs (`applied`, `pending`, or `unknown` before its first status report), and the
  highest revision of this deployment the gateway has seen (its witness, below);
- `zoeymcp policy history [--before N] [--limit N]`: the kept revisions, newest first, each with
  what made it (`policy.seed`, `policy.save`, `policy.import`, `policy.rollback`, ...), by whom
  (a passkey's fingerprint, the host and how, or the seed), its base, a rollback's target and the
  host's `--reason`. A revision in quarantine shows as a gap;
- `zoeymcp policy diff N [--against M]`: what revision N changed from its parent (or from M), one
  row per field with its direction (wider, narrower or neutral). It is rendered as the portal
  renders the policy: a client's token hash, a placeholder, an account name or a recipient shows
  only as `(set)`, `(changed)` or `(removed)`.

The portal's Policy page shows the same head, history and diffs (§26).

### Exporting the policy

`zoeymcp policy export [--revision N] [--mode managed|declarative] [--for compose]` writes the
head's policy, or a kept revision's, as YAML on stdout, and what it exported on stderr. It holds
placeholders and client token hashes, so keep it like a secret: it refuses a terminal unless
`--force-tty`, so redirect it to a file (`exec -T vault zoeymcp policy export > policy.yaml`).
Its first line names the revision and the deployment it came from; `policy import` reads it back
(below). The export is logged (`policy_exported revision=N via=socket|offline`), and the portal
has none.

`--mode declarative --for compose` is the way back to a declarative deployment: the document says
`mode: declarative`, is indented for an inline `ZOEYMCP_CONFIG` block with every `$` written as
`$$`, and stderr names each field the shipped compose files take from a variable that is now a
literal (`gateway_key_generation`, the admin port in `admin.origins`), then the next commands:
replace the policy under `ZOEYMCP_CONFIG` with it, `run --rm --no-deps vault check`, `up -d
vault`. The recreated vault runs it declaratively and parks the store (above).

### Importing a change

Everything the portal can't change (a client and its token, a caller, `admin`, the egress
settings, a key generation, a connector's account) is an export, an edit and an import:

```sh
docker compose -f deploy/compose.hardened.yaml exec -T vault zoeymcp policy export > policy.yaml
$EDITOR policy.yaml
docker compose -f deploy/compose.hardened.yaml exec -T vault zoeymcp policy import - < policy.yaml
docker compose -f deploy/compose.hardened.yaml exec -T vault zoeymcp policy import --yes - < policy.yaml
```

The import is planned on the revision the export's first line names, never on whatever the head
is now: if a portal save made a newer revision meanwhile, it is refused (`policy_moved`, 412), so
export again and redo your edit. A document from another deployment is refused, and one with no
export line needs `--base N` (`base_required`). The policy goes through the vault's own checks
with its environment, so an `env:` name the vault's container lacks is refused before any plan.
Each client token written as a literal is stored as its hash. An import can't re-pin a tool: the
head's pin is kept for every definition both have (a re-pin is a review), and a tool it includes
leaves the server's `declined` list.

The plan goes to stderr: the revision, then each change that widens the policy (a new client,
caller or origin, a move to `allow`), then the rest, what needs a restart, the secrets whose
binding stops matching, what the head kept and each grant you gave, and the store entries it
leaves unused. Answer `[y/N]`; piped on standard input there is no answer to read, so the plan is
printed and nothing is written until you run it again with `--yes`. With `--yes` a plan that
widens is refused (`import_widens`) unless `--accept-widening` is given too, so a script can't
widen by accident. The write then names the plan it showed: if anything changed since, it is
refused (`plan_changed`) and nothing is written; if its answer was lost and you run it again, it
says it was already written. The answer lists what to do next (a restart, a key to give the
gateway) and that the gateway takes the new view within seconds.

- **What the store retired** stays retired: bringing back a client's token, a caller's placeholder
  or a pin a later revision removed is refused, naming each, until you name it:
  `--allow-revive client:<name>` (or `caller:<route>/<index>`, `pin:<server>/<kind>/<name>`); a
  new `env:` name, or one sent somewhere new, needs `--allow-env <NAME>`, and the variable must be
  set in the vault's container first.
- **A removed credential's store entries** are named in the plan with their `zoeymcp secret
  delete` lines: once the import removes the credential, a refresh token can't be revoked at its
  provider any more, so delete them first, or add `--revoke-removed`, which deletes each after the
  import is written and revokes its grant with what the vault read before the import (a refused
  import deletes nothing); the answer says which it asked the provider to revoke (an entry with
  no grant, or whose credential names no `revocation_url`, is only deleted).
- **`--reason TEXT`** is kept with the revision and shown in history.
- **`--from-env`** imports the policy in the vault's own `ZOEYMCP_CONFIG` (the one it was seeded
  from, as the compose file renders it now): its plan shows every difference from the head,
  portal saves it would undo included, and once written its digest becomes the seed's, so
  `policy_seed_ignored` ends; when the head and the seed already match it, it is refused, as
  there is nothing to record. **`--from-env --baseline-only`** records that digest without
  applying anything (a revision of kind `policy.acknowledge` with the head's content), for a
  compose policy you changed only to match the deployment (a new admin port, a rotated key
  generation); it is refused when there is nothing to record.

### Rolling back

`zoeymcp policy rollback N` writes revision N's content as the next revision, with from the
head the key generations (a rotation is never undone) and the pin of every tool both have; it
takes N's `admin` block, so a rollback to the revision before a bad import is the way back from
a lockout. It is planned and confirmed as an import is, with the same flags (`--base`, `--yes`,
`--accept-widening`, `--allow-revive`, `--allow-env`, `--lockout-ok`, `--revoke-removed`,
`--reason`): a rollback past the removal of a client asks for its `--allow-revive`. A revision in
quarantine can't be rolled back to (`revision_unreadable`), nor one no longer kept
(`revision_unknown`). The portal's rollback (**Roll back to revision N** on the Policy page,
§26) keeps the head's `admin` and refuses anything wider, and a rollback past a client's or a
caller's removal (`rollback_revives`): both are this command's.

### A lockout, with and without a socket

An import or rollback that removes the last origin of a host where passkeys were enrolled, or
moves `admin.listen`, says so in its plan ("removes http://localhost:8081, where 2 passkeys were
enrolled: they stop working"), and after `[y/N]` asks you to type the origin (or the new address).
With `--yes` it needs `--lockout-ok` too (`lockout_unconfirmed`), and since a changed `admin`
widens the policy, `--accept-widening` as well (`import_widens`). If the portal is lost anyway,
roll back over the socket, or export, fix `admin` and import. Where there is no socket (Windows,
or `--admin-socket none`), the same commands take `--state /state` with the vault stopped, as the
seed and the reseed do (above: they refuse root and wait for the lock); `history`, `diff`,
`export`, `import` and `rollback` all have the form, and are written by the host offline:

```sh
docker compose -f deploy/compose.hardened.yaml stop vault
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps -T vault policy export --state /state > fixed.yaml
$EDITOR fixed.yaml
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps -T vault policy import --state /state --yes --accept-widening --lockout-ok - < fixed.yaml
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps vault setup-code --state /state
docker compose -f deploy/compose.hardened.yaml up -d vault
```

(`policy rollback N --state /state --yes --accept-widening --lockout-ok` replaces the export,
the edit and the import while the revision before the lockout is kept; in the standard tier each
`run` adds `--user 10001:10001`.) An offline import or rollback takes no `--revoke-removed`:
revoking needs the running vault. A store a declarative start parked is read but not written
offline.

### Upgrading to M6

A declarative deployment keeps working as before: nothing is written to `/state/policy`, and the
portal reads as it did. What is new for it is in §7's "Upgrading to M6" notes (the `ZOEYMCP_`
reference and YAML tag refusals, tools nobody reviewed, clearing marks). To switch a used volume to
managed mode: set `mode: managed` (with an `admin` block), run `check`, then

```sh
docker compose -f deploy/compose.hardened.yaml stop vault
docker compose -f deploy/compose.hardened.yaml run --rm --no-deps vault policy seed --state /state
docker compose -f deploy/compose.hardened.yaml up -d vault
```

(in the standard tier: `docker compose -f deploy/compose.yaml run --rm --no-deps --user
10001:10001 zoeymcp policy seed --state /state`). Recreate the vault before the gateway, and keep
the gateway on M6 too once a policy declines a tool or enables another kind.

### The revision store

In managed mode the vault keeps the policy itself, as numbered revisions in its state volume:

- `/state/policy/head.json`: which revision is the newest; writing it is what commits a change;
- `/state/policy/revisions/<10 digits>.json`: one file per revision, the newest 64 kept;
- `/state/policy/quarantine/`: files a start moved aside and never reads again (see below);
- `/state/policy-anchor.json`, beside the directory: the highest revision ever committed, so a
  `/state/policy` restored or deleted on its own is noticed.

A revision's policy and its record of what may only move forward (retired keys, tokens,
placeholders and pins) are encrypted under a key derived from the master key, and every file is
MAC'd. Revision numbers, times, kinds, digests and passkey fingerprints are in clear. A save writes
the revision, then the head, then the anchor, then removes revisions older than the newest 64; a
crash between any two leaves a store the next start sorts out. Every write is a temporary
`.policy-*` file renamed into place, and a start removes any it finds.

At each start the vault reads every kept revision, then:

- a revision one above the head that names the head as its parent is a save that never answered:
  it goes to `quarantine/<n>.uncommitted.json` and the head runs (`policy_save_uncommitted`); so
  is an acknowledged restore's revision that jumped from the head (above, "A restored volume");
- an older revision that doesn't verify (changed, under an unknown or retired master key, from
  another deployment, or not chaining to its neighbours) goes to `quarantine/<n>.unreadable.json`
  and the head still runs (`policy_revision_quarantined`): it is lost from the history only;
- a head one above the anchor (or an acknowledged restore's, jumped from the anchor's revision)
  is a crash between the two writes: the anchor is rewritten;
- revisions below the oldest kept are a removal cut short: they are removed (`policy_pruned`);
- a name the vault doesn't write in `/state/policy` is logged (`policy_stray_file`) and left alone.

Quarantined files stay until you delete them; a later file of the same name is kept beside
the first as `<n>.<why>.2.json`, then `.3`, and so on.

**Rotating the master key.** Start the vault with the new `ZOEYMCP_MASTER_KEY` and the old one in
`ZOEYMCP_MASTER_KEY_PREVIOUS`: it re-seals every kept revision under the new key, oldest first,
then the head, then the anchor, which records the old key as retired (`policy_rekeyed`). No
revision's digest changes. If the vault stops midway, start it again with both keys set and it
finishes. Once `policy_rekeyed` is logged, remove `ZOEYMCP_MASTER_KEY_PREVIOUS`: from then on a
file sealed under the old key is refused at start, or quarantined if it is an older revision,
even while the old key is still set. While a save that never answered can't be moved to
quarantine, the rotation waits for the next start. A previous key equal to the current one is
ignored, and the start logs `master_key_previous_same` (warning) with its `key_id`.

**When the store can't be written** (a full or read-only volume), a change is refused with
`policy_write_failed` and nothing changes. If only the anchor can't be written, the change is
saved and `policy_anchor_write_failed` is logged; the next change writes the anchor first, and is
refused while it still can't.

Its log lines:

| Event | Fields |
| --- | --- |
| `policy_save_uncommitted` | `revision`: a save that never answered, moved to quarantine (warning) |
| `policy_revision_quarantined` | `revision`, `reason` (`tampered`, `not_a_revision`, `unreadable`, `body`, `key_unknown`, `key_retired`, `deployment`, `misplaced` or `chain`), moved to quarantine (warning) |
| `policy_stray_file` | `name`, with hidden characters shown: a file the vault doesn't write, left alone; once per start |
| `policy_pruned` | `revisions` (how many were removed), `below` (the oldest kept) |
| `policy_rekeyed` | `revisions` (how many were re-sealed), `key_id` (the new master key's ID), `next`: remove `ZOEYMCP_MASTER_KEY_PREVIOUS` now |
| `policy_anchor_write_failed` | `revision`, `error_type`: the anchor wasn't written (warning) |
| `policy_housekeeping_failed` | `action` (`quarantine`, `prune`, `rekey` or `remove`), `error_type`, and `revision` for a quarantine or a prune: the next start tries again (warning) |
| `master_key_previous_same` | `key_id`: `ZOEYMCP_MASTER_KEY_PREVIOUS` is the current key again, and is ignored (warning) |
| `policy_seeded` | `revision` (1), `deployment` (8 characters), `tokens_hashed` (literal client tokens written as their hash), `via` (`start`, or `offline` for `policy seed --state`) |
| `policy_head` | `revision`, `digest` and `deployment` (8 characters each), `write_kind` (how the head was written): at every managed start |
| `policy_seed_ignored` | `revision`, `reason` (`changed`, `unreadable` or `fails_check`): the policy given is ignored (warning) |
| `policy_store_parked` | `revision`: a declarative start parked the store (warning); critical with `revived` and `names` when the file brings back what the store retired |
| `policy_store_unverified` | `reason`: a declarative start found a store that doesn't verify, and left it (warning) |
| `policy_resumed` | `revision`, `parked_at`, `revived` and, above 0, `names` (warning then): a managed start resumed a parked store |
| `policy_refused` | `reason`, and `file` or `revision`: a start refused over the store or its head (critical) |
| `policy_saved`, `policy_imported`, `policy_rolled_back`, `policy_acknowledged` | `revision`, `write_kind`, `origin`, `author` (a passkey's fingerprint, 8 characters, or `host`), `base`, `digest` (8), `effects` (what needs a restart or a step), `target` for a rollback, `jumped_from` for an acknowledged restore, and `from_env` and `baseline_only` for a host import |
| `policy_exported` | `revision`, `via` (`socket`, or `offline` for `--state`): the host exported the policy |
| `policy_imported` (a reseed) | `revision`, `write_kind` (`policy.reseed`), `origin` (`reseed`), `author` (`host`), `base` (the old head it was planned against, or none), `digest` and `deployment` (8 characters each), `effects` (none), `reseed` (true), `new_ratchet`, `from_env` |
| `tool_allowed`, `tool_repinned` | `server`, `def_kind`, `name`, `revision`; `tool_allowed` also `kept` for an `allow` tool kept through a re-pin: one line per tool, whatever the change |
| `policy_not_installed` | `revision`, `reason`: a saved revision couldn't be applied, and the previous one runs (critical) |
| `policy_behind_witness` | `head`, `witness` (the revision the gateway has seen): when a status report first shows the head behind it, or behind another number (critical) |
| `policy_deployment_changed` | `deployment` and `other` (8 characters each), `revision` (the other's, as the gateway saw it): when a status report first shows it (critical) |
| `reload_ok` | in managed mode `source` (`head`), `revision`, `installed` |

None holds a policy value or anything a file holds; `policy_stray_file` names the stray file only,
and `policy_store_parked` and `policy_resumed` name clients (`client:<name>`), callers
(`caller:<route>/<index>`), pins (`pin:<server>/<kind>/<name>`) and `env:` names only.
