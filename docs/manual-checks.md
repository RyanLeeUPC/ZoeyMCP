# Manual checks

What only a real browser shows, run by hand and recorded here. The portal's page holds no
decision: every rule is in the vault and tested in Python, and the page's own encoding is pinned
by the tests that drive the API with a software authenticator. What those tests can't show is how
each browser behaves: which algorithm an authenticator picks, which cookies it keeps and sends,
what it does with `sessionStorage`, Trusted Types and Fetch Metadata. This list covers that.

Run each item in Chrome or Edge, Firefox and Safari at or above the supported versions, over
`http://localhost` and one `https` origin with a certificate the browser trusts. Record every run
in the results table at the end: the commit, the date, the browser and its version, and pass or
fail. Record no account names, addresses or other personal details.

## When each item runs

Each item checks one feature of the portal's page. Run the items of a feature before a release,
and again after any change to that feature's page code or to what the vault sends it.

| Items | Feature |
| --- | --- |
| 1-7, 10, 11 | setup, enrolment, sign-in, sign-out and sessions |
| 12 | a second `localhost` port (the portal tests cover it too; run it with 1-7) |
| 8, 9 | OAuth connect by paste, and step-up |
| D-66 | OAuth against a real provider (its own section below) |
| 13, 14 | the OAuth callback |
| 15 | secrets |
| 16, 17 | the MCP servers page: the review screen and the fragments |
| 18 | the OAuth callback of a client the vault registered |
| Live S9 | onboarding by URL against a real server (its own section below) |

## The setup for every item

A vault on the host, with no admin socket, its portal on `localhost:8081` and, for the `https`
items, behind a TLS proxy for a name the browser's machine trusts (the example name below stands
for yours):

```sh
mkdir -m 700 state
export ZOEYMCP_MASTER_KEY="$(zoeymcp keygen)"
cat > portal.yaml <<'EOF'
version: 1
mode: declarative
admin:
  listen: 127.0.0.1:8081
  origins: [http://localhost:8081, https://zoeymcp.tailnet.example]
EOF
zoeymcp vault --config portal.yaml --listen 127.0.0.1:8080 --state ./state --admin-socket none
```

In a second shell with the same `ZOEYMCP_MASTER_KEY`, `zoeymcp setup-code --state ./state`
prints a code (add `--reset` where an item says so). The TLS proxy (Caddy, say) forwards
`https://zoeymcp.tailnet.example` to `127.0.0.1:8081` and passes the `Host` header unchanged.
Keep the browser's developer tools open on the Network and Console panels, and the vault's log in
view.

## The items

1. **ES256 is chosen.** With a platform authenticator (Windows Hello, Touch ID, a phone's
   passkey provider), and then with a security key that also does EdDSA: open
   `http://localhost:8081/`, choose **I have a setup code**, type a fresh code, name the passkey,
   **Create the passkey**. Pass: the enrolment answer (Network panel) and `passkey_enrolled` in
   the log show `"alg": "ES256"`, and the prompt opened from the click (no `NotAllowedError` from
   a missing user gesture). Remove the passkey afterwards with `zoeymcp passkeys --remove`.
2. **Safari with an EdDSA-only key.** In Safari, enrol a security key that only does EdDSA (or
   that is set to). Pass: the enrolment succeeds, `"alg": "EdDSA"`, and the posted
   `public_key` is `null` (Safari's `getPublicKey()` is null for EdDSA; the vault reads the key
   from the authenticator data).
3. **Sessions across reloads and tabs.** Sign in. Reload: still signed in. Open a new tab and
   type the portal's address: it asks to sign in. Close the signed-in tab and reopen it with
   "reopen closed tab" within 15 minutes: still signed in (closing a tab doesn't end a session).
   Sign out, reopen: it asks again; the same after 15 idle minutes without signing out. After
   **Sign out**, the Application panel's `sessionStorage` for the origin is empty and the session
   cookie is gone. Pass: each step as written.
4. **Fetch Metadata and `Origin`.** On any `POST` the page makes (sign in, sign out, end the
   other sessions), the request headers show `Sec-Fetch-Site: same-origin` and the real
   `Origin` (`http://localhost:8081`), not `null`, though the page sends no referrer. Pass: both,
   on every `POST`.
5. **The `http://localhost` cookie.** In Safari over `http://localhost:8081`: sign in. Pass: the
   cookie `zoeymcp-8081-session` (no `Secure`, `HttpOnly`, `SameSite=Strict`) is stored and sent
   on the next request, and the page stays signed in.
6. **The IP-literal redirect.** Open `http://127.0.0.1:8081/`. Pass: the browser lands on
   `http://localhost:8081/` (a 308), and the page loads.
7. **A passkey belongs to its host name.** With a passkey enrolled on `http://localhost:8081`,
   open `https://zoeymcp.tailnet.example/` and choose **Sign in with a passkey**. Pass: the
   browser doesn't offer the `localhost` passkey (it offers none, or only ones enrolled on that
   name).
8. **Step-up shows the summary first** (OAuth connect, step-up). With two passkeys enrolled, open
   **Passkeys**, choose **Rename** on one and give a new name. Pass: the dialog shows what the
   vault will do (the passkey, its name now, the new name) before any passkey prompt; choose
   **Confirm with your passkey** and cancel the browser's prompt: the dialog says the prompt was
   cancelled, **Close** it, and the passkey keeps its name (no `passkey_renamed` in the log).
   Then, with the policy below, open **Credentials**, choose **Connect** on `demo`, paste
   `http://127.0.0.1/callback?code=x&state=wrong` and choose **Check the address**. Pass: the
   dialog says the address belongs to another login, and no passkey prompt opens.
9. **The authorization link** (OAuth connect). Add the policy below to `portal.yaml`, restart the
   vault and sign in. Open **Credentials** and choose **Connect** on `demo`, then the dialog's
   link. Pass: it opens example.com in a new tab, and in that tab's console `window.opener` is
   `null`; the Network panel shows the request to example.com without a `Referer` header. Close
   the tab and choose **Cancel** in the dialog.

   ```yaml
   credentials:
     demo:
       kind: oauth2
       token_url: https://example.com/token
       authorize_url: https://example.com/authorize
       client_id: manual-check-client
       client_auth: none
       rotates: true
       scope: read
       refresh_token: store:demo-refresh
   routes:
     - name: demo
       prefix: /demo
       upstream: https://example.com
       credential: demo
       callers: [{placeholder: ph-manual-demo-0001}]
       rules: [{methods: [GET], paths: ["/**"]}]
   ```
10. **A neighbour on another `localhost` port.** Serve a page on another port: put this in
    `neighbour.html` and run `python -m http.server 9000` in its directory, then open
    `http://localhost:9000/neighbour.html` in the browser that is signed in to the portal:

    ```html
    <script>
    fetch("http://localhost:8081/api/session", {credentials: "include"})
      .then((r) => r.text()).then(console.log, console.error);
    fetch("http://localhost:8081/api/logout", {method: "POST", credentials: "include",
      mode: "no-cors", headers: {"Content-Type": "text/plain"}, body: "{}"});
    </script>
    ```

    Pass: the console shows a CORS error, not the session; the vault's log shows both refused
    (`cross_site`), and the portal tab is still signed in. Then copy the portal's cookie from the
    developer tools and replay it without the page's token, as a neighbour's server could:

    ```sh
    curl -si http://127.0.0.1:8081/api/session -H 'Host: localhost:8081' \
      -H 'Sec-Fetch-Site: same-origin' -H 'Cookie: zoeymcp-8081-session=<the value>'
    ```

    Pass: `401` with `"reason":"no_session"`, and the portal tab is still signed in.
11. **Trusted Types.** In Chrome or Edge (which enforce Trusted Types), with the Console open,
    run a full session: set up with a code, sign in with the new passkey, open Sessions, end the
    other sessions, sign out. Pass: no Trusted Types or Content Security Policy violation in the
    console.
12. **Two `http://localhost` ports.** Add `http://localhost:8082` to `admin.origins` and restart
    the vault, then forward that port to the portal's listener, keeping the browser's `Host`:
    `ssh -N -L 8082:127.0.0.1:8081 localhost`. Pass: a passkey enrolled through
    `http://localhost:8081` is offered and accepted on `http://localhost:8082`.
13. **The callback** (the OAuth callback). Stop the vault of the setup above. From the repository
    root, in the development environment, start the fake provider, which makes a throwaway CA,
    serves a fake OAuth server at `https://localhost:9443` whose registered redirect is
    `http://localhost:8081/oauth/callback/notes`, and writes a policy for it:

    ```sh
    python -m tests.fakes.run_oauth_server --dir ./callback-check
    ```

    Start a vault the way it prints (the policy `./callback-check/policy.json`, trusting
    `./callback-check/ca.pem` for the token exchange), set up a passkey with a setup code as
    above, and sign in at `http://localhost:8081/`. In the browser, trust `ca.pem` (a throwaway
    browser profile with the CA imported), or accept the certificate warning for
    `https://localhost:9443` once. On **Credentials**, choose **Connect** on `notes`: the dialog
    says the provider sends the tab back to the portal. Open the link and approve. Pass:
    - in the Network panel, the request to `/oauth/callback/notes` carries
      `Sec-Fetch-Site: cross-site`, `Sec-Fetch-Mode: navigate` and `Sec-Fetch-Dest: document`,
      the cookie `zoeymcp-8081-cb` (shown `SameSite=Lax`) and no `zoeymcp-8081-session` cookie;
    - the tab ends on `/callback/received`, and the back button doesn't return to the address
      that held the code; record what the browser's history list shows for that address;
    - within a few seconds the portal's tab asks for the passkey, its summary saying where and
      when the sign-in came back and "Confirm only if you have just finished approving in the
      provider's tab; if you haven't, cancel."; confirm, and **Credentials** shows `notes`
      connected.

    The fake as started above answers `/authorize` with an immediate redirect, so the navigation
    starts and ends on the portal and the browser sends `zoeymcp-8081-session` anyway. For the
    no-session-cookie line, stop it and start it again with `--consent`:

    ```sh
    python -m tests.fakes.run_oauth_server --dir ./callback-check --consent
    ```

    It then serves at `https://127.0.0.1:9443`, a different site from the portal's `localhost`
    (the certificate covers both; trust the new `ca.pem`, or accept the warning for that address
    once), rewrites the policy to match, and shows an Approve page first, whose button posts and is
    answered with the redirect, as a real provider's consent screen is. Restart the vault on the
    new policy, choose **Connect**, open the link and choose **Approve**.

    Then **Connect** again, approve, and before the tab is redirected copy the callback address
    from the Network panel (or block `localhost:8081` there first); open that address in a
    second browser profile. Pass: the refused page ("The portal didn't take this sign-in."), the
    address intact in that profile's address bar, and the first browser's dialog still waiting.

    For an `https` callback address: the fake registers only the `localhost` address, so this
    part needs a provider client of your own registered with an `https` callback address (a
    Web-application client, the optional live run of the callback). Put your own TLS proxy in
    front of the portal for a name listed in `admin.origins`, set the credential's
    `redirect_uri` to that origin's `/oauth/callback/<credential>`, reload, and repeat the first
    part from a session on that origin; the cookie is then `__Secure-zoeymcp-cb`, with `Secure`.
    Without such a client, record this part as not run.
14. **A stale callback address** (the OAuth callback). Take a callback address from item 13 whose
    login has ended (confirmed, cancelled or more than 10 minutes old) and type or paste it into the
    address bar. Pass: the request carries `Sec-Fetch-Site: none`; the refused page shows, with the
    address intact. Start a new **Connect** and paste that address into its dialog. Pass: refused as
    belonging to another login (`state_mismatch`) or as expired (`flow_unknown`), with no passkey
    prompt.
15. **The secret field isn't saved** (secrets). Sign in, open **Secrets**, enter a name and a
    value, choose **Set the secret**, confirm with the passkey. Pass: the value shows as dots while
    typed (in Chrome, Edge and Safari; other browsers may show it as typed); the browser doesn't
    offer to save it as a password (and no password manager fills or stores it); after the confirm
    the value field is empty; the page's elements (developer tools, Elements) hold no copy of it.
16. **The review screen with hostile text, under Trusted Types** (the MCP servers page). A vault
    with its portal and a gateway that polls it (either tier's compose file with an `admin` block,
    say), whose policy serves the fake MCP server as a remote server, connected. Start the fake
    from the repository root with a certificate the route trusts, once as
    `python -m tests.fakes.run_mcp_server CERT KEY --switch large` (96 tools) and once with
    `--switch inject_definitions --switch inject_server_info --switch invalid_name`, reloading
    the gateway between. In Chrome or Edge with the Console open, open **MCP servers** and choose
    **Review tools** (or **Review again**). Pass, for each:
    - no Trusted Types or Content Security Policy violation in the console;
    - every string from the server (names, titles, descriptions, the server's name and
      instructions, findings, definitions) shows as text, exactly as the vault sent it: markup
      shows as its characters, nothing is bold, linked or laid out that the page didn't make, and
      a hidden or right-to-left character shows as the visible mark the vault gives it;
    - with `large`, the counts read 96 tools, 64 the server marks read-only and 32 not
      annotated; the chips each keep those tools, the filter keeps the names holding its text,
      **Select suggested** includes the 64 as allow and no unannotated tool, **Clear** empties
      the selection, and **Generate** counts what is included;
    - **Show definition** shows the whole definition, a long line continuing on marked lines
      under it with nothing cut, and every character outside ASCII as an escape.
17. **Copy is the exact fragment** (the MCP servers page). Onboarding never fetches metadata from
    or registers with a provider on a private address, and refuses a single-label host such as
    `localhost` in metadata, so the fakes run under names that a name map gives the vault as
    public addresses, dialled on loopback (`tests/fakes/resolver.py`, as the acceptance tests do).
    From the repository root, in the development environment, start the fake provider under
    `localtest.me` (a public name for 127.0.0.1, so the browser reaches it too) with its endpoints
    under a path long enough that its authorize URL is 2,048 characters, the longest a policy
    takes (2,013 characters for this host and port):

    ```sh
    python -m tests.fakes.run_oauth_server --dir ./onboard-check --host localtest.me --metadata         --endpoint-path "/$(python -c 'print("p" * 2012)')"
    ```

    Issue a certificate for `mcp.notes.example` from its CA and write the name map
    (`localtest.me` to 9443, `mcp.notes.example` to 9444):

    ```sh
    python - <<'PY'
    from pathlib import Path
    from tests.acceptance.tls import ProviderCA, issue_cert
    from tests.fakes.resolver import FakeResolver
    d = Path("onboard-check")
    ca = ProviderCA(d / "ca.pem", d / "server.pem", d / "server.key", d / "ca.key")
    issue_cert(ca, "mcp.notes.example", d)
    names = FakeResolver()
    names.serve("localtest.me", 9443)
    names.serve("mcp.notes.example", 9444)
    names.save(d / "hooks.json")
    PY
    ```

    Then the fake MCP server, protected (a request without its key gets the 401 and the
    challenge) and naming the provider in its protected-resource metadata:

    ```sh
    python -m tests.fakes.run_mcp_server onboard-check/mcp.notes.example.pem         onboard-check/mcp.notes.example.key --port 9444 --prm path         --authorization-server https://localtest.me:9443 --static-key any-key
    ```

    Start a vault with the setup's `portal.yaml` through `tests/acceptance/procs.py`'s launcher,
    which trusts the CA and installs the name map (`python -c "$LAUNCHER" onboard-check/ca.pem
    onboard-check/hooks.json "" "" vault --config portal.yaml ...`, `LAUNCHER` printed by
    `python -c 'from tests.acceptance.procs import LAUNCHER; print(LAUNCHER)'`), and set up a
    passkey. Add `https://mcp.notes.example:9444/mcp` by URL, "This server is on my network"
    unticked, with no client ID. Make fragment 1, then choose **Copy** and paste into a text
    editor. Pass: the pasted text is the shown text, line for line and character for character,
    the 2,048-character URL whole on its line; the same after choosing the compose indent, and for
    fragment 2.
18. **The callback of a client the vault registered** (item 13 against a client from dynamic
    registration). Continue from item 17, whose fake offers registration (`--registration open`,
    the default): the plan's redirect address is this origin's `/oauth/callback/<credential>`.
    Register (a passkey), commit fragment 1 (`zoeymcp check --config portal.yaml --with
    fragment-1.yaml --print-merged`), reload (on Windows, restart the vault the same way), accept
    the certificate warning for `https://localtest.me:9443` once, then choose **Connect** on the
    server's row. Pass: as item 13's first part (the provider sends the tab back to the portal,
    which asks for the passkey), and once connected the page queues the server's review by itself
    (without a gateway polling the vault, the vault answers that request `review_unavailable`).
19. **The drift review, under Trusted Types** (the review screen's drift rows, M6). Item 16's
    setup, the fake started as `python -m tests.fakes.run_mcp_server CERT KEY --switch large
    --switch markup_echo`, so `echo`'s description ends in markup a pin can hold (`<img src=x
    onerror=alert(1)> & "quoted"`). Review the server and include `echo` as allow and `add`,
    `slow` and `read_01` as approve; commit fragment 2 and reload. Restart the fake with
    `--switch large --switch markup_echo --switch inject_definitions --drift description`:
    `echo`'s description changes with the markup still at its end, so it drifts, and `summarize`
    comes with item 16's hostile text. In Chrome or Edge with the Console and Network panels
    open, choose **Review again** on the server's row, under what the gateway reports. Pass:
    - no Trusted Types or Content Security Policy violation in the console, no alert, and no
      request for `x`;
    - `echo` reads `drift`, with **Reviewed** and **Now** side by side, each the whole definition
      in marked chunks with nothing cut and the markup shown as text in both, and the vault's
      diff under them, its `-` and `+` description lines each showing the markup as text;
      `summarize`'s text shows as item 16 says; a finding reads "warning at /pointer: ...", or
      "(definition)" for the whole definition;
    - restarted with `--drift annotations` in place of `--drift description`, **Review again**:
      `echo` now says it is destructive and not read-only (the markup as text in both columns
      again), and **Accept the new definition** on it says approve is proposed and sets its row to
      approve (unticking it puts allow back); **Generate** with allow chosen again gives the new pin under `review:`, `# changed: echo (was sha256:...)` and
      `# kept: echo (allow: ...)`, and with approve left as accepted, `echo` under `approve:`;
    - after a restart of the gateway (it keeps reviewed copies in memory) and **Review again**,
      `echo`'s row says the gateway no longer has the reviewed copy and shows the new definition
      whole;
    - **Clear** then **Select suggested**: `read_01` comes back ticked at approve, its
      classification, the other read-only tools at allow, and **Generate** puts no tool the
      policy has in `approve:` under `allow:`;
    - with **Record the rest as declined** ticked, **Generate** writes every listed tool left out
      under `declined:` at its pin (not `summarize`, which has an error finding); unticked,
      **Decline** on one tool writes that one alone; and after another fragment for the server is
      committed and reloaded, **Generate** on the old review is refused `review_stale`.
20. **Managed saves: the re-pin and approve -> allow summaries** (the review screen's **Save**,
    M6). Item 19's setup with the vault's policy set to `mode: managed` on a fresh state
    directory, so its first start seeds revision 1 from the file (operations.md §34), the fake
    started with `--switch large --switch markup_echo`. Review the server and include `echo` as
    allow and `add`, `slow`, `read_01` and `read_02` as approve, then **Save**: the dialog's first row reads
    "Revision 2, from 1 (by the seed, ...: 1 is the head)", and a passkey writes it. Then, in
    Chrome or Edge with the Console open (no Trusted Types or Content Security Policy violation
    throughout). Pass:
    - the page's texts say the policy is managed and each save asks for a passkey, and no text
      says to commit, reload or generate; **Generate** is gone and **Save** is there;
    - restarted with `--switch large --switch markup_echo --drift description`, **Review again**
      and **Accept the new definition** on `echo`, **Save**: the dialog's row shows both pins
      and "re-pinned: you read both definitions", and "No restart needed"; confirmed, the vault's
      log line `step_up_confirmed` names the kind `tool.repin`, the answer says the gateway takes
      the new view within seconds, and the server's row is `reviewed` again;
    - **Review again**, change `add` and `slow` from approve to allow, **Save**: the dialog lists
      the two moves first, each with "approve -> allow. Calls to ... will run with no prompt" and
      every chunk of its definition below it (the first naming the pin), the markup in `echo`'s
      shown as text if it is moved too; **Close** (a cancel) writes nothing: the Policy page
      still shows revision 3's tools; **Save** again and confirm: both are allow;
    - on the MCP servers page, **Allow read_01 without asking**: the dialog shows read_01's move
      and its definition as pinned; confirmed, it is allow (`step_up_confirmed` names
      `tool.allow`);
    - restart the vault (it holds reviews in memory only), sign in, and on the MCP servers page
      **Allow read_02 without asking**: the page reviews the server first, then opens the same
      dialog for read_02; **Close** writes nothing;
    - **Review again**, untick `read_02` (approve, read-only), **Save** and confirm; then
      **Review again**, **Clear** and **Select suggested**: `read_02`, dropped and once approve,
      comes back ticked at approve, every tool the policy includes at its classification and
      the other read-only tools at allow, and **Save** shows no "approve -> allow" or "was
      approve in an earlier revision" row;
    - a second browser signed in on the same origin saves first: this browser's confirm shows
      "The policy moved to revision N ... press Save again", and nothing is written.
21. **History, a diff and a rollback** (the Policy page in managed mode, M6). Item 20's vault
    after its saves, the fake started with `--switch large --switch markup_echo`, and a client
    added and then removed by two host imports, so the history has a client to bring back: stop
    the vault, `zoeymcp policy export --state ./state > policy.yaml`, add under `gateway.clients`
    a client `ci-runner` with a `token_sha256` (`zoeymcp client-token` prints one), `zoeymcp
    policy import --state ./state - --yes --accept-widening --reason 'add ci-runner <b>x</b>' <
    policy.yaml`, then remove it, import again, and start the vault (operations.md §34, "A
    lockout, with and without a socket", gives the offline forms). In Chrome or Edge with the
    Console open (no Trusted Types or Content Security Policy violation throughout), open
    **Policy**. Pass:
    - the page names the head's revision and which revision the gateway runs, and "Export the
      policy" with its command, `docker compose exec` and `-T`; no text says to commit, reload or
      generate; every revision but the head has **Roll back to revision N**;
    - **History** lists every revision newest first, each with when, by whom (a passkey's
      fingerprint, "the host (offline)", or the seed) and what made it, the import's reason with
      its markup shown as text; **Show the changes** on the revision that moved `add` and
      `slow` to allow lists those rows, each "wider", and on the seed lists the whole policy from
      an empty one, the client's token hash only as `(set)`;
    - **Roll back to revision N** on the revision before the moves to allow: the dialog's first
      row reads "Revision M, from M-1: the content of revision N (by ..., ...: M-1 is the head)",
      the moves undone are listed and no row ends "(wider)"; **Close** writes nothing (the
      history is unchanged); again, and confirmed: `add` and `slow` are approve, the
      history's newest revision is the rollback with its target, and the vault's log has
      `step_up_confirmed` with `policy.rollback` and `policy_rolled_back` with `target`;
    - **Roll back to revision N** on the revision that added `ci-runner`: refused before any
      passkey prompt, "Rolling back to revision N brings back client ci-runner, removed in
      revision M: only the host can, with zoeymcp policy rollback and --allow-revive.", and
      nothing is written;
    - **Roll back to revision N** on the revision with `add` and `slow` at allow, now wider than
      the head: refused before any passkey prompt, "The portal can't widen ... through a
      rollback", with the host's export and import, and nothing is written.

## D-66: the live OAuth test against a real provider

Run once for each release, with a provider client of your own; CI never runs it.
Record it in the results table as item `D-66`: the commit, the date, the provider and client
type (for example "Google, Desktop app client"), pass or fail per part, and what the provider
showed when something failed. Record no account name, email address, client ID or secret, and
keep no token: everything below runs in a temporary directory.

1. **The authorization request.** Register a Desktop app OAuth client with Google (the client
   type `profiles/google-oauth.yaml` names); the vault sends the default redirect URI
   `http://127.0.0.1/callback`, with no port, which a Desktop client is expected to accept
   without registering it. Then:

   ```sh
   ZOEYMCP_LIVE_GOOGLE_CLIENT_ID=<the client ID> \
     pytest tests/acceptance/test_oauth_live.py -v -k portless
   ```

   Pass: `test_google_accepts_the_portless_loopback_redirect` passes (the sign-in page loads,
   with no `redirect_uri_mismatch`). With a Spotify app whose redirect URI is
   `http://127.0.0.1/callback`, `ZOEYMCP_LIVE_SPOTIFY_CLIENT_ID` runs the Spotify test too.
2. **A connect by paste.** Run a vault with `profiles/google-oauth.yaml` (its `client_id`
   replaced by yours, the route's placeholder by any value) and the `admin` block of the setup
   above, sign in to the portal, and set `google-client-secret` on the **Secrets** page. On
   **Credentials**, choose **Connect** on `google-calendar`, open the link, approve, copy the
   address the tab lands on (it doesn't load) and paste it. Pass: the dialog shows the summary,
   the passkey confirms it, and the result says granted
   `https://www.googleapis.com/auth/calendar.readonly`; **Credentials** shows the credential
   `ok`; `zoeymcp oauth status google-calendar` agrees; the vault's log has
   `oauth_login_completed` and no code, token or pasted address.
3. **A refresh.** With the client secret and a refresh token of a throwaway grant:

   ```sh
   ZOEYMCP_LIVE_GOOGLE_CLIENT_ID=<the client ID> \
   ZOEYMCP_LIVE_GOOGLE_CLIENT_SECRET=<the client secret> \
   ZOEYMCP_LIVE_GOOGLE_REFRESH_TOKEN=<the refresh token> \
     pytest tests/acceptance/test_oauth_live.py -v -k refresh
   ```

   Pass: `test_google_refresh_and_calendar_list` passes. Revoke the grant in the Google account
   afterwards.

If the provider refuses the portless redirect, record what it showed and stop: a profile override
with a fixed `redirect_uri` is the fallback, decided then.

## Live S9: onboarding a real server by its URL

Run by hand against one public remote MCP server that protects itself with OAuth, publishes its
protected-resource metadata and offers dynamic client registration; CI never runs it, and
`tests/acceptance/test_onboard_shape.py` walks the same steps against the fakes. Record it in the
results table as item `Live S9`: the commit, the date, the kind of server (for example "a public
notes server with DCR", never its name or address), the browser, and pass or fail per part. Record
no account name, client ID, token or secret, and keep none: everything runs in a temporary state
directory, and the registered client is removed in the provider's own console afterwards. If no
such server is available, record it as not run.

1. **Discovery and registration from the CLI.** A vault with an admin socket and a policy with
   an `admin` block (the setup above, without `--admin-socket none`, on Linux or in the hardened
   compose file), and its gateway:
   `zoeymcp login --mcp <the server's URL> --name live > onboard-live-1.yaml`. Pass: the plan
   shows the resource from the protected-resource metadata, the issuer and its metadata URL,
   PKCE S256, the scopes and where they came from, a `Registration endpoint` row with the
   server's endpoint and a `Client` row reading `registered at <host> once you confirm (dynamic
   client registration)`; after the question, one registration, and fragment 1 on stdout whose
   `check --with` against the policy has no error. The vault's log has `onboard_started`,
   `discovery_fetch` lines for the probe, the protected-resource metadata and the authorization
   server's metadata, `onboard_planned` and `onboard_registered`, and no client ID, secret or
   registration access token.
2. **Connect, `tools/list` and the review from the CLI.** Commit fragment 1, reload, run the same
   command again. Pass: the comparison finds nothing changed, the sign-in link opens the
   provider's consent page, the pasted address completes the sign-in, and the review's counts are
   printed; `review live --via vault --choose --suggest` writes a choices file whose names are the
   server's tools.
3. **The same in the portal.** On a fresh state directory and the policy as it was before item 1
   (without fragment 1, or the URL is compared, not onboarded): **MCP servers**, **Add a server
   by URL**, the plan, **Register and make the YAML** with the passkey, **Copy**, the commit and
   reload, **Connect** (through the portal's callback, the passkey at completion), the review the
   page queues, **Generate** with one tool included, the commit and reload. Pass: each step as
   §26 of operations.md describes it, and the row ends `reviewed`. Then an agent lists the
   included tool through the gateway and calls it.

## Results

| Item | Commit | Date | Browser and version | Origin | Pass or fail | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | bfbbcf7 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass (phone passkey; the security-key half not run) | The phone's passkey provider showed a generic error at registration, yet the browser returned the credential and the vault verified it (ES256, synced); later logins with it work |
| 4 | bfbbcf7 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass | Every POST: `Sec-Fetch-Site: same-origin`, `Origin: http://localhost:8081` |
| 6 | bfbbcf7 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass | |
| 3 | bfbbcf7 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass, with findings | Reload, hard reload and reopening a closed tab keep the session; a new tab and a restarted browser ask to sign in; after sign-out `sessionStorage` is empty and the origin's cookie is gone (another port's cookie stays). Found: signing in from a second tab signs the first out and left its session alive until the idle limit (the owner chose one tab per browser, with the replaced session ended at once); a sign-out sent two requests that both ended the session (the page now ignores a click while its request is in flight, and ending a session is made idempotent). The idle limit was left to the portal tests |
| 11 | bfbbcf7 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass | No Trusted Types or Content Security Policy violation through setup, sign-in, Sessions, ending the other sessions and sign-out; the console showed only the double sign-out's 401 (item 3) |
| 10 | bfbbcf7 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass | The neighbour page's two requests were refused `cross_site` (403) and CORS blocked the read; the portal tab stayed signed in; the cookie replayed without the token got 401 `no_session` with every security header. On Windows the vault's console also printed asyncio `ConnectionResetError` tracebacks when Chrome reset the refused connections (a Windows event-loop quirk, outside the JSON log) |
| 12 | bfbbcf7 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8082 | Pass | A byte-for-byte forwarder from port 8082 to the portal; the passkey enrolled on `localhost:8081` was offered and signed in; the two ports keep separate cookies |
| D-66 (1) | 9575a87 | 2026-10-20 | Google, Desktop app client | `http://127.0.0.1/callback` (no port) | Pass | `test_google_accepts_the_portless_loopback_redirect` passed: the sign-in page loads with no `redirect_uri_mismatch`. Spotify not run |
| D-66 (2) | 9575a87 | 2026-10-20 | Google, Desktop app client; Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass | A connect by paste with `profiles/google-oauth.yaml`: the summary showed before the passkey prompt, the exchange answered 200, the grant is `calendar.readonly`, Credentials shows `ok`. The vault's log has `oauth_login_completed` and no code, token or pasted address |
| D-66 (3) | 9575a87 | 2026-10-20 | Google, Desktop app client | `profiles/google-oauth.yaml`'s route | Pass (in place of the refresh test) | After a restart (access tokens are in memory only), the first call through the `google-calendar` route refreshed with the stored refresh token (`grant: refresh_token`, `trigger: first_use`, 200) and the Calendar API answered 200 through the vault. The refresh-token test itself wasn't run: the vault never hands a refresh token out. No token in the vault's log |
| 8 | 9575a87 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Partial | The OAuth connect's summary showed before any passkey prompt. Not yet run: the rename cancelled at the prompt (needs two passkeys), and the mismatched paste |
| 9 | 9575a87 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass | The authorization link opened Google's page in a new tab with `window.opener` null |
| 15 | 9575a87 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Fail | Chrome offered to save the secret's value as a password after the step-up confirm, despite `autocomplete="off"` and no `name`. The owner chose a text area, masked where the browser supports it; to be run again |
| 15 | becd428 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass | Re-run with the masked text area: the value showed as dots, Chrome didn't offer to save it, and the field was empty after the confirm |
| 13 | 5d45d02 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass, with findings | Against `tests.fakes.run_oauth_server`. A clicked link arrives `Sec-Fetch-Site: cross-site`, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`; the provider's link pasted into the address bar arrives `none` (accepted by the callback's rules). The request carries `zoeymcp-8081-cb` (HttpOnly, `SameSite=Lax`), which isn't listed under Application after the confirm because the confirm expires it. It also carries `zoeymcp-8081-session`: the fake answers `/authorize` with an immediate redirect, so the navigation starts and ends on the portal and Chrome treats it as same-site for `SameSite`, with the fake at `https://localhost:9443` and again at `https://127.0.0.1:9443`. The callback reads only the binding cookie; the no-session-cookie line needs a provider with a consent page (the fake's `--consent`). The tab ends on `/callback/received`, the history list has no entry for the address that held the code, and Back doesn't return to it. The passkey summary showed where and when the sign-in came back and the "Confirm only if" line; `notes` then showed `ok`. The callback address opened in a Guest window: the refused page, the address intact, the first browser's dialog still waiting (`callback_not_taken`) |
| 13 (consent) | 023dc6a | 2026-10-23 | Chrome 155, Windows | http://localhost:8081 | Pass | Against the fake with `--consent` at `https://127.0.0.1:9443`, Approve chosen on its page: the callback request carried `zoeymcp-8081-cb` and no `zoeymcp-8081-session`, with `Sec-Fetch-Site: cross-site`, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`. The first confirm failed `exchange_failed:oauth_unavailable`: the vault's address guard refused the fake's loopback token endpoint, which the policy the fake wrote didn't list in `egress_private` (the fake now writes it). Run again on that policy: the passkey confirm completed the sign-in and `notes` showed connected; the vault's log has `oauth_login_completed` and no code or token |
| 13 (https) | 5d45d02 | 2026-10-20 | - | - | Not run | Needs a Web-application client registered with an `https` callback address |
| 14 | 5d45d02 | 2026-10-20 | Chrome 155.0.8059.85, Windows | http://localhost:8081 | Pass | Item 13's Guest-window address after its login was cancelled: typed into the address bar, `Sec-Fetch-Site: none` and the refused page; pasted into a new Connect, "That address belongs to another login" (`state_mismatch`, refused before any passkey prompt) |
| 16 | 1057bd9 | 2026-10-23 | Chrome 155, Windows | http://localhost:8081 | Pass | The standard tier (deploy/compose.yaml, the image built at a0fd851) with the fake MCP server as `fake`. With `large`: 96 tools, 64 read-only, 32 not annotated, 4 with findings and 1 with an error (the fake's URL descriptions and its invalid schema); the filter, **Select suggested** (the 64, no unannotated tool), **Clear** and **Generate** behaved; definitions whole. With `inject_definitions`, `inject_server_info` and `invalid_name`: the server's name (cut at the cap with `…[+26]`) and instructions, and `summarize`'s title and description, show every hidden character as a visible mark (`[U+200B]`, `[U+202E]` before an unreversed "desrever", `[U+001B]`, `[U+009B]`, the tag characters) and `<IMPORTANT>` as text; `summarize` and `read file!` can't be included (error findings; "name is not a valid tool name"); **Show definition** escapes every character outside ASCII, tag characters as surrogate pairs, nothing cut. No Trusted Types or Content Security Policy violation; the console's only error was the page's first `GET /api/session` 401 after the vault restarted. Seen: a finding gives its position but not which string it is in |
| 17 | 63c9fb8 | 2026-10-23 | Chrome 155, Windows | http://localhost:8081 | Pass | The setup the item now gives: the fakes under `localtest.me` and `mcp.notes.example` through a name map, the provider's endpoints under a 2,013-character path. The plan showed dynamic registration at `localtest.me`; the registration answered 201; fragment 1 pasted from **Copy** matched the screen, its `authorize_url` 2,048 characters on one line (measured in the pasted text), and `check --with` passed it; the same for the compose indent and fragment 2. The log holds no client secret or registration token. Getting here found three faults, all fixed: the vault connected only to a name's first address (63c9fb8); the item's `--issuer-path` never lengthened an endpoint, and its fakes on `localhost` could never pass onboarding's host rules |
| 18 | 63c9fb8 | 2026-10-23 | Chrome 155, Windows | http://localhost:8081 | Pass | Item 17's registered client, fragment 1 merged with `check --print-merged`, the vault restarted on it (Windows has no `SIGHUP`): **Connect** sent the tab to the fake and back to the portal's callback, the passkey confirmed, the exchange answered 200 and `notes` showed connected; the page then asked for the server's review by itself, which the vault answered `review_unavailable` (no gateway polled it in this setup). No code or token in the vault's log |
| 1 | d754563 | 2026-10-23 | Firefox, Windows | http://localhost:8081 | Pass (phone passkey; the security-key half not run) | `passkey_enrolled` with `"alg":"ES256"`, synced; the prompt opened from the click |
| 3 | d754563 | 2026-10-23 | Firefox, Windows | http://localhost:8081 | Pass (the 15-minute idle step not run) | Reload kept the session; a new tab asked to sign in; reopening the closed tab kept it; after **Sign out** the origin's cookies, local and session storage were empty |
| 4 | d754563 | 2026-10-23 | Firefox, Windows | http://localhost:8081 | Pass | Every POST (`/api/logout`, `/api/login/begin`, `/api/login/finish`): `Sec-Fetch-Site: same-origin`, `Origin: http://localhost:8081` |
| 6 | d754563 | 2026-10-23 | Firefox, Windows | http://localhost:8081 | Pass | `http://127.0.0.1:8081/` landed on `http://localhost:8081/` |
| 8 | d754563 | 2026-10-23 | Firefox, Windows | http://localhost:8081 | Partial | The mismatched paste: refused `state_mismatch` (400) with no passkey prompt. The rename cancelled at the prompt not run (needs a second authenticator) |
| 9 | d754563 | 2026-10-23 | Firefox, Windows | http://localhost:8081 | Pass | The link opened example.com in a new tab; there `[window.opener, document.referrer]` was `[null, ""]` (Firefox's developer tools don't follow a new tab, so the referrer is read from the page) |
| 10 | d754563 | 2026-10-23 | Firefox, Windows | http://localhost:8081 | Pass | The console showed the CORS error (`Access-Control-Allow-Origin` missing, 403); each load of the neighbour page logged `portal_refused` `cross_site` with `count: 2` (the read and the sign-out), and the portal tab stayed signed in. The cookie replay with curl wasn't repeated (it doesn't depend on the browser) |
| Live S9 | cfdeb04 | 2026-10-22 | - | - | Not run | No public server with dynamic registration was used yet; the fakes' run is S9 (`tests/acceptance/test_onboard_shape.py`) |
