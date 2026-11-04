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
| 19 | the review screen's drift rows: the two definitions, their diff, **Clear** and **Select suggested** |
| 20 | the review screen's **Save** in managed mode: the re-pin and approve -> allow summaries |
| 21 | the Policy page in managed mode: history, a diff and a rollback |
| 22 | the Policy page in managed mode: a connector's pause and limits |
| 23 | the MCP servers page in managed mode: onboarding, **Give to clients**, Home's attention list and the restore banner |
| 24 | the review screen's prompts and resources |
| 25-30 | the Approvals queue: a hostile text, approve, cancel, a stale decision, deny and expiry, the idle limit |
| 31, 32 | the MCP servers page and the review screen in managed mode: **Hold in the vault** and **Turn off vault approval** |
| 33 | Home's approvals item, its findings and the nav's count |
| 34 | the Ledger page's two chains |
| Live Telegram | the Telegram approver against Telegram itself (its own section below) |

Items 19-24 are also M6's exit check: each runs once in Chrome or Edge before M6 is done. Items
25-34 and the live Telegram check are M8's. Each M8 item names the page, what to do and what
passes, and ends with a "Scriptable as" line, the steps a browser harness takes; the browser
tests run every line of items 25-34 a browser can check (each item names its tests), so at M8's
exit only the lines each item leaves by hand, and the live Telegram check, are run by hand,
once, in Chrome or Edge. Items 1-24 name their tests too (M8 step 27c), each keeping only what a
browser test can't show.

## Items a browser test runs

The browser tests (`tests/browser/`) run an item's lines on every push, in Chromium on Linux and
in Edge on Windows (CI's two "portal in a browser" jobs): the real vault and portal on loopback,
the browser's own passkey stack over a virtual authenticator, the page's Content Security Policy
and Trusted Types in force, and every page watched for a violation, a console error, a dialog or
a request that leaves loopback. The rule: an item a browser test covers names its test, its row
in the results table names that test and the CI run that passed it, and the item keeps only the
lines left by hand: what a virtual authenticator or an automated browser can't show (a platform
authenticator's own prompt, a security key, reopening a closed tab, a password manager's offer),
and the item's runs in Firefox and Safari, whose own passkey stacks the tests don't drive.

On a development host, run one test at a time against the installed Chrome, which downloads
nothing: `uv sync --locked --all-extras --group browser`, then
`ZOEYMCP_BROWSER=chrome uv run pytest tests/browser/<file>::<test>` (`test_session.py`,
`test_stepup.py`, `test_callback.py`, `test_review.py`, `test_drift.py`, `test_managed.py`,
`test_approvals.py`). Without `ZOEYMCP_BROWSER` the directory is skipped.

Where an item needs an `https` site, the tests serve it on loopback under a test name with a
certificate from a throwaway CA the browser trusts by its key, so nothing reaches the network: the
fake OAuth provider at `auth.notes.example` (items 13, 14, 18, 23) and a TLS front to the portal at
`zoeymcp.tailnet.example` (item 7). The fakes run in the test's own process: the fake MCP server's
definitions reach the vault as the gateway's review reports them (its switches as the items name
them, its reviewed copies kept or removed as a gateway's `defs/` would be), and the gateway's
status report is the one the vault keeps.

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
   In Chromium and Edge:
   `test_session.py::test_item_1_the_enrolment_answer_and_the_log_say_es256`, over the virtual
   authenticator; by hand there: the platform authenticator and the security key (the virtual
   one makes P-256 keys only, so which algorithm a real one picks shows only by hand).
2. **Safari with an EdDSA-only key.** In Safari, enrol a security key that only does EdDSA (or
   that is set to). Pass: the enrolment succeeds, `"alg": "EdDSA"`, and the posted
   `public_key` is `null` (Safari's `getPublicKey()` is null for EdDSA; the vault reads the key
   from the authenticator data).
3. **Sessions across reloads and tabs.** Sign in. Reload: still signed in. Open a new tab and
   type the portal's address: it asks to sign in. Close the signed-in tab and reopen it with
   "reopen closed tab" within 15 minutes: still signed in (closing a tab doesn't end a session).
   Sign out, reopen: it asks again; the same after 15 idle minutes without signing out. After
   **Sign out**, the Application panel's `sessionStorage` for the origin is empty and the session
   cookie is gone. Pass: each step as written. In Chromium and Edge every step but the reopened
   tab is `tests/browser/test_session.py`'s `test_item_3_*` (with a restarted browser asking to
   sign in, and one signed-in tab per browser); by hand there: the reopened tab only.
4. **Fetch Metadata and `Origin`.** On any `POST` the page makes (sign in, sign out, end the
   other sessions), the request headers show `Sec-Fetch-Site: same-origin` and the real
   `Origin` (`http://localhost:8081`), not `null`, though the page sends no referrer. Pass: both,
   on every `POST`. In Chromium and Edge:
   `test_session.py::test_item_4_every_post_is_same_origin_and_carries_the_real_origin`, from
   the headers as the browser sent them; by hand there: nothing.
5. **The `http://localhost` cookie.** In Safari over `http://localhost:8081`: sign in. Pass: the
   cookie `zoeymcp-8081-session` (no `Secure`, `HttpOnly`, `SameSite=Strict`) is stored and sent
   on the next request, and the page stays signed in.
6. **The IP-literal redirect.** Open `http://127.0.0.1:8081/`. Pass: the browser lands on
   `http://localhost:8081/` (a 308), and the page loads. In Chromium and Edge:
   `test_session.py::test_item_6_a_loopback_literal_redirects_to_localhost`; by hand there:
   nothing.
7. **A passkey belongs to its host name.** With a passkey enrolled on `http://localhost:8081`,
   open `https://zoeymcp.tailnet.example/` and choose **Sign in with a passkey**. Pass: the
   browser doesn't offer the `localhost` passkey (it offers none, or only ones enrolled on that
   name). In Chromium and Edge:
   `test_session.py::test_item_7_a_passkey_enrolled_on_localhost_isnt_offered_on_another_name`,
   through an in-process TLS front (and a passkey enrolled on that name then signing in there);
   by hand there: real LAN `https` with a certificate the machine trusts.
8. **Step-up shows the summary first** (OAuth connect, step-up). With two passkeys enrolled, open
   **Passkeys**, choose **Rename** on one and give a new name. Pass: the dialog shows what the
   vault will do (the passkey, its name now, the new name) before any passkey prompt; choose
   **Confirm with your passkey** and cancel the browser's prompt: the dialog says the prompt was
   cancelled, **Close** it, and the passkey keeps its name (no `passkey_renamed` in the log).
   Then, with the policy below, open **Credentials**, choose **Connect** on `demo`, paste
   `http://127.0.0.1/callback?code=x&state=wrong` and choose **Check the address**. Pass: the
   dialog says the address belongs to another login, and no passkey prompt opens. In Chromium and
   Edge:
   `test_stepup.py::test_item_8_a_rename_shows_its_summary_first_and_a_cancelled_prompt_changes_nothing`
   (the second passkey on a second authenticator, the cancel a failed user verification) and
   `test_item_8_a_mismatched_paste_is_refused_with_no_prompt`; by hand there: pressing **Cancel**
   in the browser's own passkey dialog, which an automated browser doesn't show.
9. **The authorization link** (OAuth connect). Add the policy below to `portal.yaml`, restart the
   vault and sign in. Open **Credentials** and choose **Connect** on `demo`, then the dialog's
   link. Pass: it opens example.com in a new tab, and in that tab's console `window.opener` is
   `null`; the Network panel shows the request to example.com without a `Referer` header. Close
   the tab and choose **Cancel** in the dialog. In Chromium and Edge:
   `test_stepup.py::test_item_9_the_link_opens_a_tab_with_no_opener_and_no_referrer` (example.com
   answered in the browser, never reached); by hand there: nothing.

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

    Pass: `401` with `"reason":"no_session"`, and the portal tab is still signed in. In Chromium:
    `test_session.py::test_item_10_a_neighbour_port_gets_nothing_and_signs_nobody_out`, the
    replay included. It doesn't run in Edge on Windows: there the vault's stop hangs once the
    browser resets the refused sign-out's connection (the Windows event loop's connection-reset
    fault of register D-142), so by hand there: the item in Edge, if a Windows result is wanted.
11. **Trusted Types.** In Chrome or Edge (which enforce Trusted Types), with the Console open,
    run a full session: set up with a code, sign in with the new passkey, open Sessions, end the
    other sessions, sign out. Pass: no Trusted Types or Content Security Policy violation in the
    console. In Chromium and Edge:
    `test_session.py::test_item_11_a_full_session_makes_no_violation` (the other sessions are a
    second browser signed in with the same passkey); by hand: nothing.
12. **Two `http://localhost` ports.** Add `http://localhost:8082` to `admin.origins` and restart
    the vault, then forward that port to the portal's listener, keeping the browser's `Host`:
    `ssh -N -L 8082:127.0.0.1:8081 localhost`. Pass: a passkey enrolled through
    `http://localhost:8081` is offered and accepted on `http://localhost:8082`. In Chromium and
    Edge: `test_session.py::test_item_12_a_passkey_enrolled_on_one_port_signs_in_on_another`,
    through a byte-for-byte forwarder; by hand there: nothing.
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

    In Chromium and Edge:
    `test_callback.py::test_item_13_the_provider_sends_the_tab_back_and_a_passkey_connects`,
    `test_item_13_after_a_consent_page_the_callback_carries_no_session_cookie` and
    `test_item_13_the_address_opened_in_another_browser_is_refused_while_the_dialog_waits`, the
    fake provider served over `https` on its own site; by hand there: what the history list shows
    for the address (no browser API reads it), and the `https` callback address.
14. **A stale callback address** (the OAuth callback). Take a callback address from item 13 whose
    login has ended (confirmed, cancelled or more than 10 minutes old) and type or paste it into the
    address bar. Pass: the request carries `Sec-Fetch-Site: none`; the refused page shows, with the
    address intact. Start a new **Connect** and paste that address into its dialog. Pass: refused as
    belonging to another login (`state_mismatch`) or as expired (`flow_unknown`), with no passkey
    prompt. In Chromium and Edge:
    `test_callback.py::test_item_14_a_stale_callback_address_is_refused_typed_or_pasted` (a
    confirmed login's address); by hand there: nothing.
15. **The secret field isn't saved** (secrets). Sign in, open **Secrets**, enter a name and a
    value, choose **Set the secret**, confirm with the passkey. Pass: the value shows as dots while
    typed (in Chrome, Edge and Safari; other browsers may show it as typed); the browser doesn't
    offer to save it as a password (and no password manager fills or stores it); after the confirm
    the value field is empty; the page's elements (developer tools, Elements) hold no copy of it.
    In Chromium and Edge:
    `test_stepup.py::test_item_15_a_secret_is_masked_and_the_page_keeps_no_copy`
    (the field's computed masking, emptied once sent, and no copy in the page, its fields or its
    storage); by hand there: whether the browser offers to save it as a password (an automated
    browser shows no password manager), and Safari's masking.
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

    In Chromium and Edge:
    `test_review.py::test_item_16_a_large_server_counts_filters_and_selects_as_the_vault_says` and
    `test_item_16_hostile_server_text_shows_as_text_under_trusted_types` (each string's text
    compared with the vault's answer, and no element on the review screen the page didn't make);
    by hand there: nothing.
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
    fragment 2. In Chromium and Edge:
    `test_review.py::test_item_17_copy_puts_exactly_the_shown_fragment_on_the_clipboard` (the
    browser's clipboard read back after **Copy**; on Windows it holds the text with CRLF line ends)
    and, for fragment 2, item 18's test; by hand there: pasting into a text editor.
18. **The callback of a client the vault registered** (item 13 against a client from dynamic
    registration). Continue from item 17, whose fake offers registration (`--registration open`,
    the default): the plan's redirect address is this origin's `/oauth/callback/<credential>`.
    Register (a passkey), commit fragment 1 (`zoeymcp check --config portal.yaml --with
    fragment-1.yaml --print-merged`), reload (on Windows, restart the vault the same way), accept
    the certificate warning for `https://localtest.me:9443` once, then choose **Connect** on the
    server's row. Pass: as item 13's first part (the provider sends the tab back to the portal,
    which asks for the passkey), and once connected the page queues the server's review by itself
    (without a gateway polling the vault, the vault answers that request `review_unavailable`).
    In Chromium and Edge:
    `test_callback.py::test_item_18_a_registered_clients_callback_connects_and_the_review_queues_itself`
    (a gateway's poll waiting, so the review runs, and fragment 2 copied); by hand there: nothing.
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
      approve (unticking it puts allow back); **Generate** with **Accept** still ticked and the
      row's choice set back to allow gives the new pin under `review:`, `# changed: echo (was
      sha256:...)` and `# kept: echo (allow: ...)`, and with approve left as accepted, `echo`
      under `approve:`;
    - after a restart of the gateway and **Review again**, `echo` still shows both columns: the
      gateway keeps reviewed copies in its state directory (`defs/`), not in memory. With the old
      copy removed (as the gateway's uid: `rm /state-gateway/defs/<old pin's hex>.json`) and
      **Review again**, `echo`'s row says the gateway no longer has the reviewed copy and shows
      the new definition whole;
    - **Clear** then **Select suggested**: `read_01` comes back ticked at approve, its
      classification, the other read-only tools at allow, and **Generate** puts no tool the
      policy has in `approve:` under `allow:`;
    - with **Record the rest as declined** ticked, **Generate** writes every listed tool left out
      under `declined:` at its pin (not `summarize`, which has an error finding); unticked,
      **Decline** on one tool adds that one alone to the declines the policy already has (only a
      tool the policy doesn't include has **Decline**, so take two such tools out of `declined:`
      first, decline one, and the other stays out); and after another fragment for the server is
      committed and reloaded, **Generate** on the old review is refused `review_stale` (this needs
      a reload with the vault running: in the compose tiers a reload is a recreate, which drops
      the review held in memory).

    In Chromium and Edge:
    `test_drift.py::test_item_19_a_drifted_tool_shows_both_definitions_and_the_diff_as_text`,
    `test_item_19_accepting_a_definition_no_longer_read_only_proposes_approve`,
    `test_item_19_without_the_reviewed_copy_the_new_definition_shows_whole` (the gateway's report
    with its reviewed copies, as a restarted gateway keeps them, and without the old one) and
    `test_item_19_suggested_after_clear_declines_and_a_stale_review` (`review_stale` after a
    reload with the vault running); by hand there: nothing.
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
      comes back ticked at approve, every read-only tool the policy includes at its
      classification and the other read-only tools at allow (a tool the server doesn't mark
      read-only, such as `add`, stays unticked, so the save drops it), and **Save** shows no
      "approve -> allow" or "was approve in an earlier revision" row;
    - a second browser signed in on the same origin saves first: this browser's confirm shows
      "Something changed since you prepared this (shown below)" and, under "What the vault finds
      now", "The policy moved to revision N ... press Save again" with the plan on revision N,
      and nothing is written.

    In Chromium and Edge:
    `test_managed.py::test_item_20_a_managed_review_is_saved_with_a_passkey_and_a_repin_says_so`,
    `test_item_20_moves_to_allow_come_first_and_close_writes_nothing`,
    `test_item_20_allow_without_asking_and_select_suggested_after_a_drop`,
    `test_item_20_allow_without_asking_on_a_vault_holding_no_review_reviews_first` (a vault just
    started holds no review, as a restarted one does) and
    `test_item_20_a_second_browser_saving_first_changes_this_ones_confirm`; by hand there:
    nothing.
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

    In Chromium and Edge:
    `test_managed.py::test_item_21_the_policy_page_names_the_head_and_lists_the_history`,
    `test_item_21_a_rollback_is_planned_closed_then_confirmed` and
    `test_item_21_a_rollback_that_revives_or_widens_is_refused_before_the_passkey` (the host's
    imports written as the admin socket writes them); by hand there: nothing.
22. **A connector's pause and limits** (the Policy page in managed mode, M6). Item 21's vault,
    stopped, given an SMTP connector by a host import: `zoeymcp policy export --state ./state >
    policy.yaml`, add under `connectors` a connector `mail` in the shape of
    `profiles/smtp-implicit-tls.yaml` (any host, sender and recipient; its password
    `store:mail-pass`, which needn't be set), `zoeymcp policy import --state ./state - --yes
    --accept-widening < policy.yaml`, then start the vault. In Chrome or Edge with the Console open
    (no Trusted Types or Content Security Policy violation throughout), open **Policy**. Pass:
    - **Connectors** lists `mail: sending.` with its three limits in fields (20 sends a day, 150
      subject characters, 2200 body characters), and nothing of its host, sender or recipients;
      no text says to commit, reload or generate;
    - **Pause**: the dialog's rows read "Revision N, from N-1 (by you, ...: N-1 is the head)",
      `connectors.mail.paused` "changed" and "No restart needed"; confirmed, the row reads paused,
      the history's newest revision is "a connector's limits", and the vault's log has
      `step_up_confirmed` with `connector.limits` and `policy_saved` with `write_kind:
      connector.limits`;
    - **Resume**: the dialog's row reads "sends can go out again"; **Close** writes nothing (the
      row still reads paused); **Resume** again and confirm: sending;
    - "Sends a day" set to 50, **Save limits**: the dialog's row reads "20 -> 50: raised";
      confirmed, the field shows 50; with 0 in a field, **Save limits** is refused before any
      passkey prompt, and with the same values again, "Nothing would change.";
    - a second browser signed in on the same origin pauses it first: this browser's **Resume**
      draws the page again, saying the policy moved to revision N since it showed revision M
      ("press the connector's button again"), and nothing more is written.

    In Chromium and Edge:
    `test_managed.py::test_item_22_pause_resume_and_limits_each_write_a_revision` and
    `test_item_22_a_second_browser_pausing_first_draws_the_page_again`; by hand there: nothing.
23. **Onboarding in managed mode, and Give to clients** (the MCP servers page in managed mode,
    M6). A managed vault on a fresh state directory with a gateway that polls it, the vault
    started through `tests/acceptance/procs.py`'s launcher with item 17's CA and name map, the
    gateway as a process beside it (`zoeymcp gateway --vault http://127.0.0.1:<port>` with
    `ZOEYMCP_GATEWAY_KEY` from `KeySet.from_text(master).gateway_key(1)`), its policy giving a
    client `agent1` (a `token_sha256` from `zoeymcp client-token`) no server. Item 17's two fakes
    don't do here as two processes: the MCP fake's `--static-key` refuses the provider's tokens,
    so the review after **Connect** fails. Run them in one process as S9 does, the MCP fake built
    with `authorize=` the provider's `access_ok` (`tests/acceptance/test_onboard_shape.py`). In
    Chrome or Edge with the Console open (no Trusted Types
    or Content Security Policy violation throughout), set up a passkey and open **MCP servers**.
    Pass:
    - **Add a server by URL** with `https://mcp.notes.example:9444/mcp` and, in **More options**,
      client ID `public-check` and no secret (a public client): the row reads "discovered, nothing
      sent or stored yet", and the plan's one button, like the row's, is **Save**, with no
      registration and no passkey prompt before it; **Cancel** it (nothing is written);
    - **Add a server by URL** with `https://mcp.notes.example:9444/mcp` and no client ID: the
      plan's one button is **Register its client**; registered with a passkey, the page shows no
      fragment, and the row reads `needs_save` with **Save**; no text says to commit, reload,
      generate or make a fragment;
    - **Save**: the dialog's first row reads "Revision 2, from 1 (by the seed, ...: 1 is the
      head)", then `credentials.notes`, `routes.notes` and `gateway.servers.notes`, each "added
      (wider)", and "No restart needed"; confirmed, the row reads `needs_connect` with no reload
      or restart;
    - **Connect** (accept the certificate warning for `https://localtest.me:9443` once): the
      provider sends the tab back to the portal, a passkey confirms, and the page queues the
      server's review by itself; Home's attention list names the tools nobody reviewed, with
      **Review**; the row, not reviewed yet, already has **Give to clients**;
    - the review, `echo` included as allow and `add` as approve, **Save**: the answer ends "Then
      give notes to each client that should reach it: Give to clients, on the MCP servers page",
      and the row reads reviewed, served to no client yet; Home's list no longer names notes;
    - **Give to clients**: one box, `agent1`, unticked; ticked, **Save**: the dialog's row reads
      "agents holding client agent1's token can call notes's 2 included tools"; **Close** writes
      nothing; **Save** again and confirm: the row says served to agent1; unticked and saved
      again, the dialog shows `notes removed` and no row ending "(wider)";
    - **Give to clients** with the boxes shown, while a second browser signed in on the same
      origin gives notes to `agent1` first: this browser's `agent1` ticked and **Save** is
      refused before any passkey prompt ("press Save again to plan it on revision N"), the boxes
      are drawn again with `agent1` ticked, and nothing more is written;
    - the vault's log has `step_up_confirmed` with `onboard.register`, `policy.save`,
      `oauth.complete`, `policy.save` and `client.servers`, in that order;
    - the restore banner (`policy_behind_witness`): with the vault stopped right after the first
      **Save** above, copy `./state` aside (`state.saved`), and carry on to the end; then stop the
      vault, put the copy back in place of `./state` (the gateway's volume as it is), and start it.
      Within a minute (the gateway's next status report) every page, Home first, shows the banner
      "the gateway has applied revision N; this vault holds 2. Was the state volume restored? ..."
      with N the last save's revision, as text, its command `docker compose ... exec vault zoeymcp
      policy acknowledge-restore`; Home's count of problems includes it. Stop the vault, run
      `zoeymcp policy acknowledge-restore --state ./state` (it asks for the number: type N + 1,
      which it writes as "Acknowledged the restore as revision N + 1."), start the vault: once the
      gateway reports again the banner is gone, and **Policy**'s history shows N + 1 straight after
      2.

    In Chromium and Edge:
    `test_managed.py::test_item_23_onboarding_in_managed_mode_takes_one_passkey_a_step`,
    `test_item_23_give_to_clients_closes_takes_away_and_meets_a_second_browser` and
    `test_item_23_a_restored_state_shows_its_banner_on_every_page` (the gateway's status report
    witnessing a newer revision, the acknowledgment written as the host writes it); by hand
    there: the state copied aside and put back, and `zoeymcp policy acknowledge-restore` with the
    vault stopped.
24. **Prompts and resources on the review screen, under Trusted Types** (the review screen's kind
    rows, M6). Item 16's setup, the fake started as `python -m tests.fakes.run_mcp_server CERT KEY
    --prompts --resources --switch inject_kinds`, so it lists two prompts (`brainstorm`,
    `summarize_note`), a resource template (`notes://notes/{id}`) and a fixed resource
    (`notes://index`), and one more of each kind carrying item 16's hostile text
    (`hostile_prompt`, `notes://hostile/{id}`, `notes://hostile`). Before `enable` is added, once
    an agent has listed the server's tools, the server's row on **MCP servers** reads "offered,
    not served: prompts, resources, completions", its last step "Add enable: [prompts, resources,
    completions] to notes in your policy and reload" (in managed mode, "Export, add enable:
    [prompts, resources, completions] to notes, import"). Add `enable: [prompts,
    resources, completions]` to the server (operations.md §12), commit it and reload. In Chrome or
    Edge with the Console open (no Trusted Types or Content Security Policy violation throughout),
    choose **Review again** on the server's row. Pass:
    - after the tools, the rows sit under the headings **Prompts**, **Resource templates** and
      **Resources**, each row with its include box, **Show definition** and **Decline**, and no
      allow or approve control; the counts and the footer's "N tools changed" count tools only;
    - the three hostile rows show every hidden character as the visible mark the vault gives it
      and `<IMPORTANT>` as text, in the title, the description and an argument's title and
      description (the prompt), the description (the template), and the title and description
      (the fixed resource), and can't be included (an error finding); **Show definition** shows each definition whole,
      every character outside ASCII as an escape;
    - tick `brainstorm`, `summarize_note`, `notes://notes/{id}` and `notes://index`, **Generate**:
      fragment 2's title names the `prompts:` and `resources:` blocks, its comments read `# added:
      brainstorm (prompt)` and so on, and `# can't be included, error finding: hostile_prompt
      (prompt; ...)` for each hostile entry; commit it and reload, and `zoeymcp review notes`
      shows the four `ok`;
    - restarted with `--change-kind prompt --change-kind resource_template` added, **Review
      again**: `brainstorm` and `notes://notes/{id}` read `drift`, with **Reviewed** and **Now**
      side by side and the vault's diff under them, every string shown as text; **Accept the new
      definition** on both and **Generate**: the new pins under each block's `review:`, each with
      a `# changed:` line; **Clear** unticks every kind's box as it does the tools';
    - after that restart, before the new pins are committed, Home's list names "notes changed 1
      included prompt since the review" and "notes changed 1 included resource template since
      the review", each with **Review**, and `zoeymcp health` has both under `drift_marked`;
    - in managed mode (item 20's vault, `enable` added by a host export, edit and import as
      operations.md §12 says), the same review and **Save**: the dialog's rows name
      `gateway.servers.notes.prompts.include` and each kind's `review` pin, an accepted re-pin
      showing both pins and "re-pinned: you read both definitions"; confirmed with a passkey, the
      vault's log has `step_up_confirmed` with `policy.save`, and an agent on `/s/notes/mcp` lists
      the included prompts.

    In Chromium and Edge:
    `test_drift.py::test_item_24_prompts_and_resources_are_rows_of_their_own_and_hostile_ones_show_as_text`,
    `test_item_24_a_changed_prompt_and_template_read_drift_and_clear_unticks_every_kind`,
    `test_item_24_the_row_and_home_say_what_the_gateway_reports` and
    `test_item_24_a_managed_save_names_each_kinds_paths_and_a_repin_shows_both_pins`; the agent's
    listing is `tests/acceptance/test_prompts_resources_shape.py`'s; by hand there: `zoeymcp
    review notes` and `zoeymcp health` (the CLI, not the page).

The M8 items (25-34) run against item 23's setup (a vault started through
`tests/acceptance/procs.py`'s launcher and a gateway beside it), managed, its policy adding: the
fake MCP server as `fake` on a route with a credential, its `echo` and `slow` tools in `approve`
and `vault_approval` and its `add` in `approve` only; clients `desk` (`attended: true`), `nightly`
(`out_of_band: true`) and `batch` (neither), each given `fake`; and
`approvers: {portal: {}, timeout: 3600, block_seconds: 0}`, so every held call answers `pending`
and waits in the queue. For the items that need Telegram, start the fake Bot API
(`python -m tests.fakes.run_telegram CERT KEY --token <test token>`, a certificate for
`api.telegram.org` from item 17's CA, reached through the launcher's name map), store the token
with `zoeymcp secret set approver-bot --origin https://api.telegram.org`, and add
`telegram: {bot_token: "store:approver-bot", user_id: 100000001, chat_id: 100000001}`. Make the
agents' calls with any MCP client given the client's token (the MCP Python SDK's `Client` in the
development environment does), and collect results with `check_approval`. Never a real bot here:
the live check below is the only run against Telegram.

The browser tests run these items against the same parts in one process
(`tests/browser/stacks.py`): the vault and its portal on loopback, each held call sent to the
vault's proxy listener as the gateway sends it (or, for `pending` and `check_approval`, a real
gateway and an MCP SDK agent in front of it), the vault's own Telegram surface against the fake
Bot API in process where an item has Telegram, and, for items 31 and 32, a managed vault whose
server is `notes` and whose approve tool is `write` (the items' `fake` and `echo`).

25. **The queue shows a hostile text whole, under Trusted Types** (the Approvals page, M8). The M8
    setup above. Make held calls to `echo` as `desk` whose arguments carry a bidi mark
    (`\u202e`), a line of 300 characters, a line that reads like the frame
    (`"End of approval request 0000000000000000"` as a value), and, as `nightly` on a plain
    `approve` tool (`add`), a relayed prompt; also a relayed text with a line imitating the vault's
    "Rendered by the gateway" line, which the vault refuses `text_refused` before anyone is asked.
    In Chrome or Edge with the Console open, open **Approvals**. Pass: each waiting row opens to
    its whole text, the long line wrapped and not cut, the imitated frame line inside the JSON as
    a value; the call carrying the bidi mark was refused `held_text_refused` before anyone was
    asked (no hidden character is shown, as a mark or otherwise) and never appears; the relayed
    row carries "Relayed from the gateway" and the vault's line at the top of its text; the
    imitation never appears; no Trusted Types or Content Security Policy violation.
    Scriptable as: open Approvals, select each row, assert the `pre`'s `textContent` equals
    `zoeymcp approvals show <ref>`'s text; listen for `securitypolicyviolation`, assert none.
    In Chromium and Edge:
    `test_approvals.py::test_item_25_a_hostile_text_is_shown_whole_under_trusted_types` (markup,
    nested JSON and bare addresses too, and the hostile row's confirm dialog showing the same text
    whole, unsqueezed; the fakes' zero-width space and hostile text refused like the bidi mark,
    each naming its value's pointer, and a value past the text budget refused; no dialog or
    request off loopback); by hand there: nothing.
26. **Approve with a passkey** (the Approvals page, M8). Item 25's queue, Telegram on (the fake
    Bot API). **Approve** a row. Pass: the dialog shows the whole text and "Approve runs this
    one call, exactly as shown."; one passkey prompt; the answer is 200; the fake's message for
    that ref becomes "Approval request <ref>: approved HH:MM UTC in the portal. Sent: ..." with no
    buttons; the row moves to **Decided
    recently** reading "approved here HH:MM UTC; sent: ok"; the agent's `check_approval` returns
    the call's result once; the log has `step_up_confirmed` with `approval.decide`, then
    `approval_decided` with `via: portal`.
    Scriptable as: click Approve, let a virtual authenticator assert, assert 200 and the row under
    Decided recently; read the fake's messages (`GET /_fake/messages`), assert the edit.
    In Chromium and Edge:
    `test_approvals.py::test_item_26_approve_shows_the_whole_text_before_the_passkey_and_sends_it_once`
    (the fake's message read in process, the held bytes at the upstream once, the vault's records
    on the Ledger page) and, for `check_approval`, `test_pending_then_check_approval` (a real
    gateway and agent); by hand there: nothing.
27. **Cancel at the passkey prompt** (the Approvals page, M8; item 8's cancel path for the queue).
    **Approve** a waiting row, then cancel the browser's passkey prompt. Pass: nothing is decided,
    the row stays under **Waiting**, no `approval_decided` line; **Approve** again works.
    Scriptable as: reject the WebAuthn call, assert the row's state is still waiting and no
    `step_up_confirmed` line.
    In Chromium and Edge:
    `test_approvals.py::test_item_27_a_cancelled_passkey_prompt_decides_nothing`, the ceremony
    failed as a cancelled prompt fails it (the virtual authenticator's user verification off:
    `NotAllowedError`, "The passkey prompt was cancelled"); by hand there: pressing **Cancel** in
    the browser's own passkey dialog, which an automated browser doesn't show.
28. **A stale decision** (the Approvals page, M8). With the confirm dialog of item 26 open, press
    **Approve** for the same ref in the fake Bot API (`POST /_fake/press`). Pass: the confirm is
    refused 409 `already_decided`, "Already decided in Telegram at HH:MM: approved", and nothing
    more is sent. Then, in a second tab, prepare a review save; in the first, prepare an approval:
    the dialog first says "This replaces the save you prepared in another tab; it was cancelled.",
    and the second tab's confirm is refused.
    Scriptable as: two browser contexts; assert the 409's reason and text; assert the `replaced`
    line in the second prepare.
    In Chromium and Edge:
    `test_approvals.py::test_item_28_telegram_deciding_while_the_dialog_is_open_wins` (the press
    in the fake Bot API), `test_item_28_two_operators_the_second_is_refused` (a second browser
    confirming second: "Already decided in the portal") and
    `test_item_28_an_approval_replaces_a_change_prepared_in_another_tab` (a duplicated tab's
    passkey rename stands in for the review save, which the queue's declarative vault doesn't
    offer: one prepared action per session either way); by hand there: nothing.
29. **Deny with a session; an expired row** (the Approvals page, M8). **Deny** a waiting row.
    Pass: no passkey prompt, the row moves to Decided recently as denied, the agent's
    `check_approval` reads "declined: the operator declined this call; nothing was sent" (a call
    still blocking is told "refused: the operator declined this call"), nothing reaches the fake
    upstream. With
    `approvers.timeout: 60`, leave a row past its deadline: it leaves **Waiting** as expired, and
    an **Approve** opened before then is refused `expired`.
    Scriptable as: click Deny, assert `denied`; wait past a 60 s deadline, assert `expired`.
    In Chromium and Edge:
    `test_approvals.py::test_item_29_deny_needs_no_passkey_and_sends_nothing`,
    `test_item_29_a_row_past_its_deadline_cant_be_approved` (the hold table's clock moved past the
    deadline with the dialog open) and, for the agent's line,
    `test_a_pending_call_denied_in_the_browser_is_collected_as_declined`;
    the blocking call's line is
    `tests/acceptance/test_vault_approval_shapes.py::test_deny_expire_withdraw`'s (its deny case:
    the same refusal, whichever surface denies); by hand there: nothing.
30. **An open queue doesn't keep the session alive** (M8). Leave the Approvals page open and
    untouched for 20 minutes, while its polls run. Pass: the next action lands on the sign-in page
    (the session's idle limit is 15 minutes; the queue's polls don't count as activity).
    Scriptable as: wait 20 minutes with the page open, assert the sign-in page.
    In Chromium and Edge:
    `test_approvals.py::test_item_30_an_open_queue_doesnt_keep_the_session_alive` (the page's
    clock fires its polls, the vault's clock moves the minutes) and
    `test_a_decision_prepared_in_one_tab_ends_when_another_tab_signs_in` (one tab per browser);
    by hand there: nothing.
31. **Turn-on: Hold in the vault** (the MCP servers page and the review screen in managed mode,
    M8). The M8 setup in managed mode, `echo` in `approve` and not yet in `vault_approval`. Pass:
    the server page's **Hold in the vault** on `echo` shows, before any passkey prompt, the plan's
    lines ("fake.echo: vault_approval on.", one line for `desk`, `nightly` and `batch` each, then
    the route's credential sentence); confirmed, `echo` is held. The review screen's box of the
    same name shows the same lines in its save's plan. With `approvers` removed (a host import),
    both controls are disabled, with "Set up an approver first (Telegram or the Approvals queue):
    a host step, operations.md §36.2".
    Scriptable as: open the server page, click Hold, assert the plan's lines before
    `navigator.credentials.get`; with no approver, assert `disabled` and the line.
    In Chromium and Edge:
    `test_managed.py::test_item_31_hold_in_the_vault_shows_the_turn_on_plan_before_the_passkey`,
    `test_item_31_the_review_screens_box_shows_the_same_plan` and
    `test_item_31_with_no_approver_both_controls_are_disabled` (a vault started with no
    `approvers`); by hand there: nothing.
32. **Turn-off and its refusals** (managed mode, M8). With `echo` held: **Turn off vault approval**
    prepares `tool.vault_approval_off`, and the dialog shows "echo: vault_approval off. The gateway
    will ask instead of the vault; a compromised gateway could then skip the approval. Calls
    waiting now are withdrawn." whole; one passkey changes that one tool, and the log has
    `tool_vault_approval_off`. Held again, a review save that unticks the box, and one that drops
    `echo` from `include`, are refused `vault_approval_off_needs_its_own_step` before any passkey
    prompt; a rollback to a revision before `echo` was held is refused
    `rollback_drops_vault_approval`.
    Scriptable as: click Turn off, assert the dialog text and one change; untick in review and
    save, assert the refusal and no WebAuthn call; roll back, assert the refusal.
    In Chromium and Edge:
    `test_managed.py::test_item_32_turn_off_shows_its_sentence_and_changes_one_tool`,
    `test_item_32_a_review_save_that_drops_the_hold_is_refused_before_the_passkey`,
    `test_item_32_a_rollback_that_drops_the_hold_is_refused_before_the_passkey` and
    `test_item_32_a_connectors_writers_turn_off_in_one_step_up` (a held connector's writers on and
    off with one passkey each); by hand there: nothing.
33. **Home and the badge** (Home, M8). With two calls waiting, Home lists "2 approvals waiting: the
    oldest must be answered by HH:MM UTC" with **Open the queue**, and the nav's Approvals entry
    shows 2; with no gateway status report (the gateway stopped) the item still shows. After a
    vault kill with a call waiting and another approved and running (the fake's `slow`, also held,
    with a long count), the restarted vault's Home shows `approvals_withdrawn_at_start` (cleared by
    opening Approvals) and `approvals_outcome_unknown` naming the running call's ref. Scriptable
    as: open Home, assert the items and their actions; assert the badge's number.
    In Chromium and Edge:
    `test_approvals.py::test_item_33_home_lists_the_waiting_calls_and_the_starts_findings` (with
    and without the gateway's status report; the restart's findings drawn from the recovery's
    result, whose kill and restart `tests/acceptance/test_held_crash.py` runs in processes on
    Linux) and `test_an_arrival_shows_within_one_poll` (a new call counted within one poll); by
    hand there: nothing.
34. **The Ledger's two chains** (the Ledger page, M8). After items 26 and 25's relayed call is
    approved in the fake Bot API. Pass: the held call is one row with asked (gateway, where vault),
    decided accept via Telegram or the portal (written by the vault), the outcome and
    `approved_elsewhere` (the gateway's), each marked with its writer; the relayed call's row
    shows the gateway's outcome; no "the chains disagree" flag.
    Scriptable as: open Ledger, assert the two rows and their per-writer cells.
    In Chromium and Edge: `test_approvals.py::test_item_34_the_ledger_joins_both_chains` (the
    relayed call approved in the fake Bot API, the gateway's records posted to the vault as the
    gateway reports them); by hand there: nothing.

## Live Telegram approver

Run once by hand at M8's exit, beside items 25-34, with a free bot of your own; CI never runs it.
Record it in the results table as item `Live Telegram`: the commit, the date, the Telegram
clients used (desktop, Android, iOS), and pass or fail per part. Record no bot token, chat id,
user id, bot name or account name, and keep none: everything runs in a temporary state directory,
and the bot is deleted afterwards.

1. **The bot.** Create it directly with Telegram's own bot-making account (@BotFather), not
   through another bot: the vault can't check this, so record that it was done this way. Keep
   its privacy mode on.
2. **Enrolment.** A vault with an admin socket (on Linux or in the hardened compose file) and
   egress to `api.telegram.org`: `zoeymcp secret set approver-bot --origin
   https://api.telegram.org`, then `zoeymcp approver telegram enrol --secret approver-bot`. Pass:
   the printed link opens the bot's chat, Start sends `/start` with the code, the bot sends a
   six-digit confirmation code to that chat, typing it prints the `approvers` lines with the
   right ids; a wrong code ends `enrolment_unconfirmed`.
3. **The probe.** With the lines in the policy, `zoeymcp approver telegram test` exits 0 and the
   chat shows the test message with no buttons; `zoeymcp health` reads `approver telegram: ok`.
4. **The message's shape.** Hold a call whose arguments hold `https://example.com/x`,
   `example.com` and `t.me/x`. Pass: the message is one monospaced block, with no link preview,
   on the desktop, Android and iOS clients; record, per client, whether anything inside the block
   can be tapped as a link (D-44: if one can, the Telegram-only defang is a fix commit before M8
   closes).
5. **Approve and Deny.** Approve one call: the message becomes "...: approved HH:MM UTC in
   Telegram. Sending…", then "… Sent: the server answered ok.", with no buttons. Deny another:
   "...: denied HH:MM UTC in Telegram. Nothing was sent." A press on a decided message (from a
   notification still on screen, say) is answered "This request is no longer pending".
6. **A second poller.** While the vault runs, poll the same bot from another program
   (`getUpdates` with the token): within a minute health shows `approver_contested`; stop it, and
   revoke and rotate the token as operations.md §35 says.
7. **An edited message.** With the bot's token, edit a waiting prompt's text
   (`editMessageText`), then press its Approve: the press is refused (`edited` or
   `text_changed` in `approver_press_refused`) and nothing is sent. Also change only its buttons
   (`editMessageReplyMarkup`): record whether Telegram then sets `edit_date`; the press is refused
   either way (`markup_changed` or `edited`).

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
| 19 | 82a7522 | 2026-10-31 | Chrome 155, Windows | http://localhost:8081 | Pass | The standard tier (deploy/compose.yaml, the image built at 82a7522) with the fake as `fake`, declarative; a reload is a recreate there. No Trusted Types or Content Security Policy violation, no alert, no request for `x`; the console's only error was the page's first `GET /api/servers` 401 after the container was recreated. Description drift: `echo` read `drift` with both columns whole and the markup as text in both and in the diff; `summarize` as item 16. Annotations drift: destructive and not read-only; **Accept** proposed approve (unticked, allow came back); **Generate** with Accept ticked and allow chosen gave the new pin, `# changed:` and `# kept: echo (allow: the new definition isn't marked read-only: proposed approve)`; with approve, `echo` under `approve:`. Found: the reviewed copies are on disk (`/state-gateway/defs/`), so a gateway restart keeps them (both columns still shown); with the old copy removed, the row said the gateway no longer has it and showed the new definition whole. **Clear** then **Select suggested**: `read_01` at approve, `read_02`-`read_63` at allow, no approve tool under `allow:`. Record the rest as declined (on by default, design G-19): every left-out tool declined at its pin, not `summarize` or `bad_tool`. Unticked, with `counter` and `lookup` taken out of `declined:`: **Decline** on `lookup` added it alone, `counter` stayed `# not included`. Not run by hand: `review_stale` (needs a reload with the vault running; covered by test_reviewview, test_reviewjobs, test_drift). The item's text was corrected for the restart, the Accept step and Decline |
| 20 | 82a7522 + the confirm's layout fix | 2026-10-31 | Chrome 155, Windows | http://localhost:8081 | Pass | Item 19's stack, managed, on a fresh state: the start seeded revision 1. The first **Save**: "Revision 2, from 1 (by the seed, ...: 1 is the head)", written with a passkey; the texts say managed, no Generate, no text to commit, reload or generate. Re-pin of `echo` after `--drift description`: both pins, "re-pinned: you read both definitions", "No restart needed"; logged `step_up_confirmed` `tool.repin`, `tool_repinned`. `add` and `slow` approve -> allow: the two moves listed first, each with its sentence and its definition; **Close** wrote nothing (head stayed 3), confirmed: `tool_allowed` for each. **Allow read_01 without asking**: its move and definition; `tool.allow`. After a vault restart, **Allow read_02 without asking** ran a review first, then the dialog; **Close** wrote nothing. `read_02` dropped (and declined), then **Clear** and **Select suggested**: `read_02` back at approve, `read_01` kept allow, no move row and no "was approve" row; `add` and `slow` (not read-only) stayed unticked, so the plan dropped them (the item's text said every included tool comes back, corrected). A second browser's `tool.allow` first: this browser's confirm was refused `changed` (`policy_moved` in the log), "What the vault finds now" led with "The policy moved to revision 8 ... press Save again" and the plan on 8; nothing written. Found and fixed: the confirm dialog's label column was `max-content`, so a label naming a pin was wider than the dialog and squeezed every value to a character a line, and values lost their JSON indentation (app.css: labels `fit-content(40%)` and wrapping, values `pre-wrap`; test_portal_static pins both) |
| 21 | 82a7522 + the confirm's layout fix | 2026-10-31 | Chrome 155, Windows | http://localhost:8081 | Pass | Item 20's vault: `ci-runner` added (reason `add ci-runner <b>x</b>`) and removed by two offline host imports (`run --rm --no-deps --user 10001:10001 ... policy import --state /state`). Item 20's run had dropped `add` and `slow` (revision 7), so a rollback past it would revive their pins (`pin_retired`, host-only): a third host import put them back at allow (`--allow-revive pin:fake/tool/add`, `pin:fake/tool/slow`) so the history matches the item's. The page named the head and the gateway's revision, the export command with `docker compose exec` and `-T`, no commit, reload or generate text; history newest first with who and what, the reason's markup as text; **Show the changes** on the moves to allow and on the seed (token hash `(set)`). Rollback to 3: no "(wider)" row, **Close** wrote nothing, confirmed: `add` and `slow` approve, `policy_rolled_back` with `target: 3`. Rollback to 9 refused `rollback_revives` before any passkey prompt. Rollback to 4 (`add` and `slow` at allow, every pin still held): "The portal can't widen gateway.servers.fake.tools.allow through a rollback: export, edit and import with zoeymcp policy import." Rollbacks to 8 and later were refused `pin_retired` first (they would revive the `read_*` pins the rollback to 3 dropped): pick a widening target whose pins the head still holds |
| 22 | 82a7522 + the confirm's layout fix | 2026-10-31 | Chrome 155, Windows | http://localhost:8081 | Pass | Item 21's vault given `mail` (the shape of profiles/smtp-implicit-tls.yaml) by an offline host import. **Connectors** listed `mail: sending.` with its three limits and nothing of its host, sender or recipients. **Pause**, **Resume** (**Close** first wrote nothing) and "Sends a day" 20 -> 50 each wrote a `connector.limits` revision (`step_up_confirmed` and `policy_saved` with `write_kind: connector.limits`); 0 was refused `bad_body` and the same values `no_change`, both before any passkey prompt. A second browser paused first: this browser's **Pause** drew the page again with the moved text and wrote nothing (policy.js compares the head with the revision it showed before preparing). The first try at that step drew the page again before pressing the button, so it planned on the new head and wrote a revision: keep the first browser on the page, unreloaded |
| 23 | 82a7522 + the confirm's layout fix | 2026-10-31 | Chrome 155, Windows | http://localhost:8081 | Pass | Processes on Windows: the vault through procs.py's launcher (the fakes' CA and name map), managed, `agent1` given no server; a gateway polling it over http with the gateway key. Found: the item's two fakes as separate processes can't work past **Connect**: `--static-key` makes the MCP fake accept only that key, so the provider's tokens got 401 and every review failed (`review_failed`, `upstream`, "bad gateway" on the page). Run instead as S9 runs them, in one process with the MCP fake's bearer check the provider's `access_ok`, from a fresh state. Then: `public-check` (no secret) planned **Save** with no registration and no passkey, **Cancel** wrote nothing; with no client ID, **Register its client** (passkey), no fragment, `needs_save`; **Save**: revision 2 from the seed, the three blocks "added (wider)", `needs_connect`. **Connect**: back to the portal, passkey, the review queued itself (6 tools); the review saved with its "Give to clients" ending; **Give to clients**: one box, the sentence naming 2 included tools, **Close** wrote nothing, served, then removed with no "(wider)" row; a second browser gave first: refused `policy_moved` before any passkey prompt. Confirms in order: `onboard.register`, `policy.save`, `oauth.complete`, `policy.save`, `client.servers`. The restore banner: the state copied after revision 2 put back while the gateway had applied 6: `policy_behind_witness` (head 2, witness 6) and the banner on every page with its command; `policy acknowledge-restore --state` (typed 7) "Acknowledged the restore as revision 7."; started again, the banner went and the history shows 7 after 2. The banner's command said `exec vault` here because ZOEYMCP_EXEC_SERVICE wasn't set for this native run |
| 24 | 82a7522 + the confirm's layout fix | 2026-10-31 | Chrome 155, Windows | http://localhost:8081 | Pass | Item 19's stack (declarative; the server is `fake`), the fake with `--prompts --resources --switch inject_kinds`. Before `enable`, after an agent's listing, the row read "offered, not served: prompts, resources, completions" with the step "Add enable: [prompts, resources, completions] to fake in your policy and reload". With `enable`, the review: **Prompts**, **Resource templates**, **Resources** headings, no classification control; the hostile prompt, template and resource as text with their marks, refused (error findings). Fragment 2 named the `prompts:` and `resources:` blocks, `# added: ... (prompt)` and so on, `# can't be included, error finding: hostile_prompt (prompt; review fake shows why)` for each hostile entry; committed, `zoeymcp review fake` showed the four `ok`. With `--change-kind prompt --change-kind resource_template`: `zoeymcp health` had both `drift_marked` lines; `brainstorm` and `notes://notes/{id}` read drift; **Accept** on both and **Generate** gave the new pins with `# changed: brainstorm (prompt, was sha256:...)` and the template's. Managed (a fresh managed stack, `enable` added by an offline export, edit and import): the review's **Save** named the kinds' `include` and `review` paths, `policy.save` confirmed, an agent on `/s/fake/mcp` listed the included prompts, template and resource; the re-pin of both after `--change-kind` showed both pins and was written as `policy.save`. Seen: no `tool_repinned` line is logged for a prompt's or a resource template's re-pin (`_log_tools` logs tools only) |
| 1 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_1_*` tests in `test_session.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 3 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_3_*` tests in `test_session.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 4 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_4_*` tests in `test_session.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 6 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_6_*` tests in `test_session.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 7 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process; https://zoeymcp.tailnet.example through a TLS front | Pass | Browser tests: the `test_item_7_*` tests in `test_session.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 8 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_8_*` tests in `test_stepup.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 9 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_9_*` tests in `test_stepup.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 10 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux (CI); skipped on Edge, Windows (D-142) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_10_*` tests in `test_session.py`, CI 41875362144 (each passed in the Chromium job); the item's by-hand lines are not part of this row |
| 11 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_11_*` tests in `test_session.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 12 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process; a second port through a forwarder | Pass | Browser tests: the `test_item_12_*` tests in `test_session.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 13 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process; the fake provider at https://auth.notes.example | Pass | Browser tests: the `test_item_13_*` tests in `test_callback.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 14 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process; the fake provider at https://auth.notes.example | Pass | Browser tests: the `test_item_14_*` tests in `test_callback.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 15 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_15_*` tests in `test_stepup.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 16 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_16_*` tests in `test_review.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 17 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_17_*` tests in `test_review.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 18 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process; the fake provider at https://auth.notes.example | Pass | Browser tests: the `test_item_18_*` tests in `test_callback.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 19 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_19_*` tests in `test_drift.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 20 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_20_*` tests in `test_managed.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 21 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_21_*` tests in `test_managed.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 22 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_22_*` tests in `test_managed.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 23 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process; the fake provider at https://auth.notes.example | Pass | Browser tests: the `test_item_23_*` tests in `test_managed.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 24 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_24_*` tests in `test_drift.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 25 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_25_*` tests in `test_approvals.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 26 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_26_*` tests in `test_approvals.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 27 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_27_*` tests in `test_approvals.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 28 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_28_*` tests in `test_approvals.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 29 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_29_*` tests in `test_approvals.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 30 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_30_*` tests in `test_approvals.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 31 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_31_*` tests in `test_managed.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 32 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_32_*` tests in `test_managed.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 33 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_33_*` tests in `test_approvals.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
| 34 (browser tests) | 4798242 | 2026-11-04 | Chromium (Playwright 1.63), Linux; Edge, Windows (CI's browser jobs) | http://localhost on a free port, in process | Pass | Browser tests: the `test_item_34_*` tests in `test_approvals.py`, CI 41875362144 (each passed in both jobs); the item's by-hand lines are not part of this row |
