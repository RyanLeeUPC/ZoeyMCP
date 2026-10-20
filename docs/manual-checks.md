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

| Items | Run before the acceptance of |
| --- | --- |
| 1-7, 10, 11 | step 11 (setup, enrolment, login, logout and sessions) |
| 8, 9 | step 14a (OAuth connect by paste) |
| D-66 | step 14a: the live OAuth test against a real provider (its own section below) |
| 13, 14 | step 14b (the OAuth callback) |
| 12 | no step waits on it (the portal tests cover it); run it with 1-7 |
| 15 | step 13 (secrets) |

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
8. **Step-up shows the summary first** (step 14a). With two passkeys enrolled, open
   **Passkeys**, choose **Rename** on one and give a new name. Pass: the dialog shows what the
   vault will do (the passkey, its name now, the new name) before any passkey prompt; choose
   **Confirm with your passkey** and cancel the browser's prompt: the dialog says the prompt was
   cancelled, **Close** it, and the passkey keeps its name (no `passkey_renamed` in the log).
   Then, with the policy below, open **Credentials**, choose **Connect** on `demo`, paste
   `http://127.0.0.1/callback?code=x&state=wrong` and choose **Check the address**. Pass: the
   dialog says the address belongs to another login, and no passkey prompt opens.
9. **The authorization link** (step 14a). Add the policy below to `portal.yaml`, restart the
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
13. **The callback** (step 14b): the steps come with the callback.
14. **A stale callback address** (step 14b): the steps come with the callback.
15. **The secret field isn't saved** (step 13). Sign in, open **Secrets**, enter a name and a
    value, choose **Set the secret**, confirm with the passkey. Pass: the value shows as dots while
    typed (in Chrome, Edge and Safari; other browsers may show it as typed); the browser doesn't
    offer to save it as a password (and no password manager fills or stores it); after the confirm
    the value field is empty; the page's elements (developer tools, Elements) hold no copy of it.

## D-66: the live OAuth test against a real provider

Run once before step 14a's acceptance, with a provider client of your own; CI never runs it.
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
