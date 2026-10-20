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
| 13, 14 | step 14b (the OAuth callback) |
| 12 | no step waits on it (the portal tests cover it); run it with 1-7 |

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
8. **Step-up shows the summary first** (step 14a). Prepare a change that needs a passkey. Pass:
   the summary shows before the passkey prompt; cancelling the prompt changes nothing.
9. **The authorization link** (step 14a). Start a connect. Pass: the link opens a new tab, and
   in it `window.opener` is `null` (the console of the new tab).
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
