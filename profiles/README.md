# Provider profiles

Each file is a ready-made `credentials:` + `routes:` fragment for one service shape (design
§8.1); the MCP ones have a `gateway:` part too. Copy the parts you need into your policy, then:

- replace every `ph-replace-...` placeholder with a long random value
  (`python -c "import secrets; print(secrets.token_urlsafe(24))"`);
- adjust the rules to the calls you actually need: start narrow;
- store the secret with `zoeymcp secret set <name>` (the binding is derived from the route).
  For an OAuth profile, store only the client secret this way, if there is one, and get the
  refresh token with `docker exec -it <vault> zoeymcp login <credential>` (see
  [docs/operations.md](../docs/operations.md)).

Every profile here is exercised end to end against a fake that behaves like the real provider
where it matters, with only the upstream address swapped: by `tests/acceptance`, and the SMTP
ones by `tests/unit/test_smtp_connector.py`. `remote-mcp-oauth-discovered.yaml` is compared
instead with what onboarding by URL writes against the fakes, but for the client ID.

The portal (its `admin` block, docs/operations.md §26) does these steps in the browser instead
of the CLI:

- **Secrets** stores a profile's secret with a passkey, as `zoeymcp secret set` does.
- **Credentials** signs an OAuth profile in with **Connect**, by paste or through the portal's
  callback, the passkey confirming it at the end, as `zoeymcp login` does.
- **MCP servers** adds a remote MCP server by its URL (**Add a server by URL**) and makes fragment
  1, as `zoeymcp login --mcp` does, so a server that onboards by URL needs no profile copied.
- **MCP servers** reviews a server's tools too (**Review tools**) and makes the `tools:` and
  `review:` blocks to commit, as `zoeymcp review` does; assigning the server to clients stays
  yours.

| File | Shape | Example provider |
| --- | --- | --- |
| `openai-compatible.yaml` | S1: static bearer, JSON, streamed responses | OpenAI-compatible inference APIs |
| `lastfm.yaml` | S2: query-parameter key, a forced parameter | Last.fm |
| `telegram-bot.yaml` | S3: secret in the URL path | Telegram Bot API |
| `atlassian-basic.yaml` | S4: HTTP basic | Atlassian Cloud API tokens |
| `google-oauth.yaml` | S5: OAuth, confidential client, non-rotating refresh tokens, a scope check | Google APIs (Calendar, read-only) |
| `spotify-pkce.yaml` | S6: OAuth, public client with PKCE, rotating refresh tokens | Spotify Web API |
| `grist-document.yaml` | S7: one document, different methods per path | Grist |
| `github-readonly.yaml` | S8: GET-only API | GitHub REST API |
| `remote-mcp-static-key.yaml` | S10: a remote MCP server with a static key, behind the gateway (also a `gateway:` fragment) | any MCP server that takes an API key |
| `remote-mcp-oauth.yaml` | S6 x S10: a remote MCP server with OAuth behind the gateway: a client registered by hand, PKCE, rotating refresh tokens, the `resource` parameter, one allowed and one approved tool (also a `gateway:` fragment) | any MCP server whose OAuth client you register yourself (no discovery: for discovery, see S9 below) |
| `remote-mcp-oauth-discovered.yaml` | S9: the same server onboarded by its URL: fragment 1 as `zoeymcp login --mcp` writes it from the server's protected-resource metadata and its authorization server's metadata, with a public client registered by the vault (DCR), the issuer required on the answer, and no tools until the review (also a `gateway:` fragment) | any MCP server that publishes its metadata (RFC 9728) and registers clients (RFC 7591) |
| `smtp-implicit-tls.yaml` | S13: send mail with an app password, implicit TLS on 465, fixed recipients, optionally through CONNECT | any mail provider with app passwords |
| `smtp-starttls.yaml` | S14: the same with STARTTLS on 587, required, never optional | any mail provider with app passwords |
| `toolkit-mail.yaml` | S15: the example mail toolkit, each message approved as shown (with an SMTP profile; a `gateway:` fragment) | any of the SMTP profiles' providers |
| `toolkit-records.yaml` | S16: the example records toolkit, batch reads and approved batch writes, no delete (also a `gateway:` fragment) | any JSON records API with a key |
