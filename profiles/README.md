# Provider profiles

Each file is a ready-made `credentials:` + `routes:` fragment for one service shape (design
§8.1); the MCP one has a `gateway:` part too. Copy the parts you need into your policy, then:

- replace every `ph-replace-...` placeholder with a long random value
  (`python -c "import secrets; print(secrets.token_urlsafe(24))"`);
- adjust the rules to the calls you actually need: start narrow;
- store the secret with `zoeymcp secret set <name>` (the binding is derived from the route).
  For an OAuth profile, store only the client secret this way, if there is one, and get the
  refresh token with `docker exec -it <vault> zoeymcp login <credential>` (see
  [docs/operations.md](../docs/operations.md)).

Every profile here is exercised end to end against a fake that behaves like the real provider
where it matters, with only the upstream address swapped: by `tests/acceptance`, and the SMTP
ones by `tests/unit/test_smtp_connector.py`.

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
| `smtp-implicit-tls.yaml` | S13: send mail with an app password, implicit TLS on 465, fixed recipients, optionally through CONNECT | any mail provider with app passwords |
| `smtp-starttls.yaml` | S14: the same with STARTTLS on 587, required, never optional | any mail provider with app passwords |
