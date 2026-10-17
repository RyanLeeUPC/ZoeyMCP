# Provider profiles

Each file is a ready-made `credentials:` + `routes:` fragment for one service shape (design
§8.1). Copy the parts you need into your policy, then:

- replace every `ph-replace-...` placeholder with a long random value
  (`python -c "import secrets; print(secrets.token_urlsafe(24))"`);
- adjust the rules to the calls you actually need: start narrow;
- store the secret with `zoeymcp secret set <name>` (the binding is derived from the route).

Every profile here is exercised end to end by `tests/acceptance` against a fake that behaves
like the real provider where it matters, with only the upstream address swapped.

| File | Shape | Example provider |
| --- | --- | --- |
| `openai-compatible.yaml` | S1: static bearer, JSON, streamed responses | OpenAI-compatible inference APIs |
| `lastfm.yaml` | S2: query-parameter key, a forced parameter | Last.fm |
| `telegram-bot.yaml` | S3: secret in the URL path | Telegram Bot API |
| `atlassian-basic.yaml` | S4: HTTP basic | Atlassian Cloud API tokens |
| `grist-document.yaml` | S7: one document, different methods per path | Grist |
| `github-readonly.yaml` | S8: GET-only API | GitHub REST API |
