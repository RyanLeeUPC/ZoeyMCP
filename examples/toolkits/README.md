# Example toolkits

A small distribution of ZoeyMCP toolkits, outside the official image. A toolkit runs inside the
gateway and reaches upstreams only through the vault: it holds no credential, address or HTTP
client, only paths relative to the slots its policy maps to vault routes.

| Toolkit | Tools | Slot | What it shows |
| --- | --- | --- | --- |
| `mail` | `send_note` (approve) | `mail`: an SMTP connector route | every message approved as shown; sender and recipients fixed by the vault |
| `records` | `get_records` (allow), `add_records` and `archive_records` (approve) | `db`: an HTTP route | batch tools, one prompt per batch, per-item results, read-back, no delete |

`example_toolkits.mail_verify.verify_sender` is an offline check a mail reader would use before
trusting who a received message is from: only the receiving provider's topmost
`Authentication-Results` header counts, and it must show a passing DKIM signature for the From
domain. No mailbox reader ships yet.

The entry points (`pyproject.toml`) are what the gateway looks up: a policy can name only a
module registered under `zoeymcp.toolkits`, never an arbitrary import path.

## Tests

The tests run in the repository's own test run, with `zoeymcp.toolkit.testing`: no gateway, vault
or MCP, but the gateway's own checks, prompt rendering and send-once accounting.

```sh
uv run pytest examples/toolkits/tests
```

## By-hand checks for a real deployment

None of these runs in CI. Run them once against a real mail account after deploying the mail
toolkit with the `smtp-implicit-tls` or `smtp-starttls` profile:

1. **Decline:** ask the agent to send a note and decline the prompt. Nothing arrives; the agent
   reads "declined by operator".
2. **Accept once:** send one and accept. Exactly that message arrives, from the configured
   sender to the configured recipients, with an `Auto-Submitted: auto-generated` header.
3. **No answer:** let a prompt time out. The agent reads "no answer in time"; nothing arrives.
4. **The sandbox can't send:** from the agent's sandbox, call the vault's send route directly
   with any placeholder. The vault answers 403: only the gateway may use that route.
5. **A spoofed sender:** feed `verify_sender` a message whose From is the expected address but
   which the provider didn't sign for that domain. The verdict is not verified.

To stop sending at once: set `paused: true` on the connector and reload the vault.
