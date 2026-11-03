# Clients and approvals

An `approve` tool asks the human through the agent's own MCP client (an elicitation, in form
mode), so whether a prompt is safe to answer depends on that client. This page lists what to
check in a client before marking it `attended`, and what has been checked so far.

ZoeyMCP renders every prompt itself and refuses any text that could hide or disguise content
(hidden characters, wide runs of spaces, stacked combining marks, and, for clients that render
Markdown, code fences, HTML and links). It never cuts a prompt: one over the budget is refused,
and the agent is told why. What it can't control is how the client shows the text and what the
client lets the human or its own settings do with it.

A client you can't check, or one nobody watches, can be asked out of band instead: mark it
`approvals: {out_of_band: true}` and its prompts go to the vault's approvers (a Telegram bot, the
portal's Approvals queue), not to the client ([operations.md](operations.md) §19, §36). A tool
marked `vault_approval` is asked there for any client that is attended or out of band (any other
client is refused). What an out-of-band approval trusts in place of the
client (the chat service, your chat account, the portal page) is in operations.md §36.6.

## What to check

For each client, and each version you deploy:

| Check | Why it matters | Policy setting it informs |
| --- | --- | --- |
| Shows the whole message, and up to what length | a client that truncates shows less than was approved | `approvals.budget_chars` (per client, lower only) |
| Shows plain text or renders Markdown | Markdown can hide text or fake structure | `approvals.renders`: `plain` only if it never renders |
| Renders URLs as links | a link's target can differ from its text, and a fetched preview tells a server the prompt was shown | `renders: markdown` refuses `](`; a bare `http(s)://` URL isn't refused for any `renders` value, so check whether the client makes one a link. The vault's approvers change no byte either: Telegram gets the whole text in one monospaced block with link previews off, and the portal shows it as text |
| Can auto-accept (by default, or through hooks or settings) | an auto-accepting client approves anything; the prompt protects nothing | don't mark such a client `attended`; `confirm_code: true` stops blind hooks only |
| Offers a persistent "always allow" for elicitations | one click would approve every later call | as above |
| Merges identical prompts | two calls could share one answer | each prompt carries its own ref; check the footer |
| Declines when there is no way to answer | no answer must mean no call | the gateway times out and records `timeout` |
| Honours `notifications/cancelled` | a cancelled call's prompt should go away | the gateway withdraws on cancel either way |
| Protocol eras it speaks | modern clients answer through retries; legacy ones on the call's stream | both are served |
| Its tool-call and idle timeouts | a prompt can't outlive the client's tool call | `approvals.timeout` below the client's tool-call timeout; for out-of-band waits, `approvers.block_seconds` below it too: past it the call answers `pending <ref>` and the agent collects the result with `check_approval`. Progress notifications are sent while a call blocks, and never relied on to keep a client waiting |

How to check one: run the gateway with the example policy and a test `approve` tool, make a
call, and look at the prompt as the client shows it: the first line (`Approval request <ref>`)
and the last (`End of approval request <ref>`) must both be visible, and the ref must match.
Then decline, let one time out, cancel one, and look for any setting that answers for you.

## Checked

| Client | Version | Date | Result |
| --- | --- | --- | --- |
| MCP Python SDK `Client` (the acceptance tests' agent) | 2.3.0 | 2026-10 | shows the message whole to its callback; no auto-accept unless the callback does; answers in both eras; honours cancellation. `renders` is the caller's choice. |

## Reported, not checked

Every other client is unchecked. Treat each as able to truncate, render Markdown and auto-accept
until you have checked it as above, and record what you find here with the client's version and
the date. A client that can auto-accept without a human must not be marked `attended`.

## Known deviation: the pending answer

A call that waits out of band past `approvers.block_seconds` answers `pending <ref>` as a tool
error (`isError: true`) with no `structuredContent`, even for a tool with an `outputSchema`. The
MCP specification says such a tool returns conforming structured results, with no exception for
errors; the reference SDKs skip output validation when `isError` is set, and ZoeyMCP relies on
that. A client that validates error results too would reject the pending answer: check it, and
keep `block_seconds` long enough for its calls not to reach it, or don't hold its tools.

## The client token is the approval credential

Anyone holding an attended client's token can make calls and answer their prompts, with or
without `confirm_code`. Keep the token out of the agent's sandbox (in the client's own
configuration, not an environment the agent can read), and pin the client's source network
where the gateway sees the client directly (the hardened `agents` network, loopback). Behind the
`lan` proxy the gateway sees only the proxy, so a source pin means nothing there. A prompt asked
out of band isn't the token's to answer: mark the client `out_of_band`, or the tool
`vault_approval`.
