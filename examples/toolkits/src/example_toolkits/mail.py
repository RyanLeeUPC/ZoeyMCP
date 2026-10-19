"""Example mail toolkit: one send tool; the operator approves every message (M4 design G.4).

The vault's SMTP connector holds the password and fixes the sender and the recipients. This
toolkit reads them from the connector's config, shows the human exactly the request it will send,
and after an accept sends that request, once.
"""

from __future__ import annotations

from typing import Annotated

from zoeymcp.common.canonical import JSONValue
from zoeymcp.toolkit import (
    MessageId,
    Plan,
    PrepareContext,
    Show,
    Text,
    ToolContext,
    Toolkit,
    ToolkitError,
    VaultError,
    Write,
)

toolkit = Toolkit(
    "mail",
    slots={"mail": "smtp"},
    description="Send a note to the operator's configured recipients.",
)

# A leading space is dropped when the header is read, so the vault refuses one.
Subject = Annotated[str, Text(min=1, max=150, single_line=True, pattern=r"[^ ].*")]
Body = Annotated[str, Text(min=1, max=2200)]  # the connector's default max_body_chars


async def plan_send(
    ctx: PrepareContext, subject: str, body: str, in_reply_to: str | None = None
) -> Plan:
    config = await ctx.vault("mail").get_object("/config")  # connector config only
    if config["paused"]:
        raise ToolkitError("sending is paused by the operator")
    request: dict[str, JSONValue] = {
        "expect_from": config["from"],
        "expect_to": config["to"],
        "subject": subject,
        "body": body,
    }
    show = [Show.line("From", "/expect_from"), Show.line("To", "/expect_to")]
    if in_reply_to is not None:
        request["in_reply_to"] = in_reply_to
        show.append(Show.line("In reply to", "/in_reply_to"))
    show += [Show.line("Subject", "/subject"), Show.block("/body")]
    return Plan("Send an email", [Write.post("/send", request, show=show)])


@toolkit.tool(consequential=True, prepare=plan_send)
async def send_note(
    ctx: ToolContext, subject: Subject, body: Body, in_reply_to: MessageId | None = None
) -> str:
    """Send a plain-text note to the configured recipients. The operator approves each one."""
    if ctx.plan is None:  # always set for an approve tool; checked anyway
        raise ToolkitError("no approved plan")
    (write,) = ctx.plan.writes
    try:
        sent = await ctx.vault("mail").send(write)
    except VaultError as exc:
        if exc.code == "smtp_outcome_unknown":
            raise ToolkitError(
                "the connection dropped after sending; the note may have arrived, "
                "so don't send it again without asking"
            ) from None
        raise ToolkitError(f"not sent ({exc.code or exc.status})") from None
    return f"sent ({sent['message_id']})"
