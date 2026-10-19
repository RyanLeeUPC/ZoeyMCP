"""The example mail toolkit, through zoeymcp.toolkit.testing: the note sent is the note shown."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from example_toolkits.mail import toolkit
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from zoeymcp.common.canonical import JSONValue
from zoeymcp.common.textrules import find_violations
from zoeymcp.toolkit import VaultError
from zoeymcp.toolkit.testing import FakeSlot, load_problems, run

CONFIG: dict[str, JSONValue] = {
    "from": "Agent <agent@mail.example>",
    "to": ["partner@mail.example"],
    "max_per_day": 20,
    "sent_24h": 0,
    "paused": False,
    "max_subject_chars": 150,
    "max_body_chars": 2200,
}
EXPECT = {"expect_from": CONFIG["from"], "expect_to": CONFIG["to"]}
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def mail(**config: Any) -> FakeSlot:
    return FakeSlot(
        get={"/config": {**CONFIG, **config}},
        answer={"/send": {"message_id": "<a1@mail.example>", "sent_24h": 1}},
    )


def test_the_gateway_would_load_it() -> None:
    assert load_problems(toolkit) == {}
    assert toolkit.slots == {"mail": "smtp"}
    assert toolkit.tools["send_note"].consequential


async def test_the_note_sent_is_the_note_shown() -> None:
    slot = mail()
    out = await run(
        toolkit, "send_note", {"subject": "Hi", "body": "Hello\nthere"}, slots={"mail": slot}
    )
    assert out.prompt is not None
    assert "From: Agent <agent@mail.example>\n" in out.prompt
    assert 'To: ["partner@mail.example"]\n' in out.prompt
    assert "Subject: Hi\n\nHello\nthere\n" in out.prompt
    assert out.prompt.endswith(f"End of approval request {out.ref}")
    assert slot.sent == [("POST", "/send", {**EXPECT, "subject": "Hi", "body": "Hello\nthere"})]
    assert out.text == "sent (<a1@mail.example>)"


async def test_a_reply_shows_what_it_replies_to() -> None:
    slot = mail()
    arguments = {"subject": "Re: Hi", "body": "Yes.", "in_reply_to": "<x.1@mail.example>"}
    out = await run(toolkit, "send_note", arguments, slots={"mail": slot})
    assert out.prompt is not None
    assert "In reply to: <x.1@mail.example>\n" in out.prompt
    assert slot.sent[0][2] == {**EXPECT, **arguments}


@pytest.mark.parametrize("answer", ["decline", "none"])
async def test_nothing_is_sent_without_an_accept(answer: Any) -> None:
    slot = mail()
    out = await run(
        toolkit, "send_note", {"subject": "Hi", "body": "x"}, slots={"mail": slot}, answer=answer
    )
    assert out.is_error
    assert slot.sent == []


async def test_paused_refuses_before_asking() -> None:
    slot = mail(paused=True)
    out = await run(toolkit, "send_note", {"subject": "Hi", "body": "x"}, slots={"mail": slot})
    assert out.prompt is None
    assert out.text == f"sending is paused by the operator (ref {out.ref})"


@pytest.mark.parametrize(
    ("error", "text"),
    [
        (
            VaultError(502, "smtp_outcome_unknown"),
            "the connection dropped after sending; the note may have arrived, "
            "so don't send it again without asking",
        ),
        (VaultError(502, "smtp_refused"), "not sent (smtp_refused)"),
        (VaultError(429, "daily_limit"), "not sent (daily_limit)"),
        (VaultError(503), "not sent (503)"),
    ],
)
async def test_what_the_agent_reads_when_the_vault_refuses(error: VaultError, text: str) -> None:
    slot = mail()
    slot.fail = {"/send": error}
    out = await run(toolkit, "send_note", {"subject": "Hi", "body": "x"}, slots={"mail": slot})
    assert out.text == f"{text} (ref {out.ref})"


async def test_a_message_at_the_limits_fits_the_default_budget() -> None:
    """A.1: a 2,200-character body with the longest subject and In reply to fits 3,000."""
    arguments = {
        "subject": "s" * 150,
        "body": ("word " * 440)[:2200],
        "in_reply_to": "<" + "a" * 124 + "@" + "b" * 123 + ">",  # 250, the most
    }
    out = await run(toolkit, "send_note", arguments, slots={"mail": mail()})
    assert out.prompt is not None
    assert len(out.prompt) <= 3000


async def test_a_leading_space_is_refused_before_asking() -> None:
    """The mail header would lose it, so the message sent wouldn't be the one shown."""
    out = await run(toolkit, "send_note", {"subject": " Hi", "body": "x"}, slots={"mail": mail()})
    assert out.text == "arguments refused: at /subject: text_rules"
    assert out.prompt is None


async def test_hidden_text_is_refused_not_shown() -> None:
    out = await run(toolkit, "send_note", {"subject": "Hi", "body": "a\u202eb"}, slots={"mail": mail()})
    assert out.text == "arguments refused: at /body: text_rules"


# --- the property: accept sends exactly the shown write -----------------------------------------

line = st.text(
    alphabet=st.characters(min_codepoint=0x20, max_codepoint=0x7E),
    min_size=1,
    max_size=150,
).filter(lambda s: not find_violations(s, max_chars=150, min_chars=1, single_line=True))
body = st.lists(line, min_size=1, max_size=5).map("\n".join)
message_id = st.from_regex(r"\A<[a-z0-9.]{1,20}@[a-z0-9.]{1,20}>\Z")


@settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow], deadline=None)
@given(subject=line, text=body, reply=st.none() | message_id)
def test_accept_sends_exactly_the_shown_write(subject: str, text: str, reply: str | None) -> None:
    arguments: dict[str, Any] = {"subject": subject, "body": text}
    if reply is not None:
        arguments["in_reply_to"] = reply
    slot = mail()
    out = asyncio.run(run(toolkit, "send_note", arguments, slots={"mail": slot}))
    if out.prompt is None:  # the text check refused it (markup): nothing was sent
        assert slot.sent == []
        return
    for value in arguments.values():
        assert value in out.prompt  # every value verbatim
    assert slot.sent == [("POST", "/send", {**EXPECT, **arguments})]
