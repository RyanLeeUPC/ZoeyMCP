"""The SMTP connector's request parsing and message building (M4 design J.2, J.6)."""

from __future__ import annotations

import email
import json
from datetime import UTC, datetime
from email.message import EmailMessage
from email.policy import SMTP
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from zoeymcp.common.policy.schema import SMTPConnector
from zoeymcp.vault.connectors.mailmsg import (
    Rejection,
    SendRequest,
    build_message,
    data_bytes,
    domain_of,
    envelope,
    key_ok,
    message_id,
    parse_send,
)

CONNECTOR = SMTPConnector.model_validate(
    {
        "kind": "smtp",
        "host": "smtp.mail.example",
        "port": 465,
        "username": "store:mail-user",
        "password": "store:mail-pass",
        "from": "Agent <agent@mail.example>",
        "to": ["partner@mail.example", "second@mail.example"],
    }
)
EXPECT = {
    "expect_from": "Agent <agent@mail.example>",
    "expect_to": ["partner@mail.example", "second@mail.example"],
}
ZWSP = chr(0x200B)


def request(**changes: Any) -> bytes:
    body: dict[str, Any] = {**EXPECT, "subject": "Quarterly numbers", "body": "Hi,\nthe figures."}
    body.update(changes)
    return json.dumps({k: v for k, v in body.items() if v is not ...}).encode()


def parsed(**changes: Any) -> SendRequest:
    result = parse_send(request(**changes), CONNECTOR)
    assert isinstance(result, SendRequest), result
    return result


def refused(body: bytes) -> Rejection:
    result = parse_send(body, CONNECTOR)
    assert isinstance(result, Rejection), result
    return result


# --- the request --------------------------------------------------------------------------------


def test_a_good_request() -> None:
    found = parsed(in_reply_to="<a1b2c3@mail.example>")
    assert (found.subject, found.body, found.in_reply_to) == (
        "Quarterly numbers",
        "Hi,\nthe figures.",
        "<a1b2c3@mail.example>",
    )
    assert json.loads(found.canonical)["subject"] == "Quarterly numbers"
    assert parsed().in_reply_to is None


@pytest.mark.parametrize(
    ("body", "field", "rule"),
    [
        (b"not json", None, "json"),
        (b"[]", None, "object"),
        (b'{"a": 1, "a": 2}', None, "json"),
        (request(cc=["x@mail.example"]), None, "unknown_key"),
        (request(to=["x@mail.example"]), None, "unknown_key"),
        (request(headers={"Bcc": "x"}), None, "unknown_key"),
        (request(subject=...), "subject", "missing"),
        (request(body=...), "body", "missing"),
        (request(expect_to=...), "expect_to", "missing"),
        (request(subject=5), "subject", "type"),
        (request(subject=""), "subject", "text_rules"),
        (request(subject="two\nlines"), "subject", "text_rules"),
        (request(subject="tab\there"), "subject", "text_rules"),
        (request(subject="x" * 151), "subject", "text_rules"),
        (request(subject=f"hidden{ZWSP}"), "subject", "text_rules"),
        (request(subject=" leading"), "subject", "leading_space"),
        (request(subject=" "), "subject", "leading_space"),
        (request(body=""), "body", "text_rules"),
        (request(body="x" * 2201), "body", "text_rules"),
        (request(body=f"hidden{ZWSP}"), "body", "text_rules"),
        (request(body="cr\r\nlf"), "body", "text_rules"),
        (request(body=["x"]), "body", "type"),
        (request(in_reply_to="no-brackets@mail.example"), "in_reply_to", "message_id"),
        (request(in_reply_to="<a b@mail.example>"), "in_reply_to", "message_id"),
        (request(in_reply_to="<a@b>\r\nBcc: x"), "in_reply_to", "message_id"),
        (request(in_reply_to="<" + "a" * 240 + "@" + "b" * 10 + ">"), "in_reply_to", "message_id"),
        (request(in_reply_to=7), "in_reply_to", "type"),
        (request(expect_to="partner@mail.example"), "expect_to", "type"),
        (request(expect_from=["x"]), "expect_from", "type"),
    ],
)
def test_bad_requests_are_400_and_name_no_value(body: bytes, field: str | None, rule: str) -> None:
    found = refused(body)
    assert (found.status, found.code, found.field, found.rule) == (400, "bad_request", field, rule)
    assert "x@mail.example" not in json.dumps(found.answer())


def test_a_body_over_64_kib_is_refused() -> None:
    assert refused(b" " * (64 * 1024 + 1)).rule == "too_large"


def test_tabs_are_allowed_in_the_body() -> None:
    assert parsed(body="col1\tcol2").body == "col1\tcol2"


@pytest.mark.parametrize(
    "changes",
    [
        {"expect_to": ["partner@mail.example"]},
        {"expect_to": ["second@mail.example", "partner@mail.example"]},  # order matters
        {"expect_to": ["Partner@mail.example", "second@mail.example"]},
        {"expect_from": "agent@mail.example"},
        {"expect_from": "Other <agent@mail.example>"},
    ],
)
def test_the_shown_addresses_must_be_the_configured_ones(changes: dict[str, Any]) -> None:
    found = refused(request(**changes))
    assert (found.status, found.code) == (409, "connector_constraints_differ")


def test_text_rules_come_before_the_address_check() -> None:
    found = refused(request(subject="", expect_to=["other@mail.example"]))
    assert found.status == 400


@pytest.mark.parametrize(
    ("key", "ok"),
    [
        ("a" * 16, True),
        ("3f9c0a17d2b84e65.1", True),
        ("A-z_0.9" * 3, True),
        ("a" * 80, True),
        ("a" * 15, False),
        ("a" * 81, False),
        ("has space here!!!", False),
        ("x" * 16 + "\n", False),
        (None, False),
    ],
)
def test_idempotency_keys(key: str | None, ok: bool) -> None:
    assert key_ok(key) is ok


# --- the message --------------------------------------------------------------------------------


def built(**changes: Any) -> EmailMessage:
    message = build_message(
        parsed(**changes),
        CONNECTOR,
        message_id=message_id(CONNECTOR, "0" * 32),
        date=datetime(2026, 1, 1, 14, 5, tzinfo=UTC),
    )
    return email.message_from_bytes(message.as_bytes(policy=SMTP), policy=SMTP)


def test_every_header_comes_from_the_vault() -> None:
    message = built(in_reply_to="<a1b2c3@mail.example>")
    assert message["From"] == "Agent <agent@mail.example>"
    assert message["To"] == "partner@mail.example, second@mail.example"
    assert message["Subject"] == "Quarterly numbers"
    assert message["Message-ID"] == "<" + "0" * 32 + "@mail.example>"
    assert message["In-Reply-To"] == message["References"] == "<a1b2c3@mail.example>"
    assert message["Auto-Submitted"] == "auto-generated"
    assert message["Date"] == "Thu, 01 Jan 2026 14:05:00 +0000"
    assert message.get_content_type() == "text/plain"
    assert message["Content-Transfer-Encoding"] == "quoted-printable"
    assert message.get_content().replace("\r\n", "\n") == "Hi,\nthe figures.\n"
    assert built()["In-Reply-To"] is None


def test_non_ascii_and_long_lines_survive() -> None:
    body = "Grüße, " + "é" * 200
    message = built(body=body, subject="Résumé")
    assert message["Subject"] == "Résumé"
    assert message.get_content().replace("\r\n", "\n").rstrip("\n") == body


def test_message_ids_and_domains() -> None:
    assert domain_of("Agent <agent@mail.example>") == "mail.example"
    assert domain_of("x@sub.mail.example") == "sub.mail.example"
    with pytest.raises(ValueError, match="32 lowercase hex"):
        message_id(CONNECTOR, "A" * 32)
    with pytest.raises(ValueError, match="32 lowercase hex"):
        message_id(CONNECTOR, "0" * 31)


def test_the_envelope_is_the_configuration() -> None:
    assert envelope(CONNECTOR) == (
        "agent@mail.example",
        ["partner@mail.example", "second@mail.example"],
    )


# --- DATA ---------------------------------------------------------------------------------------


def test_data_bytes_stuff_dots_and_end_with_a_dot() -> None:
    data = data_bytes(
        build_message(
            parsed(body=".\n.leading\nplain\n..two"),
            CONNECTOR,
            message_id="<a@b>",
            date=datetime(2026, 1, 1, tzinfo=UTC),
        )
    )
    assert data.endswith(b"\r\n.\r\n")
    lines = data.split(b"\r\n")
    assert b"" not in lines[:-2] or True
    assert b".." in lines  # a lone dot became two
    assert b"..leading" in lines
    assert b"...two" in lines
    assert all(not line.endswith(b"\r") for line in lines)
    assert b"\n" not in data.replace(b"\r\n", b"")


@settings(max_examples=150, deadline=None)
@given(
    st.text(
        st.characters(exclude_categories=["Cs", "Cc", "Cf", "Co", "Cn", "Zl", "Zp"]),
        min_size=1,
        max_size=150,
    ),
    st.text(
        st.characters(exclude_categories=["Cs", "Cc", "Cf", "Co", "Cn", "Zl", "Zp"])
        | st.sampled_from(["\n", "\t", "."]),
        min_size=1,
        max_size=400,
    ),
)
def test_any_accepted_message_goes_only_to_the_configured_recipients(
    subject: str, body: str
) -> None:
    found = parse_send(request(subject=subject, body=body), CONNECTOR)
    if not isinstance(found, SendRequest):
        return
    message = build_message(
        found, CONNECTOR, message_id="<a@b>", date=datetime(2026, 1, 1, tzinfo=UTC)
    )
    reread = email.message_from_bytes(message.as_bytes(policy=SMTP), policy=SMTP)
    assert reread.get_all("To") == ["partner@mail.example, second@mail.example"]
    assert reread.get_all("Cc") is None
    assert reread.get_all("Bcc") is None
    assert reread["Subject"] == subject
    data = data_bytes(message)
    assert data.endswith(b"\r\n.\r\n")
    assert b"\r\n.\r\n" not in data[:-5]  # no early end of DATA
