"""The SMTP connector's send request and the message it builds (M4 design J.2, J.6). Pure.

A request names only what may vary: the subject, the body and an optional ``in_reply_to``, plus
``expect_from`` and ``expect_to``, which must equal the connector's configuration, so the
recipients a human was shown are the ones the vault sends to. Every header comes from the vault.
Nothing here raises with a value in its message: a refusal names the field and the rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime, parseaddr
from typing import Any, Literal

from ...common import canonical
from ...common.policy.schema import SMTPConnector
from ...common.textrules import find_violations

MAX_BODY_BYTES = 64 * 1024
KEY_PATTERN = re.compile(r"^[A-Za-z0-9._-]{16,80}$")
MESSAGE_ID = re.compile(r"^<[!-;=?-~]{1,250}@[!-;=?-~]{1,250}>$")
MAX_MESSAGE_ID = 250
REQUIRED = frozenset({"expect_from", "expect_to", "subject", "body"})
OPTIONAL = frozenset({"in_reply_to"})


@dataclass(frozen=True)
class SendRequest:
    subject: str
    body: str
    in_reply_to: str | None
    canonical: bytes  # the request as received, canonical: what the journal's HMAC covers


@dataclass(frozen=True)
class Rejection:
    """Why a request is refused. ``field`` and ``rule`` never hold a value."""

    status: int
    code: Literal["bad_request", "connector_constraints_differ"]
    field: str | None = None
    rule: str | None = None

    def answer(self) -> dict[str, Any]:
        found: dict[str, Any] = {"error": self.code, "code": self.code}
        if self.field is not None:
            found["field"] = self.field
        if self.rule is not None:
            found["rule"] = self.rule
        return found


def key_ok(key: str | None) -> bool:
    """J.2 row 1: an ``Idempotency-Key`` of 16-80 safe characters."""
    return key is not None and KEY_PATTERN.fullmatch(key) is not None


def _bad(field: str | None, rule: str) -> Rejection:
    return Rejection(400, "bad_request", field, rule)


def parse_send(body: bytes, connector: SMTPConnector) -> SendRequest | Rejection:
    """J.2 rows 2-4, in order: the JSON shape, the text rules, then the expected addresses."""
    if len(body) > MAX_BODY_BYTES:
        return _bad(None, "too_large")
    try:
        value = canonical.loads_strict(body, max_bytes=MAX_BODY_BYTES)
    except (canonical.JSONRejected, ValueError):
        return _bad(None, "json")
    if not isinstance(value, dict):
        return _bad(None, "object")
    for name in sorted(value):
        if name not in REQUIRED | OPTIONAL:
            return _bad(None, "unknown_key")  # never echo an unknown key: it's caller text
    for name in sorted(REQUIRED):
        if name not in value:
            return _bad(name, "missing")
    subject, text, reply = value["subject"], value["body"], value.get("in_reply_to")
    if not isinstance(subject, str):
        return _bad("subject", "type")
    if find_violations(
        subject,
        min_chars=1,
        max_chars=connector.max_subject_chars,
        single_line=True,
        allow_tabs=False,
    ):
        return _bad("subject", "text_rules")
    if not isinstance(text, str):
        return _bad("body", "type")
    if find_violations(text, min_chars=1, max_chars=connector.max_body_chars, allow_tabs=True):
        return _bad("body", "text_rules")
    if reply is not None:
        if not isinstance(reply, str):
            return _bad("in_reply_to", "type")
        if len(reply) > MAX_MESSAGE_ID or MESSAGE_ID.fullmatch(reply) is None:
            return _bad("in_reply_to", "message_id")
    expect_from, expect_to = value["expect_from"], value["expect_to"]
    if not isinstance(expect_from, str) or not _addresses(expect_to):
        return _bad("expect_to" if isinstance(expect_from, str) else "expect_from", "type")
    if expect_from != connector.from_ or expect_to != list(connector.to):
        return Rejection(409, "connector_constraints_differ")
    return SendRequest(subject, text, reply, canonical.dumps_canonical(value))


def _addresses(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def address_of(mailbox: str) -> str:
    """The bare address of a mailbox, display name or not."""
    return parseaddr(mailbox)[1]


def domain_of(mailbox: str) -> str:
    return address_of(mailbox).rpartition("@")[2]


def message_id(connector: SMTPConnector, random_hex: str) -> str:
    """``<{32 hex}@{From domain}>``: no host name, no process id."""
    if not re.fullmatch(r"[0-9a-f]{32}", random_hex):
        raise ValueError("a message id takes 32 lowercase hex digits")
    return f"<{random_hex}@{domain_of(connector.from_)}>"


def build_message(
    request: SendRequest, connector: SMTPConnector, *, message_id: str, date: datetime
) -> EmailMessage:
    """J.6: every header from the vault; plain text, UTF-8, quoted-printable."""
    message = EmailMessage(policy=SMTP)
    message["From"] = connector.from_
    message["To"] = ", ".join(connector.to)
    message["Subject"] = request.subject
    message["Date"] = format_datetime(date)
    message["Message-ID"] = message_id
    if request.in_reply_to is not None:
        message["In-Reply-To"] = request.in_reply_to
        message["References"] = request.in_reply_to
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(request.body, subtype="plain", charset="utf-8", cte="quoted-printable")
    return message


def envelope(connector: SMTPConnector) -> tuple[str, list[str]]:
    """The SMTP envelope: from the configuration only, never the request."""
    return address_of(connector.from_), list(connector.to)


def data_bytes(message: EmailMessage) -> bytes:
    """What follows ``DATA``: CRLF lines, each leading dot doubled, then ``.`` CRLF.

    ``smtplib.SMTP.data()`` dot-stuffs its argument even when it is bytes, so the connector sends
    these bytes itself (M4 design J.4).
    """
    raw = message.as_bytes(policy=SMTP)
    lines = raw.split(b"\r\n")
    if lines and lines[-1] == b"":
        lines.pop()
    stuffed = [b"." + line if line.startswith(b".") else line for line in lines]
    return b"\r\n".join(stuffed) + b"\r\n.\r\n"
