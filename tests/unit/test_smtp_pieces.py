"""The SMTP connector's pure pieces: the CONNECT tunnel, the send's decisions, the send journal and
the audit key (M4 design J.3, J.4)."""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zoeymcp.common import logs
from zoeymcp.vault.connectors import sendjournal, smtpflow, tunnel
from zoeymcp.vault.connectors.sendjournal import (
    DAY_MS,
    DailyLimit,
    InProgress,
    Journal,
    JournalError,
    KeyReused,
    New,
    Replay,
)
from zoeymcp.vault.keys import CONTEXT_AUDIT, AuditKey, KeySet, derive

CRLF = chr(13) + chr(10)
HMAC_A = "hmac-sha256:" + "a" * 64
HMAC_B = "hmac-sha256:" + "b" * 64
KEY = "3f9c0a17d2b84e65.1"


# --- the tunnel ---------------------------------------------------------------------------------


def head(*lines: str) -> bytes:
    return (CRLF.join(lines) + CRLF + CRLF).encode()


def test_the_connect_request_names_only_the_mail_server() -> None:
    assert tunnel.connect_request("smtp.mail.example", 465) == (
        b"CONNECT smtp.mail.example:465 HTTP/1.1\r\nHost: smtp.mail.example:465\r\n\r\n"
    )


@pytest.mark.parametrize(
    ("reply", "kind", "status"),
    [
        (head("HTTP/1.1 200 Connection established"), "open", 200),
        (head("HTTP/1.0 200"), "open", 200),
        (head("HTTP/1.1 200 OK", "Proxy-Agent: x"), "open", 200),
        (head("HTTP/1.1 403 Forbidden"), "refused", 403),
        (head("HTTP/1.1 407 Proxy Authentication Required"), "refused", 407),
        (head("HTTP/1.1 201 Created"), "refused", 201),
        (head("HTTP/2 200"), "broken", None),
        (head("SMTP 220 ready"), "broken", None),
        (head("HTTP/1.1 2000 x"), "broken", None),
        (b"HTTP/1.1 200 OK" + CRLF.encode(), "broken", None),  # no blank line yet
        (head("HTTP/1.1 200 OK", "X: " + "y" * 9000), "broken", None),  # over 8 KiB
    ],
)
def test_the_proxys_reply(reply: bytes, kind: str, status: int | None) -> None:
    assert tunnel.parse_connect_reply(reply) == tunnel.Reply(kind, status)  # type: ignore[arg-type]


def test_a_head_is_complete_only_at_the_blank_line() -> None:
    assert not tunnel.head_complete(b"HTTP/1.1 200 OK\r\n")
    assert tunnel.head_complete(b"HTTP/1.1 200 OK\r\n\r\n")


# --- the send's decisions -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tls", "handshake", "allowed"),
    [(True, True, True), (True, False, False), (False, True, False), (False, False, False)],
)
def test_auth_only_over_an_established_tls_session(
    tls: bool, handshake: bool, allowed: bool
) -> None:
    assert smtpflow.may_authenticate(tls, handshake) is allowed


@pytest.mark.parametrize("phase", [p for p in smtpflow.PHASES if p != "final_reply"])
def test_a_failure_before_the_final_dot_sent_nothing(phase: Any) -> None:
    for written in (False, True):
        for code in (None, 250, 554):
            assert smtpflow.outcome(phase, written, code) == "failed"


@pytest.mark.parametrize(
    ("written", "code", "expected"),
    [
        (False, None, "failed"),
        (False, 250, "failed"),
        (True, None, "unknown"),
        (True, 250, "sent"),
        (True, 200, "sent"),
        (True, 299, "sent"),
        (True, 300, "failed"),
        (True, 199, "failed"),
        (True, 451, "failed"),
        (True, 554, "failed"),
    ],
)
def test_after_the_final_dot(written: bool, code: int | None, expected: str) -> None:
    assert smtpflow.outcome("final_reply", written, code) == expected


def test_answer_codes() -> None:
    assert smtpflow.answer_code("final_reply", "unknown") == "smtp_outcome_unknown"
    assert smtpflow.answer_code("rcpt", "failed") == "smtp_refused"
    assert smtpflow.answer_code("auth", "failed") == "smtp_auth_failed"
    assert smtpflow.answer_code("starttls", "failed") == "smtp_tls_failed"
    assert smtpflow.answer_code("tls", "failed") == "smtp_tls_failed"
    assert smtpflow.answer_code("tunnel", "failed") == "smtp_unreachable"
    assert set(smtpflow.FAILED_CODES) == set(smtpflow.PHASES)


# --- the journal --------------------------------------------------------------------------------


def sending(key: str = KEY, ts: int = 1000, req: str = HMAC_A) -> dict[str, Any]:
    return {
        "kind": "sending",
        "ts": ts,
        "key": key,
        "req_hmac": req,
        "key_id": "0123456789abcdef",
        "subject_chars": 17,
        "body_chars": 400,
    }


def sent(key: str = KEY, ts: int = 1001) -> dict[str, Any]:
    return {
        "kind": "sent",
        "ts": ts,
        "key": key,
        "message_id": "<a1@mail.example>",
        "smtp_code": 250,
    }


def test_records_round_trip_and_hold_no_values() -> None:
    for record in (
        sending(),
        sent(),
        {
            "kind": "failed",
            "ts": 2,
            "key": KEY,
            "phase": "rcpt",
            "code": "smtp_refused",
            "smtp_code": 550,
        },
        {"kind": "unknown", "ts": 3, "key": KEY, "phase": "final_reply"},
    ):
        fields: dict[str, Any] = {k: v for k, v in record.items() if k != "kind"}
        kind: Any = record["kind"]
        line = sendjournal.encode(kind, **fields)
        assert line.endswith(b"\n")
        assert sendjournal.parse(line) == record


@pytest.mark.parametrize(
    "record",
    [
        {"kind": "sending", "ts": 1},
        {**sending(), "subject": "Hello"},
        {**sending(), "key": "short"},
        {**sending(), "key": KEY + chr(10)},
        {**sending(), "req_hmac": "sha256:" + "a" * 64},
        {**sending(), "ts": -1},
        {**sending(), "ts": True},
        {**sent(), "smtp_code": 99},
        {**sent(), "message_id": "no brackets"},
        {"kind": "deleted", "ts": 1, "key": KEY},
    ],
)
def test_bad_records(record: dict[str, Any]) -> None:
    with pytest.raises(JournalError):
        sendjournal.encode(record.pop("kind"), **record)


def test_parse_refuses_garbage() -> None:
    for line in (b"not json\n", b"[]\n", b'{"kind": "sent"}\n'):
        with pytest.raises(JournalError):
            sendjournal.parse(line)


def test_a_new_key_is_sent_and_a_finished_one_replays() -> None:
    journal = Journal()
    assert journal.decide(KEY, HMAC_A, 1000, max_per_day=20) == New()
    journal.apply(sending())
    assert journal.decide(KEY, HMAC_A, 1500, max_per_day=20) == InProgress()
    journal.apply(sent())
    assert journal.decide(KEY, HMAC_A, 2000, max_per_day=20) == Replay(sent())
    assert journal.decide(KEY, HMAC_B, 2000, max_per_day=20) == KeyReused()
    # Only the first ending of a key counts.
    journal.apply({"kind": "unknown", "ts": 3000, "key": KEY, "phase": "final_reply"})
    assert journal.decide(KEY, HMAC_A, 4000, max_per_day=20) == Replay(sent())


def test_the_limit_is_a_rolling_day_of_attempts() -> None:
    journal = Journal()
    for index in range(3):
        journal.apply(sending(f"key-{index:013d}", ts=index * 1000))
    assert journal.decide("key-new-0000000000", HMAC_A, 3000, max_per_day=3) == DailyLimit(
        DAY_MS // 1000 - 3
    )
    assert journal.sent_24h(DAY_MS) == 2  # the first attempt left the window
    assert journal.decide("key-new-0000000000", HMAC_A, DAY_MS, max_per_day=3) == New()
    # A failed attempt counts too.
    journal.apply(
        {
            "kind": "failed",
            "ts": 1,
            "key": "key-0000000000000",
            "phase": "auth",
            "code": "smtp_auth_failed",
            "smtp_code": 535,
        }
    )
    assert journal.sent_24h(DAY_MS) == 2


def test_retry_after_is_never_zero() -> None:
    journal = Journal()
    journal.apply(sending(ts=0))
    assert journal.decide("key-new-0000000000", HMAC_A, DAY_MS - 1, max_per_day=1) == DailyLimit(1)


def test_recovery_and_rebuild() -> None:
    lines = [
        sendjournal.encode(
            "sending", **{k: v for k, v in sending("key-a-00000000000").items() if k != "kind"}
        ),
        sendjournal.encode(
            "sending", **{k: v for k, v in sending("key-b-00000000000").items() if k != "kind"}
        ),
        sendjournal.encode(
            "sent", **{k: v for k, v in sent("key-a-00000000000").items() if k != "kind"}
        ),
        b"torn line\n",
    ]
    journal, bad = sendjournal.rebuild(lines)
    assert bad == 1
    assert journal.unfinished() == ["key-b-00000000000"]
    assert journal.sent_24h(2000) == 2


def test_old_finished_keys_are_forgotten() -> None:
    journal = Journal()
    journal.apply(sending("key-old-000000000", ts=0))
    journal.apply(sent("key-old-000000000", ts=1))
    journal.apply(sending("key-open-00000000", ts=0))
    journal.forget_old_keys(31 * DAY_MS)
    assert list(journal.attempts) == ["key-open-00000000"]  # an unfinished key is kept


def test_answers_replayed() -> None:
    assert sendjournal.answer(sent(), 4) == (
        200,
        {"message_id": "<a1@mail.example>", "sent_24h": 4},
    )
    failed = {
        "kind": "failed",
        "ts": 1,
        "key": KEY,
        "phase": "rcpt",
        "code": "smtp_refused",
        "smtp_code": 550,
    }
    assert sendjournal.answer(failed, 1) == (502, {"error": "smtp_refused", "code": "smtp_refused"})
    unknown = {"kind": "unknown", "ts": 1, "key": KEY, "phase": "final_reply"}
    assert sendjournal.answer(unknown, 1)[1]["code"] == "smtp_outcome_unknown"


@given(st.lists(st.integers(min_value=0, max_value=3 * DAY_MS), max_size=30), st.integers(1, 10))
def test_the_limit_never_admits_more_than_max_per_day(times: list[int], cap: int) -> None:
    journal = Journal()
    admitted: list[int] = []
    for index, now in enumerate(sorted(times)):
        key = f"key-{index:013d}"
        if journal.decide(key, HMAC_A, now, max_per_day=cap) == New():
            journal.apply(sending(key, ts=now))
            admitted.append(now)
    for now in admitted:
        assert sum(1 for t in admitted if now - DAY_MS < t <= now) <= cap


# --- the audit key ------------------------------------------------------------------------------


def test_the_audit_key_is_its_own_and_never_shows() -> None:
    master = bytes(range(32))
    keys = KeySet.from_master(master)
    audit = keys.audit_key
    assert isinstance(audit, AuditKey)
    assert audit.digest(b"request") == AuditKey(derive(master, CONTEXT_AUDIT)).digest(b"request")
    assert audit.digest(b"request") != AuditKey(keys.store_key).digest(b"request")
    assert derive(master, CONTEXT_AUDIT) not in {keys.store_key, keys.config_key}
    assert audit.digest(b"x").startswith("hmac-sha256:")
    assert "hidden" in repr(audit)
    with pytest.raises(TypeError):
        logs.Log("vault").event("probe", key=audit)
