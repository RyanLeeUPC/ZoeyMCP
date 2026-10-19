"""The vault's SMTP connector: ``GET /config`` and ``POST /send`` (M4 design J).

The decisions are pure and live beside this module (:mod:`.mailmsg`, :mod:`.tunnel`,
:mod:`.smtpflow`, :mod:`.sendjournal`); this one does the I/O around them, in J.2's order:

1-5. the ``Idempotency-Key``, the request, the text rules, the expected addresses, the pause;
6-10. under one lock per connector: the key is new, the rolling limit allows one more, the bound
      secrets resolve, ``sending`` is journaled and fsynced, then the send itself.

The send runs in a worker thread, shielded from the caller: a gateway that hangs up doesn't cut a
send half way. It is never retried. TLS is verified against the mail server's name before AUTH,
and AUTH never goes out over a session without TLS.
"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
import smtplib
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol
from urllib.parse import urlsplit

import anyio
import certifi

from ...common.policy.schema import SMTPConnector
from .. import logs
from ..keys import KeySet
from ..store import SecretUnavailable
from . import mailmsg, sendjournal, smtpflow, tunnel
from .sendjournal import DailyLimit, InProgress, Journal, KeyReused, New, Replay

SEND_DEADLINE: Final = 60.0
CONNECT_TIMEOUT: Final = 10.0
REPLY_TIMEOUT: Final = 30.0
ROTATE_BYTES: Final = 4 * 2**20
MAX_JOURNAL_BYTES: Final = 64 * 2**20
JOURNAL_DIR: Final = "connectors"
_FILE = re.compile(r"^journal-([0-9]{13})\.jsonl$")
_APPEND: Final = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)


# --- the transport ------------------------------------------------------------------------------


@dataclass(frozen=True)
class SendResult:
    """How far a send got, and what the server last said."""

    phase: smtpflow.Phase
    final_dot_written: bool = False
    reply_code: int | None = None
    code: str | None = None  # an answer code that the phase alone doesn't say

    @property
    def outcome(self) -> smtpflow.Outcome:
        if self.code is not None and self.phase != "final_reply":
            return "failed"
        return smtpflow.outcome(self.phase, self.final_dot_written, self.reply_code)

    @property
    def answer_code(self) -> str:
        if self.outcome == "failed" and self.code is not None:
            return self.code
        return smtpflow.answer_code(self.phase, self.outcome)


class Transport(Protocol):
    def __call__(
        self,
        connector: SMTPConnector,
        *,
        proxy: str | None,
        username: str,
        password: str,
        sender: str,
        recipients: list[str],
        data: bytes,
        tls: ssl.SSLContext,
    ) -> SendResult: ...


class _ProxyRefused(OSError):
    pass


def _open_tunnel(proxy: str, host: str, port: int) -> socket.socket:
    """TCP to the proxy, ``CONNECT host:port``, and the reply head read byte by byte (J.4)."""
    parts = urlsplit(proxy)
    sock = socket.create_connection((parts.hostname or "", parts.port or 80), CONNECT_TIMEOUT)
    try:
        sock.settimeout(CONNECT_TIMEOUT)
        sock.sendall(tunnel.connect_request(host, port))
        head = b""
        while not tunnel.head_complete(head) and len(head) <= tunnel.MAX_HEAD_BYTES:
            byte = sock.recv(1)
            if not byte:
                break
            head += byte
        reply = tunnel.parse_connect_reply(head)
        if reply.kind != "open":
            raise _ProxyRefused(reply.kind)
        return sock
    except BaseException:
        sock.close()
        raise


class _ConnectorSMTP(smtplib.SMTP):
    """An SMTP client whose socket may come through a tunnel. The connector's host goes to
    ``__init__``, which records it before connecting, so TLS checks the mail server's name."""

    def __init__(self, connector: SMTPConnector, proxy: str | None, tls: ssl.SSLContext) -> None:
        self._proxy, self._tls_context = proxy, tls
        self._implicit = connector.tls == "implicit"
        self.reached: smtpflow.Phase = "tunnel"
        super().__init__(
            host=connector.host,
            port=connector.port,
            local_hostname=mailmsg.domain_of(connector.from_),
            timeout=REPLY_TIMEOUT,
        )

    def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
        if self._proxy is not None:
            sock = _open_tunnel(self._proxy, host, port)
        else:
            sock = socket.create_connection((host, port), CONNECT_TIMEOUT)
        sock.settimeout(timeout)
        self.reached = "tls" if self._implicit else "greeting"
        if self._implicit:
            sock = self._tls_context.wrap_socket(sock, server_hostname=host)
            self.reached = "greeting"
        return sock


def smtp_send(
    connector: SMTPConnector,
    *,
    proxy: str | None,
    username: str,
    password: str,
    sender: str,
    recipients: list[str],
    data: bytes,
    tls: ssl.SSLContext,
) -> SendResult:
    """One send, start to finish, in J.4's order. Never raises; never retries."""
    deadline = time.monotonic() + SEND_DEADLINE
    client: _ConnectorSMTP | None = None
    phase: smtpflow.Phase = "tunnel"
    final_dot = False

    def tick(next_phase: smtpflow.Phase) -> None:
        nonlocal phase
        phase = next_phase
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("send deadline")
        if client is not None and client.sock is not None:
            client.sock.settimeout(min(REPLY_TIMEOUT, remaining))

    try:
        try:
            client = _ConnectorSMTP(connector, proxy, tls)
        except _ProxyRefused:
            return SendResult("tunnel", code="proxy_refused")
        except ssl.SSLError:
            return SendResult("tls")
        except (OSError, smtplib.SMTPException) as exc:
            reached = getattr(exc, "smtp_code", None)
            return SendResult("greeting" if reached else "tunnel", reply_code=reached)
        tick("ehlo")
        code, _ = client.ehlo()
        if code != 250:
            return SendResult("ehlo", reply_code=code)
        if connector.tls == "starttls":
            tick("starttls")
            if not client.has_extn("starttls"):
                return SendResult("starttls", code="smtp_tls_failed")
            code, _ = client.starttls(context=tls)
            if code != 220:
                return SendResult("starttls", reply_code=code)
            tick("ehlo")
            code, _ = client.ehlo()
            if code != 250:
                return SendResult("ehlo", reply_code=code)
        tick("auth")
        sock = client.sock
        tls_up = isinstance(sock, ssl.SSLSocket)
        done = isinstance(sock, ssl.SSLSocket) and sock.version() is not None
        if not smtpflow.may_authenticate(tls_up, done):
            return SendResult("auth", code="smtp_tls_failed")
        if not client.has_extn("auth"):
            return SendResult("auth", code="smtp_auth_unsupported")
        try:
            client.login(username, password)
        except smtplib.SMTPAuthenticationError as exc:
            return SendResult("auth", reply_code=exc.smtp_code)
        tick("mail")
        code, _ = client.mail(sender)
        if code != 250:
            client.rset()
            return SendResult("mail", reply_code=code)
        tick("rcpt")
        for recipient in recipients:
            code, _ = client.rcpt(recipient)
            if code not in (250, 251):
                client.rset()  # all or nothing: nothing is sent
                return SendResult("rcpt", reply_code=code)
        tick("data")
        client.putcmd("data")
        code, _ = client.getreply()
        if code != 354:
            return SendResult("data", reply_code=code)
        tick("content")
        client.send(data)  # stuffed by mailmsg.data_bytes, ending with the final dot
        final_dot = True
        tick("final_reply")
        code, _ = client.getreply()
        return SendResult("final_reply", final_dot_written=True, reply_code=code)
    except ssl.SSLError:
        return SendResult("tls" if phase in ("tunnel", "greeting") else phase, final_dot)
    except (OSError, smtplib.SMTPException, TimeoutError):
        return SendResult(phase, final_dot_written=final_dot)
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                client.quit()
            with contextlib.suppress(Exception):
                client.close()


def default_tls() -> ssl.SSLContext:
    """certifi's roots, as the vault's HTTP clients use; TLS 1.2 or later; names checked."""
    context = ssl.create_default_context(cafile=certifi.where())
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


# --- the journal on disk ------------------------------------------------------------------------


@dataclass
class JournalFile:
    """One connector's send journal: ``journal-<first ms>.jsonl`` files, mode 0600."""

    directory: Path
    clock_ms: Callable[[], int]

    def files(self) -> list[Path]:
        if not self.directory.exists():
            return []
        return sorted(p for p in self.directory.iterdir() if _FILE.fullmatch(p.name))

    def lines(self) -> list[bytes]:
        found: list[bytes] = []
        for path in self.files():
            found.extend(path.read_bytes().splitlines(keepends=True))
        return found

    def append(self, line: bytes) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        found = self.files()
        current = found[-1] if found else None
        if current is None or current.stat().st_size + len(line) > ROTATE_BYTES:
            # Named by the time, and always after the last file, even within one millisecond.
            last = _first_ms(current) if current else -1
            current = self.directory / f"journal-{max(self.clock_ms(), last + 1):013d}.jsonl"
        descriptor = os.open(current, _APPEND, 0o600)
        try:
            if os.write(descriptor, line) != len(line):
                raise OSError("short write to the send journal")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._prune()

    def _prune(self) -> None:
        found = self.files()
        sizes = {p: p.stat().st_size for p in found}
        total = sum(sizes.values())
        horizon = self.clock_ms() - sendjournal.RECORD_DAYS * sendjournal.DAY_MS
        for path in found[:-1]:
            old = _first_ms(path) < horizon
            if total <= MAX_JOURNAL_BYTES and not old:
                break
            with contextlib.suppress(OSError):
                path.unlink()
                total -= sizes[path]


def _first_ms(path: Path) -> int:
    found = _FILE.fullmatch(path.name)
    assert found is not None  # noqa: S101 - files() lists only matching names
    return int(found.group(1))


def random_message_id(connector: SMTPConnector) -> str:
    return mailmsg.message_id(connector, secrets.token_hex(16))


def now_ms() -> int:
    return int(time.time() * 1000)


# --- the connector ------------------------------------------------------------------------------


@dataclass(frozen=True)
class Answer:
    """What the vault answers: a status, a JSON body, and the headers it needs."""

    status: int
    body: dict[str, Any]
    retry_after: int | None = None
    replayed: bool = False


def _refused(connector: str, status: int, code: str, **extra: str) -> Answer:
    """A refusal before anything was sent. ``extra`` names a field and a rule, never a value."""
    logs.event("connector_refused", connector=connector, status=status, code=code, **extra)
    return Answer(status, {"error": code, "code": code, **extra})


@dataclass
class SmtpConnectors:
    """Every SMTP connector of one vault: journals, locks and the send itself."""

    state_dir: Path
    keys: KeySet
    transport: Transport = smtp_send
    tls: ssl.SSLContext = field(default_factory=default_tls)
    clock_ms: Callable[[], int] = now_ms
    # The self-test's recorder uses fixed ones; a real send's is random.
    message_id: Callable[[SMTPConnector], str] = random_message_id
    _journals: dict[str, tuple[JournalFile, Journal]] = field(default_factory=dict)
    _locks: dict[str, anyio.Lock] = field(default_factory=dict)

    def _journal(self, name: str) -> tuple[JournalFile, Journal]:
        found = self._journals.get(name)
        if found is None:
            file = JournalFile(self.state_dir / JOURNAL_DIR / name, self.clock_ms)
            journal, _ = sendjournal.rebuild(file.lines())
            found = self._journals[name] = (file, journal)
        return found

    def recover(self, names: list[str]) -> dict[str, int]:
        """At vault start: every ``sending`` with no ending gets ``unknown`` (J.3). A replay of
        such a key answers ``unknown``; nothing is sent again."""
        recovered: dict[str, int] = {}
        for name in names:
            file, journal = self._journal(name)
            unfinished = journal.unfinished()
            for key in unfinished:
                record = {"ts": self.clock_ms(), "key": key, "phase": "vault_restarted"}
                file.append(sendjournal.encode("unknown", **record))
                journal.apply({"kind": "unknown", **record})
            if unfinished:
                logs.event("connector_journal_recovered", connector=name, unknown=len(unfinished))
                recovered[name] = len(unfinished)
        return recovered

    def config(self, name: str, connector: SMTPConnector) -> Answer:
        _, journal = self._journal(name)
        return Answer(
            200,
            {
                "from": connector.from_,
                "to": list(connector.to),
                "max_per_day": connector.max_per_day,
                "sent_24h": journal.sent_24h(self.clock_ms()),
                "paused": connector.paused,
                "max_subject_chars": connector.max_subject_chars,
                "max_body_chars": connector.max_body_chars,
            },
        )

    async def send(
        self,
        name: str,
        connector: SMTPConnector,
        *,
        key: str | None,
        content_type: str | None,
        body: bytes,
        proxy: str | None,
        credentials: Callable[[], tuple[str, str]],
    ) -> Answer:
        """``POST /send``, in J.2's order."""
        if not mailmsg.key_ok(key):
            return _refused(name, 400, "bad_request", field="Idempotency-Key", rule="format")
        assert key is not None  # noqa: S101 - key_ok checked it
        if (content_type or "").split(";")[0].strip().lower() != "application/json":
            return _refused(name, 400, "bad_request", rule="content_type")
        parsed = mailmsg.parse_send(body, connector)
        if isinstance(parsed, mailmsg.Rejection):
            extra = {k: v for k, v in (("field", parsed.field), ("rule", parsed.rule)) if v}
            return _refused(name, parsed.status, parsed.code, **extra)
        if connector.paused:
            return _refused(name, 503, "connector_paused")
        lock = self._locks.setdefault(name, anyio.Lock())
        async with lock:
            return await self._send_locked(name, connector, key, parsed, proxy, credentials)

    async def _send_locked(
        self,
        name: str,
        connector: SMTPConnector,
        key: str,
        request: mailmsg.SendRequest,
        proxy: str | None,
        credentials: Callable[[], tuple[str, str]],
    ) -> Answer:
        file, journal = self._journal(name)
        audit = self.keys.audit_key
        req_hmac = audit.digest(request.canonical)
        now = self.clock_ms()
        journal.forget_old_keys(now)  # keys are remembered for 30 days (J.3)
        decision = journal.decide(key, req_hmac, now, connector.max_per_day)
        if isinstance(decision, Replay):
            status, data = sendjournal.answer(decision.terminal, journal.sent_24h(now))
            return Answer(status, data, replayed=True)
        if isinstance(decision, InProgress):
            return _refused(name, 409, "in_progress")
        if isinstance(decision, KeyReused):
            return _refused(name, 409, "key_reused")
        if isinstance(decision, DailyLimit):
            answer = _refused(name, 429, "daily_limit")
            return Answer(answer.status, answer.body, retry_after=decision.retry_after_s)
        assert isinstance(decision, New)  # noqa: S101 - the decisions are exhaustive
        try:
            username, password = credentials()
        except SecretUnavailable:
            return _refused(name, 502, "credential_unavailable")
        sending = {
            "ts": now,
            "key": key,
            "req_hmac": req_hmac,
            "key_id": self.keys.key_id,
            "subject_chars": len(request.subject),
            "body_chars": len(request.body),
        }
        try:
            await anyio.to_thread.run_sync(file.append, sendjournal.encode("sending", **sending))
        except OSError:
            logs.event("connector_journal_not_written", connector=name, level="critical")
            return _refused(name, 503, "journal_unavailable")
        journal.apply({"kind": "sending", **sending})
        message_id = self.message_id(connector)
        message = mailmsg.build_message(
            request, connector, message_id=message_id, date=datetime.now(UTC)
        )
        sender, recipients = mailmsg.envelope(connector)
        started = time.monotonic()
        with anyio.CancelScope(shield=True):  # a gateway that hangs up doesn't cut a send
            result = await anyio.to_thread.run_sync(
                lambda: self.transport(
                    connector,
                    proxy=proxy,
                    username=username,
                    password=password,
                    sender=sender,
                    recipients=recipients,
                    data=mailmsg.data_bytes(message),
                    tls=self.tls,
                )
            )
            answer = await self._finish(name, file, journal, key, message_id, result, started)
        return answer  # noqa: RET504 - mypy needs the return outside the shield

    async def _finish(
        self,
        name: str,
        file: JournalFile,
        journal: Journal,
        key: str,
        message_id: str,
        result: SendResult,
        started: float,
    ) -> Answer:
        outcome = result.outcome
        record: dict[str, Any] = {"ts": self.clock_ms(), "key": key}
        if outcome == "sent":
            record |= {"message_id": message_id, "smtp_code": result.reply_code}
        elif outcome == "unknown":
            record |= {"phase": result.phase}
        else:
            record |= {
                "phase": result.phase,
                "code": result.answer_code,
                "smtp_code": result.reply_code,
            }
        try:
            await anyio.to_thread.run_sync(file.append, sendjournal.encode(outcome, **record))
        except OSError:
            logs.event("connector_journal_not_written", connector=name, level="critical")
        journal.apply({"kind": outcome, **record})
        sent_24h = journal.sent_24h(self.clock_ms())
        logs.event(
            "connector_send",
            connector=name,
            outcome=outcome,
            phase=result.phase,
            smtp_code=result.reply_code,
            sent_24h=sent_24h,
            duration_ms=round((time.monotonic() - started) * 1000, 1),
        )
        if outcome == "sent":
            return Answer(200, {"message_id": message_id, "sent_24h": sent_24h})
        code = result.answer_code
        return Answer(502, {"error": code, "code": code})


def connector_names(connectors: Mapping[str, Any]) -> list[str]:
    return sorted(name for name, c in connectors.items() if isinstance(c, SMTPConnector))
