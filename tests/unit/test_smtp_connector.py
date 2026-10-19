"""Effect tests for the vault's SMTP connector (M4 design J): what reaches the mail server, the
proxy and the journal, and what never does.

The mail server is :class:`SmtpFake` with a certificate from a test CA; the connector trusts that
CA alone. Each test asserts what the fake saw: the sessions, AUTH, the envelope and the message.
"""

from __future__ import annotations

import asyncio
import email
import email.policy
import io
import json
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import httpx
import pytest

from tests.acceptance.tls import ProviderCA, make_ca
from tests.fakes.connect_proxy import ConnectProxy, ProxySwitch, serve_proxy
from tests.fakes.smtp_server import PASSWORD, USERNAME, SmtpFake, Switch, serve_smtp
from zoeymcp.cli.main import main
from zoeymcp.common.policy import Policy
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.vault import logs
from zoeymcp.vault.app import GATEWAY_HEADER, REFUSAL_HEADER, REPLAYED_HEADER, VaultApp
from zoeymcp.vault.connectors import sendjournal, smtp
from zoeymcp.vault.connectors.smtp import JournalFile, SmtpConnectors
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.store import SecretStore, smtp_binding

KEYS = KeySet.from_master(bytes(range(32)))
SENDER = "Agent <agent@mail.example>"
TO = ["partner@mail.example"]
START_MS = 1_800_000_000_000


@dataclass
class Clock:
    now: int = START_MS

    def __call__(self) -> int:
        return self.now


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("connector-ca"))


@pytest.fixture(scope="module")
def other_ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("other-ca"))


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


pytestmark = pytest.mark.anyio


def mail_policy(
    port: int, *, proxy: str | None = None, callers: Any = None, **connector: Any
) -> Policy:
    document: dict[str, Any] = {
        "version": 1,
        "mode": "declarative",
        "admin": {"listen": "0.0.0.0:8081", "hosts": ["localhost"]},
        "connectors": {
            "mail-out": {
                "kind": "smtp",
                "host": "localhost",
                "port": port,
                "username": USERNAME,
                "password": "store:mail-pass",
                "from": SENDER,
                "to": TO,
                **connector,
            }
        },
        "routes": [
            {
                "name": "mail-send",
                "prefix": "/mail",
                "connector": "mail-out",
                "callers": callers or ["gateway"],
                "rules": [
                    {"methods": ["GET"], "paths": ["/config"]},
                    {"methods": ["POST"], "paths": ["/send"]},
                ],
            }
        ],
    }
    if proxy is not None:
        document["egress_proxy"] = proxy
    return Policy.model_validate(document)


class Rig:
    """A vault with one connector, ``mail-out``, whose password is stored for its binding."""

    def __init__(
        self,
        state: Path,
        policy: Policy,
        tls: ProviderCA,
        *,
        clock: Clock | None = None,
        store_to: list[str] | None = None,
    ) -> None:
        self.state, self.ca, self.clock = state, tls, clock or Clock()
        self.store = SecretStore(state, KEYS)
        self.store.load()
        connector = policy.connectors["mail-out"]
        if "mail-pass" not in self.store.names():
            binding = smtp_binding(
                connector.host, connector.port, connector.from_, store_to or connector.to
            )
            self.store.put("mail-pass", PASSWORD, binding)
        self.app = self._app(policy)

    def _app(self, policy: Policy) -> VaultApp:
        connectors = SmtpConnectors(
            self.state, KEYS, tls=self.ca.client_context(), clock_ms=self.clock
        )
        return VaultApp(policy, self.store, KEYS, environ={}, connectors=connectors)

    def restart(self, policy: Policy) -> dict[str, int]:
        self.app = self._app(policy)
        return self.app.connectors.recover(["mail-out"])

    async def call(
        self, method: str, path: str, *, headers: dict[str, str] | None = None, body: Any = None
    ) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.app, client=("127.0.0.1", 40000))
        sent = {GATEWAY_HEADER: KEYS.gateway_key(1), **(headers or {})}
        content = body if isinstance(body, bytes) else json.dumps(body).encode()
        async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
            return await client.request(method, path, headers=sent, content=content)

    async def send(
        self,
        key: str = "key-0001-aaaaaaaaaaaa",
        *,
        headers: dict[str, str] | None = None,
        **fields: Any,
    ) -> httpx.Response:
        request = {
            "expect_from": SENDER,
            "expect_to": TO,
            "subject": "Hello",
            "body": "One line.\n.A line with a leading dot.",
            **fields,
        }
        sent = {"idempotency-key": key, "content-type": "application/json", **(headers or {})}
        return await self.call("POST", "/mail/send", headers=sent, body=request)

    def journal(self) -> list[dict[str, Any]]:
        file = JournalFile(self.state / smtp.JOURNAL_DIR / "mail-out", self.clock)
        return [sendjournal.parse(line) for line in file.lines()]


@pytest.fixture
def implicit(ca: ProviderCA, tmp_path: Path) -> Iterator[tuple[SmtpFake, int]]:
    fake = SmtpFake(ca, mode="implicit")
    with serve_smtp(fake, tmp_path) as (_, port):
        yield fake, port


@pytest.fixture
async def rig(implicit: tuple[SmtpFake, int], ca: ProviderCA, tmp_path: Path) -> AsyncIterator[Rig]:
    _, port = implicit
    r = Rig(tmp_path / "state", mail_policy(port), ca)
    yield r
    await r.app.aclose()


def message_of(fake: SmtpFake) -> email.message.EmailMessage:
    [raw] = fake.messages
    parsed = email.message_from_bytes(raw, policy=email.policy.SMTP)
    assert isinstance(parsed, email.message.EmailMessage)
    return parsed


# --- GET /config ----------------------------------------------------------------------------------


async def test_config_shows_the_limits_and_never_the_host_or_the_credentials(rig: Rig) -> None:
    response = await rig.call("GET", "/mail/config")
    assert response.status_code == 200
    assert response.json() == {
        "from": SENDER,
        "to": TO,
        "max_per_day": 20,
        "sent_24h": 0,
        "paused": False,
        "max_subject_chars": 150,
        "max_body_chars": 2200,
    }
    assert REFUSAL_HEADER not in response.headers
    assert "localhost" not in response.text
    assert PASSWORD not in response.text


async def test_other_methods_and_paths_are_refused(rig: Rig) -> None:
    assert (await rig.call("GET", "/mail/send")).status_code == 403  # no rule
    assert (await rig.call("POST", "/mail/config")).status_code == 403


async def test_only_the_routes_callers_reach_it(
    implicit: tuple[SmtpFake, int], ca: ProviderCA, tmp_path: Path
) -> None:
    fake, port = implicit
    r = Rig(tmp_path, mail_policy(port), ca)
    transport = httpx.ASGITransport(app=r.app, client=("127.0.0.1", 40000))
    async with httpx.AsyncClient(transport=transport, base_url="http://vault") as client:
        response = await client.post("/mail/send", headers={"Authorization": "Bearer ph-x-0001"})
    assert response.status_code == 403
    assert fake.sessions == []
    await r.app.aclose()


# --- a send ---------------------------------------------------------------------------------------


async def test_a_send_over_implicit_tls(
    rig: Rig, implicit: tuple[SmtpFake, int], log_buffer: io.StringIO
) -> None:
    fake, _ = implicit
    response = await rig.send(subject="Quarterly figures", body="Line one.\n.dot first\nDone.")
    assert response.status_code == 200
    answer = response.json()
    assert answer["sent_24h"] == 1
    [session] = fake.sessions
    assert session.ehlo == ["mail.example"]  # the From domain, not this host's name
    assert session.tls_at_auth == [True]
    assert (session.mail_from, session.rcpt_to) == ("agent@mail.example", TO)
    message = message_of(fake)
    assert message["From"] == SENDER
    assert message["To"] == "partner@mail.example"
    assert message["Subject"] == "Quarterly figures"
    assert message["Message-ID"] == answer["message_id"]
    assert answer["message_id"].endswith("@mail.example>")
    assert message["Auto-Submitted"] == "auto-generated"
    assert message.get_content().replace("\r\n", "\n") == "Line one.\n.dot first\nDone.\n"
    assert [r["kind"] for r in rig.journal()] == ["sending", "sent"]
    sending = rig.journal()[0]
    assert sending["key_id"] == KEYS.key_id
    assert sending["req_hmac"].startswith("hmac-sha256:")
    assert (sending["subject_chars"], sending["body_chars"]) == (17, 26)
    text = log_buffer.getvalue()
    assert PASSWORD not in text
    assert "Quarterly" not in text
    assert "Line one" not in text


async def test_a_send_over_starttls(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="starttls")
    with serve_smtp(fake, tmp_path) as (_, port):
        r = Rig(tmp_path / "state", mail_policy(port, tls="starttls"), ca)
        response = await r.send()
        await r.app.aclose()
    assert response.status_code == 200
    [session] = fake.sessions
    assert session.tls_at_auth == [True]
    verbs = [c.split(" ")[0].upper() for c in session.commands[:3]]
    assert verbs == ["EHLO", "STARTTLS", "EHLO"]


async def test_a_replay_sends_nothing_and_says_so(rig: Rig, implicit: tuple[SmtpFake, int]) -> None:
    fake, _ = implicit
    first = await rig.send()
    again = await rig.send()
    assert again.status_code == 200
    assert again.headers[REPLAYED_HEADER] == "1"
    assert again.json()["message_id"] == first.json()["message_id"]
    assert len(fake.messages) == 1
    other = await rig.send(subject="Something else")
    assert (other.status_code, other.json()["code"]) == (409, "key_reused")
    assert len(fake.sessions) == 1


async def test_the_same_key_at_once_is_one_transaction(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, switches={Switch.SLOW})
    with serve_smtp(fake, tmp_path) as (_, port):
        r = Rig(tmp_path / "state", mail_policy(port), ca)
        first, second = await asyncio.gather(r.send(), r.send())
        await r.app.aclose()
    assert sorted([first.status_code, second.status_code]) == [200, 200]
    assert len(fake.sessions) == 1
    assert len(fake.messages) == 1
    assert REPLAYED_HEADER in first.headers or REPLAYED_HEADER in second.headers


# --- refusals before any connection ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("key", "headers", "fields", "status", "rule"),
    [
        ("short", {}, {}, 400, "format"),
        ("key-0001-aaaaaaaaaaaa", {"content-type": "text/plain"}, {}, 400, "content_type"),
        ("key-0001-aaaaaaaaaaaa", {}, {"cc": ["x@mail.example"]}, 400, "unknown_key"),
        ("key-0001-aaaaaaaaaaaa", {}, {"to": ["x@mail.example"]}, 400, "unknown_key"),
        ("key-0001-aaaaaaaaaaaa", {}, {"subject": "two\nlines"}, 400, "text_rules"),
        ("key-0001-aaaaaaaaaaaa", {}, {"body": "x" * 2201}, 400, "text_rules"),
        ("key-0001-aaaaaaaaaaaa", {}, {"expect_to": ["x@mail.example"]}, 409, None),
    ],
)
async def test_refused_before_any_connection(
    rig: Rig,
    implicit: tuple[SmtpFake, int],
    key: str,
    headers: dict[str, str],
    fields: dict[str, Any],
    status: int,
    rule: str | None,
) -> None:
    fake, _ = implicit
    response = await rig.send(key, headers=headers, **fields)
    assert response.status_code == status
    assert response.headers[REFUSAL_HEADER] == "refused"
    assert response.json().get("rule") == rule
    assert "x@mail.example" not in response.text
    assert fake.sessions == []
    assert rig.journal() == []


async def test_paused_refuses_then_works_again(
    implicit: tuple[SmtpFake, int], ca: ProviderCA, tmp_path: Path
) -> None:
    fake, port = implicit
    r = Rig(tmp_path, mail_policy(port, paused=True), ca)
    response = await r.send()
    assert (response.status_code, response.json()["code"]) == (503, "connector_paused")
    assert (await r.call("GET", "/mail/config")).json()["paused"] is True
    assert fake.sessions == []
    r.app.reload(mail_policy(port))  # outside the binding: no secret set needed
    assert (await r.send()).status_code == 200
    await r.app.aclose()


async def test_the_daily_limit_survives_a_restart(
    implicit: tuple[SmtpFake, int], ca: ProviderCA, tmp_path: Path
) -> None:
    fake, port = implicit
    policy = mail_policy(port, max_per_day=2)
    r = Rig(tmp_path, policy, ca)
    for n in range(2):
        assert (await r.send(f"key-{n:04d}-aaaaaaaaaaaa")).status_code == 200
        r.clock.now += 1000
    refused = await r.send("key-0002-aaaaaaaaaaaa")
    assert (refused.status_code, refused.json()["code"]) == (429, "daily_limit")
    assert refused.headers["retry-after"] == str(24 * 3600 - 2)
    assert len(fake.sessions) == 2
    r.restart(policy)
    assert (await r.send("key-0003-aaaaaaaaaaaa")).status_code == 429
    r.clock.now = START_MS + sendjournal.DAY_MS
    allowed = await r.send("key-0004-aaaaaaaaaaaa")
    assert (allowed.status_code, allowed.json()["sent_24h"]) == (200, 2)
    await r.app.aclose()


async def test_a_changed_recipient_list_needs_the_secret_again(
    implicit: tuple[SmtpFake, int], ca: ProviderCA, tmp_path: Path
) -> None:
    fake, port = implicit
    r = Rig(tmp_path, mail_policy(port), ca, store_to=["someone@mail.example"])
    response = await r.send()
    assert (response.status_code, response.json()["code"]) == (502, "credential_unavailable")
    assert fake.sessions == []
    assert r.journal() == []  # not counted
    await r.app.aclose()


async def test_a_missing_password(
    implicit: tuple[SmtpFake, int], ca: ProviderCA, tmp_path: Path
) -> None:
    fake, port = implicit
    r = Rig(tmp_path, mail_policy(port, password="store:other-pass"), ca)
    response = await r.send()
    assert (response.status_code, response.json()["code"]) == (502, "credential_unavailable")
    assert fake.sessions == []
    await r.app.aclose()


async def test_a_journal_that_cant_be_written(
    rig: Rig, implicit: tuple[SmtpFake, int], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake, _ = implicit

    def broken(self: JournalFile, line: bytes) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(JournalFile, "append", broken)
    response = await rig.send()
    assert (response.status_code, response.json()["code"]) == (503, "journal_unavailable")
    assert fake.sessions == []


# --- failures at the mail server ------------------------------------------------------------------


async def test_a_refused_recipient_sends_nothing(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, switches={Switch.REJECT_ONE_RCPT})
    with serve_smtp(fake, tmp_path) as (_, port):
        policy = mail_policy(port, to=["a@mail.example", "b@mail.example"])
        r = Rig(tmp_path / "state", policy, ca)
        response = await r.send(expect_to=["a@mail.example", "b@mail.example"])
        await r.app.aclose()
    assert (response.status_code, response.json()["code"]) == (502, "smtp_refused")
    [session] = fake.sessions
    verbs = [c.split(" ")[0].upper() for c in session.commands]
    assert "RSET" in verbs
    assert "DATA" not in verbs
    assert [r["kind"] for r in r.journal()] == ["sending", "failed"]
    assert r.journal()[1]["smtp_code"] == 550


async def test_a_drop_after_the_final_dot_is_unknown_and_never_retried(
    ca: ProviderCA, tmp_path: Path
) -> None:
    fake = SmtpFake(ca, switches={Switch.DROP_AFTER_DOT})
    with serve_smtp(fake, tmp_path) as (_, port):
        r = Rig(tmp_path / "state", mail_policy(port), ca)
        response = await r.send()
        again = await r.send()
        await r.app.aclose()
    assert (response.status_code, response.json()["code"]) == (502, "smtp_outcome_unknown")
    assert again.json()["code"] == "smtp_outcome_unknown"
    assert again.headers[REPLAYED_HEADER] == "1"
    assert len(fake.sessions) == 1
    assert [r["kind"] for r in r.journal()] == ["sending", "unknown"]


async def test_a_wrong_password(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, switches={Switch.AUTH_535, Switch.ECHO_USERNAME})
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        with serve_smtp(fake, tmp_path) as (_, port):
            r = Rig(tmp_path / "state", mail_policy(port), ca)
            response = await r.send()
            await r.app.aclose()
    finally:
        logs.set_stream(None)
    assert (response.status_code, response.json()["code"]) == (502, "smtp_auth_failed")
    assert USERNAME not in response.text
    assert "authentication failed" not in buffer.getvalue()  # reply text is never logged


async def test_a_certificate_from_another_ca(
    ca: ProviderCA, other_ca: ProviderCA, tmp_path: Path
) -> None:
    fake = SmtpFake(other_ca)
    with serve_smtp(fake, tmp_path) as (_, port):
        r = Rig(tmp_path / "state", mail_policy(port), ca)
        response = await r.send()
        await r.app.aclose()
    assert (response.status_code, response.json()["code"]) == (502, "smtp_tls_failed")
    assert all(s.tls_at_auth == [] for s in fake.sessions)


@pytest.mark.parametrize(
    ("switch", "code"),
    [
        (Switch.NO_STARTTLS, "smtp_tls_failed"),
        (Switch.STARTTLS_454, "smtp_tls_failed"),
        (Switch.WRONG_NAME, "smtp_tls_failed"),
        (Switch.AUTH_ONLY_BEFORE_TLS, "smtp_auth_unsupported"),
    ],
)
async def test_starttls_failures_never_send_auth(
    ca: ProviderCA, tmp_path: Path, switch: Switch, code: str
) -> None:
    fake = SmtpFake(ca, mode="starttls", switches={switch})
    with serve_smtp(fake, tmp_path) as (_, port):
        r = Rig(tmp_path / "state", mail_policy(port, tls="starttls"), ca)
        response = await r.send()
        await r.app.aclose()
    assert (response.status_code, response.json()["code"]) == (502, code)
    assert all(s.tls_at_auth == [] for s in fake.sessions)
    assert fake.messages == []


async def test_implicit_tls_against_a_plain_server(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="starttls")
    with serve_smtp(fake, tmp_path) as (_, port):
        r = Rig(tmp_path / "state", mail_policy(port, tls="implicit"), ca)
        response = await r.send()
        await r.app.aclose()
    assert (response.status_code, response.json()["code"]) == (502, "smtp_tls_failed")
    assert all(s.tls_at_auth == [] for s in fake.sessions)


async def test_an_unreachable_server(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca)
    with serve_smtp(fake, tmp_path) as (_, port):
        pass
    r = Rig(tmp_path / "state", mail_policy(port), ca)
    response = await r.send()
    await r.app.aclose()
    assert (response.status_code, response.json()["code"]) == (502, "smtp_unreachable")


# --- through the CONNECT proxy --------------------------------------------------------------------


async def test_through_the_proxy(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="starttls")
    proxy = ConnectProxy()
    with serve_smtp(fake, tmp_path) as (_, port), serve_proxy(proxy) as url:
        r = Rig(tmp_path / "state", mail_policy(port, tls="starttls", proxy=url), ca)
        response = await r.send()
        await r.app.aclose()
    assert response.status_code == 200
    assert proxy.targets == [f"localhost:{port}"]
    assert fake.sessions[0].tls_at_auth == [True]


@pytest.mark.parametrize(
    "switch", [ProxySwitch.REFUSE_403, ProxySwitch.MALFORMED, ProxySwitch.OVERSIZED]
)
async def test_a_proxy_that_refuses(ca: ProviderCA, tmp_path: Path, switch: ProxySwitch) -> None:
    fake = SmtpFake(ca)
    with serve_smtp(fake, tmp_path) as (_, port), serve_proxy(ConnectProxy({switch})) as url:
        r = Rig(tmp_path / "state", mail_policy(port, proxy=url), ca)
        response = await r.send()
        await r.app.aclose()
    assert (response.status_code, response.json()["code"]) == (502, "proxy_refused")
    assert fake.sessions == []
    assert [r["kind"] for r in r.journal()] == ["sending", "failed"]  # counted


async def test_a_proxy_that_strips_starttls(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="starttls")
    proxy = ConnectProxy({ProxySwitch.STRIP_STARTTLS})
    with serve_smtp(fake, tmp_path) as (_, port), serve_proxy(proxy) as url:
        r = Rig(tmp_path / "state", mail_policy(port, tls="starttls", proxy=url), ca)
        response = await r.send()
        await r.app.aclose()
    assert (response.status_code, response.json()["code"]) == (502, "smtp_tls_failed")
    assert all(s.tls_at_auth == [] for s in fake.sessions)


async def test_a_greeting_right_behind_the_200(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="starttls")
    proxy = ConnectProxy({ProxySwitch.GREETING_WITH_200})
    with serve_smtp(fake, tmp_path) as (_, port), serve_proxy(proxy) as url:
        r = Rig(tmp_path / "state", mail_policy(port, tls="starttls", proxy=url), ca)
        response = await r.send()
        await r.app.aclose()
    assert response.status_code == 200


# --- the journal ----------------------------------------------------------------------------------


async def test_recovery_closes_an_unfinished_send_as_unknown(
    implicit: tuple[SmtpFake, int], ca: ProviderCA, tmp_path: Path
) -> None:
    fake, port = implicit
    policy = mail_policy(port)
    r = Rig(tmp_path, policy, ca)
    key = "key-0001-aaaaaaaaaaaa"
    await r.send(key)
    file = JournalFile(tmp_path / smtp.JOURNAL_DIR / "mail-out", r.clock)
    # A second send cut by a SIGKILL after its ``sending`` record.
    cut = {
        "ts": r.clock.now,
        "key": "key-0002-aaaaaaaaaaaa",
        "req_hmac": "hmac-sha256:" + "0" * 64,
        "key_id": KEYS.key_id,
        "subject_chars": 1,
        "body_chars": 1,
    }
    file.append(sendjournal.encode("sending", **cut))
    assert r.restart(policy) == {"mail-out": 1}
    assert r.journal()[-1] == {
        "kind": "unknown",
        "ts": r.clock.now,
        "key": "key-0002-aaaaaaaaaaaa",
        "phase": "vault_restarted",
    }
    assert r.restart(policy) == {}  # once only
    assert len(fake.messages) == 1
    await r.app.aclose()


def test_the_journal_rotates_and_prunes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = Clock()
    file = JournalFile(tmp_path / "j", clock)
    record = {"ts": 1, "key": "key-0001-aaaaaaaaaaaa", "phase": "tunnel"}
    line = sendjournal.encode("unknown", **record)
    monkeypatch.setattr(smtp, "ROTATE_BYTES", 3 * len(line))
    for _ in range(5):
        file.append(line)
        clock.now += 1
    assert len(file.files()) == 2  # three lines to a file: rotated once
    assert len(file.lines()) == 5
    assert all(oct(p.stat().st_mode)[-3:] in ("600", "666") for p in file.files())
    clock.now += (sendjournal.RECORD_DAYS + 1) * sendjournal.DAY_MS
    for _ in range(5):
        file.append(line)
    names = [p.name for p in file.files()]
    assert len(names) == 2  # the old files went; the current one stays
    assert all(int(n[8:21]) > START_MS + sendjournal.DAY_MS for n in names)


def test_the_journal_size_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clock = Clock()
    file = JournalFile(tmp_path / "j", clock)
    monkeypatch.setattr(smtp, "ROTATE_BYTES", 100)
    monkeypatch.setattr(smtp, "MAX_JOURNAL_BYTES", 300)
    line = sendjournal.encode("unknown", ts=1, key="key-0001-aaaaaaaaaaaa", phase="tunnel")
    for _ in range(10):
        file.append(line)
        clock.now += 1
    assert sum(p.stat().st_size for p in file.files()) <= 300 + len(line)


# --- the shipped profiles ------------------------------------------------------------------------

PROFILES = Path(__file__).resolve().parents[2] / "profiles"
BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "0.0.0.0:8081", "hosts": ["localhost"]},
}


@pytest.mark.parametrize("profile", ["smtp-implicit-tls.yaml", "smtp-starttls.yaml"])
def test_the_smtp_profiles_pass_check(profile: str) -> None:
    fragment = load_mapping((PROFILES / profile).read_text(encoding="utf-8"))
    out = io.StringIO()
    document = io.StringIO(json.dumps({**BASE, **fragment}))
    assert main(["check", "--config", "-"], stdin=document, out=out) == 0
    # Alone, a connector profile has no toolkit to use it; profiles/toolkit-mail.yaml adds one.
    assert out.getvalue() == (
        "warning connectors.mail-out: no toolkit slot maps a route to it\n"
        "<stdin>: ok (0 error(s), 1 warning(s))\n"
    )


@pytest.mark.parametrize(
    ("profile", "mode"),
    [("smtp-implicit-tls.yaml", "implicit"), ("smtp-starttls.yaml", "starttls")],
)
async def test_the_smtp_profiles_send(
    ca: ProviderCA, tmp_path: Path, profile: str, mode: Literal["implicit", "starttls"]
) -> None:
    """Each profile as shipped, with only the mail server's address swapped for the fake's."""
    fragment = load_mapping((PROFILES / profile).read_text(encoding="utf-8"))
    fake = SmtpFake(ca, mode=mode)
    with serve_smtp(fake, tmp_path) as (_, port):
        fragment["connectors"]["mail-out"] |= {"host": "localhost", "port": port}
        r = Rig(tmp_path / "state", Policy.model_validate({**BASE, **fragment}), ca)
        response = await r.send()
        await r.app.aclose()
    assert response.status_code == 200
    assert fake.sessions[0].tls_at_auth == [True]


async def test_a_key_is_remembered_for_thirty_days(
    implicit: tuple[SmtpFake, int], ca: ProviderCA, tmp_path: Path
) -> None:
    fake, port = implicit
    r = Rig(tmp_path, mail_policy(port), ca)
    assert (await r.send()).status_code == 200
    r.clock.now += sendjournal.KEY_DAYS * sendjournal.DAY_MS
    again = await r.send()
    assert again.headers[REPLAYED_HEADER] == "1"  # still within 30 days
    r.clock.now += 1
    fresh = await r.send()
    assert REPLAYED_HEADER not in fresh.headers  # forgotten: a new send
    assert len(fake.messages) == 2
    await r.app.aclose()
