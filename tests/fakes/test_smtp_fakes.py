"""The SMTP fake, the CONNECT proxy fake and the records API fake behave as M4's tests assume."""

from __future__ import annotations

import base64
import smtplib
import socket
import ssl
from collections.abc import Iterator
from pathlib import Path

import httpx
import pytest

from tests.acceptance.tls import ProviderCA, make_ca
from tests.fakes.connect_proxy import ConnectProxy, ProxySwitch, serve_proxy
from tests.fakes.harness import serve
from tests.fakes.records_api import SECRET, RecordsApi
from tests.fakes.smtp_server import PASSWORD, USERNAME, SmtpFake, Switch, serve_smtp


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("fakes-ca"))


def send_one(client: smtplib.SMTP) -> None:
    client.login(USERNAME, PASSWORD)
    client.sendmail("agent@mail.example", ["partner@mail.example"], b"Subject: hi\r\n\r\nbody\r\n")


# --- the SMTP fake ------------------------------------------------------------------------------


def test_implicit_tls(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="implicit")
    with (
        serve_smtp(fake, tmp_path) as (_, port),
        smtplib.SMTP_SSL("localhost", port, context=ca.client_context(), timeout=10) as client,
    ):
        client.ehlo("mail.example")
        send_one(client)
    [session] = fake.sessions
    assert session.ehlo == ["mail.example"]
    assert session.tls_at_auth == [True]
    assert (session.mail_from, session.rcpt_to) == ("agent@mail.example", ["partner@mail.example"])
    assert fake.messages == [b"Subject: hi\r\n\r\nbody\r\n"]


def test_starttls(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="starttls")
    with (
        serve_smtp(fake, tmp_path) as (_, port),
        smtplib.SMTP("localhost", port, timeout=10) as client,
    ):
        client.ehlo()
        assert not client.has_extn("auth")  # AUTH only after TLS
        client.starttls(context=ca.client_context())
        client.ehlo()
        assert client.has_extn("auth")
        send_one(client)
    assert fake.sessions[0].tls_at_auth == [True]


def test_auth_login_and_a_wrong_password(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca)
    with (
        serve_smtp(fake, tmp_path) as (_, port),
        smtplib.SMTP_SSL("localhost", port, context=ca.client_context(), timeout=10) as client,
    ):
        client.ehlo()
        code, _ = client.docmd("AUTH", "LOGIN " + base64.b64encode(USERNAME.encode()).decode())
        assert code == 334
        code, _ = client.docmd(base64.b64encode(PASSWORD.encode()).decode())
        assert code == 235
        with smtplib.SMTP_SSL("localhost", port, context=ca.client_context(), timeout=10) as client:
            client.ehlo()
            with pytest.raises(smtplib.SMTPAuthenticationError):
                client.login(USERNAME, "wrong")


@pytest.mark.parametrize(
    ("switch", "error"),
    [
        (Switch.AUTH_535, smtplib.SMTPAuthenticationError),
        (Switch.REJECT_ONE_RCPT, smtplib.SMTPRecipientsRefused),
    ],
)
def test_refusals(ca: ProviderCA, tmp_path: Path, switch: Switch, error: type[Exception]) -> None:
    fake = SmtpFake(ca, switches={switch})
    with (
        serve_smtp(fake, tmp_path) as (_, port),
        smtplib.SMTP_SSL("localhost", port, context=ca.client_context(), timeout=10) as client,
    ):
        client.ehlo()
        if switch is Switch.AUTH_535:
            with pytest.raises(error):
                client.login(USERNAME, PASSWORD)
        else:
            client.login(USERNAME, PASSWORD)
            # Two recipients, the second refused: smtplib raises only if all are refused,
            # so check the per-recipient answer instead.
            refused = client.sendmail(
                "agent@mail.example", ["a@mail.example", "b@mail.example"], b"x\r\n"
            )
            assert refused == {"b@mail.example": (550, b"no such user")}


def test_starttls_switches(ca: ProviderCA, tmp_path: Path) -> None:
    for switch in (Switch.NO_STARTTLS, Switch.STARTTLS_454):
        fake = SmtpFake(ca, mode="starttls", switches={switch})
        with (
            serve_smtp(fake, tmp_path) as (_, port),
            smtplib.SMTP("localhost", port, timeout=10) as client,
        ):
            client.ehlo()
            with pytest.raises((smtplib.SMTPNotSupportedError, smtplib.SMTPResponseException)):
                client.starttls(context=ca.client_context())


def test_a_certificate_for_another_name(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, switches={Switch.WRONG_NAME})
    with serve_smtp(fake, tmp_path) as (_, port), pytest.raises(ssl.SSLCertVerificationError):
        smtplib.SMTP_SSL("localhost", port, context=ca.client_context(), timeout=10)


def test_auth_only_before_tls(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="starttls", switches={Switch.AUTH_ONLY_BEFORE_TLS})
    with (
        serve_smtp(fake, tmp_path) as (_, port),
        smtplib.SMTP("localhost", port, timeout=10) as client,
    ):
        client.ehlo()
        assert client.has_extn("auth")
        client.starttls(context=ca.client_context())
        client.ehlo()
        assert not client.has_extn("auth")


def test_dropping_after_the_final_dot(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, switches={Switch.DROP_AFTER_DOT})
    with serve_smtp(fake, tmp_path) as (_, port):
        client = smtplib.SMTP_SSL("localhost", port, context=ca.client_context(), timeout=10)
        client.ehlo()
        client.login(USERNAME, PASSWORD)
        with pytest.raises(smtplib.SMTPServerDisconnected):
            client.sendmail("agent@mail.example", ["partner@mail.example"], b"x\r\n")
    assert fake.messages == [b"x\r\n"]  # the server got it: the outcome is unknown


def test_the_username_echo(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, switches={Switch.ECHO_USERNAME})
    with (
        serve_smtp(fake, tmp_path) as (_, port),
        smtplib.SMTP_SSL("localhost", port, context=ca.client_context(), timeout=10) as client,
    ):
        client.ehlo()
        _, text = client.login(USERNAME, PASSWORD)
    assert USERNAME.encode() in text


# --- the CONNECT proxy --------------------------------------------------------------------------


@pytest.fixture
def smtp_port(ca: ProviderCA, tmp_path: Path) -> Iterator[tuple[SmtpFake, int]]:
    fake = SmtpFake(ca, mode="starttls")
    with serve_smtp(fake, tmp_path) as (_, port):
        yield fake, port


def tunnel(proxy_url: str, port: int) -> tuple[socket.socket, bytes]:
    host, _, proxy_port = proxy_url.removeprefix("http://").rpartition(":")
    sock = socket.create_connection((host, int(proxy_port)), timeout=5)
    sock.sendall(f"CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n".encode())
    head = b""
    while not head.endswith(b"\r\n\r\n") and len(head) < 20000:
        chunk = sock.recv(1)
        if not chunk:
            break
        head += chunk
    return sock, head


def test_the_proxy_tunnels_and_records(smtp_port: tuple[SmtpFake, int]) -> None:
    _, port = smtp_port
    proxy = ConnectProxy()
    with serve_proxy(proxy) as url:
        sock, head = tunnel(url, port)
        assert head.startswith(b"HTTP/1.1 200")
        assert sock.recv(100).startswith(b"220 ")
        sock.close()
    assert proxy.targets == [f"localhost:{port}"]


@pytest.mark.parametrize(
    ("switch", "starts"),
    [
        (ProxySwitch.REFUSE_403, b"HTTP/1.1 403"),
        (ProxySwitch.REFUSE_407, b"HTTP/1.1 407"),
        (ProxySwitch.MALFORMED, b"SMTP/1.0 200"),
    ],
)
def test_proxy_refusals(
    smtp_port: tuple[SmtpFake, int], switch: ProxySwitch, starts: bytes
) -> None:
    _, port = smtp_port
    with serve_proxy(ConnectProxy({switch})) as url:
        sock, head = tunnel(url, port)
        sock.close()
    assert head.startswith(starts)


def test_an_oversized_head(smtp_port: tuple[SmtpFake, int]) -> None:
    _, port = smtp_port
    with serve_proxy(ConnectProxy({ProxySwitch.OVERSIZED})) as url:
        sock, head = tunnel(url, port)
        sock.close()
    assert len(head) > 8 * 1024


def test_the_greeting_with_the_200(smtp_port: tuple[SmtpFake, int]) -> None:
    _, port = smtp_port
    with serve_proxy(ConnectProxy({ProxySwitch.GREETING_WITH_200})) as url:
        sock, head = tunnel(url, port)
        assert head == b"HTTP/1.1 200 Connection established\r\n\r\n"  # read byte by byte
        assert sock.recv(100).startswith(b"220 ")  # the greeting wasn't swallowed
        sock.close()


def test_stripping_starttls(smtp_port: tuple[SmtpFake, int]) -> None:
    _, port = smtp_port
    with serve_proxy(ConnectProxy({ProxySwitch.STRIP_STARTTLS})) as url:
        sock, _ = tunnel(url, port)
        sock.recv(100)
        sock.sendall(b"EHLO mail.example\r\n")
        answer = b""
        while b"250 " not in answer:
            answer += sock.recv(1000)
        sock.close()
    assert b"STARTTLS" not in answer


# --- the records API ----------------------------------------------------------------------------


def test_the_records_api() -> None:
    api = RecordsApi(fail_item=1, differ_item=2)
    auth = {"authorization": f"Bearer {SECRET}"}
    with serve(api) as base:
        rows = [{"title": f"t{i}", "amount": i, "day": "2026-01-01"} for i in range(3)]
        created = httpx.post(
            f"{base}/v1/records/batch", json={"records": rows}, headers=auth
        ).json()
        assert created["created"][1] == {"index": 1, "error": "refused"}
        first = created["created"][0]["id"]
        assert httpx.get(f"{base}/v1/records/{first}", headers=auth).json()["title"] == "t0"
        third = created["created"][2]["id"]
        assert (
            httpx.get(f"{base}/v1/records/{third}", headers=auth).json()["title"] == "t2 (changed)"
        )
        assert httpx.get(f"{base}/v1/records/{first}").status_code == 401
        assert httpx.delete(f"{base}/v1/records/{first}", headers=auth).status_code == 405
        archived = httpx.post(f"{base}/v1/records/archive", json={"ids": [first]}, headers=auth)
        assert archived.json() == {"archived": 1}
    assert api.archived == [first]
