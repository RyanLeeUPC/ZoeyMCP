"""Standard library contract for the SMTP connector: M4 design N.3, items 32 to 34.

The connector's transport rests on three facts about ``smtplib`` that its documentation doesn't
promise: the host given to the constructor is what TLS verifies, even when the socket comes from
elsewhere (a CONNECT tunnel); ``data()`` dot-stuffs bytes too, so the connector sends ``DATA``
itself; and ``starttls`` refuses a server that didn't advertise it, forgetting what EHLO said.
"""

from __future__ import annotations

import inspect
import smtplib
import socket
import ssl
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.acceptance.tls import ProviderCA, make_ca
from tests.fakes.smtp_server import SmtpFake, Switch, serve_smtp


@pytest.fixture(scope="module")
def ca(tmp_path_factory: pytest.TempPathFactory) -> ProviderCA:
    return make_ca(tmp_path_factory.mktemp("smtp-ca"))


@pytest.fixture
def starttls_server(ca: ProviderCA, tmp_path: Path) -> Iterator[tuple[SmtpFake, int]]:
    fake = SmtpFake(ca, mode="starttls")
    with serve_smtp(fake, tmp_path) as (_, port):
        yield fake, port


# --- 32. the constructor's host is what TLS checks ----------------------------------------------


def test_init_sets_the_host_before_it_connects_and_get_socket_gets_it(
    starttls_server: tuple[SmtpFake, int], ca: ProviderCA
) -> None:
    _, port = starttls_server
    seen: list[tuple[Any, ...]] = []

    class Tunnelled(smtplib.SMTP):
        def _get_socket(self, host: str, port: int, timeout: float) -> socket.socket:
            seen.append((self._host, host, port))  # type: ignore[attr-defined]
            return socket.create_connection(("127.0.0.1", port), timeout)

    client = Tunnelled("localhost", port, timeout=10)
    try:
        assert seen == [("localhost", "localhost", port)]
        client.ehlo()
        client.starttls(context=ca.client_context())
        # TLS verified "localhost", the constructor's host, not the address the socket used.
        assert isinstance(client.sock, ssl.SSLSocket)
        assert client.sock.server_hostname == "localhost"
    finally:
        client.close()


def test_starttls_verifies_the_constructors_host(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="starttls", name="mail.other.example")
    with serve_smtp(fake, tmp_path) as (_, port):
        client = smtplib.SMTP("127.0.0.1", port, timeout=10)
        try:
            client.ehlo()
            with pytest.raises(ssl.SSLCertVerificationError):
                client.starttls(context=ca.client_context())
        finally:
            client.close()


def test_smtp_ssl_wraps_with_the_constructors_host(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="implicit")
    with serve_smtp(fake, tmp_path) as (_, port):
        client = smtplib.SMTP_SSL("localhost", port, context=ca.client_context(), timeout=10)
        try:
            assert isinstance(client.sock, ssl.SSLSocket)
            assert client.sock.server_hostname == "localhost"
        finally:
            client.close()


# --- 33. data() dot-stuffs bytes; the pieces the connector uses exist ---------------------------


def test_data_dot_stuffs_bytes_too() -> None:
    sent: list[bytes] = []

    class Recording(smtplib.SMTP):
        def putcmd(self, cmd: str, args: str = "") -> None:
            pass

        def getreply(self) -> tuple[int, bytes]:
            return 354, b"go"

        def send(self, s: Any) -> None:
            sent.append(s if isinstance(s, bytes) else s.encode())

    client = Recording()
    client.getreply = lambda: (354, b"go")  # type: ignore[method-assign]
    client.data(b".leading\r\nplain\r\n")
    assert sent[0].startswith(b"..leading")  # stuffed, though the docstring says bytes aren't


def test_the_low_level_calls_have_the_signatures_used() -> None:
    assert list(inspect.signature(smtplib.SMTP.putcmd).parameters) == ["self", "cmd", "args"]
    assert list(inspect.signature(smtplib.SMTP.getreply).parameters) == ["self"]
    assert list(inspect.signature(smtplib.SMTP.send).parameters) == ["self", "s"]
    assert "local_hostname" in inspect.signature(smtplib.SMTP.__init__).parameters


# --- 34. starttls refuses a server that didn't offer it -----------------------------------------


def test_starttls_needs_the_advertisement_and_forgets_ehlo(ca: ProviderCA, tmp_path: Path) -> None:
    fake = SmtpFake(ca, mode="starttls", switches={Switch.NO_STARTTLS})
    with serve_smtp(fake, tmp_path) as (_, port):
        client = smtplib.SMTP("localhost", port, timeout=10)
        try:
            client.ehlo()
            with pytest.raises(smtplib.SMTPNotSupportedError):
                client.starttls(context=ca.client_context())
        finally:
            client.close()
    fake = SmtpFake(ca, mode="starttls")
    with serve_smtp(fake, tmp_path) as (_, port):
        client = smtplib.SMTP("localhost", port, timeout=10)
        try:
            client.ehlo()
            assert "starttls" in client.esmtp_features
            client.starttls(context=ca.client_context())
            assert client.esmtp_features == {}  # forgotten: EHLO must be sent again
        finally:
            client.close()
