"""Standard library contract for the SMTP connector (M4 design N.3, items 32 to 34) and for the
address guard (M7 design O.3, item 50).

The connector's transport rests on three facts about ``smtplib`` that its documentation doesn't
promise: the host given to the constructor is what TLS verifies, even when the socket comes from
elsewhere (a CONNECT tunnel); ``data()`` dot-stuffs bytes too, so the connector sends ``DATA``
itself; and ``starttls`` refuses a server that didn't advertise it, forgetting what EHLO said.

``common.netguard`` keeps its own tables, so its decision doesn't move with ``ipaddress``'s; it
uses only the parsing and the mapped-address arithmetic, pinned here. Where ``is_global`` calls a
denied row global, the guard disagrees on purpose: the known rows are listed, and a new one, or a
mapped form judged apart from its IPv4 address, is reported by failing here.
"""

from __future__ import annotations

import inspect
import ipaddress
import smtplib
import socket
import ssl
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.acceptance.tls import ProviderCA, make_ca
from tests.fakes.smtp_server import SmtpFake, Switch, serve_smtp
from zoeymcp.common import netguard


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


# --- 50. ipaddress beside netguard's tables -----------------------------------------------------

DENIED = (*netguard.DENIED_V4, *netguard.DENIED_V6)
# Rows where is_global calls an address inside global, on a supported Python. IANA's registry
# marks neither 6to4's relay anycast nor IPv4 multicast as non-global, nor site-local or multicast
# IPv6; the mapped and compatible rows hold IPv4 addresses, which netguard judges as IPv4 and
# is_global doesn't. 3.12's early patch releases (3.12.3, Ubuntu 24.04's) also call parts of
# 192.0.0.0/24, 64:ff9b:1::/48 and 2002::/16 global.
GLOBAL_TO_STDLIB = frozenset(
    {
        "192.0.0.0/24",
        "192.88.99.0/24",
        "224.0.0.0/4",
        "::ffff:0:0/96",
        "::/96",
        "64:ff9b:1::/48",
        "2002::/16",
        "fec0::/10",
        "ff00::/8",
    }
)
# IPv4 rows whose IPv4-mapped form is_global judges apart from the IPv4 address (3.12.3 calls
# ::ffff:100.64.0.0 global, though not 100.64.0.0).
MAPPED_APART = frozenset({"100.64.0.0/10"})
NAT64 = ipaddress.IPv6Network("64:ff9b::/96")
# The rows whose addresses netguard judges by the IPv4 address they hold, mapped and compatible.
CARRIED = frozenset({"::ffff:0:0/96", "::/96"})


def _samples(row: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """The first, middle and last address of a row."""
    net = ipaddress.ip_network(row)
    return [net[0], net[net.num_addresses // 2], net[-1]]


def test_netguard_refuses_every_row_whatever_is_global_says() -> None:
    for row in DENIED:
        if row in CARRIED:
            continue  # judged by the IPv4 address they carry (the next test)
        for address in _samples(row):
            assert netguard.classify(str(address)) != "global", (row, str(address))


def test_is_global_disagrees_with_netguard_only_on_the_known_rows() -> None:
    disagree = {row for row in DENIED if any(a.is_global for a in _samples(row))}
    assert disagree <= GLOBAL_TO_STDLIB, sorted(disagree - GLOBAL_TO_STDLIB)


def test_mapped_compatible_and_nat64_forms_carry_the_ipv4_address() -> None:
    """netguard's arithmetic: ipv4_mapped, a compatible address's integer, NAT64's low bits."""
    apart = set()
    for row in netguard.DENIED_V4:
        for address in _samples(row):
            assert isinstance(address, ipaddress.IPv4Address)
            mapped = ipaddress.IPv6Address(f"::ffff:{address}")
            assert mapped.ipv4_mapped == address
            assert mapped in ipaddress.IPv6Network("::ffff:0:0/96")
            compatible = ipaddress.IPv6Address(int(address))
            assert compatible.ipv4_mapped is None
            assert ipaddress.IPv4Address(int(compatible)) == address
            nat64 = ipaddress.IPv6Address(int(NAT64.network_address) | int(address))
            assert nat64 in NAT64
            assert ipaddress.IPv4Address(int(nat64) & 0xFFFFFFFF) == address
            if mapped.is_global != address.is_global:
                apart.add(row)
            kind = netguard.classify(str(address))
            assert netguard.classify(str(mapped)) == kind
            assert netguard.classify(str(nat64)) == kind
            if int(address) > 1:  # :: and ::1 are rows of their own
                assert netguard.classify(str(compatible)) == kind
    assert apart <= MAPPED_APART, sorted(apart - MAPPED_APART)


@pytest.mark.parametrize("text", ["2130706433", "0177.0.0.1", "0x7f.1", "127.1", "0x7f000001"])
def test_ipaddress_parses_no_shorthand_ipv4(text: str) -> None:
    """These reach untrusted_host as names, where the numeric-label rule refuses them."""
    with pytest.raises(ValueError, match="does not appear to be an IPv4 or IPv6 address"):
        ipaddress.ip_address(text)
    assert not netguard.untrusted_host(text).allowed


def test_a_scoped_ipv6_address_parses_with_its_scope() -> None:
    """netguard refuses it as unparsable, on the scope_id ipaddress reports."""
    address = ipaddress.ip_address("fe80::1%eth0")
    assert isinstance(address, ipaddress.IPv6Address)
    assert address.scope_id == "eth0"
    with pytest.raises(ValueError, match="a scoped address"):
        netguard.classify("fe80::1%eth0")
