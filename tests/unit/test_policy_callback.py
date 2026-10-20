"""The portal's callback address (M5 design A.5, O.2 ``callback``): one per credential.

A ``redirect_uri`` takes the portal's callback only when it **is** the credential's callback
address on a listed origin: the origin, ``/oauth/callback/`` and the credential's own name,
compared as strings. Every near miss is paste only.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from zoeymcp.common.policy.callback import CALLBACK_PREFIX, callback_address, callback_origin

LOCAL = "http://localhost:8081"
OTHER_PORT = "http://localhost:9000"
NAMED = "https://vault.example.net"
ORIGINS = (LOCAL, OTHER_PORT, NAMED)


def test_the_address() -> None:
    assert CALLBACK_PREFIX == "/oauth/callback/"
    assert callback_address(LOCAL, "calendar") == "http://localhost:8081/oauth/callback/calendar"
    assert callback_address(NAMED, "a") == "https://vault.example.net/oauth/callback/a"


@pytest.mark.parametrize(
    ("redirect_uri", "origins", "found"),
    [
        # A.5's table, for a credential named calendar.
        ("http://127.0.0.1/callback", ORIGINS, None),
        ("http://127.0.0.1/callback", (), None),
        ("http://localhost:8081/oauth/callback/calendar", (LOCAL,), LOCAL),
        ("http://localhost:8081/oauth/callback/calendar", (OTHER_PORT,), None),
        ("http://localhost:8081/oauth/callback/calendar", (), None),
        ("http://localhost:8081/oauth/callback/mail", ORIGINS, None),
        ("http://127.0.0.1:8081/oauth/callback/calendar", (LOCAL,), None),
        ("https://vault.example.net/oauth/callback/calendar", (NAMED,), NAMED),
        ("https://vault.example.net/oauth/callback/calendar", (LOCAL, OTHER_PORT), None),
        # Which origin: the one it is on, whatever the order.
        ("https://vault.example.net/oauth/callback/calendar", ORIGINS, NAMED),
        ("http://localhost:9000/oauth/callback/calendar", ORIGINS, OTHER_PORT),
    ],
)
def test_a5s_table(redirect_uri: str, origins: tuple[str, ...], found: str | None) -> None:
    assert callback_origin(redirect_uri, "calendar", origins) == found


@pytest.mark.parametrize(
    "near",
    [
        "https://vault.example.net/oauth/callback/calendar/",  # a trailing slash
        "https://vault.example.net/oauth/callback/calendar?x=1",  # a query
        "https://vault.example.net/oauth/callback/calendar#f",  # a fragment
        "https://vault.example.net:443/oauth/callback/calendar",  # the default port written out
        "https://VAULT.example.net/oauth/callback/calendar",  # upper case
        "HTTPS://vault.example.net/oauth/callback/calendar",
        "https://vault.example.net/OAuth/callback/calendar",
        "https://vault.example.net/oauth/callback",  # no name
        "https://vault.example.net/oauth/callback/",
        "https://vault.example.net/oauth/callbacks/calendar",  # another path
        "https://vault.example.net/x/oauth/callback/calendar",
        "https://vault.example.net/oauth/callback/mail",  # another credential's name
        "https://vault.example.net/oauth/callback/calendar2",
        "https://vault.example.net/oauth/callback/%63alendar",  # a percent-encoded name
        "https://vault.example.net:8443/oauth/callback/calendar",  # another port
        "http://vault.example.net/oauth/callback/calendar",  # another scheme
        "http://localhost:8082/oauth/callback/calendar",
        "http://localhost./oauth/callback/calendar",
        "http://127.0.0.1:8081/oauth/callback/calendar",
        "http://[::1]:8081/oauth/callback/calendar",
        " https://vault.example.net/oauth/callback/calendar",
    ],
)
def test_every_near_miss_is_paste_only(near: str) -> None:
    assert callback_origin(near, "calendar", ORIGINS) is None


def test_the_name_is_the_credentials_own() -> None:
    address = callback_address(LOCAL, "calendar")
    assert callback_origin(address, "calendar", ORIGINS) == LOCAL
    assert callback_origin(address, "mail", ORIGINS) is None
    assert callback_origin(address, "calenda", ORIGINS) is None
    assert callback_origin(address, "", ORIGINS) is None


def test_the_origins_are_read_once_each() -> None:
    """A generator of origins works: the function reads them in order and stops at a match."""
    seen: list[str] = []

    def origins() -> Iterator[str]:
        for origin in ORIGINS:
            seen.append(origin)
            yield origin

    assert callback_origin(callback_address(OTHER_PORT, "c"), "c", origins()) == OTHER_PORT
    assert seen == [LOCAL, OTHER_PORT]
