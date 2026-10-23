"""The egress role's per-connection decisions (M7 design I.4, X15, O.2 ``test_egress_connect.py``).

Each step's rule both ways, both sides of every constant, the exact bytes of every answer the
role makes itself (empty, no challenge: X17), and the caps.
"""

from __future__ import annotations

import pytest

from zoeymcp.egress import connect
from zoeymcp.egress.connect import (
    ESTABLISHED,
    HEAD_MAX,
    HEADERS_MAX,
    STATUS,
    Refusal,
    Target,
    addresses,
    admit,
    answer,
    has_room,
    parse_head,
    split_head,
    still_listed,
)


def head(request: str = "CONNECT api.example:443 HTTP/1.1", *headers: str) -> bytes:
    return ("\r\n".join([request, *headers]) + "\r\n\r\n").encode("latin-1")


def test_the_constants() -> None:
    """M7 design M.6."""
    assert (connect.HEAD_MAX, connect.HEAD_TIMEOUT) == (8192, 10.0)
    assert (connect.RESOLVE_TIMEOUT, connect.CONNECT_TIMEOUT) == (5.0, 10.0)
    assert connect.HEADERS_MAX == 64
    assert (connect.TUNNELS_PER_LISTENER, connect.TUNNELS_MAX) == (256, 1024)
    assert (connect.IDLE_TIMEOUT, connect.TUNNEL_MAX_SECONDS) == (900.0, 86400.0)


def test_every_reason_has_its_status() -> None:
    """M7 design I.4 and M.3: 400, 403, 405, 408, 431, 502 and 503, nothing else."""
    assert dict(STATUS) == {
        "head_too_large": 431,
        "head_timeout": 408,
        "not_connect": 405,
        "bad_request": 400,
        "list_stale": 503,
        "no_list": 403,
        "not_allowed": 403,
        "resolve_failed": 502,
        "address_refused": 403,
        "connect_failed": 502,
        "busy": 503,
    }
    assert [Refusal(reason).status for reason in STATUS] == list(STATUS.values())


@pytest.mark.parametrize(
    ("status", "phrase"),
    [
        (400, "Bad Request"),
        (403, "Forbidden"),
        (408, "Request Timeout"),
        (431, "Request Header Fields Too Large"),
        (502, "Bad Gateway"),
        (503, "Service Unavailable"),
    ],
)
def test_an_answer_is_empty_and_carries_no_challenge(status: int, phrase: str) -> None:
    assert answer(status) == (
        f"HTTP/1.1 {status} {phrase}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode()
    )


def test_a_405_names_connect_alone() -> None:
    assert answer(405) == (
        b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n"
        b"Allow: CONNECT\r\n\r\n"
    )
    assert ESTABLISHED == b"HTTP/1.1 200 Connection established\r\n\r\n"


# --- step 1: the head -----------------------------------------------------------------------------


def test_a_head_is_split_from_what_follows_it() -> None:
    whole = head()
    assert split_head(b"") is None
    assert split_head(whole[:-1]) is None
    assert split_head(whole) == (whole, b"")
    assert split_head(whole + b"\x16\x03\x01early") == (whole, b"\x16\x03\x01early")
    assert split_head(whole + whole) == (whole, whole)
    assert split_head(b"\r\n\r\nrest") == (b"\r\n\r\n", b"rest")


def test_a_head_of_8_kib_is_read_and_one_byte_more_is_not() -> None:
    padding = HEAD_MAX - len(head("CONNECT a.example:443 HTTP/1.1", "X: "))
    exact = head("CONNECT a.example:443 HTTP/1.1", "X: " + "y" * padding)
    assert len(exact) == HEAD_MAX
    assert split_head(exact) == (exact, b"")
    over = head("CONNECT a.example:443 HTTP/1.1", "X: " + "y" * (padding + 1))
    assert split_head(over) == Refusal("head_too_large")
    assert split_head(over[:HEAD_MAX]) == Refusal("head_too_large")
    assert split_head(over[: HEAD_MAX - 1]) is None


# --- step 2: CONNECT host:port --------------------------------------------------------------------


def test_a_connect_names_its_target() -> None:
    assert parse_head(head()) == Target("api.example", 443)
    assert parse_head(head("CONNECT api.example:443 HTTP/1.0")) == Target("api.example", 443)
    assert parse_head(head("CONNECT API.Example:8443 HTTP/1.1", "Host: x")) == Target(
        "API.Example", 8443
    )
    assert parse_head(head("CONNECT 11.0.0.1:443 HTTP/1.1")) == Target("11.0.0.1", 443)
    assert parse_head(head("CONNECT [2001:DB8::1]:443 HTTP/1.1")) == Target("2001:DB8::1", 443)
    assert parse_head(head("CONNECT a_b-c.example.:1 HTTP/1.1")) == Target("a_b-c.example.", 1)
    assert parse_head(head("CONNECT a.example:65535 HTTP/1.1")) == Target("a.example", 65535)


@pytest.mark.parametrize("method", ["GET", "POST", "connect", "M-SEARCH", "OPTIONS"])
def test_another_method_is_405(method: str) -> None:
    assert parse_head(head(f"{method} http://api.example/ HTTP/1.1")) == Refusal("not_connect")
    assert parse_head(head(f"{method} /.well-known/oauth-authorization-server HTTP/1.1")) == (
        Refusal("not_connect")
    )


@pytest.mark.parametrize(
    "request_line",
    [
        "",
        "GE(T / HTTP/1.1",
        " CONNECT api.example:443 HTTP/1.1",
        "CONNECT api.example:443",
        "CONNECT api.example:443 HTTP/1.1 more",
        "CONNECT  api.example:443 HTTP/1.1",
        "CONNECT api.example:443  HTTP/1.1",
        "CONNECT api.example:443 HTTP/2",
        "CONNECT api.example:443 HTTP/1.2",
        "CONNECT api.example:443 http/1.1",
        "CONNECT api.example:443 HTTP/1.1\n",
        "CONNECT api.example:443\tHTTP/1.1",
    ],
)
def test_a_request_line_that_isnt_exactly_connect_is_400(request_line: str) -> None:
    assert parse_head(head(request_line)) == Refusal("bad_request")


@pytest.mark.parametrize(
    "target",
    [
        "api.example",
        "api.example:",
        ":443",
        "api.example:0",
        "api.example:65536",
        "api.example:123456",
        "api.example:44x",
        "api.example:+443",
        "2001:db8::1:443",
        "[2001:db8::1:443",
        "2001:db8::1]:443",
        "[zz]:443",
        "[]:443",
        "[11.0.0.1]:443",
        "api/example:443",
        "user@api.example:443",
        "api.example\x00:443",
        "a" * 254 + ":443",
        "a" * 253 + "..:443",
        "http://api.example:443",
    ],
)
def test_a_target_that_isnt_host_port_is_400(target: str) -> None:
    assert parse_head(head(f"CONNECT {target} HTTP/1.1")) == Refusal("bad_request")


def test_a_253_character_name_is_a_target() -> None:
    name = "a" * 253
    assert parse_head(head(f"CONNECT {name}:443 HTTP/1.1")) == Target(name, 443)
    # A trailing dot names the same host, as httpx sends one written in the URL (D-190).
    assert parse_head(head(f"CONNECT {name}.:443 HTTP/1.1")) == Target(f"{name}.", 443)


def test_a_non_ascii_name_is_left_to_step_4() -> None:
    """A non-ASCII host is refused 403 as unlisted, never parsed as something else."""
    assert parse_head(head("CONNECT b\xfccher.example:443 HTTP/1.1")) == Target(
        "b\xfccher.example", 443
    )
    assert parse_head("CONNECT bücher.example:443 HTTP/1.1\r\n\r\n".encode()) == Target(
        "b\xc3\xbccher.example", 443
    )


def test_headers_are_counted_up_to_64() -> None:
    lines = [f"X-{n}: v" for n in range(HEADERS_MAX)]
    assert parse_head(head("CONNECT api.example:443 HTTP/1.1", *lines)) == Target(
        "api.example", 443
    )
    lines.append("X-last: v")
    assert parse_head(head("CONNECT api.example:443 HTTP/1.1", *lines)) == Refusal("bad_request")


@pytest.mark.parametrize("header", ["X: a\nY: b", "X: a\rY: b", "X: a\n", "\rX: a"])
def test_a_bare_cr_or_lf_is_400(header: str) -> None:
    """A bare line break could hide headers from the count, or split the request differently
    for the next hop."""
    assert parse_head(head("CONNECT api.example:443 HTTP/1.1", header)) == Refusal("bad_request")


# --- steps 3 and 4: the list ----------------------------------------------------------------------

LISTS = {
    "vault": {"api.example:443": False, "lan.example:443": True, "11.0.0.1:443": False},
    "bridge-fetch": {"docs.example:443": False, "[2001:db8::1]:8443": False},
}


def test_no_fresh_list_refuses_every_target() -> None:
    assert admit(None, "vault", Target("api.example", 443)) == Refusal("list_stale")


def test_a_source_the_lists_dont_name_is_no_list() -> None:
    assert admit(LISTS, "other", Target("api.example", 443)) == Refusal("no_list")
    assert admit({}, "vault", Target("api.example", 443)) == Refusal("no_list")


def test_a_listed_target_carries_its_private_mark() -> None:
    assert admit(LISTS, "vault", Target("api.example", 443)) is False
    assert admit(LISTS, "vault", Target("lan.example", 443)) is True
    assert admit(LISTS, "vault", Target("API.Example", 443)) is False  # compared in lower case
    assert admit(LISTS, "bridge-fetch", Target("2001:DB8::1", 8443)) is False


def test_an_unlisted_target_is_not_allowed() -> None:
    for source, target in [
        ("vault", Target("api.example", 8443)),  # host and port stay paired
        ("vault", Target("docs.example", 443)),  # another source's destination
        ("bridge-fetch", Target("api.example", 443)),
        ("vault", Target("api.example.", 443)),
        ("vault", Target("11.0.0.2", 443)),
    ]:
        assert admit(LISTS, source, target) == Refusal("not_allowed")


def test_an_ip_literal_is_listed_only_literally() -> None:
    assert admit(LISTS, "vault", Target("11.0.0.1", 443)) is False
    by_name = {"vault": {"api.example:443": False}}
    assert admit(by_name, "vault", Target("11.0.0.1", 443)) == Refusal("not_allowed")


def test_a_non_ascii_host_is_never_allowed() -> None:
    lists = {"vault": {"b\xfccher.example:443": False}}
    assert admit(lists, "vault", Target("b\xfccher.example", 443)) == Refusal("not_allowed")


# --- step 5: the addresses ------------------------------------------------------------------------


def test_every_address_of_an_allowed_answer_in_the_resolvers_order() -> None:
    """D-208: each address is tried in turn, so all of them, in order, once each."""
    assert addresses(["11.0.0.1"], False) == ("11.0.0.1",)
    assert addresses(["11.0.0.2", "11.0.0.1"], False) == ("11.0.0.2", "11.0.0.1")
    assert addresses(["2a00:5a00::1", "11.0.0.1"], False) == ("2a00:5a00::1", "11.0.0.1")
    assert addresses(["10.0.0.5"], True) == ("10.0.0.5",)
    assert addresses(["11.0.0.2", "10.0.0.5"], True) == ("11.0.0.2", "10.0.0.5")
    assert addresses(["11.0.0.2", "11.0.0.1", "11.0.0.2"], False) == ("11.0.0.2", "11.0.0.1")


def test_a_refused_answer_names_netguards_verdict() -> None:
    """One refused address refuses them all: none is tried, the allowed ones included."""
    assert addresses(["10.0.0.5"], False) == Refusal("address_refused", "private")
    assert addresses(["11.0.0.1", "127.0.0.1"], False) == Refusal("address_refused", "loopback")
    assert addresses(["11.0.0.1", "10.0.0.5"], False) == Refusal("address_refused", "private")
    assert addresses(["::ffff:10.0.0.1"], False) == Refusal("address_refused", "private")
    assert addresses([], False) == Refusal("address_refused", "no_address")
    assert addresses([], True) == Refusal("address_refused", "no_address")
    assert addresses(["not-an-address"], True) == Refusal("address_refused", "unparsable")


# --- step 7 and after: the caps, and removed destinations -----------------------------------------


def test_the_tunnel_caps() -> None:
    assert has_room(0, 0, 1)
    assert not has_room(1, 1, 1)
    assert has_room(255, 255, 256)
    assert not has_room(256, 256, 256)
    assert has_room(0, 1023, 256)
    assert not has_room(0, 1024, 256)
    assert not has_room(0, 1024, 2048)


def test_a_tunnel_stays_while_its_destination_is_listed() -> None:
    assert still_listed(LISTS, "vault", "api.example:443")
    assert not still_listed(LISTS, "vault", "docs.example:443")
    assert not still_listed(LISTS, "other", "api.example:443")
    assert not still_listed({"vault": {}}, "vault", "api.example:443")
    # A list gone stale refuses new tunnels only.
    assert still_listed(None, "vault", "api.example:443")


def test_a_targets_key_is_netguards() -> None:
    assert Target("API.Example", 443).key == "api.example:443"
    assert Target("2001:DB8::1", 8443).key == "[2001:db8::1]:8443"
