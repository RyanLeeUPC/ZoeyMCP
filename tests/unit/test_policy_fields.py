"""The field rules the schema calls (M7 design A.1, O.2 ``test_policy_fields.py``; Q41).

An endpoint's query: RFC 3986 query characters without ``$``, ``;`` or ``'``, a strict parse,
1 to 16 parameters, each name as written, none twice, and no name the vault reserves on that
request. The schema-level rows (both URL fields, the length cap, the other URL fields) are in
``test_policy.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from zoeymcp.common.policy import fields
from zoeymcp.common.policy.fields import (
    AUTHORIZE_PARAMS,
    MAX_QUERY_PARAMS,
    TOKEN_PARAMS,
    URL_MAX,
    check_endpoint_query,
    endpoint_query,
    host_port_lower,
    is_squid_acl_name,
)

# Every punctuation character a query may hold, once.
PUNCTUATION = "a=-._~!()*+,:@/?&b=%2F"
CHARACTERS = "a query may hold letters, digits, %HH escapes and -._~!()*+,=&:@/? only"
PAIRS = "a query is name=value pairs joined by &, each escape UTF-8"
RESERVED = (
    "the endpoint's query sets {}, which the vault sets on this request or which changes how "
    "the server reads the vault's parameters"
)


def test_the_constants_are_pinned() -> None:
    assert URL_MAX == 2048
    assert MAX_QUERY_PARAMS == 16
    assert {
        "grant_type",
        "code",
        "redirect_uri",
        "code_verifier",
        "refresh_token",
        "client_id",
        "client_secret",
        "scope",
        "resource",
        "client_assertion",
        "client_assertion_type",
    } == TOKEN_PARAMS
    assert {
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
        "scope",
        "resource",
        "request",
        "request_uri",
        "response_mode",
    } == AUTHORIZE_PARAMS


# --- host:port and Squid names -----------------------------------------------------------------


@pytest.mark.parametrize("value", ["mcp.lan.example:443", "10.0.0.5:8443", "[fd00::1]:443"])
def test_host_port_lower_keeps_a_lower_case_entry(value: str) -> None:
    assert host_port_lower(value) == value


@pytest.mark.parametrize("value", ["MCP.lan.example:443", "mcp.lan.examplE:443", "[FD00::1]:443"])
def test_host_port_lower_refuses_upper_case(value: str) -> None:
    message = r"^write host:port in lower case: the egress role compares it as written$"
    with pytest.raises(ValueError, match=message):
        host_port_lower(value)


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("stack_vault_net", True),
        ("A", True),
        ("a" * 64, True),
        ("Az09_", True),
        ("", False),
        ("a" * 65, False),
        ("vault-net", False),
        ("vault.net", False),
        ("vault net", False),
        ("vault_net\n", False),
        ("vault_nét", False),
    ],
)
def test_squid_acl_names(value: str, valid: bool) -> None:
    assert is_squid_acl_name(value) is valid


# --- the endpoint query ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("query", "pairs"),
    [
        ("tenant=a%2Fb&p=B2C_1_signin", (("tenant", "a/b"), ("p", "B2C_1_signin"))),
        (PUNCTUATION, (("a", "-._~!()* ,:@/?"), ("b", "/"))),
        ("a=", (("a", ""),)),
        ("a==b", (("a", "=b"),)),
        ("A.b_c~d-9=x", (("A.b_c~d-9", "x"),)),
        ("n" * 128 + "=1", (("n" * 128, "1"),)),
        ("a=%C3%A9", (("a", "é"),)),
        ("&".join(f"p{i}=v" for i in range(16)), tuple((f"p{i}", "v") for i in range(16))),
    ],
)
def test_a_query_is_accepted(query: str, pairs: tuple[tuple[str, str], ...]) -> None:
    assert endpoint_query(query) == pairs


@pytest.mark.parametrize(
    "query",
    [
        "",
        "a=$",
        "a=b;c=d",
        "a='b'",
        'a="b"',
        "a=<b",
        "a=b|c",
        "a=b\\c",
        "a=b c",
        "a=é",
        "a=%zz",
        "a=%",
        "a=%2",
        "a=b#c",
        "a=[b]",
        "a=^",
        "a=`",
        "a={b}",
        "a=b\n",
    ],
)
def test_a_character_outside_the_query_set_is_refused(query: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(CHARACTERS)}$"):
        endpoint_query(query)


@pytest.mark.parametrize("query", ["a", "a=1&b", "a=1&", "&a=1", "a=1&&b=2", "a=%FF", "a=%C3"])
def test_a_malformed_pair_is_refused(query: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(PAIRS)}$"):
        endpoint_query(query)


@pytest.mark.parametrize(
    "name", ["client%5Fid", "a+b", "a!", "?a", "a/b", "a:b", "a@b", "(a)", "a*", "a,b", "n" * 129]
)
def test_a_name_is_checked_as_written(name: str) -> None:
    message = (
        f"query parameter {name!r}: a name is 1 to 128 letters, digits or -._~, with no escapes"
    )
    with pytest.raises(ValueError, match=f"^{re.escape(message)}$"):
        endpoint_query(f"{name}=1")


def test_an_empty_name_is_refused() -> None:
    with pytest.raises(ValueError, match=r"^query parameter '': a name is 1 to 128"):
        endpoint_query("=1")


def test_a_name_twice_is_refused() -> None:
    with pytest.raises(ValueError, match=r"^the query sets a twice$"):
        endpoint_query("a=1&b=2&a=3")
    with pytest.raises(ValueError, match=r"^the query sets b twice$"):
        endpoint_query("b=&b=")
    # Names are compared as written: case differs, so these are two names.
    assert endpoint_query("a=1&A=2") == (("a", "1"), ("A", "2"))


def test_at_most_sixteen_parameters() -> None:
    query = "&".join(f"p{i}=v" for i in range(17))
    with pytest.raises(ValueError, match=r"^a query has at most 16 parameters$"):
        endpoint_query(query)


# --- reserved names ----------------------------------------------------------------------------


def test_a_url_without_a_query_passes() -> None:
    check_endpoint_query("https://as.example/token", TOKEN_PARAMS)
    check_endpoint_query("https://as.example/token", frozenset())


def test_a_query_without_a_reserved_name_passes() -> None:
    url = "https://as.example/token?tenant=a%2Fb&p=B2C_1_signin"
    check_endpoint_query(url, TOKEN_PARAMS)
    check_endpoint_query(url, AUTHORIZE_PARAMS)


@pytest.mark.parametrize("name", sorted(TOKEN_PARAMS))
def test_every_reserved_token_name_is_refused(name: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(RESERVED.format(name))}$"):
        check_endpoint_query(f"https://as.example/token?tenant=t&{name}=x", TOKEN_PARAMS)


@pytest.mark.parametrize("name", sorted(AUTHORIZE_PARAMS))
def test_every_reserved_authorize_name_is_refused(name: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(RESERVED.format(name))}$"):
        check_endpoint_query(f"https://as.example/authorize?{name}=x", AUTHORIZE_PARAMS)


def test_a_name_reserved_on_the_other_request_passes() -> None:
    check_endpoint_query("https://as.example/token?state=x", TOKEN_PARAMS)
    check_endpoint_query("https://as.example/authorize?grant_type=x", AUTHORIZE_PARAMS)


def test_the_first_reserved_name_is_named() -> None:
    url = "https://as.example/token?a=1&scope=x&client_id=y"
    with pytest.raises(ValueError, match=f"^{re.escape(RESERVED.format('scope'))}$"):
        check_endpoint_query(url, TOKEN_PARAMS)


def test_the_query_is_checked_too() -> None:
    with pytest.raises(ValueError, match=r"^the query sets a twice$"):
        check_endpoint_query("https://as.example/token?a=1&a=2", frozenset())


def test_the_module_uses_fullmatch_only() -> None:
    text = Path(fields.__file__ or "").read_text(encoding="utf-8")
    assert ".match(" not in text
    assert ".search(" not in text
