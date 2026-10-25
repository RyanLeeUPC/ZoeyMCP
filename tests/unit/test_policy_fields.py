"""The field rules the schema calls (M7 design A.1, O.2 ``test_policy_fields.py``; Q41).

An endpoint's query: RFC 3986 query characters without ``$``, ``;`` or ``'``, a strict parse,
1 to 16 parameters, each name as written, none twice, and no name the vault reserves on that
request. The schema-level rows (both URL fields, the length cap, the other URL fields) are in
``test_policy.py``.

A server written ``kind: bridge``: listed by name, so the schema refuses each at its ``kind``
(M7 design A.1). The message itself is asserted whole in ``test_policy.py``.

A route's ``unix:`` upstream (Q46): ``unix:/run/zoeymcp-bridge-<name>/mcp.sock`` exactly, by
``fullmatch``, and the bridge's name read back from it.

A server's resource templates and fixed resources (M6 design L.1, A.2 row 6): a template is
``scheme://authority/segment/...`` with every expression a whole path segment ``{name}``, at most 8,
no operator, query or fragment, at most 1,024 characters; a fixed resource an absolute URI, at most
2,048 characters, without user info or a fragment. Both hold only the characters RFC 3986 lets a URI
hold, every ``%`` a whole escape. The schema-level rows (each entry and key at its path) are in
``test_policy.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest

from zoeymcp.common.policy import fields
from zoeymcp.common.policy.fields import (
    AUTHORIZE_PARAMS,
    MAX_QUERY_PARAMS,
    RESOURCE_URI_FORM,
    RESOURCE_URI_MAX,
    TEMPLATE_EXPRESSIONS_MAX,
    TEMPLATE_FORM,
    TEMPLATE_MAX,
    TOKEN_PARAMS,
    UNIX_UPSTREAM_FORM,
    URL_MAX,
    bridge_name,
    bridge_socket,
    check_endpoint_query,
    client_host,
    endpoint_query,
    host_port_lower,
    is_mail_address,
    is_numeric_label,
    is_squid_acl_name,
    no_bridge_kind,
    resource_uri,
    unix_upstream,
    uri_template,
)
from zoeymcp.common.policy.schema import RemoteServer

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


@pytest.mark.parametrize("label", ["0", "42", "0177", "0x", "0x7f", "0xdeadbeef"])
def test_a_numeric_label(label: str) -> None:
    assert is_numeric_label(label)


# Whole labels only: "42\n" is no number (the host syntax refuses the line break before this
# rule runs, D-138), and neither is a label with a letter beside the digits.
@pytest.mark.parametrize("label", ["", "42\n", "42a", "a42", "0x7g", "0X7f", "x7f", "example"])
def test_not_a_numeric_label(label: str) -> None:
    assert not is_numeric_label(label)


@pytest.mark.parametrize(
    "address", ["p@x.example", "a.b+c@x.example", "a" * 64 + "@x.example", "p@" + "x" * 253]
)
def test_a_mail_address(address: str) -> None:
    assert is_mail_address(address)


# A trailing line break is refused whole (D-138): $ also matches before a final "\n".
@pytest.mark.parametrize(
    "address",
    [
        "p@x.example\n",
        "",
        "@x.example",
        "p@",
        "p@@x.example",
        "a" * 65 + "@x.example",
        "p@" + "x" * 254,
        "p q@x.example",
        "<p>@x.example",
        '"p"@x.example',
        "p@x_y.example",
    ],
)
def test_not_a_mail_address(address: str) -> None:
    assert not is_mail_address(address)


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


# --- the client's host (D-190) ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("api.example", "api.example"),
        ("lan.example.", "lan.example."),
        ("2001:db8::5", "2001:db8::5"),
        ("10.0.0.9", "10.0.0.9"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("bücher.example.", "xn--bcher-kva.example."),
        # IDNA 2008, as httpx encodes it: not IDNA 2003's "ss.example".
        ("ß.example", "xn--zca.example"),
        ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
    ],
)
def test_the_clients_host_is_httpxs_raw_host(host: str, expected: str) -> None:
    assert client_host(host) == expected
    netloc = f"[{host}]" if ":" in host else host
    assert httpx.URL(f"https://{netloc}/").raw_host.decode("ascii") == expected


def test_a_name_idna_refuses_keeps_its_form() -> None:
    """The client can't connect to it at all, so its key only has to be stable."""
    assert client_host("☃.example") == "☃.example"
    with pytest.raises(httpx.InvalidURL):
        _ = httpx.URL("https://☃.example/").raw_host


# --- no bridge kind (M7 design A.1) --------------------------------------------------------------


def test_every_bridge_server_is_listed_in_the_order_written() -> None:
    servers = {
        "fetch": {"kind": "bridge", "url": "http://bridge.example:9000/mcp"},
        "notes": {"kind": "remote", "route": "notes"},
        "kit": {"kind": "toolkit", "module": "zoeymcp.toolkits.mail"},
        "a-bridge": {"kind": "bridge"},
    }
    assert no_bridge_kind(servers) == ["fetch", "a-bridge"]


def test_servers_without_a_bridge_list_nothing() -> None:
    assert no_bridge_kind({}) == []
    assert no_bridge_kind({"notes": {"kind": "remote", "route": "notes"}, "x": {}}) == []


@pytest.mark.parametrize("kind", ["Bridge", "bridges", " bridge", "remote", None, ["bridge"]])
def test_only_the_kind_bridge_is_listed(kind: object) -> None:
    assert no_bridge_kind({"s": {"kind": kind}}) == []


@pytest.mark.parametrize(
    "servers",
    [
        None,
        "bridge",
        [{"kind": "bridge"}],
        {"s": "bridge"},
        {"s": None},
        {"s": [("kind", "bridge")]},
        {"s": RemoteServer(kind="remote", route="notes")},
    ],
)
def test_what_isnt_a_mapping_of_mappings_is_left_to_the_schema(servers: object) -> None:
    assert no_bridge_kind(servers) == []


# --- a unix: upstream (M7 design A.1, Q46) -------------------------------------------------------


@pytest.mark.parametrize("name", ["fetch", "a", "0", "abcdefghijklmnop", "b2b"])
def test_a_bridges_socket_is_a_unix_upstream(name: str) -> None:
    upstream = f"unix:{bridge_socket(name)}"
    assert upstream == f"unix:/run/zoeymcp-bridge-{name}/mcp.sock"
    assert unix_upstream(upstream) == upstream
    assert bridge_name(upstream) == name


@pytest.mark.parametrize(
    "upstream",
    [
        "unix:/run/zoeymcp-link/vault.sock",  # every other directory
        "unix:/run/zoeymcp-admin/admin.sock",
        "unix:/tmp/zoeymcp-bridge-fetch/mcp.sock",
        "unix:/run/zoeymcp-bridge-fetch/vault.sock",
        "unix:/run/zoeymcp-bridge-fetch/mcp.sockx",
        "unix:/run/zoeymcp-bridge-fetch/mcpXsock",  # the dot is a dot
        "unix:/run/zoeymcp-bridge-/mcp.sock",
        "unix:/run/zoeymcp-bridge-abcdefghijklmnopq/mcp.sock",  # 17 characters
        "unix:/run/zoeymcp-bridge-Fetch/mcp.sock",
        "unix:/run/zoeymcp-bridge-fe_ch/mcp.sock",
        "unix:/run/zoeymcp-bridge-fe-ch/mcp.sock",
        "unix:/run/zoeymcp-bridge-../mcp.sock",
        "unix:/run/zoeymcp-bridge-fetch/../zoeymcp-link/mcp.sock",
        "unix:run/zoeymcp-bridge-fetch/mcp.sock",
        "unix://run/zoeymcp-bridge-fetch/mcp.sock",
        "unix:/run/zoeymcp-bridge-fetch/mcp.sock/",  # a trailing slash
        "unix:/run/zoeymcp-bridge-fetch/mcp.sock/mcp",  # an HTTP path
        "unix:/run/zoeymcp-bridge-fetch/mcp.sock?a=b",  # a query
        "unix:/run/zoeymcp-bridge-fetch/mcp.sock\n",
        "xunix:/run/zoeymcp-bridge-fetch/mcp.sock",
        "UNIX:/run/zoeymcp-bridge-fetch/mcp.sock",
        "/run/zoeymcp-bridge-fetch/mcp.sock",
        "http://bridge.invalid/mcp",
        "",
    ],
)
def test_every_other_upstream_is_refused(upstream: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(UNIX_UPSTREAM_FORM)}$"):
        unix_upstream(upstream)
    with pytest.raises(ValueError, match=f"^{re.escape(UNIX_UPSTREAM_FORM)}$"):
        bridge_name(upstream)


def test_the_form_is_named_in_the_refusal() -> None:
    assert UNIX_UPSTREAM_FORM == (
        "a unix: upstream is a standard-tier bridge's socket, "
        "unix:/run/zoeymcp-bridge-<name>/mcp.sock"
    )
    assert fields.UNIX_PREFIX == "unix:"


# --- resource templates and fixed resources (M6 design L.1) -------------------------------------


def plain_id(value: object) -> str:
    """A test ID pytest can find again by its node ID (as test_policyseal.py's): no escapes, line
    breaks or characters outside ASCII."""
    return re.sub(r"[^A-Za-z0-9_.:=, -]+", "_", repr(value))[:60]


LONG_TEMPLATE = "notes://h/" + "a" * (TEMPLATE_MAX - len("notes://h//{id}")) + "/{id}"
EIGHT = "notes://h/" + "/".join(f"{{v{n}}}" for n in range(TEMPLATE_EXPRESSIONS_MAX))
# What uri_template says, by the rule a template breaks.
REFUSALS = {
    "form": TEMPLATE_FORM,
    "chars": f"{TEMPLATE_FORM}, in characters a URI may hold, with no query or fragment",
    "count": f"{TEMPLATE_FORM}, at most 8 of them",
    "length": f"{TEMPLATE_FORM}, at most 1024 characters",
}
LONG_URI = "notes://h/" + "a" * (RESOURCE_URI_MAX - len("notes://h/"))


def test_the_resource_forms_are_pinned() -> None:
    assert (TEMPLATE_MAX, TEMPLATE_EXPRESSIONS_MAX, RESOURCE_URI_MAX) == (1024, 8, 2048)
    assert TEMPLATE_FORM == (
        "a resource template here is scheme://host/path with {name} as whole path segments only"
    )
    assert RESOURCE_URI_FORM == (
        "a fixed resource here is an absolute URI of printable ASCII, at most 2048 characters, "
        "with no user info or fragment"
    )
    assert (len(LONG_TEMPLATE), len(LONG_URI)) == (TEMPLATE_MAX, RESOURCE_URI_MAX)


@pytest.mark.parametrize(
    "template",
    [
        "notes://notes/{id}",
        "file:///notes/{name}",  # an empty authority
        "notes://h",  # no path, and no expression
        "notes://h/",
        "notes://h:8080/a/{a}/b/{b_2}/",
        "a+b.c-d://h/{A9}",
        "notes://h/{_}",
        "notes://h/{" + "a" * 32 + "}",
        "notes://h//{id}",  # an empty segment
        "notes://h/a,b;c=d/%41/{id}",  # sub-delims and an escape in a literal segment
        EIGHT,
        LONG_TEMPLATE,
    ],
    ids=plain_id,
)
def test_a_level_one_template_is_accepted(template: str) -> None:
    assert uri_template(template) == template


@pytest.mark.parametrize(
    ("template", "refusal"),
    [
        *(
            (f"notes://h/{{{operator}id}}", "form")
            for operator in ("+", ".", "/", ";", "&", "=", ",", "!", "@")
        ),
        ("notes://h/{|id}", "chars"),  # "|" is no URI character
        ("notes://h/{?id}", "chars"),
        ("notes://h/{#id}", "chars"),
        ("notes://h/a{id}", "form"),  # part of a segment
        ("notes://h/{id}.json", "form"),
        ("notes://h/{a}{b}", "form"),
        ("notes://h/{a,b}", "form"),  # a list of variables
        ("notes://h/{id:3}", "form"),  # a prefix modifier
        ("notes://h/{id*}", "form"),  # an explode modifier
        ("notes://{host}/x", "form"),  # outside the path
        ("notes://h{x}/y", "form"),
        ("{s}://h/x", "form"),
        ("notes://h/{1a}", "form"),
        ("notes://h/{a-b}", "form"),
        ("notes://h/{}", "form"),
        ("notes://h/{" + "a" * 33 + "}", "form"),
        ("notes://h/{id", "form"),
        ("notes://h/id}", "form"),
        ("notes://h/{{id}}", "form"),
        ("/notes/{id}", "form"),  # no scheme
        ("notes:/n/{id}", "form"),  # no authority
        ("notes:{id}", "form"),
        ("1notes://h/{id}", "form"),
        ("://h/{id}", "form"),
        ("", "form"),
        ("notes://h/{id}?q=1", "chars"),
        ("notes://h/{id}?", "chars"),
        ("notes://h/{id}#f", "chars"),
        ("notes://h/a b/{id}", "chars"),
        ("notes://h/\u00e9/{id}", "chars"),
        ("notes://h/\t/{id}", "chars"),
        ("notes://h/\x7f/{id}", "chars"),
        ("notes://h/{id}\n", "chars"),
        *((f"notes://h/a{c}b/{{id}}", "chars") for c in '<>"\\^`|'),  # outside RFC 3986
        ("notes://h/%4/{id}", "chars"),  # a cut escape
        ("notes://h/%g0/{id}", "chars"),
        ("notes://h/100%/{id}", "chars"),
        ("notes://h/%{id}", "chars"),
        (EIGHT + "/{v8}", "count"),
        (LONG_TEMPLATE + "a", "length"),
        ("x" * 2000 + "?", "length"),
    ],
    ids=plain_id,
)
def test_any_other_template_is_refused(template: str, refusal: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(REFUSALS[refusal])}$"):
        uri_template(template)


@pytest.mark.parametrize(
    "uri",
    [
        "notes://index",
        "file:///notes.txt",
        "urn:isbn:0451450523",
        "notes:a@b.example",  # no authority, so no user info
        "notes://h/x?a=b",
        "notes://h?x@y",  # an @ in the query
        "notes://h/p@q",  # an @ in the path
        "notes://h:8080/a%2Fb%c3%a9",  # escapes, in either case
        "notes://[::1]/x",  # an IP literal
        "notes://h/a-._~!$&'()*+,;=:@/?/",  # every other character a URI may hold
        "a+b.c-d:x",
        LONG_URI,
    ],
    ids=plain_id,
)
def test_a_fixed_resource_is_an_absolute_uri(uri: str) -> None:
    assert resource_uri(uri) == uri


@pytest.mark.parametrize(
    "uri",
    [
        "notes://user@h/x",
        "notes://@h/x",
        "notes://u:p@h",
        "notes://u@h?x",
        "notes://h/x#top",
        "notes://h/x#",
        "notes:",
        "notes",
        "/notes/x",
        "1x:y",
        ":x",
        "",
        "notes://h/a b",
        "notes://h/\u00e9",
        "notes://h/\t",
        "notes://h/x\n",
        "notes://h/{id}",  # a template's braces
        "x:{a}",
        *(f"notes://h/a{c}b" for c in '<>"\\^`|'),  # outside RFC 3986
        "notes://h/%4",  # a cut escape
        "notes://h/%g0",
        "notes://h/100%",
        LONG_URI + "a",
    ],
    ids=plain_id,
)
def test_any_other_fixed_resource_is_refused(uri: str) -> None:
    with pytest.raises(ValueError, match=f"^{re.escape(RESOURCE_URI_FORM)}$"):
        resource_uri(uri)
