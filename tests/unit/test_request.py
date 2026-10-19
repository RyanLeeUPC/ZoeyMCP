from __future__ import annotations

import base64
import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zoeymcp.common.policy.match import NormalizedPath, match_pattern, rule_matches
from zoeymcp.common.policy.paths import parse_path_pattern
from zoeymcp.common.policy.schema import QueryPolicy, RegexParam, Rule
from zoeymcp.vault.request import (
    REDACTED,
    RequestRejected,
    apply_query_policy,
    encode_query,
    filter_request_headers,
    filter_response_headers,
    find_rule,
    normalize_path,
    oauth_basic_credentials,
    oauth_client_variants,
    parse_query,
    scrub,
    scrub_headers,
    secret_variants,
)

BACKSLASH = chr(92)

# --- normalization -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "segments", "trailing"),
    [
        (b"/", (), False),
        (b"/a/b", ("a", "b"), False),
        (b"/a/b/", ("a", "b"), True),
        (b"/2.0/user@x", ("2.0", "user@x"), False),
        (b"/a%2Db", ("a-b",), False),  # %2D is '-': decoded once, allowed
        (b"/%41%42", ("AB",), False),
    ],
)
def test_normalize_accepts(raw: bytes, segments: tuple[str, ...], trailing: bool) -> None:
    assert normalize_path(raw) == NormalizedPath(segments, trailing)


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"a/b", "must start with '/'"),
        (b"/a//b", "empty path segment"),
        (b"//", "empty path segment"),
        (b"/a%2Fb", "slash or backslash inside"),
        (b"/a%2fb", "slash or backslash inside"),
        (b"/a%5Cb", "slash or backslash inside"),
        (b"/a" + BACKSLASH.encode() + b"b", "slash or backslash inside"),
        (b"/a%252Fb", "double percent-encoding"),
        (b"/a%25", "double percent-encoding"),
        (b"/..", "dot segment"),
        (b"/a/%2e%2e/b", "dot segment"),
        (b"/a/%2E", "dot segment"),
        (b"/a/./b", "dot segment"),
        (b"/caf%C3%A9", "non-ASCII"),
        (b"/caf\xc3\xa9", "non-printable or non-ASCII"),
        (b"/a b", "non-printable or non-ASCII"),
        (b"/a\x00b", "non-printable or non-ASCII"),
        (b"/a%00b", "characters that aren't allowed"),
        (b"/a%20b", "characters that aren't allowed"),
        (b"/a%0A", "characters that aren't allowed"),  # "$" alone allows a final "\n"
        (b"/a%0a/b", "characters that aren't allowed"),
        (b"/a%zz", "malformed percent-encoding"),
        (b"/a%4", "malformed percent-encoding"),
        (b"/a*b", "characters that aren't allowed"),
        (b"/" + b"a" * 5000, "path too long"),
    ],
)
def test_normalize_rejects(raw: bytes, reason: str) -> None:
    with pytest.raises(RequestRejected, match=reason):
        normalize_path(raw)


@given(st.binary(max_size=200))
def test_property_normalize_never_crashes(raw: bytes) -> None:
    try:
        path = normalize_path(raw)
    except RequestRejected:
        return
    # Whatever is accepted re-encodes to a path that normalizes to the same thing.
    assert normalize_path(path.encoded().encode()) == path


_segment = st.text(alphabet="abcXYZ019._~!$&'()+,;=:@-", min_size=1, max_size=8).filter(
    lambda s: s not in (".", "..")
)


@given(st.lists(_segment, min_size=1, max_size=6), st.booleans())
def test_property_round_trip(segments: list[str], trailing: bool) -> None:
    path = NormalizedPath(tuple(segments), trailing)
    assert normalize_path(path.encoded().encode()) == path


def test_without_first() -> None:
    assert normalize_path(b"/stats/2.0/").without_first() == NormalizedPath(("2.0",), True)
    assert normalize_path(b"/stats/").without_first() == NormalizedPath(())
    assert normalize_path(b"/stats").without_first().text == "/"


# --- matching ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("/2.0/**", b"/2.0", {}),
        ("/2.0/**", b"/2.0/", {}),
        ("/2.0/**", b"/2.0/a/b/c", {}),
        ("/2.0/**", b"/2.1/a", None),
        ("/a/*/c", b"/a/b/c", {}),
        ("/a/*/c", b"/a/c", None),
        ("/a/*/c", b"/a/b/x/c", None),
        ("/docs/{doc}/rows", b"/docs/d7Q/rows", {"doc": "d7Q"}),
        ("/docs/{doc}/rows", b"/docs/d7Q/rows/", None),
        ("/things/", b"/things/", {}),
        ("/things/", b"/things", None),
        ("/things", b"/things/", None),
        ("/", b"/", {}),
        ("/", b"/a", None),
        ("/mcp", b"/mcp", {}),
        ("/mcp", b"/MCP", None),
    ],
)
def test_match_pattern(pattern: str, path: bytes, expected: dict[str, str] | None) -> None:
    assert match_pattern(parse_path_pattern(pattern), normalize_path(path)) == expected


def rule(**kwargs: object) -> Rule:
    return Rule.model_validate(kwargs)


def test_rule_methods_and_params() -> None:
    r = rule(
        methods=["PATCH", "POST"],
        paths=["/api/docs/{doc}/tables/{table}/records"],
        params={"doc": ["d7Q2xk"], "table": {"regex": "[A-Za-z0-9_]{1,64}"}},
    )
    ok = normalize_path(b"/api/docs/d7Q2xk/tables/Health_Log/records")
    assert rule_matches(r, "POST", ok)
    assert not rule_matches(r, "GET", ok)
    assert not rule_matches(r, "DELETE", ok)
    assert not rule_matches(r, "POST", normalize_path(b"/api/docs/OTHER/tables/T/records"))
    assert not rule_matches(r, "POST", normalize_path(b"/api/docs/d7Q2xk/tables/a.b/records"))


def test_regex_params_are_anchored() -> None:
    r = Rule(methods=["GET"], paths=["/u/{id}"], params={"id": RegexParam(regex="[0-9]+")})
    assert rule_matches(r, "GET", normalize_path(b"/u/123"))
    assert not rule_matches(r, "GET", normalize_path(b"/u/123abc"))
    assert not rule_matches(r, "GET", normalize_path(b"/u/abc123"))


def test_find_rule_returns_first_match() -> None:
    rules = [rule(methods=["GET"], paths=["/config"]), rule(methods=["POST"], paths=["/send"])]
    assert find_rule(rules, "GET", normalize_path(b"/config")) == 0
    assert find_rule(rules, "POST", normalize_path(b"/send")) == 1
    assert find_rule(rules, "POST", normalize_path(b"/config")) is None


# --- query -------------------------------------------------------------------------------------


def test_parse_query() -> None:
    assert parse_query(b"b=2&a=1&a=3&flag&e=") == [
        ("b", "2"),
        ("a", "1"),
        ("a", "3"),
        ("flag", ""),
        ("e", ""),
    ]
    assert parse_query(b"q=a%20b&r=%C3%A9") == [("q", "a b"), ("r", "\xe9")]


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"a=%zz", "malformed percent-encoding"),
        (b"a=\xff", "raw non-ASCII"),
        (b"a=%FF", "query string refused"),
        ("&".join(f"k{i}=v" for i in range(101)).encode(), "query string refused"),
        (b"a=" + b"x" * 9000, "too long"),
    ],
)
def test_parse_query_rejects(raw: bytes, reason: str) -> None:
    with pytest.raises(RequestRejected, match=reason):
        parse_query(raw)


def test_query_policy_force_strip_remove_add() -> None:
    policy = QueryPolicy(force={"user": "alice"}, strip=["format"])
    result = apply_query_policy(
        [
            ("method", "x"),
            ("user", "mallory"),
            ("format", "xml"),
            ("api_key", "ph"),
            ("user", "eve"),
        ],
        policy,
        remove=["api_key"],
        add=[("api_key", "REAL")],
    )
    assert result == [("method", "x"), ("user", "alice"), ("api_key", "REAL")]


def test_query_allow_list_refuses_unknown() -> None:
    policy = QueryPolicy(force={"user": "alice"}, allow=["method", "page"])
    assert apply_query_policy([("method", "x"), ("user", "z")], policy) == [
        ("method", "x"),
        ("user", "alice"),
    ]
    with pytest.raises(RequestRejected, match="'sneaky' isn't allowed"):
        apply_query_policy([("sneaky", "1")], policy)


def test_encode_query_round_trips() -> None:
    params = [("q", "a b&c=d"), ("e", "\xe9"), ("plus", "+")]
    assert parse_query(encode_query(params).encode()) == params


@given(st.lists(st.tuples(st.text(min_size=1, max_size=10), st.text(max_size=10)), max_size=10))
def test_property_query_round_trip(params: list[tuple[str, str]]) -> None:
    params = [(k, v) for k, v in params if not any("\ud800" <= c <= "\udfff" for c in k + v)]
    assert parse_query(encode_query(params).encode()) == params


# --- headers -----------------------------------------------------------------------------------


def test_request_headers_drop_credentials_and_hop_by_hop() -> None:
    kept = filter_request_headers(
        [
            ("Host", "vault"),
            ("Authorization", "Bearer placeholder"),
            ("Cookie", "s=1"),
            ("Connection", "keep-alive, X-Custom-Hop"),
            ("X-Custom-Hop", "1"),
            ("Transfer-Encoding", "chunked"),
            ("X-Forwarded-For", "1.2.3.4"),
            ("X-ZoeyMCP-Gateway", "zgw1-..."),
            ("Accept-Encoding", "gzip"),
            ("X-Api-Ph", "placeholder"),
            ("Content-Type", "application/json"),
            ("User-Agent", "script/1.0"),
        ],
        drop=["x-api-ph"],
    )
    assert kept == [
        ("Content-Type", "application/json"),
        ("User-Agent", "script/1.0"),
        ("accept-encoding", "identity"),
    ]


def test_response_headers_drop_cookies() -> None:
    kept = filter_response_headers(
        [
            ("Content-Type", "application/json"),
            ("Set-Cookie", "session=upstream-credential"),
            ("Content-Encoding", "gzip"),
            ("Content-Length", "10"),
            ("Strict-Transport-Security", "max-age=1"),
            ("X-Request-Id", "abc"),
        ]
    )
    assert kept == [("Content-Type", "application/json"), ("X-Request-Id", "abc")]


# --- scrubbing ---------------------------------------------------------------------------------

SECRET = 'sk-live/Ab+Cd="q"'


def test_variants_cover_common_encodings() -> None:
    variants = secret_variants(SECRET, basic_user="bot")
    assert SECRET.encode() in variants
    assert b"sk-live%2FAb%2BCd%3D%22q%22" in variants
    assert b"sk-live%2fab%2bcd%3d%22q%22" in variants
    assert json.dumps(SECRET)[1:-1].encode() in variants
    assert base64.b64encode(SECRET.encode()) in variants
    assert base64.b64encode(f"bot:{SECRET}".encode()) in variants
    assert variants == sorted(variants, key=len, reverse=True)


@pytest.mark.parametrize(
    "echo",
    [
        SECRET,
        "https://api.example/x?api_key=sk-live%2FAb%2BCd%3D%22q%22",
        json.dumps({"error": "bad key", "key": SECRET}),
        "Authorization: Basic " + base64.b64encode(f"bot:{SECRET}".encode()).decode(),
    ],
)
def test_scrub_removes_every_form(echo: str) -> None:
    variants = secret_variants(SECRET, basic_user="bot")
    cleaned, count = scrub(f"prefix {echo} suffix".encode(), variants)
    assert count >= 1
    assert REDACTED in cleaned
    for variant in variants:
        assert variant not in cleaned


def test_scrub_leaves_other_text_alone() -> None:
    cleaned, count = scrub(b"nothing to see", secret_variants(SECRET))
    assert (cleaned, count) == (b"nothing to see", 0)


def test_short_secrets_skip_tiny_variants() -> None:
    assert secret_variants("ab") == []
    assert b"abcd" in secret_variants("abcd")


def test_scrub_headers() -> None:
    variants = secret_variants(SECRET)
    headers, count = scrub_headers([("Location", f"https://x/?k={SECRET}"), ("X", "ok")], variants)
    assert count == 1
    assert headers == [("Location", "https://x/?k=[REDACTED]"), ("X", "ok")]


# --- OAuth client secrets ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("client_id", "secret", "pair"),
    [
        ("app-1", "cs-value-1", b"app-1:cs-value-1"),
        ("my app:1", "p+%/ s", b"my+app%3A1:p%2B%25%2F+s"),
        ("a~b_c.d-e", "a*b", b"a~b_c.d-e:a%2Ab"),
        ("app", "s\u00fc\u00df", b"app:s%C3%BC%C3%9F"),
    ],
)
def test_oauth_basic_credentials_form_encode_both_parts(
    client_id: str, secret: str, pair: bytes
) -> None:
    assert oauth_basic_credentials(client_id, secret) == base64.b64encode(pair).decode()


def test_oauth_client_variants() -> None:
    variants = oauth_client_variants("my app", SECRET)
    for form in secret_variants(SECRET):
        assert form in variants
    assert b"sk-live%2FAb%2BCd%3D%22q%22" in variants
    basic = oauth_basic_credentials("my app", SECRET).encode()
    assert basic == base64.b64encode(b"my+app:sk-live%2FAb%2BCd%3D%22q%22")
    assert basic in variants
    assert variants == sorted(variants, key=len, reverse=True)
    assert len(variants) == len(set(variants))
    # The raw Basic form isn't sent, so it isn't added.
    assert base64.b64encode(f"my app:{SECRET}".encode()) not in variants


def test_oauth_client_variants_add_the_form_encoding() -> None:
    variants = oauth_client_variants("app", "a b+c")
    assert b"a+b%2Bc" in variants
    assert b"a%20b%2Bc" in variants


def test_short_client_secrets_get_no_variants() -> None:
    assert oauth_client_variants("app", "abc") == []
    assert oauth_client_variants("app", "abcd") != []


CLIENT_SECRET = "cs value+1"


@pytest.mark.parametrize(
    ("echo", "expected"),
    [
        (
            "Authorization: Basic " + oauth_basic_credentials("app", CLIENT_SECRET),
            b"Authorization: Basic " + REDACTED,
        ),
        # Only the form encoding turns the space into "+".
        (
            "grant_type=refresh_token&client_secret=cs+value%2B1",
            b"grant_type=refresh_token&client_secret=" + REDACTED,
        ),
        (
            json.dumps({"client_secret": CLIENT_SECRET}),
            b'{"client_secret": "' + REDACTED + b'"}',
        ),
    ],
)
def test_scrub_removes_oauth_client_secrets(echo: str, expected: bytes) -> None:
    cleaned, count = scrub(echo.encode(), oauth_client_variants("app", CLIENT_SECRET))
    assert (cleaned, count) == (expected, 1)


def test_only_the_oauth_variants_catch_the_form_and_basic_echoes() -> None:
    for echo in ("client_secret=cs+value%2B1", oauth_basic_credentials("app", CLIENT_SECRET)):
        assert scrub(echo.encode(), secret_variants(CLIENT_SECRET)) == (echo.encode(), 0)
