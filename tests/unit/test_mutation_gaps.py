"""Tests for gaps that mutation testing found: plausible bugs the other tests didn't notice.

Each group names the mutation that survived before the test existed.
"""

from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

import zoeymcp.vault.store as store_module
from zoeymcp.common.canonical import MAX_SAFE_INTEGER, JSONRejected, dumps_canonical, loads_strict
from zoeymcp.common.policy import Finding, check_policy, parse_policy
from zoeymcp.common.textrules import INVISIBLE_CHARACTERS, find_violations
from zoeymcp.vault.keys import KeySet
from zoeymcp.vault.request import (
    MAX_PATH_BYTES,
    MAX_QUERY_BYTES,
    RequestRejected,
    encode_query,
    normalize_path,
    parse_query,
    scrub_headers,
    secret_variants,
)
from zoeymcp.vault.store import (
    MAX_SECRET_BYTES,
    STORE_FILE,
    SecretStore,
    SecretUnavailable,
    StoreError,
    origin_binding,
)

NL, TAB, RLO = chr(10), chr(9), chr(0x202E)
KEYS = KeySet.from_master(bytes(range(32)))
OTHER_KEYS = KeySet.from_master(bytes(range(1, 33)))
API = origin_binding(["https://api.example"])


# --- text rules: `continue` -> `break` after a newline, tab or invisible character ------------


@pytest.mark.parametrize("separator", [NL, TAB, "a" + chr(0x2800) + "b"])
def test_scanning_continues_past_newlines_tabs_and_invisibles(separator: str) -> None:
    text = "line one" + separator + "line two " + RLO + " hidden"
    found = find_violations(text, max_chars=1000)
    assert any(v.codepoint == 0x202E for v in found), found


def test_text_rule_defaults() -> None:
    assert find_violations("a" + TAB + "b", max_chars=100) == []
    assert len(find_violations(chr(0x200B) * 50, max_chars=1000)) == 10


def test_violation_positions() -> None:
    [line_break] = find_violations("a" + NL + "b", max_chars=10, single_line=True)
    assert (line_break.index, line_break.codepoint) == (1, 10)
    [tab] = find_violations("ab" + TAB, max_chars=10, single_line=True)
    assert (tab.index, tab.codepoint) == (2, 9)
    [invisible] = find_violations("abc" + chr(0x3164), max_chars=10)
    assert (invisible.index, invisible.codepoint) == (3, 0x3164)
    [short] = find_violations("", max_chars=10, min_chars=1)
    assert (short.index, short.codepoint) == (-1, None)


_VISIBLE = st.characters(
    codec="utf-8",
    categories=["L", "N", "P", "S", "Zs"],
    exclude_characters="".join(INVISIBLE_CHARACTERS),
)


@given(
    st.text(alphabet=st.one_of(_VISIBLE, st.sampled_from([NL, TAB])), max_size=50),
    st.characters(categories=["Cf"]),
)
def test_property_a_format_character_after_anything_is_caught(before: str, hidden: str) -> None:
    found = find_violations(before + hidden, max_chars=200)
    assert [v.index for v in found] == [len(before)]


# --- canonical: `continue` -> `break` after null/bool; depth through objects; size boundary ---


@pytest.mark.parametrize(
    "value",
    [
        [None, float("nan")],
        [True, MAX_SAFE_INTEGER + 1],
        [False, "x", float("inf")],
        {"a": None, "b": float("nan")},
    ],
)
def test_validation_continues_past_null_and_booleans(value: Any) -> None:
    with pytest.raises(JSONRejected):
        dumps_canonical(value)


def test_depth_is_counted_through_objects() -> None:
    deep: Any = 1
    for _ in range(64):
        deep = {"k": deep}
    with pytest.raises(JSONRejected, match="nested deeper"):
        dumps_canonical(deep)
    shallow: Any = 1
    for _ in range(63):
        shallow = {"k": shallow}
    assert loads_strict(dumps_canonical(shallow)) == shallow


def test_json_size_limit_is_inclusive() -> None:
    exactly = '"' + "a" * 48 + '"'
    assert loads_strict(exactly, max_bytes=50) == "a" * 48
    assert loads_strict(exactly.encode(), max_bytes=50) == "a" * 48
    with pytest.raises(JSONRejected, match="larger than"):
        loads_strict(exactly + " ", max_bytes=50)


# --- store: timestamps, malformed entries, lenient base64, size boundary ---------------------


def _store(tmp_path: Path, keys: KeySet = KEYS, previous: KeySet | None = None) -> SecretStore:
    store = SecretStore(tmp_path, keys, previous)
    store.load()
    return store


def _raw(tmp_path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((tmp_path / STORE_FILE).read_text(encoding="utf-8"))
    return data


def _write(tmp_path: Path, data: dict[str, Any]) -> None:
    (tmp_path / STORE_FILE).write_text(json.dumps(data), encoding="utf-8")


def test_created_time_survives_replace_and_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    times = iter(f"2026-01-0{i}T00:00:00Z" for i in range(1, 9))
    monkeypatch.setattr(store_module, "_now", lambda: next(times))
    store = _store(tmp_path)
    store.put("stats", "v1", API)
    store.put("stats", "v2", API)
    [meta] = store.metadata()
    assert (meta.created, meta.updated) == ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
    rotated = SecretStore(tmp_path, OTHER_KEYS, previous=KEYS)
    rotated.load()
    [meta] = rotated.metadata()
    assert (meta.created, meta.updated) == ("2026-01-01T00:00:00Z", "2026-01-03T00:00:00Z")


def test_an_empty_store_rotates_nothing(tmp_path: Path) -> None:
    assert SecretStore(tmp_path, KEYS).load() == 0


def test_a_non_object_entry_is_a_store_error(tmp_path: Path) -> None:
    _write(tmp_path, {"format": 1, "entries": {"x": "not an object"}})
    with pytest.raises(StoreError, match="key ID None"):
        SecretStore(tmp_path, KEYS).load()


@pytest.mark.parametrize("field", ["nonce", "ciphertext"])
def test_junk_in_the_base64_is_refused(tmp_path: Path, field: str) -> None:
    _store(tmp_path).put("stats", "v", API)
    data = _raw(tmp_path)
    value = data["entries"]["stats"][field]
    data["entries"]["stats"][field] = value[:4] + "!" + value[4:]
    _write(tmp_path, data)
    with pytest.raises(SecretUnavailable, match="failed authentication"):
        _store(tmp_path).get_for_origin("stats", "https://api.example")


def test_secret_size_limit_is_inclusive(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.put("big", "x" * MAX_SECRET_BYTES, API)
    with pytest.raises(ValueError, match="larger than"):
        store.put("big", "x" * (MAX_SECRET_BYTES + 1), API)


# --- request: DEL byte, limits, query encoding, scrubbing variants ---------------------------


def test_raw_del_byte_is_refused_first() -> None:
    with pytest.raises(RequestRejected, match="non-printable or non-ASCII"):
        normalize_path(b"/a" + bytes([0x7F]) + b"b")


def test_path_and_query_limits_are_inclusive() -> None:
    path = b"/" + b"a" * (MAX_PATH_BYTES - 1)
    assert normalize_path(path).segments == ("a" * (MAX_PATH_BYTES - 1),)
    with pytest.raises(RequestRejected, match="too long"):
        normalize_path(path + b"a")
    query = b"q=" + b"x" * (MAX_QUERY_BYTES - 2)
    assert parse_query(query) == [("q", "x" * (MAX_QUERY_BYTES - 2))]
    with pytest.raises(RequestRejected, match="too long"):
        parse_query(query + b"x")


def test_spaces_are_percent_encoded_not_plus() -> None:
    assert encode_query([("q", "a b"), ("r", "~-._")]) == "q=a%20b&r=~-._"


def test_variants_for_a_non_ascii_secret() -> None:
    secret = "p" + chr(0xE4) + "ssw" + chr(0xF6) + "rd-key"
    variants = secret_variants(secret)
    assert json.dumps(secret)[1:-1].encode() in variants
    assert json.dumps(secret, ensure_ascii=False)[1:-1].encode() in variants


def test_variants_include_unpadded_urlsafe_base64() -> None:
    secret = "k>>?" + chr(0xFF) + "x"
    expected = base64.urlsafe_b64encode(secret.encode()).decode().rstrip("=").encode()
    assert expected in secret_variants(secret)


def test_scrub_headers_handles_values_outside_latin1() -> None:
    secret = "sk-live-0123456789"
    value = "caf" + chr(0x2026) + " " + secret
    headers, count = scrub_headers([("X-Note", value)], secret_variants(secret))
    assert count == 1
    assert secret not in headers[0][1]


# --- check: warnings that had no tests, a short-circuit, and early `break` --------------------

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "policy.yaml"


def _findings(mutate: Any) -> list[str]:
    raw = yaml.safe_load(EXAMPLE.read_text(encoding="utf-8"))
    raw = copy.deepcopy(raw)
    mutate(raw)
    policy = parse_policy(yaml.safe_dump(raw, sort_keys=False), "test")
    found: list[Finding] = check_policy(policy)
    return [f"{f.level} {f.path}: {f.message}" for f in found]


def _route(raw: dict[str, Any], name: str) -> dict[str, Any]:
    route: dict[str, Any] = next(r for r in raw["routes"] if r["name"] == name)
    return route


def test_placeholder_reused_on_two_routes_warns() -> None:
    def mutate(raw: dict[str, Any]) -> None:
        extra = copy.deepcopy(_route(raw, "stats"))
        extra.update(name="stats2", prefix="/stats2")
        raw["routes"].append(extra)

    found = _findings(mutate)
    assert (
        "warning routes[0].callers[0]: placeholder reused on several routes; give each "
        "client its own" in found
    )
    assert (
        "warning routes[3].callers[0]: placeholder reused on several routes; give each "
        "client its own" in found
    )


def test_token_length_boundary() -> None:
    def exactly_16(raw: dict[str, Any]) -> None:
        _route(raw, "stats")["callers"][0]["placeholder"] = "p" * 16

    assert not any("easy to guess" in f for f in _findings(exactly_16))

    def fifteen(raw: dict[str, Any]) -> None:
        _route(raw, "stats")["callers"][0]["placeholder"] = "p" * 15

    assert "warning routes[0].callers[0]: shorter than 16 characters, so easy to guess" in (
        _findings(fifteen)
    )


def test_duplicate_entries_warn() -> None:
    def mutate(raw: dict[str, Any]) -> None:
        _route(raw, "broker-mcp")["callers"] = ["gateway", "gateway"]
        _route(raw, "stats")["rules"][0]["methods"] = ["GET", "GET"]
        raw["gateway"]["servers"]["broker-read"]["tools"]["include"].append("get_quote")

    found = _findings(mutate)
    assert "warning routes[1].callers: gateway listed more than once" in found
    assert "warning routes[0].rules[0].methods: a method is listed more than once" in found
    assert "warning gateway.servers.broker-read.tools.include: a tool is listed more than once" in (
        found
    )


def test_forced_parameter_outside_allow_warns() -> None:
    def mutate(raw: dict[str, Any]) -> None:
        _route(raw, "stats")["query"]["allow"] = ["method"]

    assert "warning routes[0].query.allow: forced parameter 'user' isn't in allow" in (
        _findings(mutate)
    )


def test_plain_http_without_a_credential_warns() -> None:
    def mutate(raw: dict[str, Any]) -> None:
        route = _route(raw, "stats")
        route.update(upstream="http://api.stats.example", allow_insecure_upstream=True)
        route.pop("credential")
        route["query"]["strip"] = []

    assert "warning routes[0].upstream: plain http upstream" in _findings(mutate)


def test_mcp_route_needs_post_on_the_server_path_itself() -> None:
    def mutate(raw: dict[str, Any]) -> None:
        _route(raw, "broker-mcp")["rules"] = [
            {"methods": ["POST"], "paths": ["/other"]},
            {"methods": ["GET"], "paths": ["/mcp"]},
        ]

    assert (
        "warning gateway.servers.broker-read.path: route 'broker-mcp' has no rule allowing "
        "POST /mcp" in _findings(mutate)
    )


def test_every_bad_path_pattern_is_reported() -> None:
    def mutate(raw: dict[str, Any]) -> None:
        _route(raw, "stats")["rules"][0]["paths"] = ["/a/**/b", "/c//d", "/2.0/**"]

    found = [f for f in _findings(mutate) if f.startswith("error routes[0].rules[0].paths")]
    assert len(found) == 2, found


def test_mcp_server_path_must_be_plain() -> None:
    def mutate(raw: dict[str, Any]) -> None:
        raw["gateway"]["servers"]["broker-read"]["path"] = "mcp?x=1"

    assert "error gateway.servers.broker-read.path: must be a plain absolute path" in (
        _findings(mutate)
    )
