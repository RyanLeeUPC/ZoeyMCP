"""Killing tests for the survivors of the mutated modules that had no floor (register D-229).

From run 42159911619 (71b27bd): ``gateway.schemas`` (91.0%), ``vault.connectors.sendjournal``,
``common.canonical``, ``common.ledgerformat`` and ``vault.connectors.tunnel``, each of which gets
its first floor with these. Each test names what it pins. Several of the functions are called
only at import (``ledgerformat._member``, ``sendjournal._match``) or once per process behind a
cache (``schemas._budgeted`` inside ``schemas._extended``), so a test calls them directly: a
mutant there is otherwise never run. The mutants left alive on purpose are in
:data:`EQUIVALENT`, each with why no test can tell it from the original;
:func:`test_each_equivalent_names_a_function` keeps the list honest when a function is renamed or
removed. mutmut still counts them as survivors, so they stay in each module's score.
"""

from __future__ import annotations

import hashlib
import importlib
import re
from collections.abc import Iterator
from typing import Any, Final

import pytest
from jsonschema import Draft202012Validator, ValidationError

from zoeymcp.common import canonical, ledgerformat
from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.gateway import schemas
from zoeymcp.gateway.schemas import Budget, SchemaRefused, SchemaValidator, schema_problems
from zoeymcp.vault.connectors import sendjournal

_MESSAGE: Final = (
    "the ValidationError's message: SchemaValidator.errors reports each error as its pointer and "
    "its keyword (error.validator, which jsonschema sets), never its message"
)
_SCHEMA_PATH: Final = (
    "descend's schema_path: it only builds the error's schema_path, and SchemaValidator.errors "
    "reads absolute_path and the keyword"
)
_FORMAT_CHECKER: Final = (
    "format_checker=None dropped: it is jsonschema's default for every validator class (4.26)"
)
_ASCII: Final = 'the codec named "ASCII" for "ascii": Python looks codec names up case-blind'
_UNREACHABLE_ENCODE: Final = (
    "_encode's last branch (marked no cover): dumps_canonical and render_for_approval run "
    "_validate first, which refuses every value but the JSON types"
)
_FALSY_ASCII: Final = (
    "json.dumps with ensure_ascii=None for False: json reads the flag only for its truth"
)

EQUIVALENT: Final[dict[str, str]] = {
    # --- gateway.schemas
    "zoeymcp.gateway.schemas.x__additional_properties__mutmut_32": _MESSAGE,
    "zoeymcp.gateway.schemas.x__additional_properties__mutmut_48": _MESSAGE,
    "zoeymcp.gateway.schemas.x__additional_properties__mutmut_49": _MESSAGE,
    "zoeymcp.gateway.schemas.x__additional_properties__mutmut_50": _MESSAGE,
    "zoeymcp.gateway.schemas.x__pattern__mutmut_13": _MESSAGE,
    "zoeymcp.gateway.schemas.x__pattern__mutmut_15": _MESSAGE,
    "zoeymcp.gateway.schemas.x__pattern__mutmut_16": _MESSAGE,
    "zoeymcp.gateway.schemas.x__pattern__mutmut_17": _MESSAGE,
    "zoeymcp.gateway.schemas.x__pattern_properties__mutmut_13": _MESSAGE,
    "zoeymcp.gateway.schemas.x__pattern_properties__mutmut_17": _SCHEMA_PATH,
    "zoeymcp.gateway.schemas.x__pattern_properties__mutmut_21": _SCHEMA_PATH,
    "zoeymcp.gateway.schemas.x__header_problems__mutmut_43": (
        "header.upper() for lower() as the duplicate key: the header is an RFC 9110 token by "
        "then, which is ASCII, where upper and lower case pair up alike"
    ),
    "zoeymcp.gateway.schemas.x__metaschema_problem__mutmut_4": _FORMAT_CHECKER,
    "zoeymcp.gateway.schemas.xǁSchemaValidatorǁ__init____mutmut_6": _FORMAT_CHECKER,
    "zoeymcp.gateway.schemas.x_schema_problems__mutmut_103": (
        "`pattern_properties = None` for False: it is only read for its truth"
    ),
    "zoeymcp.gateway.schemas.x_validator_for__mutmut_19": (
        "OrderedDict.popitem(last=None): the C implementation reads last for its truth, so None "
        "pops the oldest entry as False does"
    ),
    # --- common.canonical
    "zoeymcp.common.canonical.x__encode__mutmut_41": _UNREACHABLE_ENCODE,
    "zoeymcp.common.canonical.x__encode__mutmut_42": _UNREACHABLE_ENCODE,
    "zoeymcp.common.canonical.x__encode_container__mutmut_18": _FALSY_ASCII,
    "zoeymcp.common.canonical.x_encode_scalar__mutmut_15": _FALSY_ASCII,
    "zoeymcp.common.canonical.x__has_lone_surrogate__mutmut_3": (
        '"\\uD800" for "\\ud800": the same one-character string'
    ),
    "zoeymcp.common.canonical.x__has_lone_surrogate__mutmut_7": (
        '"\\uDFFF" for "\\udfff": the same one-character string'
    ),
    "zoeymcp.common.canonical.x__utf16_key__mutmut_6": (
        'the codec named "UTF-16-BE": Python looks codec names up case-blind'
    ),
    "zoeymcp.common.canonical.x_dumps_canonical__mutmut_16": (
        "level 1 for 0 with no indent: _encode_container reads level only to indent"
    ),
    "zoeymcp.common.canonical.x_dumps_canonical__mutmut_21": (
        'the codec named "UTF-8": Python looks codec names up case-blind'
    ),
    # --- common.ledgerformat
    "zoeymcp.common.ledgerformat.x_parse__mutmut_16": (
        "loads_strict with its default max_bytes: parse has already refused a body over "
        "MAX_LINE_BYTES - 1, so the larger limit is never reached"
    ),
    "zoeymcp.common.ledgerformat.x_torn_tail__mutmut_16": (
        "rfind with None for its start: bytes.rfind takes None as a slice does, the same as 0"
    ),
    # --- vault.connectors.tunnel
    "zoeymcp.vault.connectors.tunnel.x_connect_request__mutmut_4": _ASCII,
    "zoeymcp.vault.connectors.tunnel.x_parse_connect_reply__mutmut_12": (
        "the reply head split on every CRLF, not the first: only the first part is read"
    ),
    "zoeymcp.vault.connectors.tunnel.x_parse_connect_reply__mutmut_15": (
        "the reply head split twice, not once: only the first part is read"
    ),
}


def _function(key: str) -> tuple[str, str, str | None]:
    """A mutant key's module, function and class (None for a module-level function)."""
    path, _, _ = key.partition("__mutmut_")
    if "xǁ" in path:
        module, _, rest = path.partition(".xǁ")
        cls, _, name = rest.partition("ǁ")
        return module, name, cls
    module, _, name = path.rpartition(".x_")
    return module, name, None


def test_each_equivalent_names_a_function() -> None:
    """One test over the whole list, so a key holding mutmut's class marker makes no node ID."""
    for key in sorted(EQUIVALENT):
        module_name, name, cls = _function(key)
        owner: object = importlib.import_module(module_name)
        if cls is not None:
            owner = getattr(owner, cls)
        assert callable(getattr(owner, name)), key


def test_the_reasons_hold() -> None:
    # Three of the reasons above, checked.
    assert "ascii".encode("ASCII") == b"ascii"
    assert b"a\nb\n".rfind(b"\n", None, 3) == b"a\nb\n".rfind(b"\n", 0, 3) == 1
    assert Draft202012Validator({}).format_checker is None


# --- gateway.schemas: what each refusal says ----------------------------------------------------

LIMITS = GatewayLimits()


def obj(**members: Any) -> dict[str, Any]:
    return {"type": "object", **members}


def said(schema: Any, **limits: int) -> list[tuple[str, str, str]]:
    found = schema_problems(
        schema, role="input", limits=GatewayLimits(**limits) if limits else LIMITS
    )
    return [(problem.pointer, problem.code, problem.message) for problem in found]


@pytest.mark.parametrize(
    ("schema", "expected"),
    [
        (None, ("", "schema_not_object", "the schema is not a JSON object")),
        (obj(x=2**53), ("", "schema_not_canonical", "no canonical JSON form")),
        (
            obj(**{"$schema": "https://example.com/schema"}),
            ("/$schema", "schema_dialect", "only 2020-12 and draft-07 are supported"),
        ),
        (
            obj(properties={"a": {"$schema": "https://json-schema.org/draft/2020-12/schema"}}),
            ("/properties/a/$schema", "schema_dialect", "$schema only at the root"),
        ),
        (
            obj(properties={"a": {"pattern": "("}}),
            ("/properties/a/pattern", "schema_pattern", "the pattern doesn't compile"),
        ),
        (
            obj(patternProperties={"(": {}}),
            ("/patternProperties/(", "schema_pattern", "the pattern doesn't compile"),
        ),
        (
            {"type": "object", "x-mcp-header": "Root"},
            (
                "/x-mcp-header",
                "schema_mcp_header",
                "x-mcp-header must be on a property reached from the root through properties",
            ),
        ),
        (
            obj(properties={"r": {"type": "number", "x-mcp-header": "Region"}}),
            (
                "/properties/r/x-mcp-header",
                "schema_mcp_header",
                "x-mcp-header is only allowed on a string, integer or boolean property",
            ),
        ),
    ],
    ids=[
        "not-object",
        "not-canonical",
        "dialect",
        "nested-dialect",
        "pattern",
        "pattern-key",
        "header-off-chain",
        "header-type",
    ],
)
def test_each_refusal_says_what_it_is(schema: Any, expected: tuple[str, str, str]) -> None:
    assert said(schema) == [expected]


def test_the_subschema_cap_names_its_numbers() -> None:
    schema = obj(properties={str(i): {} for i in range(16)})  # the root and 16 more
    assert said(schema, max_subschemas=16) == [
        ("", "schema_too_many_subschemas", "17 subschemas, limit 16")
    ]


def test_the_unevaluated_refusal_says_why() -> None:
    schema = obj(patternProperties={"^a": {}}, unevaluatedProperties=False)
    assert said(schema) == [
        (
            "/unevaluatedProperties",
            "schema_unevaluated",
            "unevaluatedProperties can't be used in a schema that has patternProperties",
        )
    ]


def test_a_boolean_subschema_doesnt_end_the_checks() -> None:
    # true is a schema position too; the walk goes on past it to the next property.
    schema = obj(properties={"a": True, "b": {"pattern": "("}})
    assert said(schema) == [
        ("/properties/b/pattern", "schema_pattern", "the pattern doesn't compile")
    ]
    assert schemas.patterns(obj(properties={"a": True, "b": {"pattern": "x"}})) == [
        ("/properties/b/pattern", "x")
    ]


def test_an_object_valued_data_keyword_is_not_a_map_of_schemas() -> None:
    # const and default hold data, not subschemas: an $id inside one is a value, not a keyword.
    schema = obj(const={"k": {"$id": "x"}}, default={"k": {"$id": "x"}})
    assert said(schema) == []
    assert [position.path for position in schemas._positions(schema)] == [()]


def test_depth_goes_on_past_a_scalar() -> None:
    # The scalar 2 is taken off the stack before the inner list.
    assert schemas.depth([[1], 2]) == 2


@pytest.mark.parametrize("declared", [["x"], {"a": 1}])
def test_an_unhashable_dialect_is_refused_not_crashed(declared: Any) -> None:
    assert schemas.dialect_of({"$schema": declared}) is None


def test_additional_properties_check_every_key_after_a_pattern_match() -> None:
    schema = obj(patternProperties={"^a": {}}, additionalProperties=False)
    validator = SchemaValidator(schema, Draft202012Validator)
    assert validator.errors({"a1": 1, "z": 2}, Budget.start()) == ["/: additionalProperties"]


def test_a_budgeted_keyword_gets_every_argument() -> None:
    seen: list[tuple[Any, ...]] = []

    def keyword(validator: Any, value: Any, instance: Any, schema: Any) -> Iterator[Any]:
        seen.append((validator, value, instance, schema))
        yield ValidationError("x")

    run = schemas._budgeted(keyword)
    token = schemas._BUDGET.set(Budget.start())
    try:
        assert len(list(run("v", "a", "i", "s"))) == 1
    finally:
        schemas._BUDGET.reset(token)
    assert seen == [("v", "a", "i", "s")]
    with pytest.raises(SchemaRefused):
        list(run("v", "a", "i", "s"))  # outside a budget


class _Clock:
    """A stand-in for schemas' ``time``: monotonic() starts at ``now`` and moves by ``step``."""

    def __init__(self, now: float, step: float) -> None:
        self.now = now
        self.step = step

    def monotonic(self) -> float:
        now = self.now
        self.now += self.step
        return now


def test_the_deadline_itself_is_past(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schemas, "time", _Clock(5.0, 0.0))
    validator = SchemaValidator(obj(), Draft202012Validator)
    with pytest.raises(SchemaRefused) as info:
        validator.errors({}, Budget(deadline=5.0, regex_left=1.0))
    assert info.value.code == "schema_budget_exhausted"


def test_a_spent_regex_budget_refuses_before_matching(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(schemas, "time", _Clock(0.0, 1.0))
    validator = SchemaValidator(obj(properties={"a": {"pattern": "a"}}), Draft202012Validator)
    budget = Budget(deadline=1e9, regex_left=0.0)
    with pytest.raises(SchemaRefused) as info:
        validator.errors({"a": "a"}, budget)
    assert info.value.code == "schema_regex_timeout"
    assert budget.regex_left == 0.0  # no match ran, so none was charged


def test_a_refusal_carries_its_code() -> None:
    refused = SchemaRefused("schema_dialect")
    assert refused.args == ("schema_dialect",)
    assert str(refused) == "schema_dialect"


# --- common.canonical ---------------------------------------------------------------------------


def test_an_overflow_names_at_most_32_characters() -> None:
    text = "1." + "0" * 40 + "e400"
    with pytest.raises(canonical.JSONRejected) as info:
        canonical.loads_strict(text)
    assert str(info.value) == f"number {text[:32]} overflows to infinity"


def test_a_non_scalar_names_its_type() -> None:
    with pytest.raises(canonical.JSONRejected, match=r"^list is not a JSON scalar$"):
        canonical.encode_scalar([])


def test_a_lone_surrogate_has_a_sort_key() -> None:
    # One UTF-16 code unit, as for any other character.
    assert canonical.key_order("\ud800") == b"\xd8\x00"
    assert canonical.key_order("a\udfff") == b"\x00a\xdf\xff"


# --- common.ledgerformat ------------------------------------------------------------------------


def test_member_and_optional() -> None:
    member = ledgerformat._member(frozenset({"a"}))
    assert member("a") is True
    assert member("b") is False
    assert member(1) is False
    optional = ledgerformat._optional(lambda value: value == "x")
    assert optional(None) is True
    assert optional("x") is True
    assert optional("y") is False


def _recovered() -> bytes:
    return ledgerformat.encode(
        "recovered",
        seq=0,
        prev=ledgerformat.GENESIS,
        ts=1,
        ref=None,
        abandoned=0,
        not_sent=0,
        unknown=0,
    )


def test_a_ledger_line_may_be_exactly_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    line = _recovered()
    monkeypatch.setattr(ledgerformat, "MAX_LINE_BYTES", len(line))
    assert _recovered() == line
    assert ledgerformat.parse(line).line == line[:-1]
    monkeypatch.setattr(ledgerformat, "MAX_LINE_BYTES", len(line) - 1)
    with pytest.raises(ledgerformat.LedgerFormatError) as info:
        _recovered()
    assert str(info.value) == f"a recovered record is longer than {len(line) - 1} bytes"
    with pytest.raises(ledgerformat.LedgerFormatError, match=r"^a record is longer than"):
        ledgerformat.parse(line)


def test_a_line_hash_drops_only_newlines() -> None:
    assert ledgerformat.line_hash(b"a \n") == "sha256:" + hashlib.sha256(b"a ").hexdigest()
    assert ledgerformat.line_hash(b"aX\n") == "sha256:" + hashlib.sha256(b"aX").hexdigest()


def test_an_empty_last_line_is_one_torn_byte() -> None:
    assert ledgerformat.torn_tail(_recovered() + b"\n") == 1


# --- vault.connectors.sendjournal ---------------------------------------------------------------

_KEY = "3f9c0a17d2b84e65.1"


def _unknown() -> bytes:
    return sendjournal.encode("unknown", ts=3, key=_KEY, phase="final_reply")


def test_match() -> None:
    match = sendjournal._match(re.compile("a+"))
    assert match("aa") is True
    assert match("b") is False
    assert match(5) is False


def test_a_journal_line_may_be_exactly_the_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    line = _unknown()
    monkeypatch.setattr(sendjournal, "MAX_LINE_BYTES", len(line))
    assert _unknown() == line
    monkeypatch.setattr(sendjournal, "MAX_LINE_BYTES", len(line) - 1)
    with pytest.raises(sendjournal.JournalError) as info:
        _unknown()
    assert str(info.value) == "a journal record is too long"
    # The limit is on the record without its newline, which parse takes off first.
    assert sendjournal.parse(line) == {
        "kind": "unknown",
        "ts": 3,
        "key": _KEY,
        "phase": "final_reply",
    }


def test_a_padded_journal_line_over_the_limit_is_refused() -> None:
    padded = _unknown()[:-1] + b" " * sendjournal.MAX_LINE_BYTES
    with pytest.raises(sendjournal.JournalError, match=r"^not a JSON record$"):
        sendjournal.parse(padded)
