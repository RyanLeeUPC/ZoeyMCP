"""Accepting upstream JSON Schemas, and validating against pinned ones (M3 design H).

:func:`schema_problems` decides whether a schema can be pinned and served (H.1). It runs at every
evaluation and at review, and it refuses what the validators can't check safely:

- a ``$schema`` other than 2020-12 (the MCP default) or draft-07, so ``validator_for`` is never
  called on upstream input;
- any reference but a local JSON pointer to a subschema of the same document, and ``$id`` and the
  dynamic and recursive keywords anywhere, so nothing is ever fetched or re-based;
- a ``pattern`` or ``patternProperties`` key that the ``regex`` module can't compile;
- an invalid ``x-mcp-header`` (the spec requires excluding such a tool).

Validators (H.2) are built only from pinned schemas, with an empty ``referencing`` registry and
no format checker. ``pattern``, ``patternProperties`` and ``additionalProperties`` are
reimplemented on the ``regex`` module with the ``ASCII`` flag (so ``\\d`` and ``\\w`` match
ECMA-262) and a time limit, because jsonschema's own versions use ``re``, which has none. Every
keyword runs under a per-call budget, so no reviewed schema can make a call run long. A string
ending in ``\\n`` is refused by a pattern with an unescaped ``$``, which matches before a final
newline in Python but not in ECMA-262. Error text names the pointer and the keyword, never the
value.
"""

from __future__ import annotations

import re
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextvars import ContextVar
from copy import deepcopy
from dataclasses import dataclass
from functools import cache, lru_cache
from typing import Any, Literal, cast
from urllib.parse import unquote

import referencing
import referencing.exceptions
import regex
from jsonschema import Draft7Validator, Draft202012Validator, ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import extend

from ..common import canonical, textrules
from ..common.policy.schema import GatewayLimits

Role = Literal["input", "output"]
# A tool definition's schema members, by role.
MEMBERS: tuple[tuple[Role, str], ...] = (("input", "inputSchema"), ("output", "outputSchema"))
Path = tuple[str | int, ...]

DIALECTS: Mapping[str, type[Validator]] = {
    "https://json-schema.org/draft/2020-12/schema": Draft202012Validator,
    "http://json-schema.org/draft-07/schema": Draft7Validator,
    "http://json-schema.org/draft-07/schema#": Draft7Validator,
}
REFUSED_KEYWORDS = ("$id", "$dynamicRef", "$dynamicAnchor", "$recursiveRef", "$recursiveAnchor")
HEADER_KEY = "x-mcp-header"
HEADER_TOKEN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")  # RFC 9110 token
HEADER_TYPES = frozenset({"string", "integer", "boolean"})

# Keywords whose values are subschemas, by shape, in 2020-12 and draft-07 together. Walking both
# dialects' keywords in either is stricter, never looser: more is checked, and more is a valid
# $ref target only where the validator also treats it as a schema or ignores it.
_SINGLE = frozenset(
    {
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)
_LIST = frozenset({"allOf", "anyOf", "oneOf", "prefixItems", "items"})
_MAP = frozenset({"$defs", "definitions", "dependencies", "dependentSchemas", "patternProperties"})
_CANONICAL_INDEX = re.compile(r"0|[1-9][0-9]*")

MATCH_TIMEOUT = 0.05  # seconds, per regex match
REGEX_BUDGET = 0.25  # seconds of regex matching per call
CALL_BUDGET = 2.0  # seconds of validation per call, all keywords together
MAX_ERRORS = 10
VALIDATOR_CACHE_SIZE = 1024


def json_pointer(path: Iterable[str | int]) -> str:
    """RFC 6901: ``""`` for the root, else ``/`` before each part, with ``~`` and ``/`` escaped."""
    return "".join("/" + str(part).replace("~", "~0").replace("/", "~1") for part in path)


@dataclass(frozen=True, order=True)
class SchemaProblem:
    """Why a schema is refused, at a JSON pointer into it. ``message`` never quotes the schema."""

    pointer: str
    code: str
    message: str

    def __str__(self) -> str:
        return f"{textrules.reveal_hidden(self.pointer)}: {self.message}"


# --- walking schema positions ------------------------------------------------------------------


@dataclass(frozen=True)
class _Position:
    path: Path
    node: dict[str, Any] | bool
    # The property names from the root to here through ``properties`` only; None once any other
    # keyword is crossed.
    chain: tuple[str, ...] | None


def _is_schema(value: object) -> bool:
    return isinstance(value, dict | bool)


def _positions(root: dict[str, Any]) -> Iterator[_Position]:
    """Every schema position in ``root``, in document order. ``$ref`` is not followed."""
    stack = [_Position((), root, ())]
    while stack:
        position = stack.pop()
        yield position
        node = position.node
        if not isinstance(node, dict):
            continue
        children: list[_Position] = []
        for keyword, value in node.items():
            path = (*position.path, keyword)
            if keyword == "properties" and isinstance(value, dict):
                for name, sub in value.items():
                    if _is_schema(sub):
                        chain = None if position.chain is None else (*position.chain, name)
                        children.append(_Position((*path, name), sub, chain))
            elif keyword in _LIST and isinstance(value, list):
                children.extend(
                    _Position((*path, index), sub, None)
                    for index, sub in enumerate(value)
                    if _is_schema(sub)
                )
            elif keyword in _SINGLE and _is_schema(value):
                children.append(_Position(path, value, None))
            elif keyword in _MAP and isinstance(value, dict):
                children.extend(
                    _Position((*path, key), sub, None)
                    for key, sub in value.items()
                    if _is_schema(sub)
                )
        stack.extend(reversed(children))


def _depth(value: Any) -> int:
    """How deeply objects and arrays nest in ``value`` (a scalar is 0, ``{}`` is 1)."""
    deepest = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if isinstance(item, dict):
            children: Iterable[Any] = item.values()
        elif isinstance(item, list):
            children = item
        else:
            continue
        deepest = max(deepest, depth)
        stack.extend((child, depth + 1) for child in children)
    return deepest


def _ref_target(document: dict[str, Any], ref: object) -> Path | None:
    """The path a ``$ref`` resolves to inside ``document``, decoded as ``referencing`` does it.

    None for anything but ``#`` or a ``#/...`` pointer to an existing location. An array index
    must be written canonically: ``referencing`` would also take ``01``, ``+1`` or ``-1``.
    """
    if not isinstance(ref, str) or not ref.startswith("#"):
        return None
    fragment = ref[1:]
    if not fragment:
        return ()
    if not fragment.startswith("/"):
        return None  # a plain-name anchor
    node: Any = document
    path: list[str | int] = []
    for segment in unquote(fragment[1:]).split("/"):
        if isinstance(node, list):
            if _CANONICAL_INDEX.fullmatch(segment) is None or int(segment) >= len(node):
                return None
            index = int(segment)
            node = node[index]
            path.append(index)
        elif isinstance(node, dict):
            key = segment.replace("~1", "/").replace("~0", "~")
            if key not in node:
                return None
            node = node[key]
            path.append(key)
        else:
            return None
    return tuple(path)


# --- accepting a schema (H.1) ------------------------------------------------------------------


def dialect_of(schema: Mapping[str, Any]) -> type[Validator] | None:
    """The validator class for a schema's ``$schema``, or None if it names any other dialect."""
    if "$schema" not in schema:
        return Draft202012Validator
    declared = schema["$schema"]
    return DIALECTS.get(declared) if isinstance(declared, str) else None


@lru_cache(maxsize=4096)
def _compiled(pattern: str) -> regex.Pattern[str]:
    return regex.compile(pattern, regex.ASCII)


def compiles(pattern: str) -> bool:
    try:
        _compiled(pattern)
    except (regex.error, ValueError, OverflowError, RecursionError):
        return False
    return True


def _header_problems(position: _Position, seen: dict[str, str]) -> list[SchemaProblem]:
    node = position.node
    if not isinstance(node, dict):
        return []
    where = json_pointer((*position.path, HEADER_KEY))
    header = node[HEADER_KEY]
    if not position.chain:
        return [
            SchemaProblem(
                where,
                "schema_mcp_header",
                f"{HEADER_KEY} must be on a property reached from the root through properties",
            )
        ]
    if not isinstance(header, str) or HEADER_TOKEN.fullmatch(header) is None:
        return [SchemaProblem(where, "schema_mcp_header", f"{HEADER_KEY} is not an RFC 9110 token")]
    declared = node.get("type")
    if not isinstance(declared, str) or declared not in HEADER_TYPES:
        return [
            SchemaProblem(
                where,
                "schema_mcp_header",
                f"{HEADER_KEY} is only allowed on a string, integer or boolean property",
            )
        ]
    lowered = header.lower()
    if lowered in seen:
        return [
            SchemaProblem(
                where,
                "schema_mcp_header",
                f"{HEADER_KEY} names the same header as {textrules.reveal_hidden(seen[lowered])}",
            )
        ]
    seen[lowered] = where
    return []


def _metaschema_problem(schema: dict[str, Any], dialect: type[Validator]) -> SchemaProblem | None:
    # The format checker stays off here too: "format": "regex" would check patterns with ``re``,
    # and patterns are checked with ``regex`` instead.
    meta = dialect(dialect.META_SCHEMA, format_checker=None)
    for error in meta.iter_errors(schema):
        return SchemaProblem(
            json_pointer(error.absolute_path),
            "schema_invalid",
            f"not a valid schema for its dialect (the {error.validator} keyword)",
        )
    return None


def schema_problems(schema: Any, *, role: Role, limits: GatewayLimits) -> list[SchemaProblem]:
    """H.1: why ``schema`` can't be pinned and served as a tool's input or output schema.

    Empty if it's acceptable. Size and depth are checked first, and nothing else is checked on a
    schema over either limit.
    """
    if not isinstance(schema, dict):
        return [SchemaProblem("", "schema_not_object", "the schema is not a JSON object")]
    problems: list[SchemaProblem] = []
    if role == "input" and schema.get("type") != "object":
        problems.append(
            SchemaProblem("", "schema_root_type", 'an input schema must be "type": "object"')
        )
    try:
        size = len(canonical.dumps_canonical(schema))
    except canonical.JSONRejected:
        return [*problems, SchemaProblem("", "schema_not_canonical", "no canonical JSON form")]
    if size > limits.max_schema_bytes:
        return [
            *problems,
            SchemaProblem("", "schema_too_large", f"{size} bytes, limit {limits.max_schema_bytes}"),
        ]
    depth = _depth(schema)
    if depth > limits.max_schema_depth:
        return [
            *problems,
            SchemaProblem(
                "", "schema_too_deep", f"nested {depth} levels, limit {limits.max_schema_depth}"
            ),
        ]
    positions = list(_positions(schema))
    if len(positions) > limits.max_subschemas:
        return [
            *problems,
            SchemaProblem(
                "",
                "schema_too_many_subschemas",
                f"{len(positions)} subschemas, limit {limits.max_subschemas}",
            ),
        ]
    dialect = dialect_of(schema)
    if dialect is None:
        problems.append(
            SchemaProblem("/$schema", "schema_dialect", "only 2020-12 and draft-07 are supported")
        )
    locations = {position.path for position in positions}
    headers: dict[str, str] = {}
    pattern_properties = False
    unevaluated: list[str] = []
    for position in positions:
        node = position.node
        if not isinstance(node, dict):
            continue
        here = json_pointer(position.path)
        if position.path and "$schema" in node:
            problems.append(
                SchemaProblem(f"{here}/$schema", "schema_dialect", "$schema only at the root")
            )
        problems.extend(
            SchemaProblem(f"{here}/{keyword}", "schema_keyword", f"{keyword} is not supported")
            for keyword in REFUSED_KEYWORDS
            if keyword in node
        )
        if "$ref" in node and _ref_target(schema, node["$ref"]) not in locations:
            problems.append(
                SchemaProblem(
                    f"{here}/$ref",
                    "schema_ref",
                    "$ref must be a local JSON pointer to a subschema of the same schema",
                )
            )
        pattern = node.get("pattern")
        if isinstance(pattern, str) and not compiles(pattern):
            problems.append(
                SchemaProblem(f"{here}/pattern", "schema_pattern", "the pattern doesn't compile")
            )
        keyed = node.get("patternProperties")
        if isinstance(keyed, dict):
            pattern_properties = True
            problems.extend(
                SchemaProblem(
                    json_pointer((*position.path, "patternProperties", key)),
                    "schema_pattern",
                    "the pattern doesn't compile",
                )
                for key in keyed
                if not compiles(key)
            )
        if "unevaluatedProperties" in node:
            unevaluated.append(here)
        if role == "input" and HEADER_KEY in node:
            problems.extend(_header_problems(position, headers))
    if pattern_properties:
        # jsonschema finds evaluated properties with ``re``, outside the keywords replaced here.
        problems.extend(
            SchemaProblem(
                f"{here}/unevaluatedProperties",
                "schema_unevaluated",
                "unevaluatedProperties can't be used in a schema that has patternProperties",
            )
            for here in unevaluated
        )
    if dialect is not None:
        problem = _metaschema_problem(schema, dialect)
        if problem is not None:
            problems.append(problem)
    return sorted(problems)


def mcp_headers(schema: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(pointer, header)`` for every ``x-mcp-header`` on a property reached through properties.

    For review's warning. Whether each one is valid is :func:`schema_problems`'s decision.
    """
    if not isinstance(schema, dict):
        return []
    return sorted(
        (json_pointer(position.path), position.node[HEADER_KEY])
        for position in _positions(schema)
        if position.chain
        and isinstance(position.node, dict)
        and isinstance(position.node.get(HEADER_KEY), str)
    )


def patterns(schema: Mapping[str, Any]) -> list[tuple[str, str]]:
    """``(pointer, pattern)`` for every ``pattern`` and ``patternProperties`` key, for review."""
    if not isinstance(schema, dict):
        return []
    found: list[tuple[str, str]] = []
    for position in _positions(schema):
        node = position.node
        if not isinstance(node, dict):
            continue
        pattern = node.get("pattern")
        if isinstance(pattern, str):
            found.append((json_pointer((*position.path, "pattern")), pattern))
        keyed = node.get("patternProperties")
        if isinstance(keyed, dict):
            found.extend(
                (json_pointer((*position.path, "patternProperties", key)), key) for key in keyed
            )
    return sorted(found)


# --- validators (H.2) --------------------------------------------------------------------------


class SchemaRefused(Exception):
    """Validation couldn't finish, so the call is refused. ``code`` is the stable reason."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass
class Budget:
    """What one call may spend on validation, input and output together."""

    deadline: float
    regex_left: float

    @classmethod
    def start(cls, seconds: float = CALL_BUDGET, regex_seconds: float = REGEX_BUDGET) -> Budget:
        return cls(deadline=time.monotonic() + seconds, regex_left=regex_seconds)


_BUDGET: ContextVar[Budget | None] = ContextVar("zoeymcp_schema_budget", default=None)


def _budget() -> Budget:
    budget = _BUDGET.get()
    if budget is None or time.monotonic() >= budget.deadline:
        raise SchemaRefused("schema_budget_exhausted")
    return budget


@lru_cache(maxsize=4096)
def _has_unescaped_dollar(pattern: str) -> bool:
    escaped = False
    for char in pattern:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "$":
            return True
    return False


class _Ambiguous(Exception):
    """Python and ECMA-262 could disagree on this match."""


AMBIGUOUS = "a string ending in a line break can't be checked against a pattern with $"


def _search(pattern: str, text: str) -> bool:
    if text.endswith("\n") and _has_unescaped_dollar(pattern):
        raise _Ambiguous
    budget = _budget()
    limit = min(MATCH_TIMEOUT, budget.regex_left)
    if limit <= 0:
        raise SchemaRefused("schema_regex_timeout")
    started = time.monotonic()
    try:
        return _compiled(pattern).search(text, timeout=limit) is not None
    except TimeoutError as exc:
        raise SchemaRefused("schema_regex_timeout") from exc
    finally:
        budget.regex_left -= time.monotonic() - started


Keyword = Callable[[Any, Any, Any, Any], Iterator[ValidationError]]


def _pattern(validator: Any, pattern: Any, instance: Any, schema: Any) -> Iterator[ValidationError]:
    if not validator.is_type(instance, "string"):
        return
    try:
        matched = _search(pattern, instance)
    except _Ambiguous:
        yield ValidationError(AMBIGUOUS)
        return
    if not matched:
        yield ValidationError("does not match the pattern")


def _pattern_properties(
    validator: Any, keyed: Any, instance: Any, schema: Any
) -> Iterator[ValidationError]:
    if not validator.is_type(instance, "object"):
        return
    for pattern, subschema in keyed.items():
        for key, value in instance.items():
            try:
                matched = _search(pattern, key)
            except _Ambiguous:
                yield ValidationError(AMBIGUOUS)
                return
            if matched:
                yield from validator.descend(value, subschema, path=key, schema_path=pattern)


def _additional_properties(
    validator: Any, additional: Any, instance: Any, schema: Any
) -> Iterator[ValidationError]:
    if not validator.is_type(instance, "object"):
        return
    properties = schema.get("properties", {})
    keyed = schema.get("patternProperties", {})
    extras: list[str] = []
    for key in instance:
        if key in properties:
            continue
        try:
            if any(_search(pattern, key) for pattern in keyed):
                continue
        except _Ambiguous:
            yield ValidationError(AMBIGUOUS)
            return
        extras.append(key)
    if validator.is_type(additional, "object"):
        for extra in extras:
            yield from validator.descend(instance[extra], additional, path=extra)
    elif not additional and extras:
        yield ValidationError("additional properties are not allowed")


def _budgeted(keyword: Keyword) -> Keyword:
    def run(validator: Any, value: Any, instance: Any, schema: Any) -> Iterator[ValidationError]:
        _budget()
        yield from keyword(validator, value, instance, schema)

    return run


@cache
def _extended(dialect: type[Validator]) -> type[Validator]:
    keywords: dict[str, Keyword] = dict(dialect.VALIDATORS)
    keywords.update(
        pattern=_pattern,
        patternProperties=_pattern_properties,
        additionalProperties=_additional_properties,
    )
    budgeted = {name: _budgeted(keyword) for name, keyword in keywords.items()}
    return cast(type[Validator], extend(dialect, budgeted))  # type: ignore[no-untyped-call]


def _without_dialects(schema: Mapping[str, Any]) -> dict[str, Any]:
    """A copy of ``schema`` with ``$schema`` removed from every schema position.

    jsonschema's ``descend`` calls ``validator_for`` on each subschema it enters. A ``$schema``
    there, or at the root reached again through ``$ref: "#"``, would switch to jsonschema's own
    class for that dialect, which matches patterns with ``re`` and no budget. The dialect is
    already chosen, so the declaration is removed rather than trusted.
    """
    copy = deepcopy(dict(schema))
    for position in _positions(copy):
        if isinstance(position.node, dict):
            position.node.pop("$schema", None)
    return copy


class SchemaValidator:
    """Validates instances against one pinned schema."""

    def __init__(self, schema: Mapping[str, Any], dialect: type[Validator]) -> None:
        # An empty registry has no retrieve: jsonschema's default would fetch with urlopen, which
        # also opens file:// URLs.
        self._validator = _extended(dialect)(
            _without_dialects(schema), registry=referencing.Registry(), format_checker=None
        )

    def errors(self, instance: Any, budget: Budget) -> list[str]:
        """``pointer: keyword`` for each way ``instance`` fails (at most :data:`MAX_ERRORS`).

        Raises :class:`SchemaRefused` if validation can't finish within ``budget`` or a reference
        can't be resolved.
        """
        token = _BUDGET.set(budget)
        try:
            found: list[str] = []
            for error in self._validator.iter_errors(instance):
                found.append(f"{json_pointer(error.absolute_path) or '/'}: {error.validator}")
                if len(found) >= MAX_ERRORS:
                    break
            return found
        except referencing.exceptions.Unresolvable as exc:
            raise SchemaRefused("schema_unresolvable") from exc
        except RecursionError as exc:
            raise SchemaRefused("schema_recursion") from exc
        finally:
            _BUDGET.reset(token)


_VALIDATORS: OrderedDict[tuple[str, Role], SchemaValidator] = OrderedDict()


def validator_for(pin: str, role: Role, schema: Mapping[str, Any]) -> SchemaValidator:
    """The cached validator for a pinned tool's schema. ``schema`` must be the one ``pin`` covers.

    Only pinned schemas reach here, so a server can't swap in an expensive schema after review.
    """
    key = (pin, role)
    cached = _VALIDATORS.get(key)
    if cached is not None:
        _VALIDATORS.move_to_end(key)
        return cached
    dialect = dialect_of(schema)
    if dialect is None:
        raise SchemaRefused("schema_dialect")
    validator = SchemaValidator(schema, dialect)
    _VALIDATORS[key] = validator
    if len(_VALIDATORS) > VALIDATOR_CACHE_SIZE:
        _VALIDATORS.popitem(last=False)
    return validator
