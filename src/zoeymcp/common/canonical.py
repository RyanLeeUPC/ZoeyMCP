"""Strict JSON parsing and ZoeyMCP's canonical JSON form (design §5.1, §5.2).

The canonical form is what gets hashed (review pins, ledger entries) and what an approved call
forwards, so the bytes executed are the bytes shown. It is deterministic but deliberately **not**
RFC 8785 (JCS): floats use Python's shortest round-trip ``repr``, not ECMAScript formatting. Keys
are sorted by UTF-16 code units, as in JCS.

Parsing refuses input whose meaning could differ between ZoeyMCP and an upstream:

- duplicate keys (parsers disagree on which one wins);
- ``NaN``/``Infinity`` and numbers that overflow to infinity;
- integers outside ±(2**53 - 1), which JavaScript upstreams would silently round;
- lone surrogates, which have no UTF-8 encoding;
- excessive nesting or size.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1
DEFAULT_MAX_BYTES = 1_048_576
DEFAULT_MAX_DEPTH = 64

JSONValue = Any  # None | bool | int | float | str | list[JSONValue] | dict[str, JSONValue]


class JSONRejected(ValueError):
    """Raised for JSON that ZoeyMCP refuses to parse or serialize."""


def _reject_constant(name: str) -> float:
    raise JSONRejected(f"{name} is not allowed")


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise JSONRejected(f"number {text[:32]} overflows to infinity")
    return value


def _int_parser(safe_integers: bool) -> Callable[[str], int]:
    def parse(text: str) -> int:
        if len(text) > 20:
            raise JSONRejected("integer is too long")
        value = int(text)
        if safe_integers and abs(value) > MAX_SAFE_INTEGER:
            raise JSONRejected(f"integer {value} is outside the safe range ±(2**53 - 1)")
        return value

    return parse


def _pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JSONRejected(f"duplicate key {key!r}")
        result[key] = value
    return result


def _has_lone_surrogate(text: str) -> bool:
    return any("\ud800" <= char <= "\udfff" for char in text)


def _validate(value: Any, *, max_depth: int, safe_integers: bool) -> None:
    """Walk a parsed or caller-supplied value and enforce the canonical rules."""
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        item, depth = stack.pop()
        if depth > max_depth:
            raise JSONRejected(f"nested deeper than {max_depth} levels")
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, int):
            if safe_integers and abs(item) > MAX_SAFE_INTEGER:
                raise JSONRejected(f"integer {item} is outside the safe range ±(2**53 - 1)")
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise JSONRejected("non-finite numbers are not allowed")
        elif isinstance(item, str):
            if _has_lone_surrogate(item):
                raise JSONRejected("lone surrogate in string")
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise JSONRejected(f"object key {key!r} is not a string")
                if _has_lone_surrogate(key):
                    raise JSONRejected("lone surrogate in object key")
                stack.append((child, depth + 1))
        else:
            raise JSONRejected(f"{type(item).__name__} is not a JSON type")


def loads_strict(
    data: str | bytes,
    *,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_depth: int = DEFAULT_MAX_DEPTH,
    safe_integers: bool = True,
) -> JSONValue:
    """Parse JSON, refusing anything whose meaning could be ambiguous (see the module docstring)."""
    if isinstance(data, bytes):
        if len(data) > max_bytes:
            raise JSONRejected(f"input is larger than {max_bytes} bytes")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JSONRejected("input is not valid UTF-8") from exc
    else:
        text = data
        if len(text.encode("utf-8", "surrogatepass")) > max_bytes:
            raise JSONRejected(f"input is larger than {max_bytes} bytes")
    if text.startswith("\ufeff"):
        raise JSONRejected("byte order mark is not allowed")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs_hook,
            parse_constant=_reject_constant,
            parse_float=_parse_float,
            parse_int=_int_parser(safe_integers),
        )
    except RecursionError as exc:
        raise JSONRejected(f"nested deeper than {max_depth} levels") from exc
    except json.JSONDecodeError as exc:
        raise JSONRejected(f"invalid JSON: {exc.msg} at position {exc.pos}") from exc
    _validate(value, max_depth=max_depth, safe_integers=safe_integers)
    return value


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def _encode(value: Any, out: list[str], indent: str | None, level: int) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        out.append(str(value))
    elif isinstance(value, float):
        out.append(repr(value))
    elif isinstance(value, str):
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, list):
        _encode_container("[", "]", [(None, child) for child in value], out, indent, level)
    elif isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        _encode_container("{", "}", items, out, indent, level)
    else:  # pragma: no cover - _validate runs first
        raise JSONRejected(f"{type(value).__name__} is not a JSON type")


def _encode_container(
    open_: str,
    close: str,
    items: list[tuple[str | None, Any]],
    out: list[str],
    indent: str | None,
    level: int,
) -> None:
    if not items:
        out.append(open_ + close)
        return
    out.append(open_)
    for position, (key, child) in enumerate(items):
        if position:
            out.append(",")
        if indent is not None:
            out.append("\n" + indent * (level + 1))
        if key is not None:
            out.append(json.dumps(key, ensure_ascii=False))
            out.append(": " if indent is not None else ":")
        _encode(child, out, indent, level + 1)
    if indent is not None:
        out.append("\n" + indent * level)
    out.append(close)


def dumps_canonical(value: JSONValue, *, safe_integers: bool = True) -> bytes:
    """Serialize ``value`` to canonical JSON bytes (UTF-8, sorted keys, no whitespace)."""
    _validate(value, max_depth=DEFAULT_MAX_DEPTH, safe_integers=safe_integers)
    out: list[str] = []
    _encode(value, out, None, 0)
    return "".join(out).encode("utf-8")


def digest(value: JSONValue) -> str:
    """Return ``sha256:<hex>`` of the canonical form (review pins and ledger hashes)."""
    return "sha256:" + hashlib.sha256(dumps_canonical(value)).hexdigest()


def render_for_approval(value: JSONValue) -> str:
    """Render ``value`` as indented JSON in canonical key order, for an approval prompt.

    JSON escaping keeps the rendering unambiguous: a newline inside a string appears as ``\\n``
    and can't fake another field. Characters the text rules refuse (format characters, for
    example) are left in place, so the approval check refuses the call rather than showing a
    cleaned-up version of it.
    """
    _validate(value, max_depth=DEFAULT_MAX_DEPTH, safe_integers=True)
    out: list[str] = []
    _encode(value, out, "  ", 0)
    return "".join(out)
