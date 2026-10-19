"""A toolkit tool's parameters: its JSON schema and the check of every call (M4 design G.2). Pure.

The type set is small, so every value is plain JSON and nothing is converted or filled in:

- ``Annotated[str, Text(...)]``: a string under the plain-text rules, with a length limit;
- ``Annotated[int, Range(ge, le)]``: an integer in a range;
- ``bool`` and ``Literal["a", "b"]``;
- ``Annotated[list[T], Batch(max)]``: a list of a bounded length (a bare ``list`` is refused);
- a total ``TypedDict`` of those, where ``NotRequired`` marks an optional field;
- ``T | None = None`` for an optional parameter. No other default exists, so what the human is
  shown is what the call holds.

Anything else raises :class:`TypeError` when the tool is defined, so the toolkit fails to load.
A call's arguments are checked against the same tree; a problem names the field and the rule,
never the value.
"""

from __future__ import annotations

import inspect
import re
import types
import typing
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Literal, NotRequired, Required, Union, get_args, get_origin

from ..common.canonical import MAX_SAFE_INTEGER, JSONValue
from ..common.textrules import find_violations

MAX_DEPTH = 4
MAX_DESCRIPTION = 1000
MAX_TEXT = 100_000
MAX_BATCH = 1000
MAX_ENUM = 64
TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
PARAM_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,63}$")
# A Message-ID, as RFC 5322 has it and the SMTP connector checks it.
MSG_ID = r"<[!-;=?-~]{1,250}@[!-;=?-~]{1,250}>"


# --- the markers --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Text:
    """A text parameter. ``max`` is required; ``pattern`` is matched against the whole text."""

    max: int
    min: int = 0
    single_line: bool = False
    allow_tabs: bool = True
    ascii_only: bool = False
    pattern: str | None = None

    def __post_init__(self) -> None:
        if not 0 <= self.min <= self.max <= MAX_TEXT:
            raise TypeError(f"Text needs 0 <= min <= max <= {MAX_TEXT}")
        if self.pattern is not None:
            if self.pattern.startswith("^") or self.pattern.endswith("$"):
                raise TypeError("a Text pattern matches the whole text; leave out ^ and $")
            re.compile(self.pattern)


@dataclass(frozen=True)
class Range:
    """An integer parameter, ``ge <= value <= le``."""

    ge: int
    le: int

    def __post_init__(self) -> None:
        if not -MAX_SAFE_INTEGER <= self.ge <= self.le <= MAX_SAFE_INTEGER:
            raise TypeError("Range needs ge <= le, both safe integers")


@dataclass(frozen=True)
class Batch:
    """A list parameter of ``min`` to ``max`` items. Every list needs one."""

    max: int
    min: int = 1

    def __post_init__(self) -> None:
        if not 0 <= self.min <= self.max <= MAX_BATCH:
            raise TypeError(f"Batch needs 0 <= min <= max <= {MAX_BATCH}")


MessageId = Annotated[str, Text(max=250, single_line=True, ascii_only=True, pattern=MSG_ID)]


# --- the tree -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class TextNode:
    text: Text

    def schema(self) -> dict[str, JSONValue]:
        found: dict[str, JSONValue] = {"type": "string", "maxLength": self.text.max}
        if self.text.min:
            found["minLength"] = self.text.min
        if self.text.pattern is not None:
            found["pattern"] = f"^(?:{self.text.pattern})$"
        return found


@dataclass(frozen=True)
class IntNode:
    range: Range

    def schema(self) -> dict[str, JSONValue]:
        return {"type": "integer", "minimum": self.range.ge, "maximum": self.range.le}


@dataclass(frozen=True)
class BoolNode:
    def schema(self) -> dict[str, JSONValue]:
        return {"type": "boolean"}


@dataclass(frozen=True)
class EnumNode:
    values: tuple[str, ...]

    def schema(self) -> dict[str, JSONValue]:
        return {"type": "string", "enum": list(self.values)}


@dataclass(frozen=True)
class ListNode:
    item: Node
    batch: Batch

    def schema(self) -> dict[str, JSONValue]:
        return {
            "type": "array",
            "items": self.item.schema(),
            "minItems": self.batch.min,
            "maxItems": self.batch.max,
        }


@dataclass(frozen=True)
class ObjectNode:
    fields: tuple[tuple[str, Node, bool], ...]  # name, type, required

    def schema(self) -> dict[str, JSONValue]:
        found: dict[str, JSONValue] = {
            "type": "object",
            "properties": {name: node.schema() for name, node, _ in self.fields},
        }
        required: list[JSONValue] = [name for name, _, needed in self.fields if needed]
        if required:
            found["required"] = required
        found["additionalProperties"] = False
        return found


Node = TextNode | IntNode | BoolNode | EnumNode | ListNode | ObjectNode


def _node(annotation: Any, where: str, depth: int) -> Node:
    """The node for one annotation, or :class:`TypeError` naming ``where``."""
    if depth > MAX_DEPTH:
        raise TypeError(f"{where}: nested deeper than {MAX_DEPTH}")
    origin = get_origin(annotation)
    if origin is Annotated:
        base, *markers = get_args(annotation)
        kinds = [m for m in markers if isinstance(m, Text | Range | Batch)]
        if len(kinds) != 1:
            raise TypeError(f"{where}: one Text, Range or Batch marker, exactly")
        (marker,) = kinds
        if isinstance(marker, Text) and base is str:
            return TextNode(marker)
        if isinstance(marker, Range) and base is int:
            return IntNode(marker)
        if isinstance(marker, Batch) and get_origin(base) is list:
            (item,) = get_args(base)
            return ListNode(_node(item, f"{where}[]", depth + 1), marker)
        raise TypeError(f"{where}: {type(marker).__name__} doesn't fit this type")
    if annotation is bool:
        return BoolNode()
    if origin is Literal:
        values = get_args(annotation)
        if not values or len(values) > MAX_ENUM or not all(isinstance(v, str) for v in values):
            raise TypeError(f"{where}: a Literal of 1-{MAX_ENUM} strings")
        if len(set(values)) != len(values):
            raise TypeError(f"{where}: a Literal lists a value twice")
        return EnumNode(tuple(values))
    if typing.is_typeddict(annotation):
        return _object(annotation, where, depth)
    if annotation is str:
        raise TypeError(f"{where}: a str needs Annotated[str, Text(max=...)]")
    if annotation is int:
        raise TypeError(f"{where}: an int needs Annotated[int, Range(ge=..., le=...)]")
    if origin is list or annotation is list:
        raise TypeError(f"{where}: a list needs Annotated[list[T], Batch(max=...)]")
    raise TypeError(f"{where}: unsupported type {annotation!r}")


def _object(cls: Any, where: str, depth: int) -> ObjectNode:
    if not cls.__total__:
        raise TypeError(f"{where}: a TypedDict is total; mark optional fields NotRequired")
    hints = typing.get_type_hints(cls, include_extras=True)
    fields: list[tuple[str, Node, bool]] = []
    for name in sorted(hints):
        annotation = hints[name]
        # Under postponed annotations the class can't see NotRequired, so the hint decides.
        required = name in cls.__required_keys__
        while get_origin(annotation) in (NotRequired, Required):
            required = get_origin(annotation) is Required
            (annotation,) = get_args(annotation)
        if not PARAM_NAME.fullmatch(name):
            raise TypeError(f"{where}.{name}: field names are lower-case identifiers")
        if _optional(annotation) is not None:
            raise TypeError(f"{where}.{name}: mark an optional field NotRequired, not None")
        node = _node(annotation, f"{where}.{name}", depth + 1)
        fields.append((name, node, required))
    if not fields:
        raise TypeError(f"{where}: a TypedDict with no fields")
    return ObjectNode(tuple(fields))


def _optional(annotation: Any) -> Any | None:
    """``T`` for ``T | None``, else ``None``."""
    if get_origin(annotation) in (Union, types.UnionType):
        args = get_args(annotation)
        if type(None) in args:
            rest = [a for a in args if a is not type(None)]
            if len(rest) != 1:
                raise TypeError("an optional parameter is T | None, with one T")
            return rest[0]
    return None


# --- a tool's signature -------------------------------------------------------------------------


@dataclass(frozen=True)
class Parameters:
    """What a tool takes, after its context parameter."""

    root: ObjectNode

    def schema(self) -> dict[str, JSONValue]:
        return self.root.schema()

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _, _ in self.root.fields)


def parameters(fn: Callable[..., Any]) -> Parameters:
    """The parameters of ``fn``, skipping its first one (the context). :class:`TypeError` for
    anything outside the type set."""
    signature = inspect.signature(fn)
    hints = typing.get_type_hints(fn, include_extras=True)
    found = list(signature.parameters.values())
    if not found or found[0].kind not in (found[0].POSITIONAL_ONLY, found[0].POSITIONAL_OR_KEYWORD):
        raise TypeError(f"{fn.__qualname__}: the first parameter is the context")
    fields: list[tuple[str, Node, bool]] = []
    for parameter in found[1:]:
        where = f"{fn.__qualname__}({parameter.name})"
        if parameter.kind not in (parameter.POSITIONAL_OR_KEYWORD, parameter.KEYWORD_ONLY):
            raise TypeError(f"{where}: no *args, **kwargs or positional-only parameters")
        if not PARAM_NAME.fullmatch(parameter.name):
            raise TypeError(f"{where}: parameter names are lower-case identifiers")
        if parameter.name not in hints:
            raise TypeError(f"{where}: every parameter needs a type")
        annotation = hints[parameter.name]
        inner = _optional(annotation)
        if inner is not None:
            if parameter.default is not None:
                raise TypeError(f"{where}: an optional parameter's default is None")
            fields.append((parameter.name, _node(inner, where, 1), False))
            continue
        if parameter.default is not parameter.empty:
            raise TypeError(f"{where}: the only default is None, on a T | None parameter")
        fields.append((parameter.name, _node(annotation, where, 1), True))
    return Parameters(ObjectNode(tuple(sorted(fields, key=lambda f: f[0]))))


def same_parameters(tool: Parameters, prepare: Callable[..., Any]) -> bool:
    """A ``prepare`` step takes the tool's parameters after its context: the same names, the
    same optional ones (default ``None``), nothing else. It gets the values the tool's own
    types checked, so its annotations may be plain."""
    found = list(inspect.signature(prepare).parameters.values())[1:]
    if any(p.kind not in (p.POSITIONAL_OR_KEYWORD, p.KEYWORD_ONLY) for p in found):
        return False
    if any(p.default not in (p.empty, None) for p in found):
        return False
    wanted = {(name, required) for name, _, required in tool.root.fields}
    return {(p.name, p.default is p.empty) for p in found} == wanted and len(found) == len(wanted)


def description(fn: Callable[..., Any]) -> str:
    """The tool's description: its docstring, under the text rules, at most 1,000 characters."""
    text = inspect.cleandoc(fn.__doc__ or "")
    if find_violations(text, max_chars=MAX_DESCRIPTION, min_chars=1, allow_tabs=False):
        raise TypeError(
            f"{fn.__qualname__}: a tool needs a docstring of 1-{MAX_DESCRIPTION} plain characters"
        )
    return text


def tool_name(name: str) -> str:
    if not TOOL_NAME.fullmatch(name):
        raise TypeError(f"{name!r}: a tool name is 1-128 of A-Z, a-z, 0-9, '_', '.' or '-'")
    return name


# --- checking a call ----------------------------------------------------------------------------


@dataclass(frozen=True)
class ArgumentProblem:
    """Why a call's arguments are refused: a JSON pointer and a rule, never a value."""

    pointer: str
    rule: str

    def __str__(self) -> str:
        return f"{self.pointer or '/'}: {self.rule}"


def check_arguments(params: Parameters, arguments: Mapping[str, Any]) -> list[ArgumentProblem]:
    """Every way ``arguments`` (parsed JSON) breaks ``params``; empty if the call may proceed."""
    problems: list[ArgumentProblem] = []
    _check(params.root, dict(arguments), "", problems)
    return problems


def _escape(name: str) -> str:
    return name.replace("~", "~0").replace("/", "~1")


def _check(node: Node, value: Any, pointer: str, out: list[ArgumentProblem]) -> None:
    if isinstance(node, TextNode):
        if not isinstance(value, str):
            out.append(ArgumentProblem(pointer, "type"))
        elif _text_problem(node.text, value):
            out.append(ArgumentProblem(pointer, "text_rules"))
    elif isinstance(node, IntNode):
        if not isinstance(value, int) or isinstance(value, bool):
            out.append(ArgumentProblem(pointer, "type"))
        elif not node.range.ge <= value <= node.range.le:
            out.append(ArgumentProblem(pointer, "range"))
    elif isinstance(node, BoolNode):
        if not isinstance(value, bool):
            out.append(ArgumentProblem(pointer, "type"))
    elif isinstance(node, EnumNode):
        if not isinstance(value, str):
            out.append(ArgumentProblem(pointer, "type"))
        elif value not in node.values:
            out.append(ArgumentProblem(pointer, "enum"))
    elif isinstance(node, ListNode):
        if not isinstance(value, list):
            out.append(ArgumentProblem(pointer, "type"))
        elif not node.batch.min <= len(value) <= node.batch.max:
            out.append(ArgumentProblem(pointer, "batch_size"))
        else:
            for index, item in enumerate(value):
                _check(node.item, item, f"{pointer}/{index}", out)
    else:
        if not isinstance(value, dict):
            out.append(ArgumentProblem(pointer, "type"))
            return
        known = {name for name, _, _ in node.fields}
        if any(key not in known for key in value):
            out.append(ArgumentProblem(pointer, "unknown_key"))  # never echo caller text
        for name, child, required in node.fields:
            if name not in value:
                if required:
                    out.append(ArgumentProblem(f"{pointer}/{_escape(name)}", "missing"))
                continue
            _check(child, value[name], f"{pointer}/{_escape(name)}", out)


def _text_problem(text: Text, value: str) -> bool:
    if find_violations(
        value,
        max_chars=text.max,
        min_chars=text.min,
        single_line=text.single_line,
        allow_tabs=text.allow_tabs,
        max_reported=1,
    ):
        return True
    if text.ascii_only and not value.isascii():
        return True
    return text.pattern is not None and re.fullmatch(text.pattern, value) is None
