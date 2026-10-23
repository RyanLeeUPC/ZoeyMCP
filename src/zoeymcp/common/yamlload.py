"""A strict YAML loader for policy documents.

Policy is security configuration, so the loader refuses YAML features that make a document mean
something other than what it looks like. Every refusal is a :class:`YAMLRejected` with a position
where there is one, so a caller turns it into a finding (M6 design B):

- **explicit tags** (B1), ``!!str`` included: ``!!bool yes`` and ``!!int 0755`` would bring back
  the YAML 1.1 coercions below, and ``!!binary``, ``!!set`` or ``!!timestamp`` build values that
  aren't data. Nothing ZoeyMCP writes or reads needs one;
- **U+0085, U+2028 and U+2029** (B2), which PyYAML, a YAML 1.1 parser, takes as line breaks: an
  editor or a page shows ``a: b<U+2028>c: d`` as one line, and the parser reads two keys;
- **keys that aren't strings**, at every depth (B3);
- **nesting deeper than** :data:`MAX_DEPTH` (B4), refused before Python's recursion limit is near;
- **integers of more than 32 digits and floats that aren't finite** (B5): a 5,000-digit integer
  is past Python's own digit limit, and ``1e999`` is infinity, which canonical JSON can't hold;
- **duplicate keys**, which PyYAML would otherwise resolve silently (the last one wins);
- **aliases**, which also blocks exponential "billion laughs" expansion and merge keys;
- **YAML 1.1 implicit types**: ``yes``/``no``/``on``/``off`` stay strings, as do ``0755``
  (octal), ``12:30`` (base 60) and dates. Only ``true``/``false``, decimal integers and plain
  floats are typed;
- documents larger than a size limit, more than one document, or a top level that isn't a
  mapping.

Any other exception the parser raises is a :class:`YAMLRejected` too (B6).
"""

from __future__ import annotations

import math
import re
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .canonical import DEFAULT_MAX_DEPTH

DEFAULT_MAX_BYTES = 1_048_576
# Mappings and sequences inside one another, the top-level mapping counted (B4).
MAX_DEPTH = DEFAULT_MAX_DEPTH
# U+0085 (NEXT LINE), U+2028 and U+2029: line breaks in YAML 1.1, ordinary characters in 1.2 (B2).
_BREAKS = re.compile("[\x85\u2028\u2029]")
# A plain scalar of 33 or more digits: the int resolver below types at most 32 (B5).
_LONG_INTEGER = re.compile(r"[-+]?[0-9]{33,}")
_TAGGED = (yaml.ScalarEvent, yaml.SequenceStartEvent, yaml.MappingStartEvent)
_COLLECTIONS = (yaml.SequenceStartEvent, yaml.MappingStartEvent)

_BOOL = "tag:yaml.org,2002:bool"
_INT = "tag:yaml.org,2002:int"
_FLOAT = "tag:yaml.org,2002:float"
_REPLACED = {
    _BOOL,
    _INT,
    _FLOAT,
    "tag:yaml.org,2002:timestamp",
    "tag:yaml.org,2002:merge",
    "tag:yaml.org,2002:value",
}


class YAMLRejected(ValueError):
    """Raised for a YAML document the strict loader refuses."""


def _where(node: Node) -> str:
    return f"line {node.start_mark.line + 1}, column {node.start_mark.column + 1}"


def _line(mark: Any) -> str:
    return f"line {mark.line + 1}"


class StrictLoader(yaml.SafeLoader):
    """SafeLoader with the refusals the module docstring lists, and YAML 1.2-style scalars."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0
        # Each collection's place in the document, like /servers/notes/tools, set by its parent
        # before it is constructed (construction runs from the top down).
        self._paths: dict[Node, str] = {}

    def compose_node(self, parent: Node | None, index: Any) -> Node | None:
        event = self.peek_event()  # type: ignore[no-untyped-call]
        if isinstance(event, yaml.AliasEvent):
            raise YAMLRejected(f"aliases are not allowed ({_line(event.start_mark)})")
        # PyYAML sets an event's tag only for an explicit one (contract 56).
        if isinstance(event, _TAGGED) and event.tag is not None:
            raise YAMLRejected(f"tags are not allowed ({_line(event.start_mark)})")
        # Only a plain scalar is typed by the resolvers.
        plain = isinstance(event, yaml.ScalarEvent) and event.implicit[0]
        if plain and _LONG_INTEGER.fullmatch(event.value):
            raise YAMLRejected(f"integer too long ({_line(event.start_mark)})")
        if not isinstance(event, _COLLECTIONS):
            return super().compose_node(parent, index)
        if self._depth >= MAX_DEPTH:
            raise YAMLRejected(f"nested deeper than {MAX_DEPTH} levels ({_line(event.start_mark)})")
        self._depth += 1
        try:
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        path = self._paths.get(node, "")
        seen: set[str] = set()
        for key_node, value_node in node.value:
            key = self._key(key_node, path)
            if key in seen:
                raise YAMLRejected(f"duplicate key {key!r} at {_where(key_node)}")
            seen.add(key)
            self._paths[value_node] = f"{path}/{key}"
        return super().construct_mapping(node, deep=deep)

    def construct_sequence(self, node: SequenceNode, deep: bool = False) -> list[Any]:
        path = self._paths.get(node, "")
        for index, item in enumerate(node.value):
            self._paths[item] = f"{path}/{index}"
        return super().construct_sequence(node, deep=deep)

    def _key(self, node: Node, path: str) -> str:
        """A mapping key, refused unless it is a string. A collection key isn't constructed."""
        if isinstance(node, ScalarNode):
            key = self.construct_object(node)
            if isinstance(key, str):
                return key
            shown = repr(key)
        else:
            shown = "(a sequence)" if isinstance(node, SequenceNode) else "(a mapping)"
        where = f"key {shown} at {path}" if path else f"top-level key {shown}"
        raise YAMLRejected(f"{where} is not a string")

    def construct_finite_float(self, node: ScalarNode) -> float:
        value = self.construct_yaml_float(node)
        if not math.isfinite(value):
            raise YAMLRejected(f"non-finite numbers are not allowed ({_line(node.start_mark)})")
        return value


StrictLoader.yaml_implicit_resolvers = {
    first: [(tag, regex) for tag, regex in resolvers if tag not in _REPLACED]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
StrictLoader.add_implicit_resolver(
    _BOOL, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)
StrictLoader.add_implicit_resolver(
    _INT, re.compile(r"^[-+]?(?:0|[1-9][0-9]{0,31})$"), list("-+0123456789")
)
StrictLoader.add_implicit_resolver(
    _FLOAT,
    re.compile(r"^[-+]?(?:(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|[0-9]+[eE][-+]?[0-9]+)$"),
    list("-+0123456789."),
)
StrictLoader.add_constructor(_FLOAT, StrictLoader.construct_finite_float)


def load_mapping(text: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """Parse one YAML document whose top level is a mapping with string keys."""
    if len(text.encode("utf-8", "surrogatepass")) > max_bytes:
        raise YAMLRejected(f"document is larger than {max_bytes} bytes")
    found = _BREAKS.search(text)
    if found:
        line = text.count("\n", 0, found.start()) + 1
        raise YAMLRejected(
            f"U+{ord(found.group()):04X}, a YAML 1.1 line break, is not allowed (line {line})"
        )
    try:
        data = yaml.load(text, Loader=StrictLoader)  # noqa: S506 - StrictLoader is a SafeLoader
    except YAMLRejected:
        raise
    except yaml.YAMLError as exc:
        message = f"invalid YAML: {exc}"
        if "flow" in str(exc) and "'{'" in str(exc):
            message += (
                " (hint: in an inline [a, b] list, {name} starts a mapping; "
                "put each path on its own '- ' line, or quote it)"
            )
        raise YAMLRejected(message) from exc
    except Exception as exc:
        # RecursionError, or the ValueError of Python's integer digit limit, before B4 and B5.
        raise YAMLRejected(f"invalid YAML: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise YAMLRejected("the top level must be a mapping")
    return data
