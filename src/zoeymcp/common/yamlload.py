"""A strict YAML loader for policy documents.

Policy is security configuration, so the loader refuses YAML features that make a document mean
something other than what it looks like:

- **duplicate keys**, which PyYAML would otherwise resolve silently (the last one wins);
- **aliases**, which also blocks exponential "billion laughs" expansion and merge keys;
- **YAML 1.1 implicit types**: ``yes``/``no``/``on``/``off`` stay strings, as do ``0755``
  (octal), ``12:30`` (base 60) and dates. Only ``true``/``false``, decimal integers and plain
  floats are typed;
- documents larger than a size limit, more than one document, or a top level that isn't a
  mapping.
"""

from __future__ import annotations

import re
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node

DEFAULT_MAX_BYTES = 1_048_576

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


class StrictLoader(yaml.SafeLoader):
    """SafeLoader with duplicate-key and alias rejection and YAML 1.2-style scalars."""

    def compose_node(self, parent: Node | None, index: Any) -> Node | None:
        if self.check_event(yaml.AliasEvent):
            event = self.peek_event()  # type: ignore[no-untyped-call]
            raise YAMLRejected(f"aliases are not allowed (line {event.start_mark.line + 1})")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in seen
            except TypeError as exc:
                raise YAMLRejected(f"unhashable mapping key at {_where(key_node)}") from exc
            if duplicate:
                raise YAMLRejected(f"duplicate key {key!r} at {_where(key_node)}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


StrictLoader.yaml_implicit_resolvers = {
    first: [(tag, regex) for tag, regex in resolvers if tag not in _REPLACED]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
StrictLoader.add_implicit_resolver(
    _BOOL, re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)
StrictLoader.add_implicit_resolver(
    _INT, re.compile(r"^[-+]?(?:0|[1-9][0-9]*)$"), list("-+0123456789")
)
StrictLoader.add_implicit_resolver(
    _FLOAT,
    re.compile(r"^[-+]?(?:(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:[eE][-+]?[0-9]+)?|[0-9]+[eE][-+]?[0-9]+)$"),
    list("-+0123456789."),
)


def load_mapping(text: str, *, max_bytes: int = DEFAULT_MAX_BYTES) -> dict[str, Any]:
    """Parse one YAML document whose top level is a mapping with string keys."""
    if len(text.encode("utf-8", "surrogatepass")) > max_bytes:
        raise YAMLRejected(f"document is larger than {max_bytes} bytes")
    try:
        data = yaml.load(text, Loader=StrictLoader)  # noqa: S506 - StrictLoader is a SafeLoader
    except yaml.YAMLError as exc:
        message = f"invalid YAML: {exc}"
        if "flow" in str(exc) and "'{'" in str(exc):
            message += (
                " (hint: in an inline [a, b] list, {name} starts a mapping; "
                "put each path on its own '- ' line, or quote it)"
            )
        raise YAMLRejected(message) from exc
    if not isinstance(data, dict):
        raise YAMLRejected("the top level must be a mapping")
    for key in data:
        if not isinstance(key, str):
            raise YAMLRejected(f"top-level key {key!r} is not a string")
    return data
