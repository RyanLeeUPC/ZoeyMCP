"""The YAML emitter (M7 design H.2; D-150, DD-13, X10). Pure.

:func:`emit` writes a :class:`~.change.PolicyChange` as a fragment to merge into a policy: block
YAML from the fixed field table :data:`FIELDS`, which says for each model the fields a fragment may
hold, in order, and how each is written. A field the table doesn't name is never written: a change
holding one is refused, so the table, a subset of what the policy view shows (never a hidden field,
``test_policy_emit.py`` compares them), is the whole of what a fragment can say.

- Every string is double-quoted, with ``\\`` and ``"`` escaped, and must be printable ASCII; any
  other character (a line break, a control, a non-ASCII letter, a bidi or hidden character) is
  :class:`EmitRefused`, and the caller shows the value revealed. Booleans and integers are
  written only where the table types a field as one.
- Field names are written bare; policy names (credentials, servers, tools, parameters) always
  double-quoted, so ``yes``, ``1e3`` or ``null`` stay strings.
- The compose form (``target="compose"``) is indented 8 for the shipped compose files' block
  scalar and writes every ``$`` as ``$$``, so compose's interpolation of an inline
  ``ZOEYMCP_CONFIG`` gives back exactly the change (TI-1, F-50).

The output loads with ``yamlload.load_mapping`` to exactly :meth:`~.change.PolicyChange.data`.

:func:`document` writes a whole policy for ``check --with --print-merged``: the operator's own
text, so a string outside the character rule is escaped rather than refused.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from types import MappingProxyType
from typing import Any, Final, Literal, get_args

from pydantic import BaseModel

from .change import Comment, CommentKind, PolicyChange
from .merge import replace_line
from .schema import Policy

EMIT_MAX: Final = 2 * 2**20
INDENT_MAX: Final = 16
COMPOSE_INDENT: Final = 8
Target = Literal["plain", "compose"]
# How a field is written.
STRING: Final = "string"
BOOLEAN: Final = "boolean"
INTEGER: Final = "integer"
STRINGS: Final = "strings"  # a flow list of strings
STRING_MAP: Final = "string_map"  # a mapping of names to strings
# Any other kind names a model: "Tools", a block list of models "[Rule]", or a mapping of policy
# names to models "{RemoteServer}". "Credential" is the model its kind names.
_PRINTABLE = re.compile(r"[\x20-\x7e]*")


def _table(**kinds: str) -> Mapping[str, str]:
    return MappingProxyType(kinds)


# Every field a fragment may hold, by model, in the order written (E.2, E.4, A.4).
FIELDS: Final[Mapping[str, Mapping[str, str]]] = MappingProxyType(
    {
        "Policy": _table(
            credentials="{Credential}", routes="[Route]", gateway="Gateway", egress_private=STRINGS
        ),
        "Gateway": _table(servers="{RemoteServer}"),
        "OAuth2Credential": _table(
            kind=STRING,
            token_url=STRING,
            grant=STRING,
            authorize_url=STRING,
            issuer=STRING,
            require_iss=BOOLEAN,
            revocation_url=STRING,
            resource_metadata=STRING,
            client_id=STRING,
            client_secret=STRING,
            client_auth=STRING,
            refresh_token=STRING,
            rotates=BOOLEAN,
            reseed=STRING,
            redirect_uri=STRING,
            scope_separator=STRING,
            scope=STRING,
            expected_scopes=STRINGS,
            refresh_skew=INTEGER,
            default_expires_in=INTEGER,
            grant_lifetime_days=INTEGER,
            idle_expiry_days=INTEGER,
            extra_params=STRING_MAP,
            token_body=STRING,
            authorize_params=STRING_MAP,
            # Never token_headers: their values are literal (H.3), so a credential holding
            # them is refused (``field``), and a re-registration of one can't be a fragment.
        ),
        "HeaderCredential": _table(kind=STRING, secret=STRING, header=STRING, format=STRING),
        "Route": _table(
            name=STRING,
            prefix=STRING,
            upstream=STRING,
            allow_insecure_upstream=BOOLEAN,
            credential=STRING,
            callers=STRINGS,
            stream=BOOLEAN,
            rules="[Rule]",
        ),
        "Rule": _table(methods=STRINGS, paths=STRINGS),
        "RemoteServer": _table(
            kind=STRING,
            route=STRING,
            path=STRING,
            era=STRING,
            on_drift=STRING,
            wrap_results=BOOLEAN,
            call_timeout=INTEGER,
            tools="Tools",
            review=STRING_MAP,
            declined=STRING_MAP,
        ),
        "Tools": _table(include=STRINGS, allow=STRINGS, approve=STRINGS),
    }
)
# The model a credential's kind names; any other kind is never in a fragment.
CREDENTIALS: Final[Mapping[str, str]] = MappingProxyType(
    {"oauth2": "OAuth2Credential", "header": "HeaderCredential"}
)
# Each comment kind's fixed words, before its subject.
COMMENTS: Final[Mapping[CommentKind, str]] = MappingProxyType(
    {
        "added": "added",
        "changed_was": "changed",
        "kept": "kept",
        "not_included": "not included",
        "declined": "declined",
        "error_finding": "can't be included, error finding",
        "suggested": "suggested",
        "merge_hint": "merge",
    }
)


class EmitRefused(ValueError):
    """A change the emitter won't write: ``reason`` is ``characters`` (``value`` is the string,
    for the caller to show revealed), ``field`` (not in the table), ``type`` (not what the
    table says), ``kind`` (a credential kind no fragment holds) or ``size``."""

    def __init__(self, path: str, reason: str, value: str = "") -> None:
        self.path = path
        self.reason = reason
        self.value = value
        super().__init__(f"{path}: {reason}")


def emit(change: PolicyChange, *, indent: int = 0, target: Target = "plain") -> str:
    """``change`` as a fragment: the header, its comments, then its YAML."""
    spaces = _indent(indent, target)
    lines = [f"# zoeymcp: {_printable(change.title, '(title)')}"]
    paths = change.replace()
    if paths:
        lines.append(replace_line(paths))
    lines += [_comment(comment) for comment in change.comments()]
    lines += _model(change.data(), "Policy", "") or ["{}"]
    text = _finish(lines, spaces, target)
    if len(text.encode()) > EMIT_MAX:
        raise EmitRefused("(document)", "size")
    return text


def _indent(indent: int, target: Target) -> int:
    if target == "compose":
        if indent not in (0, COMPOSE_INDENT):
            raise ValueError("the compose form is indented 8; give no other indent")
        return COMPOSE_INDENT
    if not 0 <= indent <= INDENT_MAX:
        raise ValueError(f"indent is 0 to {INDENT_MAX} spaces")
    return indent


def _finish(lines: list[str], spaces: int, target: Target) -> str:
    text = "".join(" " * spaces + line + "\n" for line in lines)
    return text.replace("$", "$$") if target == "compose" else text


def _comment(comment: Comment) -> str:
    # The subject is a tool or policy name (Comment checks it); the detail is checked here.
    line = f"# {COMMENTS[comment.kind]}: {comment.subject}"
    if comment.detail is not None:
        line += f" ({_printable(comment.detail, '(comment)')})"
    return line


def _join(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _model(data: Mapping[str, Any], model: str, path: str) -> list[str]:
    table = FIELDS[model]
    for key in data:
        if key not in table:
            raise EmitRefused(_join(path, key), "field")
    lines: list[str] = []
    for key, kind in table.items():
        if key in data:
            lines += _field(key, data[key], kind, _join(path, key))
    return lines


def _field(key: str, value: Any, kind: str, path: str) -> list[str]:
    if kind in (STRING, BOOLEAN, INTEGER, STRINGS):
        return [f"{key}: {_scalar(value, kind, path)}"]
    if kind == STRING_MAP or kind.startswith("{"):
        if not isinstance(value, Mapping):
            raise EmitRefused(path, "type")
        if not value:
            return [f"{key}: {{}}"]
        lines = [f"{key}:"]
        for name, item in value.items():
            where = f"{path}.{name}"
            if kind == STRING_MAP:
                lines.append(f"  {_quoted(name, where)}: {_scalar(item, STRING, where)}")
                continue
            body = _nested(item, kind[1:-1], where)
            lines.append(f"  {_quoted(name, where)}:" + ("" if body else " {}"))
            lines += ["    " + line for line in body]
        return lines
    if kind.startswith("["):
        if not isinstance(value, list):
            raise EmitRefused(path, "type")
        if not value:
            return [f"{key}: []"]
        lines = [f"{key}:"]
        for index, item in enumerate(value):
            body = _nested(item, kind[1:-1], f"{path}[{index}]") or ["{}"]
            lines.append("  - " + body[0])
            lines += ["    " + line for line in body[1:]]
        return lines
    body = _nested(value, kind, path)
    return [f"{key}:", *("  " + line for line in body)] if body else [f"{key}: {{}}"]


def _nested(value: Any, model: str, path: str) -> list[str]:
    if not isinstance(value, Mapping):
        raise EmitRefused(path, "type")
    if model == "Credential":
        kind = value.get("kind")
        if not isinstance(kind, str) or kind not in CREDENTIALS:
            raise EmitRefused(_join(path, "kind"), "kind")
        model = CREDENTIALS[kind]
    return _model(value, model, path)


def _scalar(value: Any, kind: str, path: str) -> str:
    if kind == STRING and isinstance(value, str):
        return _quoted(value, path)
    if kind == BOOLEAN and isinstance(value, bool):
        return "true" if value else "false"
    if kind == INTEGER and isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if kind == STRINGS and isinstance(value, list) and all(isinstance(i, str) for i in value):
        items = [_quoted(item, f"{path}[{index}]") for index, item in enumerate(value)]
        return "[" + ", ".join(items) + "]"
    raise EmitRefused(path, "type")


def _printable(text: str, path: str) -> str:
    if not _PRINTABLE.fullmatch(text):
        raise EmitRefused(path, "characters", text)
    return text


def _quoted(text: str, path: str) -> str:
    return '"' + _printable(text, path).replace("\\", "\\\\").replace('"', '\\"') + '"'


# --- a whole document (check --with --print-merged) ---------------------------------------------


def _models_in(annotation: Any) -> Iterator[type[BaseModel]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation
    for arg in get_args(annotation):
        yield from _models_in(arg)


def _field_names(model: type[BaseModel]) -> set[str]:
    """The document names of ``model``'s fields and of every model under it (none nests itself)."""
    names: set[str] = set()
    for name, info in model.model_fields.items():
        names.add(info.alias or name)
        for sub in _models_in(info.annotation):
            names |= _field_names(sub)
    return names


# Every field name of the policy's models, written bare as keys; any other key is a name, quoted.
FIELD_NAMES: Final = frozenset(_field_names(Policy))


def document(data: Mapping[str, Any], *, indent: int = 0, target: Target = "plain") -> str:
    """A whole policy as block YAML, every string double-quoted and escaped as needed."""
    spaces = _indent(indent, target)
    return _finish(_mapping(data) or ["{}"], spaces, target)


def _mapping(data: Mapping[Any, Any]) -> list[str]:
    lines: list[str] = []
    for key, value in data.items():
        lines += _entry(f"{_key(key)}:", value)
    return lines


def _entry(head: str, value: Any) -> list[str]:
    if isinstance(value, Mapping) and value:
        return [head, *("  " + line for line in _mapping(value))]
    if isinstance(value, list) and not _flat(value):
        return [head, *("  " + line for line in _items(value))]
    return [f"{head} {_inline(value)}"]


def _items(items: list[Any]) -> list[str]:
    lines: list[str] = []
    for item in items:
        if isinstance(item, Mapping) and item:
            body = _mapping(item)
        elif isinstance(item, list) and not _flat(item):
            body = _items(item)
        else:
            lines.append("- " + _inline(item))
            continue
        lines.append("- " + body[0])
        lines += ["  " + line for line in body[1:]]
    return lines


def _flat(items: list[Any]) -> bool:
    return not any(isinstance(item, Mapping | list) for item in items)


def _inline(value: Any) -> str:
    if isinstance(value, Mapping):
        return "{}"  # only an empty one is written inline
    if isinstance(value, list):
        return "[" + ", ".join(_escaped(item) for item in value) + "]"
    return _escaped(value)


def _key(key: Any) -> str:
    return key if isinstance(key, str) and key in FIELD_NAMES else _escaped(key)


def _escaped(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return repr(value)
    if not isinstance(value, str):
        raise TypeError(f"a {type(value).__name__} has no YAML form here")
    return '"' + "".join(_escape(char) for char in value) + '"'


def _escape(char: str) -> str:
    if char in '\\"':
        return "\\" + char
    point = ord(char)
    if 0x20 <= point <= 0x7E:
        return char
    if point <= 0xFF:
        return f"\\x{point:02x}"
    if point <= 0xFFFF:
        return f"\\u{point:04x}"
    return f"\\U{point:08x}"
