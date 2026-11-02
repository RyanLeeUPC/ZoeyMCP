"""The vault's envelope reader: what a POST on a held route means (M8 design B.2; Z3, Z4).

On a route that carries a vault-held server the vault reads every POST before anything goes
upstream, and admits only a request with exactly one meaning. :func:`admit` takes the body, the
headers and the query string as received, and answers:

- :class:`Held` for a ``tools/call`` of a held tool, with its :class:`Envelope`, whose
  :meth:`~Envelope.canonical` form is what the vault renders and forwards (Z2);
- :class:`Cancel` for a ``notifications/cancelled`` naming a held request (B.1 step 5, F-54);
- :class:`Pass` for anything else the gateway sends, forwarded as received;
- :class:`Refuse` with a reason and a JSON pointer, never a value (M4 H14), for anything
  ambiguous, by rules E1 to E19. A rule on the headers or the query points at the whole
  message (``""``).

``Pass`` and ``Cancel`` are read by the same rules as a held call but E9 to E11, E13 and E19, so
an ambiguous body is refused whatever its method: the vault can't know which method an upstream
would read. The method set, the ``_meta`` keys, the header allowlist and the routing-header rule
are the gateway's own (:mod:`.mcpwire`), so honest traffic always passes.

Pure and standard library only, on :mod:`.mcpwire` and :mod:`.canonical`. The held names come in
as plain sets (``HeldPath.tools`` and ``.listed``, ``HeldRoute.names``), so this never imports the
policy package.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, TypeGuard

from . import canonical
from .canonical import JSONValue
from .mcpwire import (
    HEADERS,
    META_KEYS,
    METHOD_HEADER,
    METHODS,
    NAME_BEARING,
    NAME_HEADER,
    NOTIFICATIONS,
    PARAM_HEADER_PREFIX,
    PROTOCOL_VERSION_META,
    ROUTING_HEADERS,
    VERSION_HEADER,
    decode_name,
    mismatch,
)

HELD_METHODS: Final = frozenset({"tools/call"})
MAX_HELD_BODY: Final = 1024 * 1024
# The era whose routing headers are required: at earlier eras they may be absent (E12).
MODERN_VERSION: Final = "2026-07-28"
# The gateway's marker on an Elsewhere call (C.2), and its key in the hardened tier.
MARKER_HEADER: Final = "x-zoeymcp-held"
GATEWAY_KEY_HEADER: Final = "x-zoeymcp-gateway"
# E16: the gateway's own egress allowlist (Mcp-Param-* included, which E13 refuses on a held
# call), and the x-zoeymcp-* headers the vault consumes.
ADMITTED_HEADERS: Final = HEADERS | {MARKER_HEADER, GATEWAY_KEY_HEADER}
CALL_MEMBERS: Final = frozenset({"name", "arguments", "_meta"})
CANCELLED: Final = "notifications/cancelled"

Reason = Literal[
    "content_type",
    "content_encoding",
    "encoding",
    "too_large",
    "json",
    "batch",
    "not_object",
    "jsonrpc",
    "method_form",
    "method_case",
    "id",
    "number",
    "params",
    "meta",
    "header_mismatch",
    "param_headers",
    "marker",
    "name_variant",
    "header_extra",
    "query",
    "unlisted",
    "ref_reused",
]
# B.1: every refusal is a 400 but these.
_STATUS: Final[Mapping[str, int]] = {"content_type": 415, "too_large": 413, "ref_reused": 409}

_JSON_TYPE = re.compile(r"application/json(?:[ \t]*;[ \t]*charset=utf-8)?")
_METHOD = re.compile(r"[A-Za-z0-9_./-]{1,128}")
_HELD_FOLDED: Final = frozenset(method.casefold() for method in HELD_METHODS)
# A JSON-RPC id the vault keeps (E8): at most 128 printable ASCII characters, or a safe integer.
_ID = re.compile(r"[\x20-\x7e]{0,128}")
# The MCP tool-name grammar (E18), which is the policy's ToolName.
_TOOL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}")
# E14: client= is a policy Name (schema.NAME_PATTERN), tool= a toolkit tool's name.
_MARKER = re.compile(
    r"v1; ref=([0-9a-f]{16}); client=([a-z0-9][a-z0-9_-]{0,62}); wait=(block|pending);"
    r" epoch=([0-9a-f]{12})(?:; tool=([A-Za-z0-9_.-]{1,128}))?"
)
_BOM: Final = b"\xef\xbb\xbf"


@dataclass(frozen=True, repr=False)
class Envelope:
    """A held ``tools/call`` as the vault reads it: ``arguments`` is ``{}`` when the call sent
    none, ``meta`` None when it sent no ``_meta``. No ``repr``: the arguments are shown on an
    approver surface only (Z14)."""

    id: str | int
    name: str
    arguments: dict[str, JSONValue]
    meta: dict[str, JSONValue] | None

    def canonical(self) -> bytes:
        """The bytes forwarded once approved (Z2), which :func:`admit` reads back to this."""
        params: dict[str, JSONValue] = {"name": self.name, "arguments": self.arguments}
        if self.meta is not None:
            params["_meta"] = self.meta
        message = {"jsonrpc": "2.0", "id": self.id, "method": "tools/call", "params": params}
        return canonical.dumps_canonical(message)


@dataclass(frozen=True)
class Marker:
    """The gateway's ``x-zoeymcp-held`` header on an Elsewhere call (C.2)."""

    ref: str  # 16 lowercase hex, the gateway's ledger ref
    client: str  # a policy Name, as the gateway reports it
    wait: Literal["block", "pending"]
    epoch: str  # 12 lowercase hex, the gateway process's start id (I.3)
    tool: str | None  # a toolkit write only: the toolkit tool the write belongs to (B.7)


@dataclass(frozen=True)
class Pass:
    """Not a held call: forwarded as received. ``marked``: it carried a marker, which the vault
    refuses ``view_stale`` (Z5)."""

    marked: bool


@dataclass(frozen=True)
class Held:
    """A held call, and the gateway's marker on it (None: a stale view or a compromised gateway;
    the vault mints a ref, B.3)."""

    envelope: Envelope
    marker: Marker | None


@dataclass(frozen=True)
class Cancel:
    """A cancel of the held request ``request_id``: consumed, never forwarded (B.1 step 5)."""

    request_id: str | int


@dataclass(frozen=True)
class Refuse:
    """Why the vault refuses the request (code ``held_<reason>``), and where in the body."""

    reason: Reason
    pointer: str = ""

    @property
    def status(self) -> int:
        return _STATUS.get(self.reason, 400)


Admitted = Pass | Held | Cancel | Refuse


def marker(headers: Sequence[tuple[str, str]]) -> Marker | Refuse | None:
    """The request's marker; None when it carries none; refused when it is malformed or sent
    twice (E14)."""
    values = _values(headers, MARKER_HEADER)
    if not values:
        return None
    found = _MARKER.fullmatch(values[0]) if len(values) == 1 else None
    if found is None:
        return Refuse("marker")
    ref, client, wait, epoch, tool = found.groups()
    return Marker(ref, client, "block" if wait == "block" else "pending", epoch, tool)


def admit(
    body: bytes,
    headers: Sequence[tuple[str, str]],
    query: str,
    tools: frozenset[str],
    listed: frozenset[str],
    names: frozenset[str],
    held_ids: Callable[[str | int], bool],
    used_refs: Callable[[str], bool],
) -> Admitted:
    """Read one POST on a server path of a held route (B.1 step 5). ``tools`` and ``listed`` are
    that path's ``HeldPath.tools`` and ``.listed``, ``names`` the route's held names.
    ``held_ids`` says whether a request id names a held request on this route and the request's
    ``Mcp-Session-Id`` (or none); ``used_refs`` whether a ref is in the hold table, the result
    store, the recent endings or the chain's open refs (E19)."""
    refused = _head(headers, query)
    if refused is not None:
        return refused
    found = marker(headers)
    if isinstance(found, Refuse):
        return found
    parsed = _parse(body)
    if isinstance(parsed, Refuse):
        return parsed
    text, message = parsed
    refused = _form(message)
    if refused is not None:
        return refused
    if _disagrees(headers, message):
        return Refuse("header_mismatch")
    method = message.get("method")
    params = message.get("params")
    fields: dict[str, Any] = params if isinstance(params, dict) else {}
    if method == CANCELLED:
        request_id = fields.get("requestId")
        if _id_type(request_id) and held_ids(request_id):
            return Cancel(request_id)
    if method not in HELD_METHODS:
        return Pass(found is not None)
    name = fields.get("name")
    if not isinstance(name, str):
        return Refuse("unlisted", "/params/name")
    held = names | tools
    if name not in held and _fold(name) in {_fold(each) for each in held}:
        return Refuse("name_variant", "/params/name")
    if not _TOOL_NAME.fullmatch(name) or name not in listed:
        return Refuse("unlisted", "/params/name")
    if name not in tools:
        return Pass(found is not None)
    return _held(text, message, fields, headers, found, used_refs)


def _held(
    text: str,
    message: Mapping[str, Any],
    params: Mapping[str, Any],
    headers: Sequence[tuple[str, str]],
    found: Marker | None,
    used_refs: Callable[[str], bool],
) -> Held | Refuse:
    """E10, E11, E9, E13 and E19, on a call of a held tool."""
    for member in params:
        if member not in CALL_MEMBERS:
            return Refuse("params", _pointer("params", member))
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        return Refuse("params", "/params/arguments")
    meta = params.get("_meta")
    if "_meta" in params and not isinstance(meta, dict):
        return Refuse("meta", "/params/_meta")
    for key in meta or ():
        if key not in META_KEYS:
            return Refuse("meta", _pointer("params", "_meta", key))
    pointer = _unround(text)
    if pointer is not None:
        return Refuse("number", pointer)
    if any(name.lower().startswith(PARAM_HEADER_PREFIX) for name, _value in headers):
        return Refuse("param_headers")
    if found is not None and used_refs(found.ref):
        return Refuse("ref_reused")
    return Held(Envelope(message["id"], params["name"], arguments, meta), found)


def _values(headers: Sequence[tuple[str, str]], name: str) -> tuple[str, ...]:
    return tuple(value for header, value in headers if header.lower() == name)


def _head(headers: Sequence[tuple[str, str]], query: str) -> Refuse | None:
    """E1, E2, E16 and E17: the request around the body."""
    types = _values(headers, "content-type")
    if len(types) != 1 or not _JSON_TYPE.fullmatch(types[0].lower()):
        return Refuse("content_type")
    if _values(headers, "content-encoding"):
        return Refuse("content_encoding")
    for name, _value in headers:
        lowered = name.lower()
        if lowered not in ADMITTED_HEADERS and not lowered.startswith(PARAM_HEADER_PREFIX):
            return Refuse("header_extra")
    if query:
        return Refuse("query")
    return None


def _parse(body: bytes) -> tuple[str, dict[str, Any]] | Refuse:
    """E3 to E5: one strict JSON object, and its text."""
    if len(body) > MAX_HELD_BODY:
        return Refuse("too_large")
    if body.startswith(_BOM):
        return Refuse("encoding")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return Refuse("encoding")
    try:
        # Its own size limit is MAX_HELD_BODY's 1 MiB, never reached after the check above.
        message = canonical.loads_strict(text)
    except canonical.JSONRejected:
        return Refuse("json")
    if isinstance(message, list):
        return Refuse("batch")
    if not isinstance(message, dict):
        return Refuse("not_object")
    return text, message


def _form(message: Mapping[str, Any]) -> Refuse | None:
    """E6 to E8: a JSON-RPC message the gateway sends, with an id a held method can keep."""
    if message.get("jsonrpc") != "2.0":
        return Refuse("jsonrpc", "/jsonrpc")
    if "method" not in message:
        return None if _response(message) else Refuse("method_form")
    method = message["method"]
    if not isinstance(method, str) or not _METHOD.fullmatch(method):
        return Refuse("method_form", "/method")
    if method not in HELD_METHODS and method.casefold() in _HELD_FOLDED:
        return Refuse("method_case", "/method")
    if method not in METHODS:
        return Refuse("method_form", "/method")
    if method in HELD_METHODS and not _id(message):
        return Refuse("id", "/id")
    # Shaped as the gateway sends it (gateway/egressrules.py): a notification has no id, and
    # every other method has one, so only a notification is ever read as a cancel.
    if ("id" in message) == (method in NOTIFICATIONS):
        return Refuse("method_form", "/method")
    return None


def _response(message: Mapping[str, Any]) -> bool:
    """One of the two responses the gateway sends (``gateway/egressrules.py``): an error, or an
    empty result."""
    if "id" not in message:
        return False
    if "error" in message:
        return "result" not in message
    return message.get("result") == {}


def _id_type(value: object) -> TypeGuard[str | int]:
    return isinstance(value, str | int) and not isinstance(value, bool)


def _id(message: Mapping[str, Any]) -> bool:
    """E8. An integer id is safe: :func:`canonical.loads_strict` refused any other (E4)."""
    value = message.get("id")
    if isinstance(value, str):
        return _ID.fullmatch(value) is not None
    return _id_type(value)


def _disagrees(headers: Sequence[tuple[str, str]], message: Mapping[str, Any]) -> bool:
    """E12: a routing header sent twice, or not equal to its body field. The era is read from
    ``MCP-Protocol-Version``, which a body carrying its protocol version needs, equal. At
    2026-07-28 :func:`.mcpwire.mismatch` applies whole, which requires them all; at the earlier
    eras they may be absent, and are checked when present."""
    routing = {name: _values(headers, name) for name in ROUTING_HEADERS}
    if any(len(values) > 1 for values in routing.values()):
        return True
    if "method" not in message:
        # A response has no method or name for the headers to mirror.
        return bool(routing[METHOD_HEADER] or routing[NAME_HEADER])
    params = message.get("params")
    fields: dict[str, Any] = params if isinstance(params, dict) else {}
    meta = fields.get("_meta")
    version = meta.get(PROTOCOL_VERSION_META) if isinstance(meta, dict) else None
    if version is not None and routing[VERSION_HEADER] != (version,):
        return True
    if routing[VERSION_HEADER] == (MODERN_VERSION,):
        return mismatch(routing, {**message, "params": fields}) is not None
    method = message["method"]
    if routing[METHOD_HEADER] not in ((), (method,)):
        return True
    key = NAME_BEARING.get(method)
    sent = routing[NAME_HEADER]
    if key is None or not sent:
        return False
    decoded = decode_name(sent[0])
    return decoded is None or decoded != fields.get(key)


def _fold(name: str) -> str:
    """E15: a name as a normalizing upstream might read it (G-4)."""
    return unicodedata.normalize("NFKC", name).casefold().strip()


class _Unround:
    """A number token whose text doesn't round-trip (E9)."""


_UNROUND: Final = _Unround()


def _int_token(text: str) -> int | _Unround:
    value = int(text)
    return value if str(value) == text else _UNROUND


def _float_token(text: str) -> float | _Unround:
    value = float(text)
    return value if repr(value) == text else _UNROUND


def _unround(text: str) -> str | None:
    """E9: the pointer of the first number token whose text doesn't round-trip, or None. The
    parse hooks see each token's text (contract 68); ``text`` already passed E4."""
    pending: list[tuple[str, Any]] = [
        ("", json.loads(text, parse_int=_int_token, parse_float=_float_token))
    ]
    while pending:
        pointer, value = pending.pop()
        if value is _UNROUND:
            return pointer
        if isinstance(value, dict):
            children = [(f"{pointer}/{_escape(key)}", child) for key, child in value.items()]
        elif isinstance(value, list):
            children = [(f"{pointer}/{index}", child) for index, child in enumerate(value)]
        else:
            continue
        pending.extend(reversed(children))
    return None


def _pointer(*keys: str) -> str:
    return "".join(f"/{_escape(key)}" for key in keys)


def _escape(key: str) -> str:
    """One JSON pointer reference token (RFC 6901)."""
    return key.replace("~", "~0").replace("/", "~1")
