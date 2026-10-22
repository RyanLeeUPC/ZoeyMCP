"""The relay's decisions (M7 design C.4, X14; SPEC-3, SPEC-4, TI-4, MISS-5, G10). Pure and
mutation-tested; :mod:`.server` and :mod:`.child` move the lines.

One :class:`Relay` per child: a legacy session's child, or a modern bridge's one child. Every
request sent to the child gets a fresh integer id from the child's counter, and a
``params._meta.progressToken``, when present, a bridge-unique token from the same counter: clients
choose progress tokens freely and the SDK uses the request id, so two gateway connections both
send ``progressToken: 5``, while MCP requires tokens unique across all active requests. At most
:data:`IDS_MAX` requests are in flight per child (beyond: 503 ``bridge_busy``). A
``subscriptions/listen`` request's id is remapped like any other; the ``subscriptionId`` the child
echoes is that remapped id, so no client-chosen correlator reaches it.

From the child, a response whose id is in flight goes to its exchange with the original id
restored, and anything else is dropped (``bridge_unmatched``); ``notifications/progress`` goes by
its remapped token to the one request that owns it, with the original token restored; a modern
notification naming a listen in flight goes to that listen's stream; any other notification goes
to the session's GET stream (legacy) or is dropped (modern). A request from the child is never
relayed: ``ping`` is answered ``{}`` and every other method ``-32601``.

A cancel never reaches another client's request. A legacy ``notifications/cancelled`` is resolved
against this child's requests alone, which are its session's, and only when exactly one matches;
a modern client sends none (closing the stream is the signal), and :meth:`Relay.disconnect`
cancels only the requests of the exchange that closed.

Only the id, a progress token or a subscription id is rewritten, in place in the message's bytes,
so nothing else is re-encoded (CR-6): a large result, a 64-bit number or an escape passes as the
child or the client wrote it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal

from ..common.textrules import reveal_hidden
from .framing import Era, Message, to_line

# M7 design C.4 and M.6.
IDS_MAX: Final = 256
NOT_SUPPORTED: Final = -32601
METHOD_SHOWN_MAX: Final = 64
LISTEN: Final = "subscriptions/listen"
PROGRESS: Final = "notifications/progress"
CANCELLED: Final = "notifications/cancelled"
SUBSCRIPTION_META: Final = "io.modelcontextprotocol/subscriptionId"

# Where the rewritten values sit in a message.
Path = tuple[str, ...]
ID: Final[Path] = ("id",)
TOKEN: Final[Path] = ("params", "_meta", "progressToken")
PROGRESS_TOKEN: Final[Path] = ("params", "progressToken")
REQUEST_ID: Final[Path] = ("params", "requestId")
SUBSCRIPTION: Final[Path] = ("params", "_meta", SUBSCRIPTION_META)

DropReason = Literal["unmatched", "orphaned", "progress", "notification", "invalid"]

_NOT_SPACE = re.compile(r"[^ \t\n\r]")
_DECODER = json.JSONDecoder()


@dataclass(frozen=True)
class Pending:
    """A request in flight: its exchange, its id and progress token as the client wrote them
    (value and JSON text), and what the child was sent instead."""

    exchange: int
    original_id: str | int
    id_text: str
    remapped: int
    token_text: str | None = None
    remapped_token: int | None = None
    listen: bool = False


@dataclass(frozen=True)
class Deliver:
    """A message for one exchange's stream; ``final`` when it is the answer, which ends it."""

    exchange: int
    data: bytes
    final: bool


@dataclass(frozen=True)
class Broadcast:
    """A legacy notification for the session's GET stream."""

    data: bytes


@dataclass(frozen=True)
class Reply:
    """An answer the bridge writes to the child itself. ``refused`` is the method it refused,
    cut and revealed, for ``bridge_client_request_refused``."""

    line: bytes
    refused: str | None = None


@dataclass(frozen=True)
class Drop:
    reason: DropReason


Route = Deliver | Broadcast | Reply | Drop


def _skip(text: str, index: int) -> int:
    found = _NOT_SPACE.search(text, index)
    return len(text) if found is None else found.start()


def _members(text: str, start: int) -> Iterator[tuple[str, int, int]]:
    """Each member of the object whose ``{`` is at ``start``: its key and its value's span."""
    index = _skip(text, start + 1)
    while text[index] != "}":
        key, index = _DECODER.raw_decode(text, index)
        index = _skip(text, _skip(text, index) + 1)
        _, end = _DECODER.raw_decode(text, index)
        yield key, index, end
        index = _skip(text, end)
        if text[index] == ",":
            index = _skip(text, index + 1)


def span(text: str, path: Path) -> tuple[int, int] | None:
    """Where the value at ``path`` sits in a JSON object's text, or None if it has none. The
    text is one a strict parse accepted, so no key appears twice."""
    start = _skip(text, 0)
    end = len(text)
    for key in path:
        if text[start] != "{":
            return None
        for name, value_start, value_end in _members(text, start):
            if name == key:
                start, end = value_start, value_end
                break
        else:
            return None
    return start, end


def _splice(text: str, edits: Sequence[tuple[tuple[int, int], str]]) -> bytes:
    parts = []
    last = 0
    for (start, end), new in sorted(edits):
        parts += [text[last:start], new]
        last = end
    parts.append(text[last:])
    return "".join(parts).encode("utf-8")


def rewrite(raw: bytes, edits: Sequence[tuple[Path, str]]) -> bytes:
    """``raw`` with the value at each path replaced by the given JSON text, every other byte
    kept. A path with no value is left alone."""
    text = raw.decode("utf-8")
    return _splice(text, [(where, new) for path, new in edits if (where := span(text, path))])


def _same(left: object, right: object) -> bool:
    return type(left) is type(right) and left == right


def _answer(id_text: str, outcome: str) -> bytes:
    return to_line(f'{{"jsonrpc":"2.0","id":{id_text},{outcome}}}'.encode())


def cancelled(remapped: int) -> bytes:
    """The ``notifications/cancelled`` line for a request the child was sent as ``remapped``."""
    message = {"jsonrpc": "2.0", "method": CANCELLED, "params": {"requestId": remapped}}
    return to_line(json.dumps(message, separators=(",", ":")).encode())


class Relay:
    """One child's requests in flight, and its counter."""

    def __init__(self, era: Era, limit: int = IDS_MAX) -> None:
        self.era = era
        self.limit = limit
        self.unmatched = 0
        self._counter = 0
        self._pending: dict[int, Pending] = {}
        self._tokens: dict[int, int] = {}
        # Requests whose exchange ended first: their answers are dropped without counting.
        self._orphans: dict[int, None] = {}

    def __len__(self) -> int:
        return len(self._pending)

    def _next(self) -> int:
        self._counter += 1
        return self._counter

    def outbound(self, message: Message, exchange: int) -> tuple[bytes, Pending] | None:
        """The line to send the child for a request, and what is now in flight; None when
        :attr:`limit` requests are (503 ``bridge_busy``)."""
        if len(self._pending) >= self.limit:
            return None
        text = message.raw.decode("utf-8")
        id_span = span(text, ID)
        assert id_span is not None  # noqa: S101 - a request has an id
        remapped = self._next()
        edits = [(id_span, str(remapped))]
        token_text = remapped_token = None
        token_span = span(text, TOKEN)
        if token_span is not None:
            remapped_token = self._next()
            token_text = text[token_span[0] : token_span[1]]
            edits.append((token_span, str(remapped_token)))
            self._tokens[remapped_token] = remapped
        pending = Pending(
            exchange,
            message.value["id"],
            text[id_span[0] : id_span[1]],
            remapped,
            token_text,
            remapped_token,
            message.value["method"] == LISTEN,
        )
        self._pending[remapped] = pending
        return to_line(_splice(text, edits)), pending

    def _done(self, pending: Pending) -> None:
        self._pending.pop(pending.remapped, None)
        if pending.remapped_token is not None:
            self._tokens.pop(pending.remapped_token, None)

    def inbound(self, message: Message) -> Route:
        """Where a message from the child goes."""
        value = message.value
        kind = message.kind
        if kind == "response":
            return self._response(message)
        if kind == "request":
            text = message.raw.decode("utf-8")
            id_span = span(text, ID)
            assert id_span is not None  # noqa: S101 - a request has an id
            id_text = text[id_span[0] : id_span[1]]
            if value["method"] == "ping":
                return Reply(_answer(id_text, '"result":{}'))
            error = f'"error":{{"code":{NOT_SUPPORTED},"message":"not supported by this bridge"}}'
            return Reply(_answer(id_text, error), reveal_hidden(value["method"][:METHOD_SHOWN_MAX]))
        if kind == "invalid":
            return Drop("invalid")
        params = value.get("params", {})
        if value["method"] == PROGRESS:
            return self._progress(message, params.get("progressToken"))
        if self.era == "legacy":
            return Broadcast(message.raw)
        meta = params.get("_meta")
        subscription = meta.get(SUBSCRIPTION_META) if isinstance(meta, dict) else None
        listen = self._pending.get(subscription) if type(subscription) is int else None
        if listen is None or not listen.listen:
            return Drop("notification")
        data = rewrite(message.raw, [(SUBSCRIPTION, listen.id_text)])
        return Deliver(listen.exchange, data, False)

    def _response(self, message: Message) -> Route:
        response_id = message.value["id"]
        pending = self._pending.get(response_id) if type(response_id) is int else None
        if pending is None:
            if type(response_id) is int and response_id in self._orphans:
                del self._orphans[response_id]
                return Drop("orphaned")
            self.unmatched += 1
            return Drop("unmatched")
        self._done(pending)
        return Deliver(pending.exchange, rewrite(message.raw, [(ID, pending.id_text)]), True)

    def _progress(self, message: Message, token: Any) -> Route:
        remapped = self._tokens.get(token) if type(token) is int else None
        pending = self._pending.get(remapped) if remapped is not None else None
        if pending is None:
            return Drop("progress")
        assert pending.token_text is not None  # noqa: S101 - only a token's request is in _tokens
        data = rewrite(message.raw, [(PROGRESS_TOKEN, pending.token_text)])
        return Deliver(pending.exchange, data, False)

    def cancel(self, message: Message) -> bytes | None:
        """The line for a legacy client's ``notifications/cancelled``, its ``requestId``
        remapped; None when no request in flight, or more than one, has that id (dropped), and
        always in the modern era, where a client cancels by closing its stream."""
        if self.era != "legacy":
            return None
        request_id = message.value.get("params", {}).get("requestId")
        found = [p for p in self._pending.values() if _same(p.original_id, request_id)]
        if len(found) != 1:
            return None
        return to_line(rewrite(message.raw, [(REQUEST_ID, str(found[0].remapped))]))

    def disconnect(self, exchange: int) -> list[bytes]:
        """An exchange ended before its answer: forget its requests, whose answers are then
        dropped. Modern: the disconnect is the cancel, so a ``notifications/cancelled`` line for
        each; legacy: none ("Disconnection SHOULD NOT be interpreted as the client cancelling")."""
        lines = []
        for pending in [p for p in self._pending.values() if p.exchange == exchange]:
            self._done(pending)
            self._orphans[pending.remapped] = None
            if len(self._orphans) > self.limit:
                del self._orphans[next(iter(self._orphans))]
            if self.era == "modern":
                lines.append(cancelled(pending.remapped))
        return lines

    def fail(self) -> list[Pending]:
        """The child is gone: every request in flight, each answered 502, and nothing kept."""
        gone = list(self._pending.values())
        self._pending.clear()
        self._tokens.clear()
        self._orphans.clear()
        return gone
