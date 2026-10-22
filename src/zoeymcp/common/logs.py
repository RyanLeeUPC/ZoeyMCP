"""JSON-lines logging on stdout, shared by every role (design R56, R61, M3 design M).

Log fields are chosen by the caller and must never include secrets, placeholders, query values
or raw paths. As a last line of defense, :meth:`Log.event` refuses any value of a registered
type, at the top level or inside a list, tuple, set or dict. Each role registers its own
secret-holding types (the vault its ``Secret``), so this module never imports role code.

Every line carries the role that wrote it, so one process can host several roles (tests do).
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import threading
import time
from collections.abc import Iterator
from typing import Any, Literal, TextIO

Role = Literal["vault", "gateway", "launcher", "egress"]
# Field names every line sets itself.
RESERVED_FIELDS = frozenset({"ts", "role", "event"})

_lock = threading.Lock()
# None means "whatever sys.stdout is when a line is written", so a replaced stdout is honored.
_stream: TextIO | None = None
_refused: tuple[type, ...] = ()


def refuse_type(kind: type) -> None:
    """Make :meth:`Log.event` raise for any value of ``kind`` (or a subclass)."""
    global _refused
    with _lock:
        if kind not in _refused:
            _refused = (*_refused, kind)


def refused_types() -> tuple[type, ...]:
    return _refused


def set_stream(stream: TextIO | None) -> None:
    """Send log lines elsewhere (tests); ``None`` goes back to stdout."""
    global _stream
    _stream = stream


@contextlib.contextmanager
def quiet() -> Iterator[None]:
    """Discard log lines for the duration (self-tests run thousands of requests)."""
    global _stream
    previous, _stream = _stream, io.StringIO()
    try:
        yield
    finally:
        _stream = previous


def _check(key: str, value: Any) -> None:
    """Raise if ``value`` holds an instance of a refused type."""
    refused = _refused
    stack = [value]
    seen: set[int] = set()
    while stack:
        item = stack.pop()
        if isinstance(item, refused):
            raise TypeError(f"refusing to log a secret ({type(item).__name__}) in field {key!r}")
        if id(item) in seen:
            continue  # a container that holds itself
        seen.add(id(item))
        if isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list | tuple | set | frozenset):
            stack.extend(item)


class Log:
    """Writes the lines of one role."""

    def __init__(self, role: Role) -> None:
        self.role = role

    def event(self, kind: str, **fields: Any) -> None:
        record: dict[str, Any] = {"ts": round(time.time(), 3), "role": self.role, "event": kind}
        for key, value in fields.items():
            if key in RESERVED_FIELDS:
                raise TypeError(f"field {key!r} is set by the logger")
            _check(key, value)
            record[key] = value
        line = json.dumps(record, default=str, separators=(",", ":"))
        with _lock:
            stream = _stream or sys.stdout
            stream.write(line + "\n")
            stream.flush()
