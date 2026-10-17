"""JSON-lines logging on stdout (design R56).

Log fields are chosen by the caller and must never include secrets, placeholders, query values
or raw paths. :func:`event` refuses values of type :class:`~zoeymcp.vault.store.Secret` as a
last line of defense.
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import threading
import time
from collections.abc import Iterator
from typing import Any, TextIO

from .store import Secret

_lock = threading.Lock()
# None means "whatever sys.stdout is when a line is written", so a replaced stdout is honored.
_stream: TextIO | None = None


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


def event(kind: str, **fields: Any) -> None:
    record: dict[str, Any] = {"ts": round(time.time(), 3), "event": kind}
    for key, value in fields.items():
        if isinstance(value, Secret):
            raise TypeError(f"refusing to log a secret in field {key!r}")
        record[key] = value
    line = json.dumps(record, default=str, separators=(",", ":"))
    with _lock:
        stream = _stream or sys.stdout
        stream.write(line + "\n")
        stream.flush()
