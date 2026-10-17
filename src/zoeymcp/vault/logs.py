"""JSON-lines logging on stdout (design R56).

Log fields are chosen by the caller and must never include secrets, placeholders, query values
or raw paths. :func:`event` refuses values of type :class:`~zoeymcp.vault.store.Secret` as a
last line of defense.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from typing import Any, TextIO

from .store import Secret

_lock = threading.Lock()
_stream: TextIO = sys.stdout


def set_stream(stream: TextIO) -> None:
    """Send log lines elsewhere (tests)."""
    global _stream
    _stream = stream


def event(kind: str, **fields: Any) -> None:
    record: dict[str, Any] = {"ts": round(time.time(), 3), "event": kind}
    for key, value in fields.items():
        if isinstance(value, Secret):
            raise TypeError(f"refusing to log a secret in field {key!r}")
        record[key] = value
    line = json.dumps(record, default=str, separators=(",", ":"))
    with _lock:
        _stream.write(line + "\n")
        _stream.flush()
