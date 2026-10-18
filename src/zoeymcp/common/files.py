"""Small file helpers shared by the vault and the gateway."""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def write_atomic(path: Path, data: bytes, *, prefix: str) -> None:
    """Replace ``path`` with ``data`` (mode 0600), so a crash leaves the old file or the new.

    The temporary file sits beside ``path``, named with ``prefix``. The file is synced, and on
    POSIX so is its directory, so the rename survives a power loss.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    if hasattr(os, "O_DIRECTORY"):
        dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
