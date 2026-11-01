"""Test IDs that mutmut can rerun by node ID (register D-227).

pytest keeps the IDs a parametrize mark's ``ids=`` made on the mark, and a second collection in
the same process escapes them again, so an ID holding a backslash (the escape pytest writes for a
line break, a byte or a character outside ASCII) is never found again. mutmut's workers collect a
second time, so such an ID ends the whole mutation shard ("not found"). :func:`plain_id` keeps
only characters a node ID survives; ``conftest.py`` refuses the IDs it would have fixed.
"""

from __future__ import annotations

import re
from typing import Any


def plain_id(value: Any) -> str:
    """A test ID pytest can find again by its node ID: the value's ``repr`` with every run of
    other characters one ``_``, at most 60 characters."""
    return re.sub(r"[^A-Za-z0-9_.:=, -]+", "_", repr(value))[:60]
