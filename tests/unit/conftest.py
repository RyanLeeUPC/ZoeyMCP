from __future__ import annotations

from collections.abc import Iterable, Iterator
from functools import cache
from pathlib import Path
from typing import Any, Protocol

import pytest

from zoeymcp.common.yamlload import load_mapping

EXAMPLE_POLICY = Path(__file__).resolve().parents[2] / "examples" / "policy.yaml"
UNIT = Path(__file__).resolve().parent


@pytest.fixture
def example_text() -> str:
    return EXAMPLE_POLICY.read_text(encoding="utf-8")


@pytest.fixture
def example_raw(example_text: str) -> dict[str, Any]:
    """The example policy as a plain mapping, for tests that mutate one field at a time."""
    return load_mapping(example_text)


class Collected(Protocol):
    """What the node-ID guard reads of a collected test."""

    @property
    def nodeid(self) -> str: ...

    def iter_markers(self, name: str | None = None) -> Iterator[pytest.Mark]: ...


def refused(items: Iterable[Collected]) -> list[str]:
    """The node IDs mutmut couldn't rerun, each with why (register D-227; ``plainid.py``).

    Every ID must be printable ASCII, so no line break. An ID a parametrize mark's ``ids=`` made
    must hold no backslash either: pytest escapes those again on a second collection in one
    process, as mutmut's workers do. pytest's own IDs from the values (``[caf\\xe9]``) are made
    afresh each time and rerun. ``ids=repr`` is refused outright: use ``plain_id``.
    """
    found = []
    for item in items:
        marks = list(item.iter_markers("parametrize"))
        if any(ids_of(mark) is repr for mark in marks):
            found.append(f"{item.nodeid!a}: ids=repr; use plainid.plain_id")
        elif not all(" " <= char <= "~" for char in item.nodeid):
            found.append(f"{item.nodeid!a}: not printable ASCII")
        elif "\\" in item.nodeid and any(has_ids(mark) for mark in marks):
            found.append(f"{item.nodeid!a}: a backslash in an ID ids= made; use plainid.plain_id")
    return found


def ids_of(mark: pytest.Mark) -> object:
    """A parametrize mark's ``ids``, given by name or as its fourth argument; ``None`` if none."""
    return mark.kwargs.get("ids", mark.args[3] if len(mark.args) > 3 else None)


def has_ids(mark: pytest.Mark) -> bool:
    """Whether pytest keeps the IDs a parametrize mark makes, to escape again on the next
    collection: pytest's own rule (``Mark._has_param_ids``), so ``ids=None`` counts too."""
    return "ids" in mark.kwargs or len(mark.args) > 3


@cache
def here(folder: Path) -> bool:
    """Whether a test's folder is under ``tests/unit``, resolved as ``UNIT`` is, so a checkout
    reached through a link or a substituted drive still has its tests checked."""
    resolved = folder.resolve()
    return resolved == UNIT or UNIT in resolved.parents


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Refuse the whole run when a test here has a node ID mutmut couldn't rerun by: one such ID
    ends a whole mutation shard, and the run says why only in that shard's log."""
    found = refused(item for item in items if here(item.path.parent))
    if found:
        raise pytest.UsageError(
            "test node IDs mutmut can't rerun (tests/unit/plainid.py):\n" + "\n".join(found)
        )
