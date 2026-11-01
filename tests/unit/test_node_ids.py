"""The node-ID guard (register D-227): ``conftest.py`` refuses, before any test here runs, a node
ID mutmut couldn't rerun by: ``ids=repr``, an ID outside printable ASCII, and a backslash in an ID
a parametrize mark's ``ids=`` made. pytest's own escaped IDs from the values pass, and so does
every ID ``plain_id`` makes.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import pytest

from tests.unit.plainid import plain_id

from .conftest import UNIT, here, pytest_collection_modifyitems, refused

REPR = pytest.mark.parametrize("value", ["a"], ids=repr).mark
# ``ids`` given as parametrize's fourth argument.
POSITIONAL = pytest.mark.parametrize.with_args("value", ["a"], False, repr).mark
GIVEN = pytest.mark.parametrize("value", ["a"], ids=plain_id).mark
# ``ids=None`` given explicitly: pytest still keeps the IDs it makes from the values.
NONE = pytest.mark.parametrize("value", ["a"], ids=None).mark
NONE_POSITIONAL = pytest.mark.parametrize.with_args("value", ["a"], False, None).mark
VALUES = pytest.mark.parametrize("value", ["a"]).mark
OTHER = pytest.mark.filterwarnings("error").mark


@dataclass
class Item:
    """A collected test as the guard reads it."""

    nodeid: str
    marks: tuple[pytest.Mark, ...] = ()
    path: Path = UNIT / "test_x.py"

    def iter_markers(self, name: str | None = None) -> Iterator[pytest.Mark]:
        return iter([mark for mark in self.marks if name is None or mark.name == name])


def test_ids_repr_is_refused_whatever_it_makes() -> None:
    items = [Item("t.py::test[a]", (REPR,)), Item("t.py::test[b]", (OTHER, POSITIONAL))]
    assert refused(items) == [
        "'t.py::test[a]': ids=repr; use plainid.plain_id",
        "'t.py::test[b]': ids=repr; use plainid.plain_id",
    ]


def test_an_id_outside_printable_ascii_is_refused() -> None:
    for nodeid in [
        "t.py::test[a\nb]",
        "t.py::test[a\rb]",
        "t.py::test[a\tb]",
        "t.py::test[caf\u00e9]",
        "t.py::test[\u202e]",
        "t.py::test[\x7f]",
        "t.py::test[\x00]",
    ]:
        assert refused([Item(nodeid, (VALUES,))]) == [f"{nodeid!a}: not printable ASCII"]
    assert refused([Item("t.py::test[ ~]", (GIVEN,))]) == []


def test_a_backslash_is_refused_only_in_an_id_ids_made() -> None:
    nodeid = "t.py::test[caf\\xe9]"
    said = f"{nodeid!a}: a backslash in an ID ids= made; use plainid.plain_id"
    assert refused([Item(nodeid, (VALUES,))]) == []
    assert refused([Item(nodeid)]) == []
    assert refused([Item(nodeid, (OTHER,))]) == []
    assert refused([Item(nodeid, (GIVEN,))]) == [said]
    assert refused([Item(nodeid, (VALUES, GIVEN))]) == [said]
    assert refused([Item(nodeid, (NONE,))]) == [said]
    assert refused([Item(nodeid, (NONE_POSITIONAL,))]) == [said]
    assert refused([Item("t.py::test[a]", (NONE,))]) == []
    assert refused([Item("t.py::test[a]", (GIVEN,)), Item(nodeid, (GIVEN,))]) == [said]


def test_every_id_plain_id_makes_is_taken() -> None:
    for value in [
        "a\nb",
        "caf\u00e9",
        "hidden \u202e text",
        b"\xff\x00",
        {"big": "x" * 100},
        "a\\b",
        None,
    ]:
        made = plain_id(value)
        assert len(made) <= 60
        assert refused([Item(f"t.py::test[{made}]", (GIVEN,))]) == []
    assert plain_id({"v": 2}) == "_v_: 2_"
    assert plain_id("x" * 100) == "_" + "x" * 59


def test_the_hook_stops_the_run_for_a_test_here_only(tmp_path: Path) -> None:
    elsewhere = Item("t.py::test[a]", (REPR,), tmp_path / "test_x.py")
    pytest_collection_modifyitems(cast(Any, [elsewhere, Item("t.py::test[b]", (GIVEN,))]))
    with pytest.raises(pytest.UsageError) as caught:
        pytest_collection_modifyitems(cast(Any, [elsewhere, Item("t.py::test[c]", (REPR,))]))
    assert str(caught.value) == (
        "test node IDs mutmut can't rerun (tests/unit/plainid.py):\n"
        "'t.py::test[c]': ids=repr; use plainid.plain_id"
    )


def test_the_hook_reads_the_tests_pytest_collects_here(request: pytest.FixtureRequest) -> None:
    assert here(request.node.path.parent)
    assert here(UNIT)
    assert not here(UNIT.parent)
