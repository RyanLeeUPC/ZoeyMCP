from __future__ import annotations

import io
import json
from collections.abc import Iterator
from typing import Any

import pytest

from zoeymcp.common import logs as common_logs
from zoeymcp.vault import logs
from zoeymcp.vault.store import Secret


class ClientTokenLike:
    """A stand-in for a role's secret-holding type."""


@pytest.fixture
def lines() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


@pytest.fixture
def refused_stand_in() -> Iterator[None]:
    before = common_logs.refused_types()
    common_logs.refuse_type(ClientTokenLike)
    try:
        yield
    finally:
        common_logs._refused = before


def records(buffer: io.StringIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines()]


def test_writes_to_the_current_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    # Test runners and supervisors replace sys.stdout after import; the log must follow.
    replacement = io.StringIO()
    monkeypatch.setattr("sys.stdout", replacement)
    logs.event("probe", n=1)
    record = json.loads(replacement.getvalue())
    assert record["event"] == "probe"
    assert record["n"] == 1


def test_quiet_discards_and_restores(monkeypatch: pytest.MonkeyPatch) -> None:
    replacement = io.StringIO()
    monkeypatch.setattr("sys.stdout", replacement)
    with logs.quiet():
        logs.event("hidden")
    logs.event("shown")
    assert [json.loads(line)["event"] for line in replacement.getvalue().splitlines()] == ["shown"]


def test_the_vault_reexports_the_shared_module() -> None:
    assert logs.quiet is common_logs.quiet
    assert logs.set_stream is common_logs.set_stream
    assert Secret in common_logs.refused_types()


def test_every_line_carries_its_role(lines: io.StringIO) -> None:
    logs.event("one", n=1)
    common_logs.Log("gateway").event("two", server="notes")
    common_logs.Log("launcher").event("three")
    first, second, third = records(lines)
    assert list(first) == ["ts", "role", "event", "n"]
    assert {k: v for k, v in first.items() if k != "ts"} == {
        "role": "vault",
        "event": "one",
        "n": 1,
    }
    assert {k: v for k, v in second.items() if k != "ts"} == {
        "role": "gateway",
        "event": "two",
        "server": "notes",
    }
    assert (third["role"], third["event"]) == ("launcher", "three")
    assert lines.getvalue().endswith("\n")
    assert lines.getvalue().count("\n") == 3
    assert '"role":"vault","event":"one"' in lines.getvalue()


@pytest.mark.parametrize("field", ["ts", "role", "event"])
def test_reserved_fields_are_refused(field: str, lines: io.StringIO) -> None:
    with pytest.raises(TypeError, match=f"^field '{field}' is set by the logger$"):
        logs.event("oops", **{field: "x"})
    assert lines.getvalue() == ""


def test_refuses_to_log_a_secret(lines: io.StringIO) -> None:
    message = r"^refusing to log a secret \(Secret\) in field 'value'$"
    with pytest.raises(TypeError, match=message):
        logs.event("oops", value=Secret("fake-value-0001"))
    assert lines.getvalue() == ""


@pytest.mark.parametrize(
    "value",
    [
        [1, Secret("fake-value-0001")],
        ("a", Secret("fake-value-0001")),
        {Secret("fake-value-0001")},
        frozenset({Secret("fake-value-0001")}),
        {"key": Secret("fake-value-0001")},
        {Secret("fake-value-0001"): "value"},
        {"outer": [{"inner": (Secret("fake-value-0001"),)}]},
    ],
)
def test_refuses_a_secret_inside_a_container(value: Any, lines: io.StringIO) -> None:
    with pytest.raises(TypeError, match=r"^refusing to log a secret \(Secret\) in field 'f'$"):
        logs.event("oops", f=value)
    assert lines.getvalue() == ""


def test_a_registered_type_is_refused_in_every_role(
    refused_stand_in: None, lines: io.StringIO
) -> None:
    message = r"^refusing to log a secret \(ClientTokenLike\) in field 'token'$"
    for role in ("vault", "gateway", "launcher"):
        log = common_logs.Log(role)
        with pytest.raises(TypeError, match=message):
            log.event("oops", token=ClientTokenLike())
    # A subclass is refused too.
    subclass = type("Sub", (ClientTokenLike,), {})
    with pytest.raises(TypeError, match=r"\(Sub\)"):
        logs.event("oops", token=[subclass()])
    assert lines.getvalue() == ""


def test_registering_twice_keeps_one_entry(refused_stand_in: None) -> None:
    common_logs.refuse_type(ClientTokenLike)
    assert common_logs.refused_types().count(ClientTokenLike) == 1


def test_unregistered_values_are_logged(lines: io.StringIO) -> None:
    logs.event("fine", items=[1, "a", (2, 3)], mapping={"k": [None]}, other=ClientTokenLike)
    [record] = records(lines)
    assert record["items"] == [1, "a", [2, 3]]
    assert record["mapping"] == {"k": [None]}


def test_a_container_that_holds_itself_ends_the_check() -> None:
    looped: list[Any] = [1]
    looped.append(looped)
    # The check ends; the JSON encoder then refuses the cycle.
    with pytest.raises(ValueError, match="Circular reference"):
        logs.event("loop", value=looped)


def test_a_seen_value_does_not_end_the_check(lines: io.StringIO) -> None:
    # The walk skips values it has seen and goes on to the rest.
    message = r"^refusing to log a secret \(Secret\) in field 'f'$"
    shared = ["a"]
    for value in ([Secret("fake-value-0001"), 1, 1], [Secret("fake-value-0001"), shared, shared]):
        with pytest.raises(TypeError, match=message):
            logs.event("oops", f=value)
    looped: list[Any] = [Secret("fake-value-0001")]
    looped.append(looped)
    with pytest.raises(TypeError, match=message):
        logs.event("oops", f=looped)
    assert lines.getvalue() == ""


def test_a_dict_that_holds_itself_ends_the_check() -> None:
    looped: dict[str, Any] = {}
    looped["self"] = looped
    with pytest.raises(ValueError, match="Circular reference"):
        logs.event("loop", value=looped)


def test_ts_is_seconds_to_the_millisecond(
    monkeypatch: pytest.MonkeyPatch, lines: io.StringIO
) -> None:
    monkeypatch.setattr("zoeymcp.common.logs.time.time", lambda: 1700000000.123456)
    logs.event("probe")
    assert lines.getvalue() == '{"ts":1700000000.123,"role":"vault","event":"probe"}\n'


def test_the_launcher_names_a_child_without_the_reserved_role(lines: io.StringIO) -> None:
    # The design's child_exited{role, status} would clash with the line's own role.
    common_logs.Log("launcher").event("child_exited", child="gateway", status=1)
    [record] = records(lines)
    assert {k: v for k, v in record.items() if k != "ts"} == {
        "role": "launcher",
        "event": "child_exited",
        "child": "gateway",
        "status": 1,
    }
