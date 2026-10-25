"""The gateway as the restore witness (M6 design K.3; Y24, T-4, T-5): what a view answer's
revision header states (``gateway/witness.py``'s :func:`stated`), what the gateway records of it
(:func:`seen`: a new deployment, a higher revision, a regression, at most 8 kept, the lowest
revision let go first), the file's form (:func:`dumps`, :func:`loads`), and the policy client's
:class:`Witness`, which keeps the file and logs a new deployment and a regression.
"""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from zoeymcp.common import canonical
from zoeymcp.common.policy.view import MODE_HEADER, REVISION_HEADER
from zoeymcp.gateway import logs
from zoeymcp.gateway.policyclient import Witness
from zoeymcp.gateway.witness import (
    FILE,
    MAX_BYTES,
    REVISION_MAX,
    VERSION,
    WITNESS_DEPLOYMENTS_MAX,
    Entry,
    Regressed,
    Seen,
    Stated,
    WitnessError,
    dumps,
    loads,
    seen,
    stated,
)
from zoeymcp.vault import policyseal, statusreport

A = "a" * 32
B = "b" * 32


def deployment(n: int) -> str:
    return f"{n:032x}"


def plain_id(value: Any) -> str:
    """A test ID pytest finds again: the value's repr, ASCII only and no backslash, ``/`` in its
    place (mutmut reruns by node ID)."""
    return repr(value).encode("ascii", "backslashreplace").decode().replace("\\", "/")


@pytest.fixture
def log() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def events(buffer: io.StringIO, name: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [
        {k: v for k, v in line.items() if k not in ("ts", "role")}
        for line in lines
        if line["event"] == name
    ]


def test_the_header_and_the_bounds_are_the_vaults() -> None:
    """The header beside the mode, and the vault's own bounds: a revision's (D.2, T-4) and the
    deployments the status report may name (K.1)."""
    assert REVISION_HEADER == "x-zoeymcp-policy-revision"
    assert MODE_HEADER == "x-zoeymcp-policy-mode"
    assert REVISION_MAX == policyseal.REVISION_MAX == 9_999_999_999
    assert WITNESS_DEPLOYMENTS_MAX == statusreport.WITNESS_DEPLOYMENTS_MAX == 8
    assert (FILE, VERSION, MAX_BYTES) == ("policy-seen.json", 1, 65536)


# --- the header ---------------------------------------------------------------------------------


def test_a_statement_is_a_deployment_and_a_revision() -> None:
    assert stated(f"{A}.1") == Stated(A, 1)
    assert stated(f"{A}.27") == Stated(A, 27)
    assert stated(f"{A}.9999999999") == Stated(A, REVISION_MAX)


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        A,
        f"{A}.",
        f"{A}.0",
        f"{A}.01",
        f"{A}.-1",
        f"{A}.10000000000",
        f"{A}.1.2",
        f"{A}.1 ",
        f" {A}.1",
        f"{A.upper()}.1",
        f"{'a' * 31}.1",
        f"{'a' * 33}.1",
        f"{'g' * 32}.1",
        f"{A}.1\n",
        f"{A}.\u0661",
    ],
    ids=plain_id,
)
def test_anything_else_states_nothing(header: str | None) -> None:
    """A declarative vault, an older one, or a header that isn't one: no statement, so nothing
    is recorded; a revision above 9,999,999,999 is none either (T-4)."""
    assert stated(header) is None


# --- what the gateway records (K.3) ---------------------------------------------------------------


def test_a_new_deployment_is_recorded_with_when_it_was_first_seen() -> None:
    first = seen(Seen(), Stated(A, 3), 100)
    assert isinstance(first, Seen)
    assert dict(first.deployments) == {A: Entry(3, 100)}
    assert first.counted == 1
    second = seen(first, Stated(B, 1), 200)
    assert isinstance(second, Seen)
    assert list(second.deployments.items()) == [(A, Entry(3, 100)), (B, Entry(1, 200))]
    assert second.counted == 2
    assert second.report() == {A: 3, B: 1}
    assert list(second.report()) == [A, B]


def test_the_same_revision_changes_nothing() -> None:
    old = Seen(MappingProxyType({A: Entry(3, 100)}), 1)
    assert seen(old, Stated(A, 3), 500) is old


def test_a_higher_revision_is_recorded_where_it_was() -> None:
    """The first-seen time and the order stay: the order is when each was first seen."""
    old = Seen(MappingProxyType({A: Entry(3, 100), B: Entry(1, 200)}), 2)
    new = seen(old, Stated(A, 4), 500)
    assert isinstance(new, Seen)
    assert list(new.deployments.items()) == [(A, Entry(4, 100)), (B, Entry(1, 200))]
    assert new.counted == 2
    assert dict(old.deployments) == {A: Entry(3, 100), B: Entry(1, 200)}  # unchanged


def test_a_lower_revision_is_a_regression_and_the_higher_stays() -> None:
    """Y24: the gateway keeps the higher record and says what it saw."""
    old = Seen(MappingProxyType({A: Entry(31, 100)}), 1)
    found = seen(old, Stated(A, 27), 500)
    assert found == Regressed(A, 31, 27)
    assert dict(old.deployments) == {A: Entry(31, 100)}


def test_at_most_eight_and_the_lowest_revision_goes_first() -> None:
    """T-5: a ninth deployment lets go the one at the lowest revision, the earliest seen on a
    tie, never the one just seen; so deployments seeded again and again can't push out the one
    that reached a high revision. The count keeps every one recorded."""
    found = Seen()
    for n in range(8):
        step = seen(found, Stated(deployment(n), 31 if n == 0 else 1 + n % 2), n)
        assert isinstance(step, Seen)
        found = step
    assert len(found.deployments) == 8
    # Revisions 31, 2, 1, 2, 1, 2, 1, 2: the earliest at 1 is deployment 2.
    ninth = seen(found, Stated(deployment(8), 1), 8)
    assert isinstance(ninth, Seen)
    assert list(ninth.deployments) == [deployment(n) for n in (0, 1, *range(3, 9))]
    assert ninth.counted == 9
    tenth = seen(ninth, Stated(deployment(9), 1), 9)
    assert isinstance(tenth, Seen)
    assert deployment(4) not in tenth.deployments
    assert deployment(8) in tenth.deployments  # at 1 too, but seen later
    assert deployment(9) in tenth.deployments
    assert tenth.deployments[deployment(0)] == Entry(31, 0)
    assert tenth.counted == 10


def test_a_new_deployment_at_a_high_revision_still_keeps_eight() -> None:
    found = Seen(MappingProxyType({deployment(n): Entry(50 + n, n) for n in range(8)}), counted=8)
    added = seen(found, Stated(A, 1), 100)
    assert isinstance(added, Seen)
    assert len(added.deployments) == 8
    assert deployment(0) not in added.deployments
    assert added.deployments[A] == Entry(1, 100)


# --- the file -----------------------------------------------------------------------------------


def test_the_file_is_canonical_and_keeps_the_order() -> None:
    found = Seen(MappingProxyType({B: Entry(4, 200), A: Entry(31, 100)}), 3)
    data = dumps(found)
    assert data == (
        b'{"counted":3,"deployments":['
        b'{"deployment":"' + B.encode() + b'","first_seen":200,"revision":4},'
        b'{"deployment":"' + A.encode() + b'","first_seen":100,"revision":31}],"v":1}'
    )
    back = loads(data)
    assert back == found
    assert list(back.deployments) == [B, A]
    assert loads(dumps(Seen())) == Seen()


def entry(**changes: Any) -> dict[str, Any]:
    return {"deployment": A, "revision": 3, "first_seen": 100, **changes}


def document(**changes: Any) -> dict[str, Any]:
    return {"v": 1, "deployments": [entry()], "counted": 1, **changes}


def padded(size: int) -> bytes:
    """A file that would be one but for its size: a document, then spaces up to ``size`` bytes.
    Strict JSON under the library's own bound, so only the witness's bound refuses it."""
    data = canonical.dumps_canonical(document())
    return data + b" " * (size - len(data))


def case(name: str, data: bytes | dict[str, Any], said: str) -> Any:
    raw = data if isinstance(data, bytes) else canonical.dumps_canonical(data)
    return pytest.param(raw, said, id=name)


MALFORMED = "a deployment entry is malformed"
COUNTED = "counted is not a count of the deployments seen"


@pytest.mark.parametrize(
    ("data", "said"),
    [
        case("empty", b"", "not strict JSON"),
        case("repeated-key", b'{"v":1,"v":1}', "not strict JSON"),
        case("too-large", padded(MAX_BYTES + 1), "not strict JSON"),
        case("a-list", b"[]", "not a witness document"),
        case("no-count", {"v": 1, "deployments": []}, "not a witness document"),
        case("another-key", document(extra=1), "not a witness document"),
        case("version-2", document(v=2), "version 2 is not 1"),
        case("version-true", document(v=True), "version True is not 1"),
        case(
            "deployments-object",
            document(deployments={}),
            "deployments is not a list of at most 8",
        ),
        case(
            "nine",
            document(deployments=[entry(deployment=deployment(n)) for n in range(9)], counted=9),
            "deployments is not a list of at most 8",
        ),
        case("entry-list", document(deployments=[[]]), MALFORMED),
        case("entry-short", document(deployments=[{"deployment": A}]), MALFORMED),
        case("deployment-number", document(deployments=[entry(deployment=1)]), MALFORMED),
        case("deployment-upper", document(deployments=[entry(deployment=A.upper())]), MALFORMED),
        case("deployment-twice", document(deployments=[entry(), entry()], counted=2), MALFORMED),
        case("revision-0", document(deployments=[entry(revision=0)]), MALFORMED),
        case(
            "revision-over",
            document(deployments=[entry(revision=REVISION_MAX + 1)]),
            MALFORMED,
        ),
        case("revision-true", document(deployments=[entry(revision=True)]), MALFORMED),
        case("revision-text", document(deployments=[entry(revision="3")]), MALFORMED),
        case("first-seen-negative", document(deployments=[entry(first_seen=-1)]), MALFORMED),
        case("first-seen-false", document(deployments=[entry(first_seen=False)]), MALFORMED),
        case("counted-0", document(counted=0), COUNTED),
        case("counted-true", document(counted=True), COUNTED),
        case("counted-text", document(counted="1"), COUNTED),
    ],
)
def test_anything_else_isnt_a_witness_file(data: bytes, said: str) -> None:
    """Each refusal says what it is, whole."""
    with pytest.raises(WitnessError) as raised:
        loads(data)
    assert str(raised.value) == said


def test_the_bounds_of_a_file_are_held_exactly() -> None:
    """Revision 9,999,999,999, first seen at 0, a count above the deployments kept, eight
    deployments and 64 KiB are all a file's."""
    data = document(
        deployments=[
            entry(deployment=deployment(n), revision=REVISION_MAX, first_seen=0) for n in range(8)
        ],
        counted=20,
    )
    found = loads(canonical.dumps_canonical(data))
    assert (len(found.deployments), found.counted) == (8, 20)
    assert loads(padded(MAX_BYTES)).report() == {A: 3}
    assert loads(canonical.dumps_canonical(document(deployments=[entry(revision=1)]))).report() == {
        A: 1
    }


# --- the policy client's Witness (I/O) ----------------------------------------------------------


def test_a_witness_without_a_file_is_empty(tmp_path: Path) -> None:
    held = Witness.load(tmp_path)
    assert held.seen == Seen()
    assert not (tmp_path / FILE).exists()


def test_a_file_that_cant_be_used_stops_the_load(tmp_path: Path) -> None:
    (tmp_path / FILE).write_bytes(b"{}")
    with pytest.raises(WitnessError, match="not a witness document"):
        Witness.load(tmp_path)


def test_what_the_witness_notes_it_writes_and_logs(tmp_path: Path, log: io.StringIO) -> None:
    """K.3, N.3: the first deployment is info, one beside others a warning; a higher revision is
    written; a regression is logged once (critical) and the file keeps the higher; a header that
    states nothing changes nothing. The file is read back at the next start (FM-20)."""
    now = [100.0]
    held = Witness(tmp_path / FILE, wall=lambda: now[0])
    held.note(None)
    held.note("nonsense")
    assert not (tmp_path / FILE).exists()
    held.note(f"{A}.3")
    assert loads((tmp_path / FILE).read_bytes()) == Seen(MappingProxyType({A: Entry(3, 100)}), 1)
    now[0] = 150.0
    held.note(f"{A}.3")
    held.note(f"{A}.5")
    held.note(f"{B}.1")
    seen_lines = events(log, "policy_deployment_seen")
    assert seen_lines == [
        {"event": "policy_deployment_seen", "level": "info", "deployment": A[:8]},
        {"event": "policy_deployment_seen", "level": "warning", "deployment": B[:8]},
    ]
    held.note(f"{A}.2")
    held.note(f"{A}.2")
    held.note(f"{A}.4")
    assert events(log, "policy_revision_regressed") == [
        {
            "event": "policy_revision_regressed",
            "level": "critical",
            "deployment": A[:8],
            "seen": 5,
            "now": 2,
        },
        {
            "event": "policy_revision_regressed",
            "level": "critical",
            "deployment": A[:8],
            "seen": 5,
            "now": 4,
        },
    ]
    again = Witness.load(tmp_path)
    assert again.seen.report() == {A: 5, B: 1}
    assert again.seen.counted == 2
    assert again.seen.deployments[B] == Entry(1, 150)


def test_a_record_that_cant_be_written_holds_in_memory(
    tmp_path: Path, log: io.StringIO, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zoeymcp.common import files

    def refuse(path: Path, data: bytes, *, prefix: str) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(files, "write_atomic", refuse)
    held = Witness(tmp_path / FILE, wall=lambda: 1.0)
    held.note(f"{A}.7")
    assert held.seen.report() == {A: 7}
    assert events(log, "policy_seen_not_written") == [
        {"event": "policy_seen_not_written", "level": "warning", "error": "No space left on device"}
    ]
