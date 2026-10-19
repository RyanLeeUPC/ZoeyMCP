"""The example records toolkit: one prompt per batch, per-item results, read-back, no delete."""

from __future__ import annotations

import json
from typing import Any

import pytest
from example_toolkits.records import toolkit

from zoeymcp.toolkit import VaultError
from zoeymcp.toolkit.testing import FakeSlot, load_problems, run

APPROVED = ("/v1/records/batch", "/v1/records/archive")
pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def records(n: int) -> list[dict[str, Any]]:
    return [{"title": f"t{i}", "amount": i, "day": "2026-01-0" + str(i + 1)} for i in range(n)]


def test_the_gateway_would_load_it() -> None:
    assert load_problems(toolkit) == {}
    assert sorted(toolkit.tools) == ["add_records", "archive_records", "get_records"]
    assert [t.consequential for _, t in sorted(toolkit.tools.items())] == [True, True, False]


async def test_reads_are_one_call_per_batch() -> None:
    db = FakeSlot(get={"/v1/records/a": {"id": "a"}}, approved=APPROVED)
    out = await run(toolkit, "get_records", {"ids": ["a", "b"]}, slots={"db": db})
    assert out.prompt is None  # routine: never asked
    assert json.loads(out.text) == {
        "ok": 1,
        "failed": 1,
        "items": [
            {"index": 0, "ok": True, "value": {"id": "a"}},
            {"index": 1, "ok": False, "error": "vault answered 404"},
        ],
    }


async def test_an_id_stays_one_segment() -> None:
    out = await run(toolkit, "get_records", {"ids": [".."]}, slots={"db": FakeSlot()})
    assert out.text == "arguments refused: at /ids/0: text_rules"


async def test_a_batch_is_one_prompt_and_each_record_is_read_back() -> None:
    db = FakeSlot(
        get={
            "/v1/records/r1": {"id": "r1", "title": "t0", "amount": 0, "day": "2026-01-01"},
            "/v1/records/r3": {
                "id": "r3",
                "title": "t2 (changed)",
                "amount": 2,
                "day": "2026-01-03",
            },
        },
        answer={
            "/v1/records/batch": {
                "created": [
                    {"index": 0, "id": "r1"},
                    {"index": 1, "error": "refused"},
                    {"index": 2, "id": "r3"},
                ]
            }
        },
        approved=APPROVED,
    )
    out = await run(toolkit, "add_records", {"records": records(3)}, slots={"db": db})
    assert out.prompt is not None
    assert out.prompt.count("Approval request") == 1
    assert "Add 3 records\n" in out.prompt
    assert "Records (3):\n" in out.prompt
    assert db.sent == [("POST", "/v1/records/batch", {"records": records(3)})]
    assert json.loads(out.text)["items"] == [
        {"index": 0, "ok": True, "value": "r1"},
        {"index": 1, "ok": False, "error": "refused by the records API"},
        {"index": 2, "ok": False, "error": "read-back differs", "value": "r3"},
    ]


async def test_read_back_failures_and_missing_answers() -> None:
    db = FakeSlot(
        fail={"/v1/records/r1": VaultError(502, "upstream_down")},
        answer={"/v1/records/batch": {"created": [{"index": 0, "id": "r1"}]}},
        approved=APPROVED,
    )
    out = await run(toolkit, "add_records", {"records": records(2)}, slots={"db": db})
    assert json.loads(out.text)["items"] == [
        {"index": 0, "ok": False, "error": "read-back failed (upstream_down)"},
        {"index": 1, "ok": False, "error": "no answer for this record"},
    ]


async def test_a_declined_batch_sends_nothing() -> None:
    db = FakeSlot(approved=APPROVED)
    out = await run(
        toolkit, "add_records", {"records": records(2)}, slots={"db": db}, answer="decline"
    )
    assert out.is_error
    assert db.sent == []


async def test_archive_never_deletes() -> None:
    db = FakeSlot(answer={"/v1/records/archive": {"archived": 2}}, approved=APPROVED)
    out = await run(toolkit, "archive_records", {"ids": ["r1", "r2"]}, slots={"db": db})
    assert out.prompt is not None
    assert 'Ids: ["r1","r2"]\n' in out.prompt
    assert db.sent == [("POST", "/v1/records/archive", {"ids": ["r1", "r2"]})]
    assert out.text == "archived 2 of 2"
    assert all(method != "DELETE" for method, _, _ in db.sent)


async def test_a_batch_over_its_limit_is_refused() -> None:
    out = await run(toolkit, "add_records", {"records": records(1) * 26}, slots={"db": FakeSlot()})
    assert out.text == "arguments refused: at /records: batch_size"
