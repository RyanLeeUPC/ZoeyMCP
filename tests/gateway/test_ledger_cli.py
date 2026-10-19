"""``zoeymcp ledger`` and the gateway admin socket's ledger endpoints (M4 design F.4)."""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import httpx
import pytest

from tests.gateway.test_ledger import REF_A, REF_B, Clock, call
from zoeymcp.cli import admin_client
from zoeymcp.cli import ledger as ledger_view
from zoeymcp.cli.main import main
from zoeymcp.gateway.ledger import LEDGER_DIR, Ledger
from zoeymcp.gateway.server import AdminApp


def built(tmp_path: Path) -> Ledger:
    ledger, _ = Ledger.open_at(tmp_path, max_bytes=2**26, clock=Clock())

    async def fill() -> None:
        await call(ledger, REF_A, args={"subject": "Hi"}, client="agent1")
        await call(ledger, REF_B, decision="decline", outcome="not_sent", client="agent2")

    anyio.run(fill)
    return ledger


def admin_for(ledger: Ledger | None) -> AdminApp:
    return AdminApp(SimpleNamespace(ledger=ledger))  # type: ignore[arg-type]


def answer(
    admin: AdminApp, method: str, path: str, query: str = "", body: bytes = b""
) -> tuple[int, dict[str, Any]]:
    return anyio.run(admin.answer, method, path, query, body)


def run(monkeypatch: pytest.MonkeyPatch, admin: AdminApp, *argv: str) -> tuple[int, str, str]:
    seen: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        path, _, query = request.url.raw_path.decode().partition("?")
        seen.append(request.url.raw_path.decode())
        code, data = answer(admin, request.method, path, query, request.content)
        return httpx.Response(code, json=data)

    monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(handle))
    out, err = io.StringIO(), io.StringIO()
    code = main(["ledger", *argv], stdin=io.StringIO(), out=out, err=err)
    run.seen = seen  # type: ignore[attr-defined]
    return code, out.getvalue(), err.getvalue()


# --- the admin endpoints ------------------------------------------------------------------------


def test_the_endpoints(tmp_path: Path) -> None:
    admin = admin_for(built(tmp_path))
    code, data = answer(admin, "GET", "/ledger")
    assert code == 200
    assert [r["seq"] for r in data["records"]] == list(range(6))
    assert data["head_seq"] == 5
    code, data = answer(admin, "GET", "/ledger", "client=agent2&after=-1&limit=10")
    assert {r["ref"] for r in data["records"]} == {REF_B}
    assert answer(admin, "POST", "/ledger/verify")[1]["ok"] is True
    body = json.dumps({"ref": REF_A, "args": {"subject": "Hi"}}).encode()
    assert answer(admin, "POST", "/ledger/check", body=body)[1]["matches"] is True


@pytest.mark.parametrize(
    ("method", "path", "query", "body", "code"),
    [
        ("GET", "/ledger", "after=x", b"", 400),
        ("GET", "/ledger", "client=a%20b", b"", 400),
        ("GET", "/ledger", "secret=1", b"", 400),
        ("POST", "/ledger", "", b"", 405),
        ("GET", "/ledger/verify", "", b"", 405),
        ("POST", "/ledger/nope", "", b"", 404),
        ("POST", "/ledger/check", "", b"not json", 400),
        ("POST", "/ledger/check", "", b'{"ref": "x", "args": {}}', 400),
        ("POST", "/ledger/check", "", b'{"ref": "000000000000000a"}', 400),
        ("POST", "/ledger/check", "", b"[]", 400),
    ],
)
def test_bad_requests(
    tmp_path: Path, method: str, path: str, query: str, body: bytes, code: int
) -> None:
    admin = admin_for(built(tmp_path))
    assert answer(admin, method, path, query, body)[0] == code


def test_no_ledger_is_a_503() -> None:
    assert answer(admin_for(None), "GET", "/ledger") == (503, {"error": "no approval ledger"})


# --- the CLI ------------------------------------------------------------------------------------


def test_one_line_per_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, out, err = run(monkeypatch, admin_for(built(tmp_path)))
    assert (code, err) == (0, "")
    first, second = out.splitlines()
    assert first.endswith(f"{REF_A} agent1 mail/send_note legacy accept ok")
    assert second.endswith(f"{REF_B} agent2 mail/send_note legacy decline not_sent")
    assert first.startswith("2026-01-01 ")


def test_filters_go_to_the_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, out, _ = run(
        monkeypatch, admin_for(built(tmp_path)), "--client", "agent2", "--tool", "send_note"
    )
    assert code == 0
    assert [line.split()[2] for line in out.splitlines()] == [REF_B]
    assert "client=agent2" in run.seen[0]  # type: ignore[attr-defined]
    assert "tool=send_note" in run.seen[0]  # type: ignore[attr-defined]


def test_json_output_is_the_records(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, out, _ = run(monkeypatch, admin_for(built(tmp_path)), "--format", "json")
    assert code == 0
    assert out.isascii()
    records = [json.loads(line) for line in out.splitlines()]
    assert [r["seq"] for r in records] == list(range(6))
    assert records[0]["args"].startswith("hmac-sha256:")


def test_since(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = admin_for(built(tmp_path))
    assert run(monkeypatch, admin, "--since", "1d")[1] == ""  # the clock says 2026-01-01
    assert run(monkeypatch, admin, "--since", "999999d")[1].count("\n") == 2
    code, _, err = run(monkeypatch, admin, "--since", "week")
    assert (code, err) == (2, "zoeymcp ledger: --since takes a number and m, h or d, like 7d\n")


def test_verify(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = built(tmp_path)
    code, out, _ = run(monkeypatch, admin_for(ledger), "--verify")
    assert code == 0
    assert out.startswith("ok: 6 records chain; head seq 5, hash sha256:")
    newest = tmp_path / LEDGER_DIR / "000000000000.jsonl"
    lines = newest.read_bytes().splitlines(keepends=True)
    newest.write_bytes(b"".join(lines[:2] + lines[3:]))
    code, out, _ = run(monkeypatch, admin_for(ledger), "--verify")
    assert code == 1
    assert out.startswith("broken at seq 3: 2 records chain before it")


def test_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    admin = admin_for(built(tmp_path))
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"subject": "Hi"}), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"subject": "Hello"}), encoding="utf-8")
    assert run(monkeypatch, admin, "check", REF_A, str(good)) == (
        0,
        f"{REF_A}: the call had exactly these arguments\n",
        "",
    )
    assert run(monkeypatch, admin, "check", REF_A, str(bad))[0] == 1
    code, out, _ = run(monkeypatch, admin, "check", "00000000000000ff", str(good))
    assert (code, out) == (1, "00000000000000ff: no asked record (pruned, or never asked)\n")
    assert run(monkeypatch, admin, "check", REF_A)[0] == 2
    assert run(monkeypatch, admin, "check", REF_A, str(tmp_path / "missing.json"))[0] == 2
    code, _, err = run(monkeypatch, admin, REF_A)  # a REF without check
    assert (code, err) == (2, "zoeymcp ledger: the only action is 'check REF FILE'\n")


def test_an_unreachable_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    code, _, err = run(monkeypatch, admin_for(None))
    assert code == 2
    assert err == "zoeymcp ledger: no approval ledger\n"


def test_pages_are_followed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(admin_client, "LEDGER_PAGE", 2)
    code, out, _ = run(monkeypatch, admin_for(built(tmp_path)), "--format", "json")
    assert code == 0
    assert len(out.splitlines()) == 6
    assert len(run.seen) == 4  # type: ignore[attr-defined]  # 2 + 2 + 2, then an empty page


def test_ledger_level_records_get_their_own_line() -> None:
    records = [
        {
            "v": 1,
            "seq": 0,
            "prev": "x",
            "ts": 1_767_225_600_000,
            "ref": None,
            "kind": "recovered",
            "writer": "gateway",
            "abandoned": 1,
            "not_sent": 1,
            "unknown": 0,
        },
    ]
    assert ledger_view.lines(records) == [
        "2026-01-01 00:00:00Z ledger recovered abandoned=1 not_sent=1 unknown=0"
    ]
