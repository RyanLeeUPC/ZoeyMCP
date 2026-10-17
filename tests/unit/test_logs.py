from __future__ import annotations

import io
import json

import pytest

from zoeymcp.vault import logs
from zoeymcp.vault.store import Secret


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


def test_refuses_to_log_a_secret() -> None:
    with pytest.raises(TypeError, match="refusing to log a secret"):
        logs.event("oops", value=Secret("hunter2-hunter2"))
