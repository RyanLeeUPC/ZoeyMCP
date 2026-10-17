from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from zoeymcp.cli.main import EXIT_FINDINGS, EXIT_OK, EXIT_UNREADABLE, main

from .conftest import EXAMPLE_POLICY


def run(argv: list[str], stdin: str = "") -> tuple[int, str]:
    out = io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin), out=out)
    return code, out.getvalue()


def test_check_example_file() -> None:
    code, out = run(["check", "--config", str(EXAMPLE_POLICY)])
    assert code == EXIT_OK
    assert out.strip().endswith("ok (0 error(s), 0 warning(s))")


def test_check_from_stdin(example_text: str) -> None:
    code, out = run(["check", "--config", "-"], stdin=example_text)
    assert code == EXIT_OK
    assert out.startswith("<stdin>: ok")


def test_check_from_env(example_text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZOEYMCP_CONFIG", example_text)
    code, out = run(["check"])
    assert code == EXIT_OK
    assert out.startswith("$ZOEYMCP_CONFIG: ok")


def test_check_reports_errors_as_json(example_text: str) -> None:
    bad = example_text.replace(
        "callers: [gateway] # the gateway only", "callers: [{placeholder: ph-sandbox-0123456789}]"
    )
    code, out = run(["check", "--config", "-", "--format", "json"], stdin=bad)
    assert code == EXIT_FINDINGS
    report = json.loads(out)
    assert report["ok"] is False
    assert report["readable"] is True
    assert report["errors"] == 1
    assert report["findings"][0]["path"] == "routes[1].callers"


def test_schema_errors_exit_with_findings() -> None:
    code, out = run(["check", "--config", "-"], stdin="version: 1\n")
    assert code == EXIT_FINDINGS
    assert "mode: Field required" in out


def test_resolve_env_flag(example_text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    text = example_text.replace("secret: store:music-stats", "secret: env:ZMCP_TEST_STATS")
    monkeypatch.delenv("ZMCP_TEST_STATS", raising=False)
    assert run(["check", "--config", "-"], stdin=text)[0] == EXIT_OK
    code, out = run(["check", "--config", "-", "--resolve-env"], stdin=text)
    assert code == EXIT_FINDINGS
    assert "env var ZMCP_TEST_STATS is not set" in out


def test_missing_file_is_unreadable(tmp_path: Path) -> None:
    code, out = run(["check", "--config", str(tmp_path / "absent.yaml")])
    assert code == EXIT_UNREADABLE
    assert "can't read" in out


def test_no_policy_at_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZOEYMCP_CONFIG", raising=False)
    code, out = run(["check"])
    assert code == EXIT_UNREADABLE
    assert "no policy given" in out


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0
    assert capsys.readouterr().out.startswith("zoeymcp ")


def test_keygen_prints_a_matching_pair() -> None:
    from zoeymcp.vault.keys import KeySet

    code, out = run(["keygen"])
    assert code == EXIT_OK
    lines = dict(line.split("=", 1) for line in out.splitlines())
    assert set(lines) == {"ZOEYMCP_MASTER_KEY", "ZOEYMCP_GATEWAY_KEY"}
    assert (
        KeySet.from_text(lines["ZOEYMCP_MASTER_KEY"]).gateway_key(1) == lines["ZOEYMCP_GATEWAY_KEY"]
    )
    assert run(["keygen"])[1] != out
