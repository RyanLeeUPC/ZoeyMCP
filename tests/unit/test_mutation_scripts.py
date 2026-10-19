"""The mutation workflow's scripts: shards cover every mutated module once, and the merged stats
fail the gate when a mutant ran in no shard or in two."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"


def load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SCRIPTS / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


shard = load("mutation-shard")
merge = load("mutation-merge")
gate = load("mutation-gate")


def test_the_module_list_comes_from_pyproject() -> None:
    found = shard.modules()
    assert "zoeymcp.common.policy.check" in found
    assert "zoeymcp.toolkit.rules" in found
    assert all(name.startswith("zoeymcp.") and "/" not in name for name in found)


@pytest.mark.parametrize("count", [1, 2, 6, 8])
def test_every_module_is_in_exactly_one_shard(count: int) -> None:
    groups = shard.shards(shard.modules(), count)
    flat = [name for group in groups for name in group]
    assert sorted(flat) == sorted(shard.modules())
    assert len(flat) == len(set(flat))
    assert shard.shards(shard.modules(), count) == groups  # deterministic


def test_the_weights_name_real_modules() -> None:
    assert set(shard.WEIGHTS) <= set(shard.modules())


def test_six_shards_are_balanced() -> None:
    loads = [
        sum(shard.WEIGHTS.get(n, shard.DEFAULT_WEIGHT) for n in group)
        for group in shard.shards(shard.modules(), 6)
    ]
    assert max(loads) < 1.1 * min(loads)


def test_the_cli_prints_patterns(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["mutation-shard.py", "--shard", "0", "--of", "6"])
    assert shard.main() == 0
    patterns = capsys.readouterr().out.split()
    assert patterns
    assert all(p.endswith(".*") for p in patterns)
    monkeypatch.setattr(sys, "argv", ["mutation-shard.py", "--shard", "6", "--of", "6"])
    assert shard.main() == 2


def stats(**counts: int) -> dict[str, Any]:
    base = dict.fromkeys(merge.OUTCOMES, 0)
    return {**base, "total": 10, **counts}


def test_merge_sums_and_finds_what_no_shard_ran() -> None:
    merged = merge.merge([stats(killed=4, survived=1), stats(killed=3, timeout=1)])
    assert (merged["killed"], merged["survived"], merged["timeout"]) == (7, 1, 1)
    assert merged["not_checked"] == 1
    merged = merge.merge([stats(killed=6), stats(killed=6)])
    assert merged["not_checked"] == -2
    with pytest.raises(ValueError, match="disagree"):
        merge.merge([stats(), {**stats(), "total": 11}])


def run_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data: dict[str, Any]) -> int:
    path = tmp_path / "merged.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["mutation-gate.py", str(path), "--min-score", "89"])
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    result: int = gate.main()
    return result


def test_the_gate_needs_every_mutant_run_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    full = merge.merge([stats(killed=9, survived=1)])
    assert run_gate(tmp_path, monkeypatch, full) == 0
    missing = merge.merge([stats(killed=8, survived=1)])
    assert run_gate(tmp_path, monkeypatch, missing) == 1
    twice = merge.merge([stats(killed=9, survived=1), stats(killed=1)])
    assert run_gate(tmp_path, monkeypatch, twice) == 1
    low = merge.merge([stats(killed=8, survived=2)])
    assert run_gate(tmp_path, monkeypatch, low) == 1
