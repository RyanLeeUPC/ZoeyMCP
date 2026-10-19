"""The mutation workflow's scripts: shards cover every mutated module once, the merge counts each
mutant once from the shards' .meta files, and the gate fails a mutant no shard ran, a low overall
score and a module below its floor."""

from __future__ import annotations

import importlib.util
import json
import sys
from fnmatch import fnmatch
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from mutmut.stats import status_by_exit_code

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
weights = load("mutation-weights")


def test_the_module_list_comes_from_pyproject() -> None:
    found = shard.modules()
    assert "zoeymcp.common.policy.check" in found
    assert "zoeymcp.toolkit.rules" in found
    assert all(name.startswith("zoeymcp.") and "/" not in name for name in found)


def mutant_names(module: str) -> list[str]:
    """Names in mutmut's forms: functions, private functions and methods, numbered from 1."""
    bar = chr(0x01C1)  # mutmut's separator in method names
    stems = [f"{module}.x_send", f"{module}.x__reset", f"{module}.x{bar}Store{bar}open"]
    return [f"{stem}__mutmut_{number}" for stem in stems for number in range(1, 125)]


@pytest.mark.parametrize("count", [1, 2, 6, 8])
def test_every_mutant_is_in_exactly_one_shard(count: int) -> None:
    groups = shard.shards(shard.modules(), count)
    patterns = [[part.pattern() for part in group] for group in groups]
    for module in shard.modules():
        for name in mutant_names(module):
            hits = [i for i, group in enumerate(patterns) if any(fnmatch(name, p) for p in group)]
            assert len(hits) == 1, (name, hits)
    assert shard.shards(shard.modules(), count) == groups  # deterministic


def test_a_heavy_module_is_cut_by_last_digit() -> None:
    cut = [p for p in shard.parts(shard.modules(), 6) if p.module == "zoeymcp.common.policy.check"]
    assert len(cut) > 1
    assert "".join(p.digits for p in cut) == shard.DIGITS
    assert cut[0].pattern() == f"zoeymcp.common.policy.check.*__mutmut_*[{cut[0].digits}]"
    assert sum(p.weight for p in cut) == pytest.approx(shard.WEIGHTS["zoeymcp.common.policy.check"])
    whole = [p for p in shard.parts(shard.modules(), 6) if p.module == "zoeymcp.toolkit.plan"]
    assert [p.pattern() for p in whole] == ["zoeymcp.toolkit.plan.*"]


def test_the_weights_name_real_modules() -> None:
    assert set(shard.WEIGHTS) <= set(shard.modules())


def test_six_shards_are_balanced() -> None:
    loads = [sum(part.weight for part in group) for group in shard.shards(shard.modules(), 6)]
    assert max(loads) < 1.05 * min(loads)


def test_the_cli_prints_patterns(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sys, "argv", ["mutation-shard.py", "--shard", "0", "--of", "6"])
    assert shard.main() == 0
    patterns = capsys.readouterr().out.split()
    assert patterns
    assert all(p.startswith("zoeymcp.") for p in patterns)
    monkeypatch.setattr(sys, "argv", ["mutation-shard.py", "--shard", "6", "--of", "6"])
    assert shard.main() == 2


def write_meta(
    root: Path,
    shard_dir: str,
    module: str,
    codes: dict[str, int | None],
    durations: dict[str, float] | None = None,
) -> None:
    """A .meta file where download-artifact puts it: SHARDS_DIR/<artifact>/mutants/src/..."""
    path = root / shard_dir / "mutants" / "src" / (module.replace(".", "/") + ".py.meta")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"exit_code_by_key": codes, "durations_by_key": durations or {}}
    path.write_text(json.dumps(data), encoding="utf-8")


def test_weights_come_from_the_shard_that_ran_each_module(tmp_path: Path) -> None:
    def meta(shard_dir: str, module: str, durations: dict[str, float]) -> None:
        write_meta(tmp_path, shard_dir, module, dict.fromkeys(durations, 1), durations)

    meta("mutation-shard-0", "zoeymcp.vault.peer", {"a__mutmut_1": 1.5, "a__mutmut_2": 2.0})
    meta("mutation-shard-0", "zoeymcp.vault.store", {"b__mutmut_2": 0.5})
    meta("mutation-shard-1", "zoeymcp.vault.store", {"b__mutmut_1": 4.0})
    meta("mutation-shard-1", "zoeymcp.vault.peer", {})
    assert weights.weights(tmp_path) == {"zoeymcp.vault.peer": 3.5, "zoeymcp.vault.store": 4.5}
    meta("mutation-shard-2", "zoeymcp.vault.store", {"b__mutmut_1": 4.0})
    with pytest.raises(ValueError, match="two shards ran b__mutmut_1"):
        weights.weights(tmp_path)


def test_the_merge_has_mutmuts_exit_code_table() -> None:
    assert dict(status_by_exit_code) == merge.STATUS_BY_EXIT_CODE
    assert status_by_exit_code.default_factory is not None
    assert status_by_exit_code.default_factory() == merge.OTHER_STATUS
    assert set(merge.OUTCOMES) < {name.replace(" ", "_") for name in status_by_exit_code.values()}


def test_a_split_module_counts_each_mutant_once(tmp_path: Path) -> None:
    key = [f"zoeymcp.vault.store.x_open__mutmut_{number}" for number in range(1, 5)]
    first = {key[0]: 1, key[1]: 0, key[2]: None, key[3]: None}
    write_meta(tmp_path, "mutation-shard-0", "zoeymcp.vault.store", first, {key[0]: 2, key[1]: 1})
    second = {key[0]: None, key[1]: None, key[2]: -24, key[3]: 33}
    write_meta(tmp_path, "mutation-shard-1", "zoeymcp.vault.store", second, {key[2]: 4.0})
    write_meta(tmp_path, "mutation-shard-0", "zoeymcp.vault.peer", {"p__mutmut_1": None})
    write_meta(tmp_path, "mutation-shard-1", "zoeymcp.vault.peer", {"p__mutmut_1": 1})
    merged = merge.merge(tmp_path)
    store = merged["modules"]["zoeymcp.vault.store"]
    assert (store["killed"], store["survived"], store["timeout"], store["no_tests"]) == (1, 1, 1, 1)
    assert (store["total"], store["not_checked"]) == (4, 0)
    assert merged["modules"]["zoeymcp.vault.peer"]["killed"] == 1
    assert (merged["killed"], merged["total"], merged["not_checked"]) == (2, 5, 0)
    assert merged["seconds_by_shard"] == {"mutation-shard-0": 3.0, "mutation-shard-1": 4.0}
    assert merged["shards"] == 2


def test_a_mutant_no_shard_ran_is_not_checked(tmp_path: Path) -> None:
    write_meta(tmp_path, "mutation-shard-0", "zoeymcp.vault.peer", {"a": 1, "b": None})
    write_meta(tmp_path, "mutation-shard-1", "zoeymcp.vault.peer", {"a": None, "b": None})
    assert merge.merge(tmp_path)["not_checked"] == 1


def test_a_mutant_two_shards_report_fails(tmp_path: Path) -> None:
    write_meta(tmp_path, "mutation-shard-0", "zoeymcp.vault.peer", {"a": 1, "b": None})
    write_meta(tmp_path, "mutation-shard-1", "zoeymcp.vault.peer", {"a": 0, "b": 1})
    with pytest.raises(ValueError, match=r"two shards report a$"):
        merge.merge(tmp_path)
    with pytest.raises(ValueError, match=r"no \.meta files"):
        merge.merge(tmp_path / "empty")


def test_the_merge_cli_writes_the_stats(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    write_meta(tmp_path, "mutation-shard-0", "zoeymcp.vault.peer", {"a": 1}, {"a": 2.4})
    out = tmp_path / "merged.json"
    monkeypatch.setattr(sys, "argv", ["mutation-merge.py", str(out), str(tmp_path)])
    assert merge.main() == 0
    assert json.loads(out.read_text(encoding="utf-8"))["modules"]["zoeymcp.vault.peer"]["killed"]
    assert "mutation-shard-0: 2 s of test time" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["mutation-merge.py", str(out)])
    assert merge.main() == 2


def stats(**modules: dict[str, int]) -> dict[str, Any]:
    """Merged stats of ten mutants a module, named with "_" for "."."""
    by_module = {}
    for name, counts in modules.items():
        found = {**dict.fromkeys(merge.OUTCOMES, 0), "total": 10, **counts}
        found["not_checked"] = found["total"] - sum(found[n] for n in merge.OUTCOMES)
        by_module[name.replace("_", ".")] = found
    columns = (*merge.OUTCOMES, "total", "not_checked")
    return {**{n: sum(m[n] for m in by_module.values()) for n in columns}, "modules": by_module}


def run_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, data: dict[str, Any], floors: str = ""
) -> int:
    path = tmp_path / "merged.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(f"[tool.zoeymcp.mutation-floors]\n{floors}\n", encoding="utf-8")
    argv = ["mutation-gate.py", str(path), "--min-score", "89", "--pyproject", str(pyproject)]
    monkeypatch.setattr(sys, "argv", argv)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    result: int = gate.main()
    return result


def test_the_gate_needs_every_mutant_run_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    full = stats(a_x={"killed": 9, "survived": 1})
    assert run_gate(tmp_path, monkeypatch, full) == 0
    missing = stats(a_x={"killed": 8, "survived": 1})
    assert run_gate(tmp_path, monkeypatch, missing) == 1
    low = stats(a_x={"killed": 8, "survived": 2})
    assert run_gate(tmp_path, monkeypatch, low) == 1
    untested = stats(a_x={"no_tests": 10})
    assert run_gate(tmp_path, monkeypatch, untested) == 1


def test_a_module_below_its_floor_fails_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = stats(a_x={"killed": 10}, a_y={"killed": 10}, b_z={"killed": 8, "survived": 2})
    assert run_gate(tmp_path, monkeypatch, data) == 0  # 93.3% overall
    assert run_gate(tmp_path, monkeypatch, data, '"a.*" = 90') == 0
    assert run_gate(tmp_path, monkeypatch, data, '"b.z" = 80') == 0
    assert run_gate(tmp_path, monkeypatch, data, '"b.*" = 90') == 1
    assert run_gate(tmp_path, monkeypatch, data, '"*" = 80\n"b.z" = 90') == 1
    assert run_gate(tmp_path, monkeypatch, data, '"c.*" = 90') == 1  # matches no module


def test_the_repository_floors_parse() -> None:
    found = gate.floors(gate.ROOT / "pyproject.toml")
    assert all(0 < percent <= 100 for percent in found.values())
