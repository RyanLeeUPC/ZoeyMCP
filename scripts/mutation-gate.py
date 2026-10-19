"""Report mutmut's results and fail below a minimum mutation score, overall or per module.

Usage: python scripts/mutation-gate.py STATS_JSON --min-score PERCENT [--pyproject PATH]

STATS_JSON is mutation-merge.py's output. The per-module floors are pyproject.toml's
``[tool.zoeymcp.mutation-floors]``: a glob over dotted module names to a percentage, like
``"zoeymcp.portal.*" = 90``. A module must reach every floor whose glob matches it, and a floor
that matches no module fails, so a renamed module can't drop its floor unnoticed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tomllib
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def floors(pyproject: Path) -> dict[str, float]:
    with pyproject.open("rb") as handle:
        table = tomllib.load(handle).get("tool", {}).get("zoeymcp", {})
    return {glob: float(percent) for glob, percent in table.get("mutation-floors", {}).items()}


def score(stats: dict[str, Any]) -> tuple[int, float]:
    """The mutants tested, and the percentage killed (a timeout counts as a kill)."""
    tested: int = stats["killed"] + stats["survived"] + stats["timeout"] + stats["suspicious"]
    return tested, 100.0 * (stats["killed"] + stats["timeout"]) / tested if tested else 0.0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stats")
    parser.add_argument("--min-score", type=float, required=True)
    parser.add_argument("--pyproject", type=Path, default=ROOT / "pyproject.toml")
    args = parser.parse_args()
    with open(args.stats, encoding="utf-8") as handle:
        stats = json.load(handle)
    tested, overall = score(stats)
    modules: dict[str, dict[str, Any]] = stats["modules"]
    floor_by_module: dict[str, float] = {}
    unmatched = []
    for glob, percent in floors(args.pyproject).items():
        matched = [name for name in modules if fnmatchcase(name, glob)]
        if not matched:
            unmatched.append(glob)
        for name in matched:
            floor_by_module[name] = max(percent, floor_by_module.get(name, 0.0))
    lines = [
        "## Mutation testing",
        "",
        f"Score: **{overall:.1f}%** (minimum {args.min_score:.1f}%)",
        "",
        "| killed | survived | timeout | suspicious | no tests | skipped | total |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        f"| {stats['killed']} | {stats['survived']} | {stats['timeout']} | {stats['suspicious']} "
        f"| {stats['no_tests']} | {stats['skipped']} | {stats['total']} |",
        "",
        "| module | score | floor | killed | survived | timeout | no tests | total |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    below = []
    for name, counts in sorted(modules.items()):
        module_score = score(counts)[1]
        floor = floor_by_module.get(name)
        if floor is not None and module_score < floor:
            below.append(f"{name}: {module_score:.1f}% is below its floor of {floor:.1f}%")
        lines.append(
            f"| {name} | {module_score:.1f}% | {'' if floor is None else f'{floor:.1f}%'} "
            f"| {counts['killed']} | {counts['survived']} | {counts['timeout']} "
            f"| {counts['no_tests']} | {counts['total']} |"
        )
    report = "\n".join(lines)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(report + "\n")
    if tested == 0:
        print("no mutant was tested: the mutation run is broken", file=sys.stderr)
        return 1
    if stats["not_checked"]:
        print(
            f"{stats['not_checked']} mutant(s) have no result: the shards don't cover the modules",
            file=sys.stderr,
        )
        return 1
    if stats.get("segfault"):
        print("mutation run had segfaults", file=sys.stderr)
        return 1
    for glob in unmatched:
        print(f"the mutation floor {glob!r} matches no module", file=sys.stderr)
    for line in below:
        print(line, file=sys.stderr)
    if unmatched or below:
        return 1
    return 0 if overall >= args.min_score else 1


if __name__ == "__main__":
    sys.exit(main())
