"""Merge the mutation shards' results into overall and per-module counts for the gate.

Usage: python scripts/mutation-merge.py OUT_JSON SHARDS_DIR

SHARDS_DIR holds the downloaded shard artifacts, one directory each, with mutmut's .meta files
under ``mutants/src``. Every shard's .meta lists every mutant of its module: an exit code for the
mutants the shard ran, ``None`` for the rest. So the merge takes each mutant's one exit code
across the shards, and fails if two shards report one. ``not_checked`` counts the mutants with no
outcome, chiefly those no shard ran; the gate fails on any. The gate job runs on the runner's own
Python with nothing installed, so the exit-code table is a copy of mutmut's, which a unit test
checks.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

OUTCOMES = ("killed", "survived", "timeout", "suspicious", "no_tests", "skipped", "segfault")
# mutmut 3.8.0's mutmut.stats.status_by_exit_code, a defaultdict: any other code is suspicious.
STATUS_BY_EXIT_CODE: dict[int | None, str] = {
    1: "killed",
    3: "killed",
    0: "survived",
    5: "no tests",
    2: "check was interrupted by user",
    None: "not checked",
    33: "no tests",
    34: "skipped",
    35: "suspicious",
    36: "timeout",
    37: "caught by type check",
    -24: "timeout",
    24: "timeout",
    152: "timeout",
    255: "timeout",
    -11: "segfault",
    -9: "segfault",
}
OTHER_STATUS = "suspicious"


def module_of(meta: Path) -> str:
    """The dotted module a .meta file belongs to, like ``zoeymcp.vault.request``."""
    src = next(parent for parent in meta.parents if parent.name == "src")
    return ".".join(meta.relative_to(src).with_suffix("").with_suffix("").parts)


def counts(codes: list[int | None]) -> dict[str, int]:
    found = dict.fromkeys(OUTCOMES, 0)
    for code in codes:
        name = STATUS_BY_EXIT_CODE.get(code, OTHER_STATUS).replace(" ", "_")
        if name in found:
            found[name] += 1
    found["total"] = len(codes)
    found["not_checked"] = found["total"] - sum(found[name] for name in OUTCOMES)
    return found


def merge(root: Path) -> dict[str, Any]:
    codes: dict[str, dict[str, int | None]] = {}
    seconds: dict[str, float] = {}
    for meta in sorted(root.rglob("*.meta")):
        shard = meta.relative_to(root).parts[0]
        data = json.loads(meta.read_text(encoding="utf-8"))
        seconds[shard] = seconds.get(shard, 0.0) + sum(data.get("durations_by_key", {}).values())
        merged = codes.setdefault(module_of(meta), {})
        for key, code in data["exit_code_by_key"].items():
            if code is None:
                merged.setdefault(key, None)
            elif merged.get(key) is not None:
                raise ValueError(f"two shards report {key}")
            else:
                merged[key] = code
    if not codes:
        raise ValueError(f"no .meta files under {root}")
    return {
        **counts([code for module in codes.values() for code in module.values()]),
        "shards": len(seconds),
        "seconds_by_shard": seconds,
        "modules": {name: counts(list(module.values())) for name, module in codes.items()},
    }


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    merged = merge(Path(sys.argv[2]))
    Path(sys.argv[1]).write_text(json.dumps(merged, indent=4) + "\n", encoding="utf-8")
    for shard, seconds in merged["seconds_by_shard"].items():
        print(f"{shard}: {round(seconds)} s of test time")
    print(json.dumps({name: merged[name] for name in (*OUTCOMES, "total", "not_checked")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
