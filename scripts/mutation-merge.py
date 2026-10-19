"""Merge the mutation shards' stats into one file for the gate.

Usage: python scripts/mutation-merge.py OUT_JSON SHARD_JSON...

Each shard's ``mutmut export-cicd-stats`` counts every mutant in ``total``, and only its own in
the outcome columns. So the merge sums the outcomes, takes ``total`` from the shards (they must
agree), and records ``not_checked``: mutants no shard ran (positive) or that two shards ran
(negative). The gate fails on either.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUTCOMES = ("killed", "survived", "timeout", "suspicious", "no_tests", "skipped", "segfault")


def merge(shards: list[dict[str, int]]) -> dict[str, int]:
    totals = {shard["total"] for shard in shards}
    if len(totals) != 1:
        raise ValueError(f"the shards disagree about the number of mutants: {sorted(totals)}")
    merged = {name: sum(int(shard.get(name, 0)) for shard in shards) for name in OUTCOMES}
    merged["total"] = totals.pop()
    merged["not_checked"] = merged["total"] - sum(merged[name] for name in OUTCOMES)
    merged["shards"] = len(shards)
    return merged


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    shards = [json.loads(Path(path).read_text(encoding="utf-8")) for path in sys.argv[2:]]
    merged = merge(shards)
    Path(sys.argv[1]).write_text(json.dumps(merged, indent=4) + "\n", encoding="utf-8")
    print(json.dumps(merged))
    return 0


if __name__ == "__main__":
    sys.exit(main())
