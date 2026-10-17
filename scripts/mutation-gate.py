"""Report mutmut's results and fail below a minimum mutation score.

Usage: python scripts/mutation-gate.py STATS_JSON --min-score PERCENT
"""

from __future__ import annotations

import argparse
import json
import os
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("stats")
    parser.add_argument("--min-score", type=float, required=True)
    args = parser.parse_args()
    with open(args.stats, encoding="utf-8") as handle:
        stats = json.load(handle)
    tested = stats["killed"] + stats["survived"] + stats["timeout"] + stats["suspicious"]
    score = 100.0 * (stats["killed"] + stats["timeout"]) / tested if tested else 0.0
    lines = [
        "## Mutation testing",
        "",
        f"Score: **{score:.1f}%** (minimum {args.min_score:.1f}%)",
        "",
        "| killed | survived | timeout | suspicious | no tests | skipped | total |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        f"| {stats['killed']} | {stats['survived']} | {stats['timeout']} | {stats['suspicious']} "
        f"| {stats['no_tests']} | {stats['skipped']} | {stats['total']} |",
    ]
    report = "\n".join(lines)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(report + "\n")
    if tested == 0:
        print("no mutant was tested: the mutation run is broken", file=sys.stderr)
        return 1
    if stats.get("segfault"):
        print("mutation run had segfaults", file=sys.stderr)
        return 1
    return 0 if score >= args.min_score else 1


if __name__ == "__main__":
    sys.exit(main())
