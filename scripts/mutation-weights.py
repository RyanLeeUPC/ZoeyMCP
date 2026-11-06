"""Print mutation-shard.py's WEIGHTS and DIGIT_WEIGHTS tables from a mutation run's artifacts.

Usage: gh run download RUN_ID --pattern 'mutation-shard-*' --dir DIR
       python scripts/mutation-weights.py DIR

Each shard uploads mutmut's .meta files, which hold the test time of every mutant it ran. A
module's weight is the sum over its mutants, from the shards that ran them: a module cut by last
digit is run by several. A module with at least DIGIT_SHARE of the total also gets its weight per
last digit of the mutant number, so a cut module's digits are balanced by measured time.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

DIGIT_SHARE = 0.01


def by_digit(root: Path) -> dict[str, list[float]]:
    """Each module's test time per last digit of its mutant numbers, 0 to 9."""
    found: dict[str, list[float]] = {}
    seen: set[str] = set()
    for meta in sorted(root.rglob("*.meta")):
        durations = json.loads(meta.read_text(encoding="utf-8")).get("durations_by_key", {})
        if not durations:
            continue  # a module other shards ran
        for key in durations:
            if key in seen:
                raise ValueError(f"two shards ran {key}")
        seen.update(durations)
        src = next(parent for parent in meta.parents if parent.name == "src")
        module = ".".join(meta.relative_to(src).with_suffix("").with_suffix("").parts)
        digits = found.setdefault(module, [0.0] * 10)
        for key, seconds in durations.items():
            digits[int(key[-1])] += seconds
    return found


def weights(root: Path) -> dict[str, float]:
    return {module: sum(digits) for module, digits in by_digit(root).items()}


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    digits = by_digit(Path(sys.argv[1]))
    found = {module: sum(each) for module, each in digits.items()}
    order = sorted(found, key=lambda module: (-round(found[module]), module))
    print("WEIGHTS = {")
    for module in order:
        print(f'    "{module}": {max(1, round(found[module]))},')
    print("}")
    print("DIGIT_WEIGHTS = {")
    total = sum(found.values())
    for module in order:
        if found[module] >= DIGIT_SHARE * total:
            print(f'    "{module}": ({", ".join(str(round(s)) for s in digits[module])}),')
    print("}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
