"""Print mutation-shard.py's WEIGHTS table from a mutation run's shard artifacts.

Usage: gh run download RUN_ID --pattern 'mutation-shard-*' --dir DIR
       python scripts/mutation-weights.py DIR

Each shard uploads mutmut's .meta files, which hold the test time of every mutant it ran. A
module's weight is the sum over its mutants, from the shards that ran them: a module cut by last
digit is run by several.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def weights(root: Path) -> dict[str, float]:
    found: dict[str, float] = {}
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
        found[module] = found.get(module, 0.0) + sum(durations.values())
    return found


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    found = weights(Path(sys.argv[1]))
    print("WEIGHTS = {")
    for module, seconds in sorted(found.items(), key=lambda item: (-round(item[1]), item[0])):
        print(f'    "{module}": {max(1, round(seconds))},')
    print("}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
