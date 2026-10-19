"""Print the diff of every surviving mutant, in one process.

Usage: python scripts/mutation-diffs.py  (from the project root, after ``mutmut run``)

``mutmut show`` starts a new interpreter per mutant, which took minutes for a few hundred
survivors; this reads mutmut's own results and diffs once.
"""

from __future__ import annotations

import sys
from pathlib import Path

from mutmut.__main__ import (  # mutmut 3.8's own helpers: the CI job pins the version
    SourceFileMutationData,
    get_diff_for_mutant,
    status_by_exit_code,
    walk_mutatable_files,
)


def main() -> int:
    shown = 0
    for path in walk_mutatable_files():
        if not (Path("mutants") / (str(path) + ".meta")).exists():
            continue
        data = SourceFileMutationData(path=path)
        data.load()
        for name, code in sorted(data.exit_code_by_key.items()):
            if code is None or status_by_exit_code[code] != "survived":
                continue
            print(f"# {name}: survived")
            print(get_diff_for_mutant(name, path=path))
            shown += 1
    print(f"{shown} surviving mutant(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
