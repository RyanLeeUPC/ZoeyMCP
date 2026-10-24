"""The required Windows portal job runs every portal module's unit tests (D-203; M6 design O.7).

``.github/workflows/ci.yml``'s ``portal-windows`` job runs ``tests/portal`` and a hand-kept list
of unit files. A new portal module's unit test left off the list never runs on Windows and
nothing fails (M7's ``test_mutation_gaps_5.py`` slipped once). So: for each
``zoeymcp/portal/<m>.py`` in mutmut's ``only_mutate``, ``tests/unit/test_<m>.py`` is in the job's
command, and every file the command names exists. A rule by imports would be wrong: about 13 unit
files import ``zoeymcp.portal`` and are Linux-only on purpose.

``test_mutation_gaps_6.py`` is left out on purpose (recorded in :data:`LEFT_OUT`): it kills
mutants of M7's modules, mostly outside the portal (the bridge, health, the store, onboarding),
and the one portal module among them, ``reviewview``, has ``test_reviewview.py`` on the list.

The repository's own files are read, so mutmut skips this file (``pytest_add_cli_args``), as it
skips the other checks of the repository itself.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
PORTAL = re.compile(r"\*zoeymcp/portal/([a-z_]+)\.py")
# Unit files that import zoeymcp.portal and stay off the Windows job, each with why.
LEFT_OUT = {
    "test_mutation_gaps_6.py": (
        "M7's survivors, mostly outside the portal; reviewview's own tests are on the list"
    ),
}


def windows_command() -> str:
    """The portal-windows job's pytest command."""
    jobs: dict[str, Any] = yaml.safe_load(WORKFLOW.read_bytes())["jobs"]
    steps = jobs["portal-windows"]["steps"]
    [command] = [
        str(step["run"]) for step in steps if "pytest tests/portal" in str(step.get("run", ""))
    ]
    return command


def listed(command: str) -> list[str]:
    """The test files the command names, as paths from the repository's root."""
    return re.findall(r"tests/[a-z0-9_/]+\.py", command)


def only_mutate() -> list[str]:
    data = tomllib.loads((ROOT / "pyproject.toml").read_bytes().decode("utf-8"))
    patterns: list[str] = data["tool"]["mutmut"]["only_mutate"]
    return patterns


def missing(patterns: Iterable[str], files: Iterable[str]) -> list[str]:
    """Each mutated portal module's unit test the list doesn't name."""
    named = set(files)
    wanted = [f"tests/unit/test_{m}.py" for p in patterns for m in PORTAL.findall(p)]
    return [path for path in wanted if path not in named]


def test_the_guard_catches_what_it_is_for() -> None:
    patterns = ["*zoeymcp/portal/routes.py", "*zoeymcp/portal/drafts.py", "*zoeymcp/vault/x.py"]
    files = ["tests/unit/test_routes.py", "tests/unit/test_x.py"]
    assert missing(patterns, files) == ["tests/unit/test_drafts.py"]
    assert listed("pytest tests/portal\n  tests/unit/test_a.py tests/fakes/test_b.py") == [
        "tests/unit/test_a.py",
        "tests/fakes/test_b.py",
    ]
    # A file with a digit in its name is one too (test_mutation_gaps_5.py is on the list).
    gaps = "pytest tests/portal tests/unit/test_mutation_gaps_5.py"
    assert listed(gaps) == ["tests/unit/test_mutation_gaps_5.py"]


def test_every_mutated_portal_module_has_its_tests_on_windows() -> None:
    command = windows_command()
    assert command.startswith("uv run --locked pytest tests/portal")
    files = listed(command)
    portal = [p for p in only_mutate() if PORTAL.fullmatch(p)]
    assert len(portal) >= 13  # the thirteen of M7, and M6's as they join
    assert missing(portal, files) == []
    for path in files:
        assert (ROOT / path).is_file(), path
    assert len(files) == len(set(files))


def test_what_is_left_out_is_left_out_on_purpose() -> None:
    files = {Path(path).name for path in listed(windows_command())}
    for name in LEFT_OUT:
        assert (ROOT / "tests" / "unit" / name).is_file(), name
        assert name not in files, name
    assert "test_portal_windows_list.py" in files  # this guard runs there too
