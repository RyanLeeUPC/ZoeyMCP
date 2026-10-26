"""Every M6 log event and health finding is emitted by the code (M6 design M.5's last sentence,
N.3; COV-10, step 22).

The events of N.3's table, and the ones the build added beside them (each named in the build
notes), are found by an AST walk of every ``logs.event(...)`` call in ``src/zoeymcp``: the event
is the call's first argument when it is a literal, or a literal in what that argument reads (a
module's table of event names, a name assigned in the module). An f-string's pieces are never
an event. Each event must come from a module that logs as its role (``from . import logs`` in
the gateway, the vault's ``logs`` elsewhere). The findings of M.5's two sections are found the
same way, as the first argument of ``_finding(...)`` inside ``vault/health.py``'s ``_policy``
and ``_gateway``, the builders of the ``policy`` and ``gateway`` sections.

Only M6's own events and findings are listed; the repository-wide check is the pre-main pass's
(M.5). The walk reads the source files of the installed package, so under mutmut it reads the
mutated copy, whose original functions are kept beside their mutants.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

import zoeymcp

PACKAGE = Path(zoeymcp.__file__).resolve().parent
HEALTH = PACKAGE / "vault" / "health.py"

# N.3's events and the role whose log carries each ("gateway:" rows are the gateway's).
EVENTS = {
    "policy_head": "vault",
    "policy_seeded": "vault",
    "policy_saved": "vault",
    "policy_rolled_back": "vault",
    "policy_imported": "vault",
    "policy_acknowledged": "vault",
    "tool_allowed": "vault",
    "tool_repinned": "vault",
    "policy_refused": "vault",
    "policy_save_uncommitted": "vault",
    "policy_revision_quarantined": "vault",
    "policy_stray_file": "vault",
    "policy_anchor_write_failed": "vault",
    "policy_store_unverified": "vault",
    "policy_not_installed": "vault",
    "policy_seed_ignored": "vault",
    "policy_store_parked": "vault",
    "policy_resumed": "vault",
    "policy_rekeyed": "vault",
    "policy_pruned": "vault",
    "policy_exported": "vault",
    "policy_behind_witness": "vault",
    "policy_deployment_changed": "vault",
    "status_refused": "vault",
    "status_received": "vault",
    "policy_revision_regressed": "gateway",
    "policy_deployment_seen": "gateway",
    "drift_cleared": "gateway",
}
# The events the build added beside N.3's, by the step whose build note names them.
ADDED = {
    "status_push_failed": "gateway",  # step 7, note 11
    "policy_housekeeping_failed": "vault",  # step 13a, deviation 1
    "master_key_previous_same": "vault",  # step 13b
    "policy_seen_not_written": "gateway",  # step 17, deviation 5
    "kind_list_failed": "gateway",  # step 19, deviation 5
    "kind_list_cut": "gateway",  # step 19, deviation 5
}
# M.5's findings, by the section that raises them.
FINDINGS = {
    "policy": (
        "policy_not_running",
        "policy_behind_witness",
        "policy_deployment_changed",
        "policy_declarative_revives",
        "policy_seed_ignored",
        "policy_restart_needed",
        "revisions_unreadable",
        "policy_store_parked",
        "policy_store_unverified",
        "policy_quarantine_kept",
    ),
    "gateway": (
        "tools_unreviewed",
        "drift_marked",
        "server_listing_invalid",
        "server_blocked",
        "gateway_view_behind",
        "gateway_status_stale",
    ),
}
# Each section's builder in vault/health.py.
BUILDERS = {"policy": "_policy", "gateway": "_gateway"}


def strings(expr: ast.AST, assigned: Mapping[str, list[ast.expr]]) -> set[str]:
    """Every string literal ``expr`` holds or reads through a name assigned in its module, each
    name followed once; an f-string's pieces are left out."""
    found: set[str] = set()
    followed: set[str] = set()
    pending: list[ast.AST] = [expr]
    while pending:
        node = pending.pop()
        if isinstance(node, ast.JoinedStr):
            continue
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            found.add(node.value)
        elif isinstance(node, ast.Name) and node.id in assigned and node.id not in followed:
            followed.add(node.id)
            pending.extend(assigned[node.id])
        pending.extend(ast.iter_child_nodes(node))
    return found


def assignments(tree: ast.Module) -> dict[str, list[ast.expr]]:
    """What each plain name is assigned anywhere in the module."""
    found: dict[str, list[ast.expr]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    found.setdefault(target.id, []).append(node.value)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.value is not None
        ):
            found.setdefault(node.target.id, []).append(node.value)
    return found


def logs_role(tree: ast.Module, package: tuple[str, ...]) -> str | None:
    """The role whose ``logs`` module this one imports, from its ``from ... import logs``;
    None when it imports none."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if not any(alias.name == "logs" and alias.asname is None for alias in node.names):
            continue
        base = list(package[: len(package) - node.level + 1]) if node.level else []
        module = [*base, *(node.module.split(".") if node.module else [])]
        if len(module) >= 2 and module[0] == "zoeymcp":
            return module[1]
    return None


def emitted(source: str, package: tuple[str, ...]) -> Iterator[tuple[str, str | None]]:
    """Each event a module's ``logs.event(...)`` calls can log, with its ``logs``'s role."""
    tree = ast.parse(source)
    role = logs_role(tree, package)
    assigned = assignments(tree)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and node.args):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "event"
            and isinstance(func.value, ast.Name)
            and func.value.id == "logs"
        ):
            for name in strings(node.args[0], assigned):
                yield name, role


def every_event() -> dict[str, set[str | None]]:
    """Every event the package's code can log, with the roles that log it."""
    found: dict[str, set[str | None]] = {}
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE.parent).with_suffix("")
        package = relative.parts[:-1]  # a package's __init__ is in the package itself
        for name, role in emitted(path.read_bytes().decode("utf-8"), package):
            found.setdefault(name, set()).add(role)
    return found


def raised(source: str, builder: str) -> set[str]:
    """The finding codes ``builder`` passes to ``_finding`` as a literal."""
    tree = ast.parse(source)
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == builder:
            for call in ast.walk(node):
                if (
                    isinstance(call, ast.Call)
                    and isinstance(call.func, ast.Name)
                    and call.func.id == "_finding"
                    and call.args
                    and isinstance(call.args[0], ast.Constant)
                    and isinstance(call.args[0].value, str)
                ):
                    found.add(call.args[0].value)
    return found


EMITTED = every_event()


@pytest.mark.parametrize("event", sorted({**EVENTS, **ADDED}))
def test_each_event_is_emitted_by_its_role(event: str) -> None:
    role = {**EVENTS, **ADDED}[event]
    assert role in EMITTED.get(event, set()), f"no {role} code logs {event}"


@pytest.mark.parametrize("section", sorted(FINDINGS))
def test_each_finding_is_raised_by_its_section(section: str) -> None:
    found = raised(HEALTH.read_bytes().decode("utf-8"), BUILDERS[section])
    assert set(FINDINGS[section]) - found == set()


def test_the_walk_finds_what_it_is_for() -> None:
    """A literal, a table the argument reads and a name assigned in the module are found; an
    f-string's pieces and another object's ``event`` are not; the role is the imported
    ``logs``'s."""
    source = """
from . import logs
TABLE = {"policy.rollback": "table_event"}
def f(kind, other):
    logs.event("literal_event", x=1)
    logs.event(TABLE.get(kind, "default_event"))
    chosen = "assigned_event" if kind else "other_event"
    logs.event(chosen)
    logs.event(f"{kind}_changed_sent")
    other.event("not_logs")
"""
    found = dict(emitted(source, ("zoeymcp", "gateway")))
    assert set(found) == {
        "literal_event",
        "policy.rollback",
        "table_event",
        "default_event",
        "assigned_event",
        "other_event",
    }
    assert set(found.values()) == {"gateway"}
    vault_side = dict(emitted("from ..vault import logs\nlogs.event('x')\n", ("zoeymcp", "cli")))
    assert vault_side == {"x": "vault"}
    assert dict(emitted("logs.event('x')\n", ("zoeymcp", "cli"))) == {"x": None}


def test_the_finding_walk_reads_one_builder() -> None:
    source = """
def _policy(state):
    findings.append(_finding("in_policy", "warning", text, None))
def _gateway(policy):
    findings.append(_finding("in_gateway", "info", text, None))
    _finding(code, "info", text, None)
"""
    assert raised(source, "_policy") == {"in_policy"}
    assert raised(source, "_gateway") == {"in_gateway"}
    assert raised(source, "_other") == set()
