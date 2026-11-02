"""Every M8 log event is emitted by the code, by the role that logs it (M8 design K.2, P.2; BP-8,
D-49's lesson).

Built on M6's walk (``test_m6_events_emitted.py``): every ``logs.event(...)`` call in
``src/zoeymcp``, the event its first argument holds, credited to the role whose ``logs`` the
module imports. The ledger's file layer (``common/ledgerfile.py``) logs through the ``event``
callable it is given (``self.event(...)``), so its events are credited, besides, to the role of
each module that builds a ``LedgerFile`` with ``event=logs.event``: the gateway's ledger and the
vault's chain (M8 build note, step 2's deviation 8).

Each step that adds an M8 event lists it here with its role, in that step's commit. The walk reads
the source files of the installed package, so under mutmut it reads the mutated copy, whose
original functions are kept beside their mutants.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator

import pytest

from .test_m6_events_emitted import PACKAGE, assignments, every_event, logs_role, strings

LEDGER_FILE = PACKAGE / "common" / "ledgerfile.py"

# M8's events, by the step that adds each, and the role whose log carries it.
EVENTS = {
    # Step 8: the vault's chain (J.1), on the gateway's ledger's file layer and failure event.
    "ledger_chain_broken": "vault",
    "ledger_repaired": "vault",
    "ledger_recovered": "vault",
    "ledger_pruned": "vault",
    "ledger_write_failed": "vault",
    # Step 9: the vault hold (K.2), its decisions on the vault side (with via), and the
    # builder's three failure events (a surface's error type, a forward or an ending that
    # raised), none with a text, an argument, an id or a secret.
    "approval_held": "vault",
    "approval_decided": "vault",
    "approval_detached": "vault",
    "approval_forwarded": "vault",
    "approval_withdrawn": "vault",
    "approval_result_evicted": "vault",
    "approvals_saturated": "vault",
    "approver_surface_failed": "vault",
    "approval_forward_failed": "vault",
    "approval_hold_failed": "vault",
    # Step 10: the gateway's Elsewhere (C.2's last row), and the builder's failure event for a
    # withdraw the vault couldn't be told of (its error type only), and the vault's answer to a
    # held call that ended before it came (its ref and status only).
    "elsewhere_unheld": "gateway",
    "approval_withdraw_failed": "gateway",
    "held_answer_dropped": "gateway",
    # Step 11: check_approval (F; K.2): the vault hands a result over once, the gateway names an
    # upstream tool that takes the gateway's own tool's name (F.4), and the builder's failure
    # event for a collect the vault couldn't answer (its status or error type only).
    "approval_collected": "vault",
    "reserved_tool_name": "gateway",
    "approval_collect_failed": "gateway",
    # Step 12a: the epoch rule's withdrawals (K.2, the withdrawn count only), and the builder's
    # failure event for a decisions poll the vault couldn't answer (its reason only).
    "gateway_epoch_changed": "vault",
    "approval_decisions_failed": "gateway",
    # Step 12b: the relay (K.2): the vault relays a gateway-held prompt (ref, server, tool,
    # surfaces, wait), the gateway refuses an approval of another text, and the builder's
    # failure event for an ask the vault couldn't be asked (its error type only).
    "approval_relayed": "vault",
    "relay_digest_mismatch": "gateway",
    "approval_relay_failed": "gateway",
}


def file_events(source: str) -> set[str]:
    """The events the file layer's ``self.event(...)`` calls can log."""
    tree = ast.parse(source)
    assigned = assignments(tree)
    found: set[str] = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and node.args):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "event"
            and isinstance(func.value, ast.Name)
            and func.value.id == "self"
        ):
            found |= strings(node.args[0], assigned)
    return found


def builds_file_layer(source: str, package: tuple[str, ...]) -> str | None:
    """The role whose log a module hands a ``LedgerFile`` it builds (``event=logs.event``), or
    None when it builds none that way."""
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "LedgerFile"
        ):
            continue
        for keyword in node.keywords:
            value = keyword.value
            if (
                keyword.arg == "event"
                and isinstance(value, ast.Attribute)
                and value.attr == "event"
                and isinstance(value.value, ast.Name)
                and value.value.id == "logs"
            ):
                return logs_role(tree, package)
    return None


def file_layer_roles() -> Iterator[str]:
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE.parent).with_suffix("")
        role = builds_file_layer(path.read_bytes().decode("utf-8"), relative.parts[:-1])
        if role is not None:
            yield role


def emitted_by_role() -> dict[str, set[str | None]]:
    """Every event the package can log, with the roles that log it, the file layer's included."""
    found = every_event()
    roles = set(file_layer_roles())
    for name in file_events(LEDGER_FILE.read_bytes().decode("utf-8")):
        found.setdefault(name, set()).update(roles)
    return found


EMITTED = emitted_by_role()


@pytest.mark.parametrize("event", sorted(EVENTS))
def test_each_event_is_emitted_by_its_role(event: str) -> None:
    assert EVENTS[event] in EMITTED.get(event, set()), f"no {EVENTS[event]} code logs {event}"


def test_the_file_layers_events_are_both_roles() -> None:
    """The gateway's ledger and the vault's chain each build the file layer on their own log, so
    each of its four events is credited to both (step 2 moved them off ``logs.event``)."""
    assert set(file_layer_roles()) == {"gateway", "vault"}
    events = file_events(LEDGER_FILE.read_bytes().decode("utf-8"))
    assert events == {"ledger_chain_broken", "ledger_repaired", "ledger_recovered", "ledger_pruned"}
    for name in events:
        assert {"gateway", "vault"} <= EMITTED[name]


def test_the_file_layer_walk_finds_what_it_is_for() -> None:
    """A ``self.event`` literal and a name assigned in the module are found, another object's
    ``event`` is not; a ``LedgerFile`` built with ``event=logs.event`` names the module's role,
    one built with another callable names none."""
    source = """
KIND = "assigned_event"
class Layer:
    def f(self, other):
        self.event("literal_event", x=1)
        self.event(KIND)
        other.event("not_self")
"""
    assert file_events(source) == {"literal_event", "assigned_event"}
    built = "from . import logs\nfile = LedgerFile(path, writer='vault', event=logs.event)\n"
    assert builds_file_layer(built, ("zoeymcp", "vault")) == "vault"
    other = "from . import logs\nfile = LedgerFile(path, writer='vault', event=print)\n"
    assert builds_file_layer(other, ("zoeymcp", "vault")) is None
    assert builds_file_layer("from . import logs\nlogs.event('x')\n", ("zoeymcp", "vault")) is None
