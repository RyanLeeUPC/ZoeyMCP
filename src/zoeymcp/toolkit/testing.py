"""Testing a toolkit without a gateway, a vault or MCP (M4 design G.6).

:func:`run` takes a call through the gateway's own pieces: the definition checks it makes at load
(the text rules and the schema checks), the argument checks, the ``prepare`` step under the plan
phase's rules, the rendered prompt and its text check, the human's answer, then the body with
send-once accounting. It refuses what the gateway would, with the same texts. What it can't
check is what only a policy decides: the classification (the code's, unless ``classification``
says otherwise), pins and the slots' rules.

:class:`FakeSlot` plays a vault slot. It records every request and answers from fixed tables.

This module needs the gateway's environment (it uses ``zoeymcp.gateway``'s checks), where
toolkits run anyway.
"""

from __future__ import annotations

import asyncio
import copy
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from ..common import approvaltext, canonical
from ..common.approvaltext import Header, Write
from ..common.canonical import JSONValue
from ..common.policy.schema import GatewayLimits
from ..gateway import approve, pins
from ..gateway.pipeline import new_ref
from . import rules
from .context import PrepareContext, ToolContext, Toolkit, ToolkitError, ToolSpec, VaultError
from .params import check_arguments
from .plan import SendLedger
from .results import failure, render
from .rules import Phase, Slot, SlotRule

Answer = Literal["accept", "decline", "none"]
FAKE_PREFIX = "/slot"
PREPARE_TIMEOUT = 10.0


class ToolkitLoadError(AssertionError):
    """The gateway would refuse to load this toolkit or tool. Raised, so a test fails loudly."""


@dataclass
class FakeSlot:
    """A vault slot in tests. ``get`` answers reads, ``answer`` answers writes, ``fail`` raises a
    :class:`VaultError` for a path. ``sent`` lists every write as (method, path, body).

    ``approved`` lists the paths whose writes only an accepted plan may send, as the policy's
    ``approved: true`` rules would; an smtp slot's ``/send`` always is. Every other path is
    allowed, since only the policy knows the slot's real rules."""

    get: Mapping[str, JSONValue] = field(default_factory=dict)
    answer: Mapping[str, JSONValue] = field(default_factory=dict)
    fail: Mapping[str, VaultError] = field(default_factory=dict)
    approved: tuple[str, ...] = ()
    sent: list[tuple[str, str, JSONValue]] = field(default_factory=list)
    read: list[str] = field(default_factory=list)


class _Bound:
    """A :class:`FakeSlot` in one phase of one call, applying the gateway's phase rules."""

    def __init__(
        self, fake: FakeSlot, kind: Literal["smtp", "http"], phase: Phase, ledger: SendLedger
    ) -> None:
        self.fake, self.phase, self.ledger = fake, phase, ledger
        connector: Literal["smtp"] | None = "smtp" if kind == "smtp" else None
        approved = (*fake.approved, "/send") if kind == "smtp" else fake.approved
        writes = frozenset(rules.METHODS - {"GET"})
        self._slot = Slot(
            FAKE_PREFIX,
            connector,
            (
                SlotRule(frozenset(rules.METHODS), (f"{FAKE_PREFIX}/**",)),
                *(SlotRule(writes, (FAKE_PREFIX + path,), True) for path in approved),
            ),
        )

    def close(self) -> None:
        self.phase = "closed"

    def _check(self, method: str, path: str, claim: Any = None) -> None:
        blocked = rules.check_call(self._slot, self.phase, method, path, plan_write=claim)
        if blocked is not None:
            raise VaultError(403, f"blocked_{blocked}")

    def _answer(self, table: Mapping[str, JSONValue], path: str) -> dict[str, JSONValue]:
        if path in self.fake.fail:
            raise self.fake.fail[path]
        found = table.get(path, {})
        if not isinstance(found, dict):
            raise TypeError("a FakeSlot answer is a JSON object")
        return copy.deepcopy(found)

    async def get_object(
        self, path: str, *, query: Mapping[str, str] | None = None
    ) -> dict[str, JSONValue]:
        self._check("GET", path)
        self.fake.read.append(path)
        if path not in self.fake.get and path not in self.fake.fail:
            raise VaultError(404)
        return self._answer(self.fake.get, path)

    async def _write(self, method: str, path: str, body: Mapping[str, JSONValue]) -> Any:
        self._check(method, path)
        frozen = canonical.loads_strict(canonical.dumps_canonical(dict(body)), max_bytes=2**20)
        self.fake.sent.append((method, path, frozen))
        return self._answer(self.fake.answer, path)

    async def post_json(self, path: str, body: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
        found: dict[str, JSONValue] = await self._write("POST", path, body)
        return found

    async def put_json(self, path: str, body: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
        found: dict[str, JSONValue] = await self._write("PUT", path, body)
        return found

    async def patch_json(self, path: str, body: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
        found: dict[str, JSONValue] = await self._write("PATCH", path, body)
        return found

    async def delete(self, path: str) -> dict[str, JSONValue]:
        self._check("DELETE", path)
        self.fake.sent.append(("DELETE", path, None))
        return self._answer(self.fake.answer, path)

    async def send(self, write: Write) -> dict[str, JSONValue]:
        claim = self.ledger.claim(write) if self.phase == "approve" else "not_in_plan"
        self._check(write.method, write.path, claim)
        self.fake.sent.append((write.method, write.path, write.data))
        return self._answer(self.fake.answer, write.path)


@dataclass
class Outcome:
    """What a call came to. ``prompt`` is the exact text the human saw (``None`` if not asked);
    ``text`` is what the agent reads; ``ran`` says whether the body ran."""

    ref: str
    text: str
    is_error: bool
    prompt: str | None = None
    ran: bool = False
    log: list[tuple[str, dict[str, Any]]] = field(default_factory=list)


def load_problems(toolkit: Toolkit, limits: GatewayLimits | None = None) -> dict[str, list[str]]:
    """Per tool, why the gateway would hide it at load (text rules, schema checks)."""
    return {
        name: found
        for name, spec in sorted(toolkit.tools.items())
        if (found := pins.tool_problems(spec.definition(), limits or GatewayLimits()))
    }


async def run(
    toolkit: Toolkit,
    tool: str,
    arguments: Mapping[str, Any],
    *,
    slots: Mapping[str, FakeSlot],
    answer: Answer = "accept",
    classification: Literal["allow", "approve"] | None = None,
    client: str = "agent1",
    server: str | None = None,
    budget: int = 3000,
    renders: Literal["markdown", "plain"] = "markdown",
    timeout: float = 60.0,
) -> Outcome:
    """One call of ``tool``, as the gateway would make it. ``answer`` is the human's, for an
    ``approve`` call; with ``decline`` or ``none`` the body never runs."""
    spec = toolkit.tools.get(tool)
    if spec is None:
        raise ToolkitLoadError(f"no tool named {tool!r}")
    problems = load_problems(toolkit).get(tool)
    if problems:
        raise ToolkitLoadError(f"{tool}: the gateway would hide it: {problems[0]}")
    if set(slots) != set(toolkit.slots):
        raise ToolkitLoadError("give a FakeSlot for every slot the toolkit declares")
    tool_class = classification or ("approve" if spec.consequential else "allow")
    if rules.classification_hidden(spec.consequential, tool_class):
        raise ToolkitLoadError(f"{tool}: consequential in code, so it can't be allowed")
    server = server or toolkit.name
    ref = new_ref()
    shaped = _shape(arguments)
    if isinstance(shaped, str):
        return Outcome(ref, shaped, True)
    found = check_arguments(spec.params, shaped)
    if found:
        return Outcome(ref, f"arguments refused: at {found[0]}", True)
    ledger = SendLedger(None)
    if tool_class == "allow":
        return await _body(
            toolkit, spec, shaped, slots, "allow", ledger, client, server, ref, None, timeout
        )
    plan = None
    prompt: approvaltext.ApprovalText
    deadline = datetime.now(UTC) + timedelta(seconds=300)
    header = Header(ref, client, server, tool, deadline)
    if spec.prepare is not None:
        bound = {
            name: _Bound(fake, toolkit.slots[name], "prepare", ledger)
            for name, fake in slots.items()
        }
        context = PrepareContext(client, server, ref, bound)
        try:
            async with asyncio.timeout(PREPARE_TIMEOUT):
                plan = await spec.prepare(context, **shaped)
        except Exception as exc:  # G.7: the agent reads a fixed text
            return _failed(exc, ref)
        finally:
            for slot in bound.values():
                slot.close()
        if not isinstance(plan, approvaltext.Plan):
            return _failed(TypeError("prepare returns a Plan"), ref)
        prompt = approvaltext.render_plan(header, plan)
    else:
        prompt = approvaltext.render_call(header, shaped)
    text_problems = approvaltext.problems(prompt, budget=budget, renders=renders)
    if text_problems:
        return Outcome(ref, f"{approvaltext.describe(text_problems[0])} (ref {ref})", True)
    if answer != "accept":
        decision = "decline" if answer == "decline" else "timeout"
        text = f"{approve.DECISION_TEXTS[decision]} (ref {ref})"
        return Outcome(ref, text, True, prompt=prompt.value)
    ledger = SendLedger(plan)
    outcome = await _body(
        toolkit, spec, shaped, slots, "approve", ledger, client, server, ref, plan, timeout
    )
    outcome.prompt = prompt.value
    return outcome


def _shape(arguments: Mapping[str, Any]) -> dict[str, Any] | str:
    if not isinstance(arguments, Mapping):
        return "arguments refused: not an object"
    try:
        data = canonical.dumps_canonical(dict(arguments))
    except canonical.JSONRejected:
        return "arguments refused: not plain JSON"
    shaped: dict[str, Any] = canonical.loads_strict(data, max_bytes=len(data) + 1)
    return shaped


def _failed(exc: BaseException, ref: str) -> Outcome:
    found = failure(exc, ref)
    return Outcome(ref, found.text, True, log=[(found.event, found.fields)])


async def _body(
    toolkit: Toolkit,
    spec: ToolSpec,
    shaped: dict[str, Any],
    slots: Mapping[str, FakeSlot],
    phase: Literal["allow", "approve"],
    ledger: SendLedger,
    client: str,
    server: str,
    ref: str,
    plan: approvaltext.Plan | None = None,
    timeout: float = 60.0,
) -> Outcome:
    bound = {name: _Bound(fake, toolkit.slots[name], phase, ledger) for name, fake in slots.items()}
    context = ToolContext(client, server, ref, plan, bound)
    try:
        async with asyncio.timeout(timeout):
            value = await spec.fn(context, **shaped)
        text = render(value)
    except Exception as exc:  # G.7: the agent reads a fixed text
        outcome = _failed(exc, ref)
        outcome.ran = True
        return outcome
    finally:
        for slot in bound.values():
            slot.close()
    return Outcome(ref, text, False, ran=True)


__all__ = ["FakeSlot", "Outcome", "ToolkitError", "ToolkitLoadError", "load_problems", "run"]
