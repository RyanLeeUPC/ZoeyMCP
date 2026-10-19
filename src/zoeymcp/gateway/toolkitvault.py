"""A toolkit's only way out: its slots, through the vault (M4 design H.4).

Each call gets its own slots, bound to the call's phase: ``prepare`` may read an smtp connector's
config and nothing else; an ``allow`` call's body may use the slot's plain rules; an accepted
``approve`` call's body may also send each of the plan's writes once, exactly as frozen. After the
call returns, its slots refuse everything. The decisions are :func:`..toolkit.rules.check_call`;
a request it refuses raises :class:`VaultError` ``403 blocked_<reason>`` in the toolkit, is
logged without its path (paths can hold ids) and never leaves the gateway.

Nothing from the agent is forwarded: the gateway builds every request, with a JSON body of at
most 1 MiB, ``Accept`` and ``Content-Type`` and, for a write through an smtp slot, an
``Idempotency-Key`` of the call's ref and the write's number. An answer must be JSON, at most
4 MiB; anything else, a redirect included, is a :class:`VaultError`. No request is ever retried.
At most 4 are in flight per call.

This is the gateway enforcing on itself: it stops toolkit bugs and model-driven misuse, not a
compromised gateway.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlencode

import anyio
import httpx2

from ..common import canonical
from ..common.approvaltext import Write
from ..common.canonical import JSONValue
from ..common.policy.match import RequestRejected, normalize_path
from ..common.policy.view import ViewSlot, ViewToolkitServer
from ..toolkit import rules
from ..toolkit.context import VaultError
from ..toolkit.plan import Claim, SendLedger
from . import logs
from .vaultlink import (
    TOOLKIT_MAX_ANSWER_BYTES,
    TOOLKIT_MAX_REQUEST_BYTES,
    KeySource,
    Link,
    ResponseTooLarge,
    UpstreamBlocked,
    UpstreamRedirect,
    toolkit_client,
    vault_refusal_code,
)

MAX_IN_FLIGHT: Final = 4
MAX_QUERY_BYTES: Final = 2048


def slots_of(policy: ViewToolkitServer) -> dict[str, rules.Slot]:
    """The view's slots as :mod:`..toolkit.rules` takes them."""
    return {name: _slot(slot) for name, slot in policy.slots.items()}


def _slot(slot: ViewSlot) -> rules.Slot:
    return rules.Slot(
        slot.prefix,
        slot.connector,
        tuple(
            rules.SlotRule(frozenset(rule.methods), tuple(rule.paths), rule.approved)
            for rule in slot.rules
        ),
    )


@dataclass
class CallState:
    """One call's phase and accounting, shared by its slots."""

    tool: str
    ref: str
    phase: rules.Phase
    ledger: SendLedger
    gate: anyio.Semaphore = field(default_factory=lambda: anyio.Semaphore(MAX_IN_FLIGHT))

    def close(self) -> None:
        self.phase = "closed"


class ToolkitVault:
    """One toolkit server's HTTP client and slots. Build one per (server, slots)."""

    def __init__(
        self,
        server: str,
        slots: Mapping[str, rules.Slot],
        link: Link,
        keys: KeySource | None,
        *,
        inner: Any = None,
    ) -> None:
        self.server = server
        self.slots = dict(slots)
        self._prefixes = {slot.prefix.lstrip("/") for slot in self.slots.values()}
        self.client = toolkit_client(
            link, keys, server=server, check=self._transport_check, inner=inner
        )

    def _transport_check(self, method: str, raw_path: str) -> str | None:
        """The transport's own last look: a method the SDK uses, a path the vault reads the same
        way, under one of this toolkit's slots."""
        if method not in rules.METHODS:
            return "method"
        try:
            path = normalize_path(raw_path.encode("ascii"))
        except (RequestRejected, UnicodeError):
            return "bad_path"
        if not path.segments or path.segments[0] not in self._prefixes:
            return "not_a_slot"
        return None

    def bind(self, state: CallState) -> dict[str, BoundSlot]:
        return {name: BoundSlot(self, name, slot, state) for name, slot in self.slots.items()}

    async def aclose(self) -> None:
        await self.client.aclose()


class BoundSlot:
    """A slot within one call: what the toolkit's ``ctx.vault(slot)`` returns."""

    def __init__(self, vault: ToolkitVault, name: str, slot: rules.Slot, state: CallState) -> None:
        self._vault, self._name, self._slot, self._state = vault, name, slot, state

    def __repr__(self) -> str:
        return f"BoundSlot({self._name!r}, {self._state.phase})"

    def _blocked(self, method: str, reason: str) -> VaultError:
        logs.event(
            "toolkit_vault_blocked",
            server=self._vault.server,
            tool=self._state.tool,
            slot=self._name,
            method=method,
            reason=reason,
        )
        return VaultError(403, f"blocked_{reason}")

    async def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        query: Mapping[str, str] | None = None,
        claim: Claim | None = None,
        number: int | None = None,
    ) -> dict[str, JSONValue]:
        reason = rules.check_call(self._slot, self._state.phase, method, path, plan_write=claim)
        if reason is not None:
            raise self._blocked(method, reason)
        target = rules.join(self._slot.prefix, path).encoded()
        if query:
            encoded = urlencode(sorted(query.items()))
            if len(encoded) > MAX_QUERY_BYTES:
                raise self._blocked(method, "query")
            target += "?" + encoded
        headers = {"accept": "application/json"}
        if body is not None:
            if len(body) > TOOLKIT_MAX_REQUEST_BYTES:
                raise self._blocked(method, "too_large")
            headers["content-type"] = "application/json"
        if self._slot.connector == "smtp" and method != "GET":
            headers["idempotency-key"] = f"{self._state.ref}.{number or 1}"
        async with self._state.gate:
            try:
                response = await self._vault.client.request(
                    method, target, content=body, headers=headers
                )
                data = await response.aread()
            except UpstreamBlocked:
                raise self._blocked(method, "transport") from None
            except UpstreamRedirect:
                raise VaultError(502, "redirect") from None
            except ResponseTooLarge:
                raise VaultError(502, "too_large") from None
            except httpx2.HTTPError:
                raise VaultError(502, "unreachable") from None
        if not 200 <= response.status_code < 300:
            raise VaultError(response.status_code, vault_refusal_code(data))
        if not response.headers.get("content-type", "").startswith("application/json"):
            raise VaultError(502, "bad_answer")
        try:
            value = canonical.loads_strict(data, max_bytes=TOOLKIT_MAX_ANSWER_BYTES)
        except canonical.JSONRejected:
            raise VaultError(502, "bad_answer") from None
        if not isinstance(value, dict):
            raise VaultError(502, "bad_answer")
        return value

    @staticmethod
    def _json(body: Mapping[str, JSONValue]) -> bytes:
        try:
            return canonical.dumps_canonical(dict(body))
        except canonical.JSONRejected:
            raise VaultError(400, "bad_body") from None

    async def get_object(
        self, path: str, *, query: Mapping[str, str] | None = None
    ) -> dict[str, JSONValue]:
        return await self._request("GET", path, query=query)

    async def post_json(self, path: str, body: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
        return await self._request("POST", path, body=self._json(body))

    async def put_json(self, path: str, body: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
        return await self._request("PUT", path, body=self._json(body))

    async def patch_json(self, path: str, body: Mapping[str, JSONValue]) -> dict[str, JSONValue]:
        return await self._request("PATCH", path, body=self._json(body))

    async def delete(self, path: str) -> dict[str, JSONValue]:
        return await self._request("DELETE", path)

    async def send(self, write: Write) -> dict[str, JSONValue]:
        """One of the accepted plan's writes, exactly as frozen, at most once."""
        ledger = self._state.ledger
        number = (
            next((i for i, planned in enumerate(ledger.plan.writes, 1) if planned is write), None)
            if ledger.plan is not None
            else None
        )
        claim = ledger.claim(write) if self._state.phase == "approve" else "not_in_plan"
        return await self._request(
            write.method, write.path, body=write.body, claim=claim, number=number
        )
