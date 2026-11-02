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

Under an Elsewhere grant (a ``vault_approval`` tool, M8 design B.7, C.2) the body runs as an
accepted one, and its one write leaves marked for the vault to hold: the slot registers the write
with the call's marker, the transport adds the marker only after its own checks passed for that
registration, and the vault's answer is kept on the call (:attr:`CallState.held`). An
``approved: true`` rule is then used only toward a connector, which the vault holds (H11); any
other such use is refused.

This is the gateway enforcing on itself: it stops toolkit bugs and model-driven misuse, not a
compromised gateway.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final
from urllib.parse import urlencode

import anyio
import httpx2

from ..common import canonical
from ..common.approvaltext import Write
from ..common.canonical import JSONValue
from ..common.envelope import Marker
from ..common.policy.match import RequestRejected, normalize_path
from ..common.policy.view import ViewSlot, ViewToolkitServer
from ..toolkit import rules
from ..toolkit.context import VaultError
from ..toolkit.plan import Claim, SendLedger
from . import logs
from .upstream import Held
from .vaultlink import (
    TOOLKIT_MAX_ANSWER_BYTES,
    TOOLKIT_MAX_REQUEST_BYTES,
    KeySource,
    Link,
    ResponseTooLarge,
    UpstreamBlocked,
    UpstreamRedirect,
    held_answer,
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
    # An Elsewhere grant's marker, and once its write is answered, the vault's answer (C.2).
    held: Held | None = None

    def close(self) -> None:
        self.phase = "closed"


# A held write's registration: method, path, the body's SHA-256 and its Idempotency-Key.
MarkKey = tuple[str, str, str, str | None]


def _mark_key(method: str, path: str, body: bytes, idempotency: str | None) -> MarkKey:
    return (method, path, hashlib.sha256(body).hexdigest(), idempotency)


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
        # Held writes registered and not yet sent, by (method, path, SHA-256 of the body, and
        # the Idempotency-Key, which names the call's ref): one registration per key (Z27).
        self._marked: dict[MarkKey, Marker] = {}
        self.client = toolkit_client(
            link,
            keys,
            server=server,
            check=self._transport_check,
            inner=inner,
            held=self._take_marked,
        )

    def mark(
        self, method: str, path: str, body: bytes, idempotency: str | None, marker: Marker
    ) -> MarkKey | None:
        """Register a held write for the transport to mark once its checks pass (C.2); None,
        and nothing registered, while the same write of the same call is registered."""
        key = _mark_key(method, path, body, idempotency)
        if key in self._marked:
            return None
        self._marked[key] = marker
        return key

    def unmark(self, key: MarkKey) -> None:
        """A registered write whose request ended, sent or not."""
        self._marked.pop(key, None)

    def _take_marked(
        self, method: str, path: str, body: bytes, idempotency: str | None
    ) -> Marker | None:
        return self._marked.pop(_mark_key(method, path, body, idempotency), None)

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
        held = self._state.held
        if held is not None and claim is not None and self._slot.connector != "smtp":
            # H11 under an Elsewhere grant: an approved write goes only to a held connector.
            raise self._blocked(method, "not_held")
        target = rules.join(self._slot.prefix, path).encoded()
        unqueried = target  # the transport reads the path without its query
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
            marked = None
            try:
                if held is not None and claim is not None:
                    # Registered here, after every check of its own, so each path out of the
                    # request ends the registration in the finally below.
                    marked = self._vault.mark(
                        method,
                        unqueried,
                        body or b"",
                        headers.get("idempotency-key"),
                        held.marker,
                    )
                    if marked is None:
                        raise self._blocked(method, "held_busy")
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
            finally:
                if marked is not None:
                    self._vault.unmark(marked)
        if held is not None and marked is not None:
            held.answer = held_answer(response.status_code, response.headers, data)
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
