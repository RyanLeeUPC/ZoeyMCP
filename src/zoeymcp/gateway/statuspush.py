"""The gateway's status report to the vault (M6 design K.1, K.2; D-29, D-174's bridge half). I/O.

The vault never connects to the gateway (X12), so the operator's Home page and health learn of
drift and of tools nobody reviewed without asking only if the gateway tells the vault. One task,
beside the policy client, the reporter and the review poller, posts a small summary of its
status (:func:`.server.pushed_status`: the admin socket's ``GET /status`` with each unreviewed
tool's pin) to the vault's status path through ``vaultlink.status_client``, whose transport
reaches that path and nothing else:

- on any change of the content, at most once per :data:`DEBOUNCE` (the vault takes at most one
  report per 5 s, and answers a sooner one 429);
- and at least every :data:`EVERY`, so a vault that restarted holds a report again within a
  minute (FM-20), and health can tell a gateway that stopped reporting (``gateway_status_stale``).

:func:`content` is the report: ``{"v": 1, "view", "started", "servers", "witness",
"deployments_seen", "policy_mode"}``, per server its kind, state, era, whether ``on_drift: fail``
blocked it, counts, ``offered`` and the attention decision's lists (``drift``, ``marked``,
``unreviewed`` with each tool's pin, ``declined_changed``, ``missing``), plus ``invalid``. A
server that enables prompts or resources also has ``kinds``: per kind it enables, the attention
decision for that kind in its plain form (``drifted``, ``marked``, ``new``, ``changed_declined``,
``missing``), names only and no pins; a server that enables neither, and every toolkit, has no
``kinds``, so its entry is as before (M6 design K.1, D-216). A kind's names can be URIs of up to
2,048 characters, where a tool's are 128, so ``kinds`` alone never takes a report over
:data:`MAX_BYTES`: its lists are cut from the end until it fits (:func:`_fitted`), first the names
health and Home only count (``new``, ``changed_declined``), then those they name, each list
keeping one name while any other can go, so every finding still fires. Never a definition, a
token hash or a client name, every list at most ``max_tools_per_server`` long, and the two tool
counts at most that limit's own ceiling. The upstream reports invalid and duplicate tools
under their raw names, which often aren't tool names: only names that are go in ``invalid``, and the
rest are counted (``invalid_unnamed``, ``duplicate_unnamed``; T-7). ``policy_mode`` is the mode
the vault last stated beside the view (K.3), as the status names it. ``witness`` is the restore
witness's record (K.3, :mod:`.witness`): the highest revision of each deployment the view answers
stated, first seen first, which the vault reads in that order; ``deployments_seen`` how many
deployments it has recorded in all (T-5). Both are empty before a managed vault's first view.

A post that fails, or is refused, backs off from 1 s up to 30 s, logged ``status_push_failed`` at
most once a minute; a 429 waits the debounce. Nothing the gateway serves waits for it.
"""

from __future__ import annotations

import json
import random
import re
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Final

import anyio
import httpx2

from ..common.policy.attention import loaded
from ..common.reviewreport import NAMES_MAX
from . import logs
from .policyclient import Snapshot, backoff
from .vaultlink import STATUS_PATH, vault_refusal_code

DEBOUNCE: Final = 5.0  # the vault's STATUS_MIN_INTERVAL
EVERY: Final = 60.0
STEP: Final = 1.0  # how often the content is looked at
LOG_EVERY: Final = 60.0  # status_push_failed at most this often
MAX_BYTES: Final = 256 * 1024  # the vault's STATUS_MAX_BYTES
_TOOL: Final = re.compile(r"[A-Za-z0-9_.-]{1,128}")

Status = Callable[[Any], Mapping[str, Any]]


def content(status: Mapping[str, Any], *, started: int, max_tools: int) -> dict[str, Any] | None:
    """The status report for ``status`` (:func:`.server.pushed_status`), or None before a view."""
    view = status.get("view")
    if view is None:
        return None
    servers = {name: _server(entry, max_tools) for name, entry in sorted(status["servers"].items())}
    document = {
        "v": 1,
        "view": view,
        "started": started,
        "servers": servers,
        "witness": dict(status.get("witness", {})),
        "deployments_seen": status.get("deployments_seen", 0),
        "policy_mode": status.get("policy_mode", "unknown"),
    }
    return _fitted(document)


# The order a kind's lists give up names in when the report is over MAX_BYTES (D-216): those
# health and Home only count first, then the included names they name.
CUT_ORDER: Final = ("new", "changed_declined", "missing", "marked", "drifted")


def _fitted(document: dict[str, Any]) -> dict[str, Any]:
    """``document`` with its servers' ``kinds`` cut until it is at most :data:`MAX_BYTES`, or
    until they hold no name (the tools' lists are never cut): in :data:`CUT_ORDER`, each time
    the last name of the list of that member with the most names across servers (the first
    such, by server name), every list kept to one name before any is emptied."""
    over = len(encoded(document)) - MAX_BYTES
    lists = [
        (member, decided[member])
        for entry in document["servers"].values()
        for decided in entry.get("kinds", {}).values()
        for member in CUT_ORDER
    ]
    for keep in (1, 0):
        for member in CUT_ORDER:
            named = [names for each, names in lists if each == member]
            while over > 0 and named:
                longest = max(named, key=len)
                if len(longest) <= keep:
                    break
                name = longest.pop()
                # What dropping it saves: the name, quoted, and its comma while another is left.
                over -= len(json.dumps(name, ensure_ascii=True)) + bool(longest)
    return document


def _server(entry: Mapping[str, Any], max_tools: int) -> dict[str, Any]:
    state = entry["state"]
    found = loaded(entry.get("attention") or {})
    reports: Mapping[str, list[str]] = entry.get("reports", {})
    pins: Mapping[str, str] = entry.get("unreviewed_pins", {})
    invalid = [*reports.get("invalid", ()), *reports.get("duplicate", ())]

    def capped(names: Any) -> list[str]:
        return sorted(set(names))[:max_tools]

    sent: dict[str, Any] = {
        "kind": entry["kind"],
        "state": [state] if isinstance(state, str) else list(state),
        "era": entry.get("era"),
        "blocked": entry.get("blocked", False),
        "included": min(entry.get("included", 0), NAMES_MAX),
        "exposed": min(entry.get("exposed", 0), NAMES_MAX),
        "marked": capped(found.marked),
        "unreviewed": [[name, pins[name]] for name in capped(found.unreviewed()) if name in pins],
        "declined_changed": capped(found.changed_declined),
        "drift": capped(found.drifted),
        "missing": capped(found.missing),
        "invalid": capped(name for name in invalid if _TOOL.fullmatch(name)),
        "invalid_unnamed": min(_unnamed(reports.get("invalid", ())), max_tools),
        "duplicate_unnamed": min(_unnamed(reports.get("duplicate", ())), max_tools),
        "offered": entry.get("offered"),
    }
    kinds: Mapping[str, Mapping[str, Any]] = entry.get("kinds") or {}
    if kinds:  # only a server that enables a kind beyond tools: the rest as before, byte for byte
        sent["kinds"] = {
            kind: {member: capped(names) for member, names in loaded(lists).as_dict().items()}
            for kind, lists in kinds.items()
        }
    return sent


def _unnamed(names: Any) -> int:
    return sum(_TOOL.fullmatch(name) is None for name in names)


def encoded(document: Mapping[str, Any]) -> bytes:
    # ASCII: an upstream's odd name can't make the body unencodable (none is sent, but cheaply).
    return json.dumps(document, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()


class StatusPusher:
    """Pushes the gateway's status report. ``status`` reads the status of ``app``
    (:func:`.server.pushed_status`); ``clock``, ``wall``, ``jitter`` and ``sleep`` are the
    loop's."""

    def __init__(
        self,
        app: Any,
        http: httpx2.AsyncClient,
        status: Status,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        jitter: Callable[[], float] = random.random,
        sleep: Callable[[float], Awaitable[None]] = anyio.sleep,
    ) -> None:
        self._app = app
        self._http = http
        self._status = status
        self._clock = clock
        self._jitter = jitter
        self._sleep = sleep
        self.started = int(wall())
        self.sent: dict[str, Any] | None = None  # the last report the vault accepted
        self._sent_at: float | None = None
        self._next_try: float | None = None
        self._failures = 0
        self._logged: float | None = None

    def document(self) -> dict[str, Any] | None:
        """The report now, or None before the first view."""
        snapshot: Snapshot | None = self._app.policy.snapshot
        if snapshot is None:
            return None
        limits = snapshot.view.gateway.limits
        return content(
            self._status(self._app), started=self.started, max_tools=limits.max_tools_per_server
        )

    def due(self, document: Mapping[str, Any], now: float) -> bool:
        """Whether to post ``document`` now: the first, a change once the debounce has passed,
        or the same again once :data:`EVERY` has; never before a failure's backoff ends."""
        if self._next_try is not None and now < self._next_try:
            return False
        if self._sent_at is None:
            return True
        since = now - self._sent_at
        return since >= EVERY or (document != self.sent and since >= DEBOUNCE)

    async def run(self) -> None:
        """Push for ever; every failure ends only its round."""
        while True:
            try:
                document = self.document()
                due = document is not None and self.due(document, self._clock())
            except Exception as exc:  # a status that can't be read is a failed round
                self._failed(type(exc).__name__, self._clock())
                document, due = None, False
            if document is not None and due:
                await self.push_once(document)
            await self._sleep(STEP)

    async def push_once(self, document: dict[str, Any]) -> bool:
        """Post ``document``; whether the vault took it. Never raises."""
        body = encoded(document)
        now = self._clock()
        if len(body) > MAX_BYTES:
            self._failed("too_large", now)
            return False
        try:
            response = await self._http.post(
                STATUS_PATH, content=body, headers={"content-type": "application/json"}
            )
            answer = await response.aread()
        except Exception as exc:  # every failure is the same to the loop
            self._failed(type(exc).__name__, self._clock())
            return False
        now = self._clock()
        if response.status_code == 200:
            self.sent, self._sent_at = document, now
            self._next_try = None
            self._failures = 0
            return True
        code = vault_refusal_code(answer) or f"status_{response.status_code}"
        if response.status_code == 429:
            self._next_try = now + DEBOUNCE  # one was accepted just now, or is being read
            return False
        self._failed(code, now)
        return False

    def _failed(self, reason: str, now: float) -> None:
        self._failures += 1
        self._next_try = now + backoff(self._failures, 0.5 + self._jitter())
        if self._logged is None or now - self._logged >= LOG_EVERY:
            self._logged = now
            logs.event("status_push_failed", reason=reason, level="warning")
