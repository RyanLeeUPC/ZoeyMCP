"""Loading toolkits into the gateway (M4 design H.2).

When a view names a toolkit server, and on every view change:

1. the module is never ``zoeymcp`` or under it;
2. it must be registered: an entry point in the ``zoeymcp.toolkits`` group whose value names
   that module. Nothing is imported to find it, so a policy can never make the gateway import an
   arbitrary module;
3. every file of its distribution must sit under the environment's ``purelib`` or ``platlib``,
   and neither they, their directories nor ``sys.path`` may be writable by the gateway's uid.
   ``allow_writable`` skips this, for development and tests, and logs that it did on every start;
4. it is imported once per process, and must hold a :class:`~..toolkit.Toolkit`;
5. the code's slots must equal the policy's, kind for kind;
6. its definitions are projected, checked, pinned and marked on drift exactly like a remote
   server's. With ``pinning: off`` each tool is pinned to its own definition, and no drift mark
   is kept: a definition changes only with a new image and a restart;
7. a tool the code marks consequential that the policy allows without asking is hidden.

A failed load makes the server unavailable, with a reason that never holds a message. Python
can't unload a module: a changed module needs a new image and a restart.
"""

from __future__ import annotations

import importlib.metadata
import os
import sys
import sysconfig
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from mcp.types import Tool

from ..common import canonical
from ..common.policy.schema import GatewayLimits, Tools
from ..common.policy.view import ViewGateway, ViewToolkitServer
from ..toolkit import Toolkit, rules
from . import logs, pins
from .marks import DriftMarks
from .toolkitvault import ToolkitVault, slots_of
from .vaultlink import KeySource, Link

GROUP = "zoeymcp.toolkits"
EntryPoints = Callable[[], Iterable[importlib.metadata.EntryPoint]]


def installed_entry_points() -> list[importlib.metadata.EntryPoint]:
    return list(importlib.metadata.entry_points(group=GROUP))


@dataclass(frozen=True)
class Unavailable:
    """Why a toolkit server can't be served. ``detail`` holds names, never messages."""

    reason: Literal[
        "refused_name", "not_registered", "origin", "import_error", "not_a_toolkit", "slot_mismatch"
    ]
    detail: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SelfPinned:
    """A ``pinning: off`` server as :func:`.pins.evaluate` reads it: every tool pinned to its
    own definition, and drift hides only the tool (H.2 step 6)."""

    tools: Tools
    review: dict[str, str]
    on_drift: Literal["hide", "fail"] = "hide"
    declined: Mapping[str, str] = field(default_factory=dict)  # the policy's (M6 design J.5)


@dataclass
class Loaded:
    """A served toolkit server."""

    module: str
    toolkit: Toolkit
    distribution: str | None
    version: str | None
    policy: ViewToolkitServer
    evaluation: pins.Evaluation
    definitions: dict[str, dict[str, Any]]  # every generated definition, projected, by tool
    vault: ToolkitVault


@dataclass
class _Module:
    toolkit: Toolkit | None
    unavailable: Unavailable | None
    distribution: str | None = None
    version: str | None = None


class Toolkits:
    """Every toolkit server of one gateway process."""

    def __init__(
        self,
        link: Link,
        keys: KeySource | None,
        marks: DriftMarks,
        *,
        entry_points: EntryPoints = installed_entry_points,
        allow_writable: bool = False,
        inner_transport: Callable[[], Any] | None = None,
    ) -> None:
        self.link, self.keys, self.marks = link, keys, marks
        self.entry_points = entry_points
        self.allow_writable = allow_writable
        self.inner_transport = inner_transport
        self.limits = GatewayLimits()
        self._modules: dict[str, _Module] = {}
        self._servers: dict[str, Loaded | Unavailable] = {}
        self._vaults: dict[str, ToolkitVault] = {}
        self._retired: list[ToolkitVault] = []
        self._reported: set[tuple[str, str, str]] = set()
        if allow_writable:
            logs.event("toolkit_origin_unchecked", level="warning")

    def get(self, server: str) -> Loaded | Unavailable | None:
        return self._servers.get(server)

    def servers(self) -> dict[str, Loaded | Unavailable]:
        return dict(self._servers)

    def apply(self, gateway: ViewGateway) -> None:
        """Load and evaluate every toolkit server the view names; forget the rest."""
        self.limits = gateway.limits
        named = {
            name: server
            for name, server in gateway.servers.items()
            if isinstance(server, ViewToolkitServer)
        }
        for name in set(self._servers) - set(named):
            del self._servers[name]
            vault = self._vaults.pop(name, None)
            if vault is not None:
                self._retired.append(vault)
        for name, policy in sorted(named.items()):
            self._servers[name] = self._load(name, policy)

    async def aclose(self) -> None:
        """Close every client. Run after committed calls finished (M4 design B.6)."""
        vaults = [*self._vaults.values(), *self._retired]
        self._vaults.clear()
        self._retired.clear()
        for vault in vaults:
            await vault.aclose()

    # --- one server ------------------------------------------------------------------------------

    def _load(self, server: str, policy: ViewToolkitServer) -> Loaded | Unavailable:
        module = self._module(policy.module)
        if module.unavailable is not None or module.toolkit is None:
            found = module.unavailable or Unavailable("not_a_toolkit")
            self._once("toolkit_unavailable", server, {"reason": found.reason, **found.detail})
            return found
        toolkit = module.toolkit
        policy_slots = {name: slot.connector for name, slot in policy.slots.items()}
        mismatch = rules.slot_mismatch(toolkit.slots, policy_slots)
        if mismatch is not None:
            found = Unavailable("slot_mismatch", {"slot": mismatch})
            self._once("toolkit_unavailable", server, {"reason": found.reason, "slot": mismatch})
            return found
        definitions = {name: spec.definition() for name, spec in sorted(toolkit.tools.items())}
        listing = [Tool.model_validate(d) for d in definitions.values()]
        evaluation = self._evaluate(server, policy, listing)
        evaluation = self._floor(server, policy, toolkit, evaluation)
        projected = {}
        for tool in listing:
            try:
                projected[tool.name] = dict(pins.project_and_pin(tool).definition)
            except pins.ProjectionError:
                continue
        self._once(
            "toolkit_loaded",
            server,
            {
                "module": policy.module,
                "distribution": module.distribution,
                "version": module.version,
                "tools": {n: e.pin for n, e in sorted(evaluation.exposed.items())},
            },
        )
        return Loaded(
            module=policy.module,
            toolkit=toolkit,
            distribution=module.distribution,
            version=module.version,
            policy=policy,
            evaluation=evaluation,
            definitions=projected,
            vault=self._vault(server, policy),
        )

    def _evaluate(
        self, server: str, policy: ViewToolkitServer, listing: list[Tool]
    ) -> pins.Evaluation:
        if policy.pinning == "off":
            own: dict[str, str] = {}
            for tool in listing:
                try:
                    own[tool.name] = pins.project_and_pin(tool).pin
                except pins.ProjectionError:
                    continue
            reviewed = SelfPinned(policy.tools, own, declined=policy.declined)
            # An old mark whose pin equals a self-pin would keep the tool hidden: none are kept.
            self.marks.replace(server, frozenset())
            return pins.evaluate(listing, reviewed, frozenset(), self.limits)
        evaluation = pins.evaluate(listing, policy, self.marks.for_server(server), self.limits)
        added, removed = self.marks.replace(server, evaluation.marks)
        for name, _ in sorted(added):
            logs.event("drift_marked", server=server, tool=name)
        if removed:
            logs.event(
                "drift_cleared", server=server, tools=sorted(t for t, _ in removed), by="policy"
            )
        for report in evaluation.reports:
            if report.kind == "declined":
                continue  # the operator's own record: nothing to log
            if report.kind != "unreviewed" or report.tool in policy.tools.include:
                self._once(
                    f"tool_{report.kind}", server, {"tool": report.tool, "observed": report.pin}
                )
        return evaluation

    def _floor(
        self, server: str, policy: ViewToolkitServer, toolkit: Toolkit, evaluation: pins.Evaluation
    ) -> pins.Evaluation:
        """H.2 step 7: consequential in code but allowed in policy is hidden."""
        hidden = {
            name
            for name in evaluation.exposed
            if name in policy.tools.allow
            and rules.classification_hidden(toolkit.tools[name].consequential, "allow")
        }
        for name in sorted(hidden):
            self._once("toolkit_tool_invalid", server, {"tool": name, "reason": "classification"})
        if not hidden:
            return evaluation
        return pins.Evaluation(
            exposed={n: e for n, e in evaluation.exposed.items() if n not in hidden},
            reports=evaluation.reports,
            marks=evaluation.marks,
            blocked=evaluation.blocked,
            listed=evaluation.listed,
        )

    def _vault(self, server: str, policy: ViewToolkitServer) -> ToolkitVault:
        slots = slots_of(policy)
        vault = self._vaults.get(server)
        if vault is not None and vault.slots == slots:
            return vault
        if vault is not None:
            self._retired.append(vault)  # calls in flight still hold it
        inner = self.inner_transport() if self.inner_transport is not None else None
        vault = self._vaults[server] = ToolkitVault(
            server, slots, self.link, self.keys, inner=inner
        )
        return vault

    # --- the module ------------------------------------------------------------------------------

    def _module(self, module: str) -> _Module:
        found = self._modules.get(module)
        if found is None:
            found = self._modules[module] = self._import(module)
        return found

    def _import(self, module: str) -> _Module:
        if rules.module_refused(module):
            return _Module(None, Unavailable("refused_name"))
        entry = next(
            (e for e in self.entry_points() if rules.entry_module(e.value) == module), None
        )
        if entry is None:
            return _Module(None, Unavailable("not_registered"))
        dist = getattr(entry, "dist", None)
        name = dist.metadata["Name"] if dist is not None else None
        version = dist.version if dist is not None else None
        if not self.allow_writable:
            problem = origin_problem(dist)
            if problem is not None:
                return _Module(None, Unavailable("origin", {"problem": problem}), name, version)
        try:
            loaded = entry.load()
        except Exception as exc:  # anything the import raises: never its message
            return _Module(
                None, Unavailable("import_error", {"error_type": type(exc).__name__}), name, version
            )
        if not isinstance(loaded, Toolkit):
            return _Module(None, Unavailable("not_a_toolkit"), name, version)
        return _Module(loaded, None, name, version)

    def _once(self, event: str, server: str, fields: dict[str, Any]) -> None:
        """One log line per distinct event, server and fields per process: every view change
        re-evaluates, and the same news needn't be logged each time."""
        token = (event, server, canonical.dumps_canonical(fields).decode())
        if token in self._reported:
            return
        self._reported.add(token)
        logs.event(event, server=server, **fields)


def origin_problem(dist: importlib.metadata.Distribution | None) -> str | None:
    """Why a distribution may not be imported: a file outside the environment, or anything the
    gateway could write (H.2 step 3). ``None`` if it may."""
    if dist is None or not dist.files:
        return "no_record"
    if sys.platform == "win32":
        return "no_ownership_on_this_platform"
    roots = {sysconfig.get_paths()[k] for k in ("purelib", "platlib")}
    files = [Path(str(dist.locate_file(f))).resolve() for f in dist.files]
    outside = rules.outside_roots(
        [f.as_posix() for f in files], [Path(r).resolve().as_posix() for r in roots]
    )
    if outside:
        return "outside_environment"
    paths: set[Path] = set()
    for file in files:
        paths.add(file)
        paths.update(
            p
            for p in file.parents
            if any(p.is_relative_to(r) for r in roots) or p in map(Path, roots)
        )
    paths.update(Path(p).resolve() for p in sys.path if p)
    entries = []
    for path in sorted(paths):
        try:
            info = path.stat()
        except OSError:
            continue
        entries.append(rules.Entry(path.as_posix(), info.st_mode, info.st_uid, info.st_gid))
    if rules.writable_problems(entries, uid=os.getuid(), gids=frozenset(os.getgroups())):
        return "writable"
    return None
