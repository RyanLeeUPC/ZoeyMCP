"""The restart classifier: what a policy change needs besides taking effect (M6 design I.2;
D-193, and D-47 and D-61 by Q16 (a); Y16). Pure, mutation-tested.

A running vault takes a new policy at once, but a few values are read only when a process starts,
or are kept outside ZoeyMCP. :func:`classify` names each such change from ``old`` (the running
policy) to ``new`` as an :class:`Effect`, in this order:

- ``vault_restart``: ``egress_proxy`` or ``egress_proxy_kind`` (every vault client, connector and
  onboarding keeps the pair the vault started with, D-61), and ``admin.listen`` (the portal's
  listener). Each is compared with what the vault started with (:class:`Started`), not with
  ``old``: it is named again on every change until the restart, and a change back names nothing;
- ``gateway_restart``: a raised ``gateway.limits.max_request_bytes`` or ``session_idle_timeout``.
  The gateway's SDK session manager keeps the limit it started with; a lower one applies now,
  since the gateway's own checks follow every view (D-47);
- ``redeliver_gateway_key`` and ``redeliver_egress_key``: a raised key generation. A lowered one
  never gets here: it is refused first;
- ``reemit_proxy_allowlist``: the file ``check --emit-egress-allowlist --check`` compares changed,
  in any of its forms (every source ``egresslist.derive`` gives, the ``vault``'s and each route
  program's, and the Squid form's ``egress_proxy_acls`` names), while ``egress_proxy`` is set and
  is the operator's own proxy (advisory: the vault keeps no copy of the proxy's file);
- ``start_bridge``: a route's ``unix:`` upstream names a bridge the launcher didn't start
  (advisory).

Everything else is ``live``, and :func:`classify` names nothing for it. Each text is fixed
wording, with the policy's own values only. A declarative reload logs its two vault lines from
these (``egress_proxy_change_needs_restart``, ``admin_listen_change_needs_restart``); a managed
plan carries them all (G.5, G.7).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal

from .. import egresslist
from . import fields
from .findings import format_location
from .schema import GatewayLimits, Policy

EffectKind = Literal[
    "live",
    "vault_restart",
    "gateway_restart",
    "redeliver_gateway_key",
    "redeliver_egress_key",
    "reemit_proxy_allowlist",
    "start_bridge",
]

PROXY_TEXT: Final = "the vault's HTTP clients keep the proxy they started with: restart the vault"
LISTEN_TEXT: Final = "the portal keeps listening where it started: restart the vault"
LIMIT_TEXT: Final = (
    "the gateway's session manager keeps the limit it started with: restart the gateway for the "
    "higher value; a lower one applies now"
)
# Five minutes: vault/gatewaykeys.py's WINDOW, the previous key's grace.
GATEWAY_KEY_TEXT: Final = (
    "give the gateway key({generation}) within 5 minutes (zoeymcp gateway-key), or it is refused"
)
EGRESS_KEY_TEXT: Final = (
    "write the egress role's new key (zoeymcp egress-key) and restart the role: the old key is "
    "refused at once"
)
ALLOWLIST_TEXT: Final = (
    "your proxy's allowlist is out of date: check --emit-egress-allowlist --check"
)
BRIDGE_TEXT: Final = (
    "the launcher didn't start bridge {name}: add --bridge {name} and recreate the container"
)
# The path an allowlist effect names: the derived list, not one field of the policy.
ALLOWLIST_PATH: Final = "(egress allowlist)"
# The forms check --emit-egress-allowlist writes and --check compares (M7 design I.6).
_FORMATS: Final[tuple[egresslist.Format, ...]] = ("text", "json", "squid")
# The limits the gateway's session manager keeps from its start (F-35).
_STARTUP_LIMITS: Final = ("max_request_bytes", "session_idle_timeout")


@dataclass(frozen=True)
class Started:
    """What the running vault started with."""

    egress_proxy: str | None
    egress_proxy_kind: str
    admin_listen: str | None
    bridges: frozenset[str]  # --bridge names (standard tier)


@dataclass(frozen=True)
class Effect:
    kind: EffectKind
    path: str
    text: str  # fixed wording, with policy names only


def _limits(policy: Policy) -> GatewayLimits:
    return GatewayLimits() if policy.gateway is None else policy.gateway.limits


def _own_proxy(policy: Policy) -> bool:
    """Whether ``egress_proxy`` is the operator's own proxy, whose allowlist they keep."""
    return policy.egress_proxy is not None and policy.egress_proxy_kind == "own"


def _allowlist(policy: Policy) -> tuple[str, ...]:
    """The allowlist in every form ``--check`` compares, as ``check --emit-egress-allowlist``
    writes it. A destination's reasons are never emitted, so a change to them alone is none."""
    lists = egresslist.derive(policy)
    acl_names = policy.egress_proxy_acls
    return tuple(egresslist.render(lists, fmt, acl_names=acl_names) for fmt in _FORMATS)


def classify(old: Policy, new: Policy, started: Started) -> tuple[Effect, ...]:
    """Every change from ``old`` to ``new`` that needs more than taking effect, in the module
    docstring's order; empty when the whole change is live."""
    effects: list[Effect] = []
    if new.egress_proxy != started.egress_proxy:
        effects.append(Effect("vault_restart", "egress_proxy", PROXY_TEXT))
    if new.egress_proxy_kind != started.egress_proxy_kind:
        effects.append(Effect("vault_restart", "egress_proxy_kind", PROXY_TEXT))
    listen = None if new.admin is None else new.admin.listen
    if listen != started.admin_listen:
        effects.append(Effect("vault_restart", "admin.listen", LISTEN_TEXT))
    before, after = _limits(old), _limits(new)
    for name in _STARTUP_LIMITS:
        if getattr(after, name) > getattr(before, name):
            effects.append(Effect("gateway_restart", f"gateway.limits.{name}", LIMIT_TEXT))
    if new.gateway_key_generation > old.gateway_key_generation:
        text = GATEWAY_KEY_TEXT.format(generation=new.gateway_key_generation)
        effects.append(Effect("redeliver_gateway_key", "gateway_key_generation", text))
    if new.egress_key_generation > old.egress_key_generation:
        effects.append(Effect("redeliver_egress_key", "egress_key_generation", EGRESS_KEY_TEXT))
    if _own_proxy(new) and _allowlist(old) != _allowlist(new):
        effects.append(Effect("reemit_proxy_allowlist", ALLOWLIST_PATH, ALLOWLIST_TEXT))
    for index, route in enumerate(new.routes):
        upstream = route.upstream
        if upstream is None or not upstream.startswith(fields.UNIX_PREFIX):
            continue
        name = fields.bridge_name(upstream)
        if name not in started.bridges:
            path = format_location(("routes", index, "upstream"))
            effects.append(Effect("start_bridge", path, BRIDGE_TEXT.format(name=name)))
    return tuple(effects)
