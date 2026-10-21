"""The decision of a secret write or delete (M5 design G). Pure, so each reason can be tested.

The admin socket's ``PUT/DELETE /secrets/{name}``, and the portal's ``secret.put`` and
``secret.delete``, decide here and carry the plan out with :mod:`.secretops`, so every write
takes one path whatever asked for it (D-17).

An onboarding's client secret (M7 design D.7) is planned here too, by
:func:`plan_onboard_secret`: a write under the binding fragment 1 will derive, with clear
``meta`` to find the entry by, which no refusal or injection reads.

A refusal's ``message`` is the socket's text. Its ``reason`` is stable, so another caller can
answer each case in its own words. Reading the body (``too_large``, ``bad_json``) is the
caller's.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from ..common.policy.schema import Policy
from ..common.textrules import find_violations
from .bindings import VAULT_PREFIX, BindingError, BindingReason, derive_binding, oauth_secret_names
from .store import MAX_SECRET_BYTES, origin_binding

# The same shape as the name in a store: reference.
NAME: Final = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
MAX_VALUE_CHARS: Final = 65536
NOT_WRITTEN: Final = "kept in memory, not written to disk; check the state volume"

Reason = Literal[
    "invalid_name",
    "vault_managed",
    "bad_body",
    "empty_value",
    "bad_value",
    "value_too_large",
    "origins_type",
    "origins_on_oauth",
    "bad_origins",
    "unbound",
    "no_route",
    "orphan_slot",
    "binding_conflict",
    "not_oauth",
    "not_written",
    "not_found",
    "name_taken",
]

_BINDING_REASONS: Final[dict[BindingReason, Reason]] = {
    "unbound": "unbound",
    "no_route": "no_route",
    "orphan_slot": "orphan_slot",
    "conflict": "binding_conflict",
    "not_oauth": "not_oauth",
}


@dataclass(frozen=True)
class SecretRefusal:
    status: int
    reason: Reason
    message: str


NOT_WRITTEN_REFUSAL: Final = SecretRefusal(500, "not_written", NOT_WRITTEN)
NOT_FOUND: Final = SecretRefusal(404, "not_found", "no such secret")


@dataclass(frozen=True)
class PutPlan:
    """A write that passed every check. ``oauth``: an oauth2 credential uses the name, so the
    token manager writes it when there is one."""

    name: str
    value: str = field(repr=False)
    binding: dict[str, Any]
    oauth: bool


@dataclass(frozen=True)
class OnboardPutPlan:
    """An onboarding's client secret (M7 design D.7, CR-12): written by the store under the
    binding fragment 1 will derive, with ``meta``. No running credential uses the name yet, so
    ``oauth`` is always false: the token manager never writes it."""

    name: str
    value: str = field(repr=False)
    binding: dict[str, Any]
    meta: dict[str, Any]
    oauth: Literal[False] = False


@dataclass(frozen=True)
class DeletePlan:
    """A delete. ``oauth`` as in :class:`PutPlan`."""

    name: str
    oauth: bool


def check_name(name: str) -> SecretRefusal | None:
    """The checks on the name of a write, which the socket makes before it reads the body."""
    if not NAME.fullmatch(name):
        return SecretRefusal(400, "invalid_name", "invalid secret name")
    if name.startswith(VAULT_PREFIX):
        return SecretRefusal(409, "vault_managed", "managed by the vault; use zoeymcp login")
    return None


def plan_put(name: str, data: Any, policy: Policy) -> PutPlan | SecretRefusal:
    """Check a write of ``data`` (``{value, origins?}``, as parsed) and find its binding.

    Without ``origins`` the binding is derived from the policy; with them it is those origins,
    which an OAuth secret never takes.
    """
    refusal = check_name(name)
    if refusal is not None:
        return refusal
    if not isinstance(data, dict) or not set(data) <= {"value", "origins"}:
        return SecretRefusal(400, "bad_body", "expected {value, origins?}")
    value = _value(data.get("value"))
    if isinstance(value, SecretRefusal):
        return value
    origins = data.get("origins")
    oauth = name in oauth_secret_names(policy)
    if origins is not None:
        if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
            return SecretRefusal(400, "origins_type", "origins must be a list of URLs")
        if oauth:
            return SecretRefusal(
                409, "origins_on_oauth", "OAuth secrets are bound by the policy; drop --origin"
            )
    try:
        binding = derive_binding(policy, name) if origins is None else origin_binding(origins)
    except BindingError as exc:
        return binding_refusal(exc)
    except ValueError as exc:
        return SecretRefusal(409, "bad_origins", str(exc))
    refusal = _check_size(value)
    if refusal is not None:
        return refusal
    return PutPlan(name, value, binding, oauth)


def plan_onboard_secret(
    name: str,
    value: object,
    binding: Mapping[str, Any],
    meta: Mapping[str, Any],
    *,
    store_names: Collection[str],
) -> OnboardPutPlan | SecretRefusal:
    """Check an onboarding's client secret (D.7): a name the store doesn't have yet
    (``name_taken``) and a value a write would take. ``binding`` is the one fragment 1 will
    derive for the name; ``meta`` says what the entry is for, and nothing decides on it."""
    refusal = check_name(name)
    if refusal is not None:
        return refusal
    if name in store_names:
        return SecretRefusal(409, "name_taken", f"the store already has {name}")
    checked = _value(value)
    if isinstance(checked, SecretRefusal):
        return checked
    refusal = _check_size(checked)
    if refusal is not None:
        return refusal
    return OnboardPutPlan(name, checked, dict(binding), dict(meta))


def _value(value: object) -> str | SecretRefusal:
    """A value a write takes: a non-empty string on one line, with no hidden characters."""
    if not isinstance(value, str) or not value:
        return SecretRefusal(400, "empty_value", "value must be a non-empty string")
    if find_violations(value, max_chars=MAX_VALUE_CHARS, single_line=True, allow_tabs=False):
        return SecretRefusal(
            400, "bad_value", "value has line breaks, control or invisible characters"
        )
    return value


def _check_size(value: str) -> SecretRefusal | None:
    """The store's own limit, checked here so a plan never fails on it. A character can take up
    to four bytes, so the character limit of :func:`_value` doesn't cover it."""
    if len(value.encode("utf-8")) > MAX_SECRET_BYTES:
        return SecretRefusal(
            409, "value_too_large", f"a secret can't be larger than {MAX_SECRET_BYTES} bytes"
        )
    return None


def plan_delete(name: str, policy: Policy) -> DeletePlan:
    """A delete of any name: no name or prefix check, so a live slot can be deleted (it re-seeds
    from the policy on next use). Whether it existed is the store's answer (:data:`NOT_FOUND`).
    """
    return DeletePlan(name, name in oauth_secret_names(policy))


def binding_refusal(exc: BindingError) -> SecretRefusal:
    """The refusal of a write the policy can't bind."""
    return SecretRefusal(409, _BINDING_REASONS[exc.reason], str(exc))
