"""Carrying out a secret plan (M5 design G): the store and token-manager writes, and their logs.

The I/O half of :mod:`.secretplan`, apart so mutation testing covers only the decisions. A
secret an oauth2 credential uses is written and deleted through the token manager, which first
waits for any refresh of that slot (design D.12). If the store can't write its file, the change
is kept in memory and the answer is ``not_written`` (B.4). An onboarding's client secret (an
:class:`~.secretplan.OnboardPutPlan`, M7 design D.7) is written by the store with its plan's
``meta``; nothing reads that ``meta`` to refuse or inject. A re-registration that fails after
its write puts the entry it replaced back as it was (:func:`restore`).

``secret_set`` and ``secret_deleted`` say which interface asked, in ``via``.
"""

from __future__ import annotations

from typing import Any, Literal

from . import logs
from .bindings import BindingError
from .oauth.tokens import TokenManager
from .secretplan import (
    NOT_FOUND,
    NOT_WRITTEN_REFUSAL,
    DeletePlan,
    OnboardPutPlan,
    PutPlan,
    SecretRefusal,
    binding_refusal,
)
from .store import KEEP, EntryMeta, Secret, SecretStore, StoreWriteError

Via = Literal["socket", "portal"]


async def put(
    store: SecretStore, tokens: TokenManager | None, plan: PutPlan | OnboardPutPlan, *, via: Via
) -> dict[str, Any] | SecretRefusal:
    """Write a planned secret. Returns the binding it was stored with, or the refusal."""
    try:
        if plan.oauth and tokens is not None:
            # The manager derives the binding again, from the policy it runs.
            binding = await tokens.replace_secret(plan.name, plan.value)
        else:
            binding = plan.binding
            meta = plan.meta if isinstance(plan, OnboardPutPlan) else KEEP
            store.put(plan.name, plan.value, binding, meta=meta)
    except StoreWriteError as exc:
        logs.event(
            "secret_set", name=plan.name, persisted=False, error_type=type(exc).__name__, via=via
        )
        return NOT_WRITTEN_REFUSAL
    except BindingError as exc:
        return binding_refusal(exc)
    except ValueError as exc:
        # The manager runs no oauth2 credential that uses the name: its policy moved since the
        # plan.
        return SecretRefusal(409, "not_oauth", str(exc))
    logs.event("secret_set", name=plan.name, binding=binding, via=via)
    return binding


async def restore(
    store: SecretStore, entry: EntryMeta, value: Secret, *, via: Via
) -> SecretRefusal | None:
    """Put an entry back as it was before a write replaced it: its value, binding and ``meta``
    (M7 design OPS-3, OPS-5). Returns the refusal, or ``None`` once it is back."""
    try:
        store.put(entry.name, value.reveal(), entry.binding, meta=entry.meta)
    except StoreWriteError as exc:
        logs.event(
            "secret_set", name=entry.name, persisted=False, error_type=type(exc).__name__, via=via
        )
        return NOT_WRITTEN_REFUSAL
    logs.event("secret_set", name=entry.name, binding=entry.binding, via=via)
    return None


async def delete(
    store: SecretStore, tokens: TokenManager | None, plan: DeletePlan, *, via: Via
) -> SecretRefusal | None:
    """Delete a planned secret. Returns the refusal, or ``None`` once it is gone."""
    try:
        if plan.oauth and tokens is not None:
            existed = await tokens.forget(plan.name)
        else:
            existed = store.delete(plan.name)
    except StoreWriteError as exc:
        logs.event(
            "secret_deleted",
            name=plan.name,
            persisted=False,
            error_type=type(exc).__name__,
            via=via,
        )
        return NOT_WRITTEN_REFUSAL
    if not existed:
        return NOT_FOUND
    logs.event("secret_deleted", name=plan.name, via=via)
    return None
