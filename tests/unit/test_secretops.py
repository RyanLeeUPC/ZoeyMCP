"""Carrying out secret plans (M5 design G), and an onboarding's client secret (M7 design D.7,
CR-12): the store branch writes the plan's ``meta``, and no refusal or injection reads it.

The meta helps find an entry; the binding alone decides where the secret may go, so an edited
meta changes no answer.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.vault import logs, secretops
from zoeymcp.vault.secretplan import (
    NOT_WRITTEN_REFUSAL,
    OnboardPutPlan,
    SecretRefusal,
    plan_delete,
    plan_onboard_secret,
    plan_put,
)
from zoeymcp.vault.store import SecretStore, SecretUnavailable

from .conftest import EXAMPLE_POLICY
from .test_oauth_tokens import KEYS, Captured, FailingWrites

pytestmark = pytest.mark.anyio

NAME = "notes-client-secret"
VALUE = "fake-notes-client-secret-0001"
TOKEN_URL = "https://auth.notes.example/token"
BINDING = {
    "oauth": {
        "token": "https://auth.notes.example:443",
        "resources": ["https://mcp.notes.example:443"],
    }
}
META = {
    "onboarded": "auth.notes.example",
    "resource": "https://mcp.notes.example/mcp",
    "client_id": "notes-client",
    "client_secret_expires_at": None,
}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def captured() -> Iterator[Captured]:
    capture = Captured()
    logs.set_stream(capture.stream)
    try:
        yield capture
    finally:
        logs.set_stream(None)


@pytest.fixture
def store(tmp_path: Path) -> SecretStore:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    held = SecretStore(state, KEYS)
    held.load()
    return held


def example_policy() -> Policy:
    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


def planned(store: SecretStore) -> OnboardPutPlan:
    plan = plan_onboard_secret(NAME, VALUE, BINDING, META, store_names=store.names())
    assert isinstance(plan, OnboardPutPlan)
    return plan


async def test_an_onboarding_secret_is_written_with_its_meta(
    store: SecretStore, captured: Captured
) -> None:
    written = await secretops.put(store, None, planned(store), via="socket")
    assert written == BINDING
    entry = store.entry(NAME)
    assert entry is not None
    assert (entry.binding, entry.meta) == (BINDING, META)
    assert store.get_for_oauth(NAME, token_url=TOKEN_URL)[0].reveal() == VALUE
    [line] = captured.events("secret_set")
    assert line == {**line, "name": NAME, "binding": BINDING, "via": "socket"}
    assert VALUE not in captured.text
    # Survives a restart: the meta is part of the entry on disk.
    reloaded = SecretStore(store.path.parent, KEYS)
    reloaded.load()
    assert reloaded.entry(NAME) == entry


async def test_a_plain_write_keeps_the_meta(store: SecretStore) -> None:
    """``zoeymcp secret set`` of the same name later: its plan has no meta, so the entry keeps
    the one it had."""
    await secretops.put(store, None, planned(store), via="socket")
    plan = plan_put(
        NAME, {"value": "fake-new-value-0002", "origins": ["https://x.example"]}, example_policy()
    )
    assert not isinstance(plan, SecretRefusal)
    assert await secretops.put(store, None, plan, via="portal") == plan.binding
    entry = store.entry(NAME)
    assert entry is not None
    assert (entry.binding, entry.meta) == (plan.binding, META)


async def test_no_refusal_or_injection_reads_the_meta(store: SecretStore) -> None:
    """F-44: the meta is clear text anyone with the state file can edit. Edited to name
    another resource and client, it changes where the secret may go not at all."""
    await secretops.put(store, None, planned(store), via="socket")
    store.update_meta(
        NAME,
        {
            "onboarded": "attacker.example",
            "resource": "https://attacker.example/mcp",
            "client_id": "x",
        },
    )
    assert store.get_for_oauth(NAME, token_url=TOKEN_URL)[0].reveal() == VALUE
    with pytest.raises(SecretUnavailable):
        store.get_for_oauth(NAME, token_url="https://attacker.example/token")
    with pytest.raises(SecretUnavailable):
        store.get_for_origin(NAME, "https://attacker.example/mcp")
    # A second onboarding under the name is name_taken, whatever the meta says.
    again = plan_onboard_secret(NAME, VALUE, BINDING, META, store_names=store.names())
    assert again == SecretRefusal(409, "name_taken", f"the store already has {NAME}")


async def test_a_write_that_cant_be_persisted(
    store: SecretStore, monkeypatch: pytest.MonkeyPatch, captured: Captured
) -> None:
    plan = planned(store)
    writes = FailingWrites(monkeypatch)
    writes.failing = True
    assert await secretops.put(store, None, plan, via="socket") == NOT_WRITTEN_REFUSAL
    [line] = captured.events("secret_set")
    assert line == {**line, "name": NAME, "persisted": False, "via": "socket"}
    # Kept in memory, with its meta, as any write that failed on disk (B.4).
    entry = store.entry(NAME)
    assert entry is not None
    assert entry.meta == META


async def test_an_onboarding_secret_is_deleted_as_any_other(
    store: SecretStore, captured: Captured
) -> None:
    await secretops.put(store, None, planned(store), via="socket")
    assert (
        await secretops.delete(store, None, plan_delete(NAME, example_policy()), via="socket")
        is None
    )
    assert store.entry(NAME) is None
    assert [line["name"] for line in captured.events("secret_deleted")] == [NAME]
