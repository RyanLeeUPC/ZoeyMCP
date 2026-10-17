from __future__ import annotations

from pathlib import Path

import pytest

from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.server import StartupError, load_runtime
from zoeymcp.vault.store import SecretStore, origin_binding

from .conftest import EXAMPLE_POLICY


def env(**extra: str) -> dict[str, str]:
    return {"ZOEYMCP_MASTER_KEY": generate_master_key(), **extra}


def test_starts_with_the_example(tmp_path: Path) -> None:
    runtime = load_runtime(str(EXAMPLE_POLICY), tmp_path, env())
    assert runtime.policy.mode == "declarative"
    assert runtime.store.names() == []


def test_needs_a_master_key(tmp_path: Path) -> None:
    with pytest.raises(StartupError, match="ZOEYMCP_MASTER_KEY is not set"):
        load_runtime(str(EXAMPLE_POLICY), tmp_path, {})
    with pytest.raises(StartupError, match="32 bytes"):
        load_runtime(str(EXAMPLE_POLICY), tmp_path, {"ZOEYMCP_MASTER_KEY": "c2hvcnQ"})


def test_refuses_a_policy_that_fails_check(tmp_path: Path, example_text: str) -> None:
    bad = example_text.replace(
        "callers: [gateway] # the gateway only", "callers: [{placeholder: ph-sandbox-0123456789}]"
    )
    policy_file = tmp_path / "bad.yaml"
    policy_file.write_text(bad, encoding="utf-8")
    with pytest.raises(StartupError, match="fails check"):
        load_runtime(str(policy_file), tmp_path, env())


def test_refuses_managed_mode_for_now(tmp_path: Path, example_text: str) -> None:
    policy_file = tmp_path / "managed.yaml"
    policy_file.write_text(example_text.replace("mode: declarative", "mode: managed"), "utf-8")
    with pytest.raises(StartupError, match="managed mode arrives in M6"):
        load_runtime(str(policy_file), tmp_path, env())


def test_refuses_a_store_from_another_key(tmp_path: Path) -> None:
    old = generate_master_key()
    store = SecretStore(tmp_path, KeySet.from_text(old))
    store.load()
    store.put("x", "v", origin_binding(["https://api.example"]))
    with pytest.raises(StartupError, match="ZOEYMCP_MASTER_KEY_PREVIOUS"):
        load_runtime(str(EXAMPLE_POLICY), tmp_path, env())
    rotated = load_runtime(str(EXAMPLE_POLICY), tmp_path, env(ZOEYMCP_MASTER_KEY_PREVIOUS=old))
    assert rotated.store.names() == ["x"]
