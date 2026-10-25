"""Managed mode's running policy (M6 design G.6, F.6, K.1, M.5; Y1, Y16; G-3, G-5, MISS-9), in
process: the one write path and its order (the head check, the gate, the plan the caller
confirmed, ``gatewaykeys.check``, the commit, the install), a write synchronous from its first
line to its return, so nothing else on the event loop runs inside it (FM-15), a retry whose
answer was lost (FM-16), an install that can't write the gateway-key state and the ``SIGHUP``
that installs it after (FM-5), the revision-to-view-digest map, the log lines of a save, and a
declarative start's view of a store it parked (F.4, T-16).

Each test starts a managed vault with ``load_runtime`` on a fresh volume (the seed, F.3) and
builds the holder on a :class:`VaultApp` as ``server.build`` does.
"""

from __future__ import annotations

import asyncio
import errno
import io
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.unit.conftest import EXAMPLE_POLICY
from zoeymcp.cli import onboard as onboard_cli
from zoeymcp.common.policy import restart
from zoeymcp.common.policy.plan import WritePlan
from zoeymcp.common.policy.ratchet import Grants
from zoeymcp.common.policy.schema import Policy
from zoeymcp.portal.policyview import view as policy_view
from zoeymcp.vault import gatewaykeys, logs, policystore
from zoeymcp.vault import managed as managed_module
from zoeymcp.vault.admin import HealthReader
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.keys import generate_master_key
from zoeymcp.vault.managed import (
    DEFAULT_COMPOSE_CMD,
    DEFAULT_SERVICE,
    DeclarativeStore,
    ManagedPolicy,
    WriteRefused,
    Written,
    commands,
    plan_digest,
)
from zoeymcp.vault.policystart import Commands
from zoeymcp.vault.policystore import PolicyStore
from zoeymcp.vault.server import Runtime, load_runtime
from zoeymcp.vault.statusreport import Report, ServerStatus

HOST = {"by": "host", "via": "socket"}
OTHER = {"by": "host", "via": "offline"}
PASSKEY = {"by": "passkey", "fingerprint": "0123456789abcdef"}
NEW_PIN = "sha256:" + "a" * 64


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def events(buffer: io.StringIO) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    for line in lines:
        del line["ts"]
        del line["role"]
    return lines


def managed_text() -> str:
    return EXAMPLE_POLICY.read_text(encoding="utf-8").replace("mode: declarative", "mode: managed")


@dataclass
class Rig:
    state: Path
    environ: dict[str, str]
    runtime: Runtime
    app: VaultApp
    managed: ManagedPolicy

    @property
    def store(self) -> PolicyStore:
        held = self.runtime.policy_store
        assert held is not None
        return held


def start(
    tmp_path: Path, text: str | None = None, *, key: str | None = None, **environ: str
) -> Rig:
    """A managed vault: on a fresh volume, revision 1 seeded from ``text``; on one it started
    before (with its ``key``), the head."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700, exist_ok=True)
    found = {"ZOEYMCP_MASTER_KEY": key or generate_master_key(), **environ}
    config = tmp_path / "policy.yaml"
    config.write_bytes((text or managed_text()).encode())
    runtime = load_runtime(str(config), state, found)
    assert runtime.policy_store is not None
    assert runtime.ratchet is not None
    app = VaultApp(
        runtime.policy, runtime.store, runtime.keys, environ={}, gateway_keys=runtime.gateway_keys
    )
    managed = ManagedPolicy(
        runtime.policy_store,
        app,
        policy=runtime.policy,
        ratchet=runtime.ratchet,
        secrets=runtime.store,
        environ=found,
        started=restart.Started(
            app.egress_proxy,
            app.egress_proxy_kind,
            None if runtime.policy.admin is None else runtime.policy.admin.listen,
            frozenset(),
        ),
        reopen=lambda: PolicyStore.open(state, runtime.keys, runtime.previous, strays=False),
        seed_ignored=runtime.seed_ignored,
    )
    return Rig(state, found, runtime, app, managed)


def close(rig: Rig) -> None:
    asyncio.run(rig.app.aclose())


def edited(change: Callable[[dict[str, Any]], None]) -> Callable[[Policy], Policy]:
    """A candidate builder: the policy it is given, changed by ``change``."""

    def build(policy: Policy) -> Policy:
        data = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        change(data)
        return Policy.model_validate(data)

    return build


def generation(value: int) -> Callable[[Policy], Policy]:
    return edited(lambda data: data.update(gateway_key_generation=value))


def move_and_repin(data: dict[str, Any]) -> None:
    """cancel_order from approve to allow, and place_order re-pinned."""
    trade = data["gateway"]["servers"]["broker-trade"]
    trade["tools"]["approve"] = ["place_order"]
    trade["tools"]["allow"] = ["cancel_order"]
    trade["review"]["place_order"] = NEW_PIN


def import_(rig: Rig, build: Callable[[Policy], Policy], **kw: Any) -> Written | WriteRefused:
    """A socket import planned on the head."""
    return rig.managed.write(
        "policy.import",
        "socket",
        kw.pop("base", rig.managed.revision),
        build,
        author=kw.pop("author", HOST),
        expected=kw.pop("expected", None),
        **kw,
    )


# --- the host's commands (J5b, J16) ------------------------------------------------------------


def test_the_commands_are_the_onboardings_and_the_tiers() -> None:
    """The refusals name the host's own commands (11c's Commands, from ZOEYMCP_COMPOSE_CMD and
    ZOEYMCP_EXEC_SERVICE as onboarding's next lines do, M7 M.7), with the standard tier's
    --user (OPS-5)."""
    assert (DEFAULT_COMPOSE_CMD, DEFAULT_SERVICE) == (
        onboard_cli.DEFAULT_COMPOSE_CMD,
        onboard_cli.DEFAULT_EXEC_SERVICE,
    )
    assert commands({}, "/state", standard=False) == Commands(
        "docker compose -f deploy/compose.hardened.yaml", "vault", None, "/state"
    )
    environ = {
        onboard_cli.COMPOSE_CMD_ENV: "docker compose -f deploy/compose.yaml",
        onboard_cli.EXEC_SERVICE_ENV: "zoeymcp",
    }
    found = commands(environ, "/state", standard=True)
    assert found == Commands("docker compose -f deploy/compose.yaml", "zoeymcp", "10001:10001")
    assert found.run("policy seed --state /state") == (
        "docker compose -f deploy/compose.yaml run --rm --no-deps --user 10001:10001 zoeymcp "
        "policy seed --state /state"
    )


# --- the write (G.6) ---------------------------------------------------------------------------


def test_a_write_commits_installs_and_logs(tmp_path: Path, log_buffer: io.StringIO) -> None:
    """G.6 steps 3-9: the candidate built on the head is committed as the next revision and
    installed; the answer carries the plan's effects and gateway pending (K.1); the map gains
    the new view's digest; the log has the revision's line (N.3, with the write's kind as
    ``write_kind``), a ``tool_allowed`` per move and a ``tool_repinned`` per re-pin (Q27)."""
    rig = start(tmp_path)
    before = rig.app.view_digest
    log_buffer.truncate(0)
    log_buffer.seek(0)
    written = import_(rig, edited(move_and_repin))
    assert isinstance(written, Written)
    assert (written.revision, written.already_saved, written.gateway) == (2, False, "pending")
    assert written.digest == rig.store.head.digest  # type: ignore[union-attr]
    assert written.effects == ()
    trade = rig.app.policy.gateway.servers["broker-trade"]  # type: ignore[union-attr]
    assert trade.tools.allow == ["cancel_order"]
    assert rig.managed.view_digests == {1: before, 2: rig.app.view_digest}
    assert before != rig.app.view_digest
    assert rig.store.header["kind"] == "policy.import"  # type: ignore[index]
    assert rig.store.header["author"] == HOST  # type: ignore[index]
    lines = events(log_buffer)
    saved = [line for line in lines if line["event"] == "policy_imported"]
    assert saved == [
        {
            "event": "policy_imported",
            "revision": 2,
            "write_kind": "policy.import",
            "origin": "import",
            "author": "host",
            "base": 1,
            "digest": written.digest.removeprefix("sha256:")[:8],
            "effects": [],
        }
    ]
    tools = [line for line in lines if line["event"] in ("tool_allowed", "tool_repinned")]
    assert tools == [
        {
            "event": "tool_allowed",
            "server": "broker-trade",
            "def_kind": "tool",
            "name": "cancel_order",
            "revision": 2,
        },
        {
            "event": "tool_repinned",
            "server": "broker-trade",
            "def_kind": "tool",
            "name": "place_order",
            "revision": 2,
        },
    ]
    assert rig.managed.state().not_running is None
    close(rig)


def test_an_acknowledged_restore_logs_where_it_jumped_from(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    """K.3, N.3: ``policy_acknowledged`` carries ``jumped_from``, as the header does."""
    rig = start(tmp_path)
    written = rig.managed.write(
        "policy.acknowledge", "socket", 1, generation(2), author=HOST, expected=None, jumped_from=1
    )
    assert isinstance(written, Written)
    assert rig.store.header["jumped_from"] == 1  # type: ignore[index]
    [line] = [line for line in events(log_buffer) if line["event"] == "policy_acknowledged"]
    assert line["jumped_from"] == 1
    close(rig)


def test_a_portal_save_is_logged_by_the_passkeys_fingerprint(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    """A portal save (here a client's servers) is ``policy_saved`` with the passkey's first 8."""
    rig = start(tmp_path)
    written = rig.managed.write(
        "client.servers",
        "portal",
        1,
        edited(lambda data: data["gateway"]["clients"]["agent1"].update(servers=["mail"])),
        author=PASSKEY,
        expected=None,
    )
    assert isinstance(written, Written)
    [saved] = [line for line in events(log_buffer) if line["event"] == "policy_saved"]
    assert (saved["author"], saved["origin"], saved["write_kind"]) == (
        "01234567",
        "save",
        "client.servers",
    )
    close(rig)


def test_commit_is_serial(tmp_path: Path) -> None:
    """FM-15 (T29, G-3): ``write`` holds no await, so a coroutine scheduled while it runs (here
    from inside the candidate's build) runs only after it returns; the second of two writes
    planned on the same revision meets the moved head (``policy_moved``, naming the revision,
    when and by whom)."""
    rig = start(tmp_path)
    ran: list[str] = []

    async def other() -> None:
        ran.append("other")

    def build(policy: Policy) -> Policy:
        asyncio.get_running_loop().call_soon(ran.append, "callback")
        tasks.append(asyncio.ensure_future(other()))
        return edited(move_and_repin)(policy)

    tasks: list[asyncio.Future[None]] = []

    async def main() -> tuple[Written | WriteRefused, Written | WriteRefused]:
        first = import_(rig, build, base=1)
        ran.append("returned")
        second = import_(rig, generation(2), base=1)
        ran.append("second returned")
        await asyncio.gather(*tasks)
        return first, second

    first, second = asyncio.run(main())
    assert ran[:2] == ["returned", "second returned"]
    assert sorted(ran[2:]) == ["callback", "other"]
    assert isinstance(first, Written)
    assert first.revision == 2
    assert isinstance(second, WriteRefused)
    assert second.reason == "policy_moved"
    assert second.revision == 2
    assert second.detail.startswith("the policy moved to revision 2, saved ")
    assert second.detail.endswith(" by the host (socket) since you started")
    assert rig.store.head.revision == 2  # type: ignore[union-attr]
    close(rig)


def test_retry_is_idempotent(tmp_path: Path) -> None:
    """FM-16 (MISS-9, Q39): the same write retried on its base, whose answer was lost, answers
    ``already_saved`` with the revision it made; one by another author, of another kind, or
    building another policy is ``policy_moved``."""
    rig = start(tmp_path)
    build = edited(move_and_repin)
    first = import_(rig, build)
    assert isinstance(first, Written)
    again = import_(rig, build, base=1)
    assert again == Written(2, first.digest, already_saved=True)
    for refused in (
        import_(rig, build, base=1, author=OTHER),
        import_(rig, generation(2), base=1),
        rig.managed.write("policy.acknowledge", "socket", 1, build, author=HOST, expected=None),
    ):
        assert isinstance(refused, WriteRefused)
        assert refused.reason == "policy_moved"
    assert rig.store.head.revision == 2  # type: ignore[union-attr]
    close(rig)


def test_a_retry_whose_base_isnt_kept_is_moved(tmp_path: Path) -> None:
    """A retry whose base can't be read again (pruned, or failing now) can't be told apart: it
    is ``policy_moved``, never a second commit."""
    rig = start(tmp_path)
    build = edited(move_and_repin)
    assert isinstance(import_(rig, build), Written)
    (rig.state / "policy" / "revisions" / "0000000001.json").write_bytes(b"{}")
    refused = import_(rig, build, base=1)
    assert isinstance(refused, WriteRefused)
    assert refused.reason == "policy_moved"
    close(rig)


def test_the_plan_must_be_the_one_confirmed(tmp_path: Path) -> None:
    """G.6 step 4 (Y8, F-20): a portal write whose held plan differs is ``changed``, a socket
    write whose plan digest differs ``plan_changed``, each with the new plan; the same plan or
    digest commits."""
    rig = start(tmp_path)
    build = edited(move_and_repin)
    wrong = import_(rig, build, expected="sha256:" + "0" * 64)
    assert isinstance(wrong, WriteRefused)
    assert wrong.reason == "plan_changed"
    assert wrong.plan is not None
    other = import_(rig, generation(2), expected=None)
    assert isinstance(other, Written)
    # The held plan was made on revision 1: re-planned on 2 it is another plan.
    moved = import_(rig, build, expected=wrong.plan)
    assert isinstance(moved, WriteRefused)
    assert moved.reason == "changed"
    assert moved.plan is not None
    assert moved.plan != wrong.plan
    digest = plan_digest(moved.plan)
    assert isinstance(import_(rig, build, expected=digest), Written)
    close(rig)


def test_a_held_plan_equal_to_the_new_one_commits(tmp_path: Path) -> None:
    rig = start(tmp_path)
    build = edited(move_and_repin)
    refused = import_(rig, build, expected="sha256:" + "0" * 64)
    assert isinstance(refused, WriteRefused)
    assert isinstance(refused.plan, WritePlan)
    written = import_(rig, build, expected=refused.plan)
    assert isinstance(written, Written)
    assert written.revision == 2
    close(rig)


def test_what_the_gate_or_the_planner_refuses_writes_nothing(tmp_path: Path) -> None:
    """G.6 steps 3 and 4: a candidate that fails check is ``import_refused`` with the gate's
    text, and the planner's refusal passes through with its reason (here rule 6's
    ``no_change``); neither writes a file or changes the running policy."""
    rig = start(tmp_path)
    head = rig.store.head
    running = rig.app.policy
    secret = {"kind": "header", "header": "X-Key", "format": "{secret}", "secret": "env:UNSET_K"}
    failing = import_(rig, edited(lambda data: data["credentials"].update(k=secret)))
    assert isinstance(failing, WriteRefused)
    assert failing.reason == "import_refused"
    assert failing.detail == (
        "policy revision 2 fails check (1 error(s)): credentials.k.secret: env var UNSET_K is "
        "not set"
    )
    same = import_(rig, edited(lambda data: None))
    assert same == WriteRefused("no_change")
    assert rig.store.head == head
    assert rig.app.policy is running
    assert not (rig.state / "policy" / "revisions" / "0000000002.json").exists()
    close(rig)


def test_a_lower_gateway_key_generation_is_refused_before_any_file(tmp_path: Path) -> None:
    """G.6 step 5 (G-4): ``gatewaykeys.check`` against the gateway-key state, here ahead of the
    policy's generation, refuses before the commit, so an install fails only on I/O."""
    rig = start(tmp_path)
    head = rig.store.head
    rig.app.gateway_keys.advance(3)
    refused = import_(rig, edited(move_and_repin))
    assert isinstance(refused, WriteRefused)
    assert refused.reason == "generation_lowered"
    assert "below 3" in refused.detail
    assert rig.store.head == head
    close(rig)


def test_a_store_that_cant_write_refuses_with_nothing_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """G.6 step 7, FM-4: the store's ``policy_write_failed`` passes through; the head and the
    running policy stay."""
    rig = start(tmp_path)
    head = rig.store.head
    running = rig.app.policy

    def broken(*args: Any) -> None:
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(policystore, "write_revision", broken)
    refused = import_(rig, edited(move_and_repin))
    assert isinstance(refused, WriteRefused)
    assert refused.reason == "policy_write_failed"
    assert rig.store.head == head
    assert rig.app.policy is running
    close(rig)


def test_install_fails_then_sighup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, log_buffer: io.StringIO
) -> None:
    """FM-5 (Y1, G-5): the gateway-key state can't be written at the install, so the revision
    stays committed and the old head runs: ``saved_not_running``, ``policy_not_installed``
    (critical), health's ``policy_not_running`` (error), the policy view still naming the
    revision it shows (G.10), and the next write refused ``policy_not_running``. A SIGHUP that
    still can't write it is refused; one that can installs the head and clears it all."""
    rig = start(tmp_path)
    health = HealthReader(rig.runtime.store, lambda: rig.app.policy, policy_state=rig.managed.state)
    real = gatewaykeys.write_atomic

    def broken(*args: Any) -> None:
        raise OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    refused = import_(rig, generation(2))
    assert isinstance(refused, WriteRefused)
    assert refused.reason == "saved_not_running"
    assert refused.revision == 2
    assert refused.detail == (
        "saved as revision 2, but the vault couldn't apply it: send SIGHUP to the vault or "
        "restart it"
    )
    assert rig.store.head.revision == 2  # type: ignore[union-attr]
    assert rig.app.policy.gateway_key_generation == 1
    [line] = [line for line in events(log_buffer) if line["event"] == "policy_not_installed"]
    assert (line["level"], line["revision"]) == ("critical", 2)
    assert "can't write" in line["reason"]
    assert rig.managed.not_running == 2
    assert rig.managed.header["revision"] == 1  # type: ignore[index]
    shown = policy_view(rig.app.policy, "managed", header=rig.managed.header)["source_shown"]
    assert shown.startswith("revision 1, saved ")
    section = health.report()["policy"]
    assert section["level"] == "error"
    assert [f["code"] for f in section["findings"]] == ["policy_not_running"]
    assert section["findings"][0]["action"] == {"kind": "reload_vault"}
    blocked = import_(rig, edited(move_and_repin))
    assert blocked == WriteRefused(
        "policy_not_running",
        "revision 2 is saved but not running: send SIGHUP to the vault or restart it",
        revision=2,
    )
    # A SIGHUP that still can't write it keeps the old head running.
    assert rig.managed.reverify(None) is None
    assert events(log_buffer)[-1]["event"] == "reload_refused"
    assert rig.managed.not_running == 2
    monkeypatch.setattr(gatewaykeys, "write_atomic", real)
    assert rig.managed.reverify(None) is True
    assert rig.app.policy.gateway_key_generation == 2
    assert rig.managed.not_running is None
    assert rig.managed.header["revision"] == 2
    assert 2 in rig.managed.view_digests
    assert health.report()["policy"]["findings"] == []
    # Nothing left to install: a SIGHUP now installs nothing.
    assert rig.managed.reverify(None) is False
    assert isinstance(import_(rig, edited(move_and_repin)), Written)
    close(rig)


def test_the_map_keeps_the_newest_revisions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """K.1's map: the view digest of each revision installed, the newest KEEP of them."""
    monkeypatch.setattr("zoeymcp.vault.managed.KEEP", 2)
    rig = start(tmp_path)
    for value in (2, 3, 4):
        assert isinstance(import_(rig, generation(value)), Written)
    assert sorted(rig.managed.view_digests) == [3, 4]
    assert rig.managed.view_digests[4] == rig.app.view_digest
    close(rig)


# --- SIGHUP (F.6) ------------------------------------------------------------------------------


def test_a_sighup_never_applies_the_source(tmp_path: Path, log_buffer: io.StringIO) -> None:
    """F.5, F.6 (DD-7, Y19): a SIGHUP with the head running installs nothing and compares the
    source: an unchanged one is no finding, a changed one ``policy_seed_ignored`` (and health's
    finding), never applied."""
    from zoeymcp.vault.server import configured

    rig = start(tmp_path)
    config = str(tmp_path / "policy.yaml")
    assert rig.managed.reverify(configured(config, rig.environ)) is False
    assert rig.managed.state().seed_ignored is None
    (tmp_path / "policy.yaml").write_bytes(
        managed_text().replace("timeout: 300", "timeout: 120").encode()
    )
    assert rig.managed.reverify(configured(config, rig.environ)) is False
    assert rig.managed.state().seed_ignored == "changed"
    assert rig.app.policy.gateway.approvals.timeout == 300  # type: ignore[union-attr]
    [line] = [line for line in events(log_buffer) if line["event"] == "policy_seed_ignored"]
    assert line == {
        "event": "policy_seed_ignored",
        "level": "warning",
        "revision": 1,
        "reason": "changed",
    }
    # Standard input isn't read again: the start's answer stays.
    assert rig.managed.reverify(None, recheck=False) is False
    assert rig.managed.state().seed_ignored == "changed"
    close(rig)


def test_a_sighup_logs_no_stray_and_names_a_parked_store(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    """Q35 (D.6 row 15): a stray name is logged once per start, not again at a SIGHUP; a store
    parked under the running vault is refused as ``policy_store_parked``."""
    rig = start(tmp_path)
    (rig.state / "policy" / "notes.txt").write_bytes(b"stray\n")
    log_buffer.truncate(0)
    log_buffer.seek(0)
    assert rig.managed.reverify(None) is False
    assert not [line for line in events(log_buffer) if line["event"] == "policy_stray_file"]
    PolicyStore.open(rig.state, rig.runtime.keys, None).park()
    assert rig.managed.reverify(None) is None
    assert events(log_buffer)[-1] == {"event": "reload_refused", "reason": "policy_store_parked"}
    close(rig)


def test_a_sighup_meets_a_store_changed_under_it(tmp_path: Path, log_buffer: io.StringIO) -> None:
    """F.6: the store is verified again at a SIGHUP; a head changed under the running vault is
    refused, with the running policy kept."""
    rig = start(tmp_path)
    running = rig.app.policy
    (rig.state / "policy" / "head.json").write_bytes(b"{}")
    assert rig.managed.reverify(None) is None
    assert events(log_buffer)[-1] == {"event": "reload_refused", "reason": "tampered"}
    assert rig.app.policy is running
    close(rig)


def test_a_sighup_refuses_a_head_that_now_fails_check(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    """F.6: the gate runs on the head's policy with the vault's environment; a head that fails
    is refused by name, the running policy kept."""
    secret = {"kind": "header", "header": "X-Key", "format": "{secret}", "secret": "env:SOME_K"}
    rig = start(tmp_path, SOME_K="v")
    # A new env: name is the host's to allow (E5, --allow-env).
    granted = Grants(env=frozenset({"SOME_K"}))
    written = import_(
        rig, edited(lambda data: data["credentials"].update(k=secret)), grants=granted
    )
    assert isinstance(written, Written)
    del rig.environ["SOME_K"]
    assert rig.managed.reverify(None) is None
    assert events(log_buffer)[-1]["reason"] == (
        "policy revision 2 fails check (1 error(s)): credentials.k.secret: env var SOME_K is not "
        "set"
    )
    close(rig)


# --- health (M.5) ------------------------------------------------------------------------------


def test_the_state_names_unreadable_revisions_and_the_quarantine(tmp_path: Path) -> None:
    """M.5: a kept revision that fails to verify is quarantined at the next start (D.6 row 14)
    and named by number, and the quarantine's files are counted."""
    rig = start(tmp_path)
    for value in (2, 3):
        assert isinstance(import_(rig, generation(value)), Written)
    (rig.state / "policy" / "revisions" / "0000000002.json").write_bytes(b"{}")
    again = start(tmp_path, key=rig.environ["ZOEYMCP_MASTER_KEY"])
    found = again.managed.state()
    assert (found.mode, found.revision, found.oldest) == ("managed", 3, 1)
    assert found.unreadable == (2,)
    assert found.quarantine == 1
    close(rig)
    close(again)


def status(started: int) -> Report:
    """A gateway status report whose gateway started at ``started``."""
    return Report(view="sha256:" + "0" * 64, started=started, servers={})


def test_a_restart_note_stays_until_the_restart(tmp_path: Path) -> None:
    """I.2: a change installed after the start that needs a restart is health's
    ``policy_restart_needed`` until then; the gateway's half until its status says it started
    at or after the install that raised the limit, and an unrelated save after doesn't bring it
    back; a limit raised again waits for the next gateway start."""
    rig = start(tmp_path)
    now = [1000.0]
    rig.managed._wall = lambda: now[0]
    limit = "gateway.limits.session_idle_timeout"

    def raise_limit(value: int) -> Callable[[Policy], Policy]:
        def change(data: dict[str, Any]) -> None:
            data["gateway"].setdefault("limits", {})["session_idle_timeout"] = value
            data["admin"]["listen"] = "127.0.0.1:8082"

        return edited(change)

    def paths() -> set[str]:
        return {path for path, _ in rig.managed.state().restart_needed}

    assert isinstance(import_(rig, raise_limit(7200)), Written)
    assert paths() == {"admin.listen", limit}
    rig.app.keep_status(status(999))
    assert paths() == {"admin.listen", limit}
    rig.app.keep_status(status(1000))
    assert paths() == {"admin.listen"}
    now[0] = 2000.0
    assert isinstance(import_(rig, generation(2)), Written)
    assert paths() == {"admin.listen"}
    now[0] = 3000.0
    assert isinstance(import_(rig, raise_limit(9000)), Written)
    assert paths() == {"admin.listen", limit}
    rig.app.keep_status(status(3000))
    assert paths() == {"admin.listen"}
    close(rig)


def test_a_gateway_behind_after_the_grace(tmp_path: Path) -> None:
    """K.1, M.5, FM-18 (step 15a): health's ``gateway_view_behind`` once the gateway's reported
    view has been another revision's for longer than GATEWAY_APPLY_GRACE after the install,
    naming that revision when this vault installed it; never before a report, within the grace,
    or once the gateway runs the head's view."""
    rig = start(tmp_path)
    now = [1000.0]
    rig.managed._wall = lambda: now[0]
    assert managed_module.GATEWAY_APPLY_GRACE == 30.0
    first = rig.app.view_digest
    hide = edited(lambda data: data["gateway"]["servers"]["broker-trade"].update(on_drift="hide"))
    assert isinstance(import_(rig, hide), Written)
    assert rig.app.view_digest != first

    def behind() -> tuple[bool, int | None]:
        found = rig.managed.state()
        return found.gateway_behind, found.gateway_revision

    assert behind() == (False, None)  # no report yet: unknown, not behind
    rig.app.keep_status(Report(view=first, started=1, servers={}))
    assert behind() == (False, None)  # within the grace
    now[0] = 1030.0
    assert behind() == (False, None)
    now[0] = 1030.5
    assert behind() == (True, 1)
    rig.app.keep_status(Report(view="sha256:" + "0" * 64, started=1, servers={}))
    assert behind() == (True, None)  # a view this vault didn't install
    rig.app.keep_status(Report(view=rig.app.view_digest, started=1, servers={}))
    assert behind() == (False, None)
    close(rig)


def test_the_marks_the_gateway_reports_and_the_head_ratchet(tmp_path: Path) -> None:
    """J.4 (step 15a): the planner's ``marked`` reads the gateway's latest status, every
    server's marked tools as definitions; the portal's rows read the head's ratchet; and a move
    from a server's page shows a definition at the head's pin for the tool."""
    rig = start(tmp_path)
    assert rig.managed.marked() == frozenset()
    marked = ServerStatus("remote", ("ready",), "modern", 2, 1, marked=("a", "b"))
    rig.app.keep_status(Report(view="sha256:" + "0" * 64, started=1, servers={"notes": marked}))
    assert rig.managed.marked() == {("notes", "tool", "a"), ("notes", "tool", "b")}
    assert rig.managed.ratchet == rig.runtime.ratchet
    policy = rig.managed.policy
    assert policy.gateway is not None
    [(server, entry)] = [
        (name, entry) for name, entry in policy.gateway.servers.items() if entry.review
    ][:1]
    tool, pin = next(iter(entry.review.items()))
    assert managed_module.allow_pin(policy, server, tool) == (pin, False)
    assert managed_module.allow_pin(policy, server, "nope") == (None, False)
    assert managed_module.allow_pin(policy, "nope", tool) == (None, False)
    off = {"kind": "toolkit", "module": "examples.kit", "pinning": "off"}
    data = policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    data["gateway"]["servers"]["kit"] = off
    assert managed_module.allow_pin(Policy.model_validate(data), "kit", "x") == (None, True)
    close(rig)


# --- a declarative start's view (F.4) ----------------------------------------------------------


def test_a_declarative_start_shows_the_parked_store(tmp_path: Path) -> None:
    """F.4, T-16: the parked head, and what the running policy brings back that the parked
    ratchet retired (judged at each read, so a reload is judged too)."""
    rig = start(tmp_path)
    assert isinstance(
        import_(rig, edited(lambda data: data["gateway"]["clients"].pop("agent1"))), Written
    )
    reopened = PolicyStore.open(rig.state, rig.runtime.keys, None)
    running = [rig.runtime.policy]
    found = DeclarativeStore(reopened, lambda: running[0]).state()
    assert found is not None
    assert (found.mode, found.revision, found.revived) == ("declarative", 2, ("client:agent1",))
    running[0] = Policy.model_validate({"version": 1, "mode": "declarative"})
    after = DeclarativeStore(reopened, lambda: running[0]).state()
    assert after is not None
    assert after.revived == ()
    assert repr(DeclarativeStore(reopened, lambda: running[0])) == "DeclarativeStore(parked=2)"
    close(rig)


def test_a_declarative_start_with_no_store_shows_nothing(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    keys = load_runtime(str(EXAMPLE_POLICY), state, {"ZOEYMCP_MASTER_KEY": generate_master_key()})
    store = PolicyStore.open(state, keys.keys, None)
    assert DeclarativeStore(store, lambda: keys.policy).state() is None


def test_the_holder_can_be_shown_and_never_logged(tmp_path: Path) -> None:
    rig = start(tmp_path)
    assert repr(rig.managed) == "ManagedPolicy(revision=1, not_running=None)"
    with pytest.raises(TypeError, match=r"refusing to log a secret"):
        logs.event("oops", held=rig.managed)
    close(rig)


# --- the restore witness (K.3; J11, T-4, T-5) ------------------------------------------------

OTHER_DEPLOYMENT = "fedcba9876543210" * 2


def witnessed(witness: dict[str, int]) -> Report:
    """A status report whose gateway has seen ``witness``, first seen first."""
    return Report(view="sha256:" + "0" * 64, started=1, servers={}, witness=witness)


def test_the_view_answers_state_the_running_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """K.3: from the start, and after each install, the view answers name the running head; a
    revision saved but not running isn't stated (FM-5) until a SIGHUP installs it."""
    rig = start(tmp_path)
    deployment = rig.store.head.deployment  # type: ignore[union-attr]
    assert rig.app._head_stated == f"{deployment}.1"
    assert isinstance(import_(rig, generation(2)), Written)
    assert rig.app._head_stated == f"{deployment}.2"

    def broken(*args: Any) -> None:
        raise OSError(errno.EROFS, "Read-only file system")

    real = gatewaykeys.write_atomic
    monkeypatch.setattr(gatewaykeys, "write_atomic", broken)
    assert isinstance(import_(rig, generation(3)), WriteRefused)
    assert rig.app._head_stated == f"{deployment}.2"
    monkeypatch.setattr(gatewaykeys, "write_atomic", real)
    assert rig.managed.reverify(None) is True
    assert rig.app._head_stated == f"{deployment}.3"
    close(rig)


def test_a_head_behind_the_witness_is_found_logged_once_and_acknowledged(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    """J11: the whole /state put back, the gateway's volume not: health's
    ``policy_behind_witness`` (error) with J11's text and the host's exec command, logged
    critical when a report first shows it; acknowledged by a revision with the head's content,
    numbered one above the gateway's claim, the finding gone."""
    rig = start(tmp_path, ZOEYMCP_COMPOSE_CMD="docker compose -f deploy/compose.yaml")
    health = HealthReader(rig.runtime.store, lambda: rig.app.policy, policy_state=rig.managed.state)
    deployment = rig.store.head.deployment  # type: ignore[union-attr]
    assert rig.managed.witness() is None
    rig.app.keep_status(witnessed({deployment: 1}))
    found = rig.managed.witness()
    assert found is not None
    assert (found.claim, found.behind, found.target) == (1, False, None)
    assert health.report()["policy"]["findings"] == []
    rig.app.keep_status(witnessed({deployment: 31}))
    rig.app.keep_status(witnessed({deployment: 31}))
    state = rig.managed.state()
    assert (state.witness_behind, state.witness_other) == (31, None)
    [finding] = health.report()["policy"]["findings"]
    assert (finding["code"], finding["level"]) == ("policy_behind_witness", "error")
    assert finding["action"] == {"kind": "acknowledge_restore"}
    assert finding["text"] == (
        "the gateway has applied revision 31; this vault holds 1. Was the state volume restored? "
        "Removed clients and moves back to approve since 1 are undone. Re-apply them (import "
        "your latest export: it restores clients, classifications and declines, not pins), "
        "review again each server Home lists as drifted, then acknowledge: docker compose -f "
        "deploy/compose.yaml exec vault zoeymcp policy acknowledge-restore"
    )
    rig.app.keep_status(witnessed({deployment: 32}))
    lines = [line for line in events(log_buffer) if line["event"] == "policy_behind_witness"]
    assert lines == [
        {"event": "policy_behind_witness", "level": "critical", "head": 1, "witness": 31},
        {"event": "policy_behind_witness", "level": "critical", "head": 1, "witness": 32},
    ]
    written = rig.managed.write(
        "policy.acknowledge",
        "socket",
        1,
        managed_module.acknowledge_shaped().candidate_of,
        author=HOST,
        expected=None,
        jumped_from=1,
        revision=33,
    )
    assert isinstance(written, Written)
    assert (written.revision, rig.store.header["jumped_from"]) == (33, 1)  # type: ignore[index]
    assert rig.app._head_stated == f"{deployment}.33"
    assert rig.managed.state().witness_behind is None
    assert health.report()["policy"]["findings"] == []
    [line] = [line for line in events(log_buffer) if line["event"] == "policy_acknowledged"]
    assert (line["revision"], line["base"], line["jumped_from"]) == (33, 1, 1)
    close(rig)


def test_a_deployment_changed_under_the_witness(tmp_path: Path, log_buffer: io.StringIO) -> None:
    """J11, T-5: /state wiped whole and seeded again under a new deployment while the gateway
    holds the old one at 31: ``policy_deployment_changed`` (error), logged critical once, with
    both deployments by their first 8; an acknowledgment past the old one's revision clears it."""
    rig = start(tmp_path)
    health = HealthReader(rig.runtime.store, lambda: rig.app.policy, policy_state=rig.managed.state)
    deployment = rig.store.head.deployment  # type: ignore[union-attr]
    rig.app.keep_status(witnessed({OTHER_DEPLOYMENT: 31, deployment: 1}))
    rig.app.keep_status(witnessed({OTHER_DEPLOYMENT: 31, deployment: 1}))
    state = rig.managed.state()
    assert (state.witness_behind, state.witness_other) == (None, 31)
    [finding] = health.report()["policy"]["findings"]
    assert (finding["code"], finding["level"]) == ("policy_deployment_changed", "error")
    assert finding["text"] == (
        "the gateway has seen revision 31 of another deployment of this vault, and this one "
        "starts at 1. Was /state deleted? Everything removed since the seed is back. "
        "Restore /state from one backup, or import your latest export, then acknowledge: docker "
        "compose -f deploy/compose.hardened.yaml exec vault zoeymcp policy acknowledge-restore"
    )
    lines = [line for line in events(log_buffer) if line["event"] == "policy_deployment_changed"]
    assert lines == [
        {
            "event": "policy_deployment_changed",
            "level": "critical",
            "deployment": deployment[:8],
            "other": OTHER_DEPLOYMENT[:8],
            "revision": 31,
        }
    ]
    assert managed_module.witness_answer(rig.managed.witness()) == {
        "revision": 1,
        "behind": False,
        "other": {"deployment8": OTHER_DEPLOYMENT[:8], "revision": 31},
        "target": 32,
    }
    assert isinstance(import_(rig, generation(2)), Written)
    [finding] = health.report()["policy"]["findings"]
    assert "and this one is at revision 2." in finding["text"]
    written = rig.managed.write(
        "policy.acknowledge",
        "socket",
        2,
        managed_module.acknowledge_shaped().candidate_of,
        author=HOST,
        expected=None,
        jumped_from=2,
        revision=32,
    )
    assert isinstance(written, Written)
    assert health.report()["policy"]["findings"] == []
    assert managed_module.witness_answer(rig.managed.witness()) == {
        "revision": 1,
        "behind": False,
        "other": None,
        "target": None,
    }
    assert managed_module.witness_answer(None) is None
    close(rig)


def test_an_acknowledgment_plan_names_its_jump(tmp_path: Path) -> None:
    """K.3: the plan's first row says where the number jumps from and what is never written, so
    the plan's digest names the number; the same plan at another number is another digest."""
    rig = start(tmp_path)
    shaped = managed_module.acknowledge_shaped()
    planned = rig.managed.plan(
        "policy.acknowledge", "socket", 1, shaped.candidate_of, author=HOST, revision=32
    )
    assert isinstance(planned, WritePlan)
    assert planned.rows[0] == ("Revision", "32, from 1, past 2-31, which are never written")
    assert managed_module.plan_answer(planned, (), 32)["revision"] == 32
    next_one = rig.managed.plan(
        "policy.acknowledge", "socket", 1, shaped.candidate_of, author=HOST, revision=2
    )
    assert isinstance(next_one, WritePlan)
    assert next_one.rows[0] == ("Revision", "2, from 1")
    assert plan_digest(planned) != plan_digest(next_one)
    one_past = rig.managed.plan(
        "policy.acknowledge", "socket", 1, shaped.candidate_of, author=HOST, revision=3
    )
    assert isinstance(one_past, WritePlan)
    assert one_past.rows[0] == ("Revision", "3, from 1, past 2, which is never written")
    plain = rig.managed.plan("policy.acknowledge", "socket", 1, shaped.candidate_of, author=HOST)
    assert isinstance(plain, WritePlan)
    assert plain.rows[0] == ("Revision", "2, from 1")
    assert managed_module.plan_answer(plain, ())["revision"] == 2
    close(rig)


def test_the_acknowledge_command_is_the_hosts_exec() -> None:
    assert managed_module.acknowledge_command({}) == (
        "docker compose -f deploy/compose.hardened.yaml exec vault zoeymcp policy "
        "acknowledge-restore"
    )
    environ = {
        managed_module.COMPOSE_CMD_ENV: "docker compose -f deploy/compose.yaml",
        managed_module.EXEC_SERVICE_ENV: "zoeymcp",
    }
    assert managed_module.acknowledge_command(environ) == (
        "docker compose -f deploy/compose.yaml exec zoeymcp zoeymcp policy acknowledge-restore"
    )
