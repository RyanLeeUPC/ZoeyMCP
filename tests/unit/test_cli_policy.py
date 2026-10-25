"""The host's offline policy commands (M6 design F.3, M.6, I.1; OPS-5, OPS-6, OPS-20, T-8; Y4,
Y18), in process: ``policy seed --state`` on a volume the vault won't seed, and ``policy import
--state --reseed``, planned against the old ratchet or with ``--new-ratchet``.

Each test makes its state directory with a real vault start (``load_runtime``): a declarative
one for a used volume, a managed one for a store; a store's later revisions come from the
managed holder (``tests/unit/test_managed.py``). What each command prints is on stderr, its log
lines on stdout. ``state_locked`` needs ``flock``, so it runs where there is one.
"""

from __future__ import annotations

import asyncio
import errno
import io
import json
import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from anyio.from_thread import BlockingPortal, start_blocking_portal

from zoeymcp.cli import main as main_module
from zoeymcp.cli.main import main
from zoeymcp.common.policy.ratchet import initial
from zoeymcp.common.policy.schema import Policy, hash_token
from zoeymcp.vault import gatewaykeys, logs, policystore
from zoeymcp.vault.admin import AdminApp, SetupCodes
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.managed import Written, head_policy
from zoeymcp.vault.policystart import Ok
from zoeymcp.vault.policystore import PolicyStore
from zoeymcp.vault.server import acquire_state_lock, load_runtime

from .conftest import EXAMPLE_POLICY
from .test_admin_policy import Holder, PolicyRig, deployment_of, serve, witness_of
from .test_managed import edited, import_
from .test_managed import start as managed_start

TOKEN = "example-agent2-token-0123"
# A client written with a literal token, which a revision holds as its hash (D.5).
AGENT2 = f"  clients:\n    agent2:\n      token: {TOKEN}\n"
# A credential whose secret comes from env:K, so the policy allows an env: name.
ENV_K = 'credentials:\n  k: {kind: header, header: X-Key, format: "{secret}", secret: "env:K"}\n'
HARDENED = "docker compose -f deploy/compose.hardened.yaml"
OFFLINE = {"by": "host", "via": "offline"}


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


@pytest.fixture
def master(monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """The host's environment: the vault's master key and K, run as the vault's user, with the
    compose command left to its default."""
    environ = {"ZOEYMCP_MASTER_KEY": generate_master_key(), "K": "v"}
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    for name in (
        "ZOEYMCP_MASTER_KEY_PREVIOUS",
        "ZOEYMCP_CONFIG",
        "ZOEYMCP_COMPOSE_CMD",
        "ZOEYMCP_EXEC_SERVICE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(main_module, "running_as_root", lambda: False)
    return environ


def cli(argv: list[str], stdin: str = "") -> tuple[int, str]:
    err = io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin), out=io.StringIO(), err=err)
    return code, err.getvalue()


def managed_text(*, agent2: bool = True) -> str:
    text = EXAMPLE_POLICY.read_text(encoding="utf-8").replace("mode: declarative", "mode: managed")
    text = text.replace("credentials:\n", ENV_K, 1)
    return text.replace("  clients:\n", AGENT2, 1) if agent2 else text


def write(tmp_path: Path, text: str, name: str = "policy.yaml") -> str:
    path = tmp_path / name
    path.write_bytes(text.encode())
    return str(path)


def used(tmp_path: Path, environ: dict[str, str], text: str | None = None) -> Path:
    """A state volume a declarative vault used: no store, no anchor."""
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    declarative = text or EXAMPLE_POLICY.read_text(encoding="utf-8")
    load_runtime(write(tmp_path, declarative, "declarative.yaml"), state, environ)
    assert (state / gatewaykeys.STATE_FILE).is_file()
    return state


def reopened(state: Path, environ: dict[str, str]) -> PolicyStore:
    return PolicyStore.open(state, KeySet.from_text(environ["ZOEYMCP_MASTER_KEY"]), None)


def events(buffer: io.StringIO, name: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [
        {k: v for k, v in line.items() if k not in ("ts", "role")}
        for line in lines
        if line["event"] == name
    ]


def with_two_revisions(tmp_path: Path, environ: dict[str, str]) -> Path:
    """A managed store: revision 1 seeded with agent2, revision 2 a socket import without it,
    which the ratchet retires."""
    rig = managed_start(tmp_path, managed_text(), key=environ["ZOEYMCP_MASTER_KEY"], K="v")
    removed = import_(rig, edited(lambda data: data["gateway"]["clients"].pop("agent2")))
    assert (type(removed).__name__, removed.revision) == ("Written", 2)
    asyncio.run(rig.app.aclose())
    return rig.state


# --- policy seed (F.3, J5b) ---------------------------------------------------------------------


def test_seed_on_a_used_volume(
    tmp_path: Path, master: dict[str, str], log_buffer: io.StringIO
) -> None:
    """J5b, Y18: a used volume the vault refuses to seed is seeded by the host, as revision 1
    whose author is the host offline (13a's open question, settled in policyseal); the summary
    names the clients, routes and servers, the env: names and the tokens it hashes, never a
    token; the vault then starts from the head, and the source it was seeded from is no
    change (F.5)."""
    state = used(tmp_path, master)
    config = write(tmp_path, managed_text())
    code, err = cli(["policy", "seed", "--state", str(state), "--config", config, "--yes"])
    assert code == 0, err
    store = reopened(state, master)
    assert isinstance(store.verdict, Ok)
    head, header = store.head, store.header
    assert head is not None
    assert header is not None
    assert (head.revision, header["origin"], header["kind"]) == (1, "seed", "policy.seed")
    assert header["author"] == OFFLINE
    assert err == (
        "Seeding revision 1 of a new deployment from the policy given:\n"
        "  Clients: agent1, agent2\n"
        "  Routes: stats, broker-mcp, mail-send\n"
        "  Servers: broker-read, broker-trade, mail\n"
        "  env: names it allows: K\n"
        "  Client tokens written as their hash: 1\n"
        f"Seeded revision 1 of deployment {head.deployment[:8]}. Start the vault:\n"
        f"  {HARDENED} up -d vault\n"
    )
    assert events(log_buffer, "policy_seeded") == [
        {
            "event": "policy_seeded",
            "revision": 1,
            "deployment": head.deployment[:8],
            "tokens_hashed": 1,
            "via": "offline",
        }
    ]
    assert TOKEN not in log_buffer.getvalue() + err
    runtime = load_runtime(config, state, master)
    assert runtime.policy_store is not None
    assert runtime.policy_store.head == head
    assert runtime.seed_ignored is None
    assert runtime.policy.gateway is not None
    agent2 = runtime.policy.gateway.clients["agent2"]
    assert (agent2.token, agent2.token_sha256) == (None, hash_token(TOKEN))


def test_seed_asks_first(tmp_path: Path, master: dict[str, str]) -> None:
    """[y/N] unless --yes: anything but yes writes nothing; a policy on standard input leaves no
    answer to read, so the plan is printed and nothing is written."""
    state = used(tmp_path, master)
    config = write(tmp_path, managed_text())
    argv = ["policy", "seed", "--state", str(state), "--config", config]
    code, err = cli(argv, "n\n")
    assert code == 1
    assert err.endswith(
        "  Client tokens written as their hash: 1\nWrite it? [y/N] Nothing written.\n"
    )
    assert not (state / "policy").exists()
    assert not (state / "policy-anchor.json").exists()
    piped = ["policy", "seed", "--state", str(state), "--config", "-"]
    code, err = cli(piped, managed_text())
    assert code == 1
    assert err.endswith(
        "Nothing written: the policy came on standard input, so there is no answer to read. "
        "Read the plan above, then run this again with --yes.\n"
    )
    assert not (state / "policy-anchor.json").exists()
    code, err = cli(argv, "y\n")
    assert code == 0, err
    assert "Write it? [y/N] Seeded revision 1 of deployment " in err
    assert (state / "policy-anchor.json").is_file()


def test_seed_refuses_a_store_and_names_the_reseed(tmp_path: Path, master: dict[str, str]) -> None:
    """F.3: with a store or its anchor present the seed refuses and names --reseed."""
    rig = managed_start(tmp_path, managed_text(), key=master["ZOEYMCP_MASTER_KEY"], K="v")
    asyncio.run(rig.app.aclose())
    state = str(rig.state)
    code, err = cli(
        ["policy", "seed", "--state", state, "--config", write(tmp_path, managed_text())]
    )
    assert (code, err) == (
        1,
        f"zoeymcp policy seed: The state directory {state} already holds a policy store or its "
        f"anchor: replace it with zoeymcp policy import --state {state} --reseed.\n",
    )


def test_seed_refuses_a_lower_gateway_key_generation(
    tmp_path: Path, master: dict[str, str]
) -> None:
    """F.3, G-4 (13b's carry-in): the volume's gateway-key state is at generation 2, so a policy
    at 1 is refused before anything is written, naming the field."""
    raised = EXAMPLE_POLICY.read_text(encoding="utf-8").replace(
        "gateway_key_generation: 1", "gateway_key_generation: 2"
    )
    state = used(tmp_path, master, raised)
    config = write(tmp_path, managed_text())
    code, err = cli(["policy", "seed", "--state", str(state), "--config", config, "--yes"])
    assert (code, err) == (
        1,
        "zoeymcp policy seed: The policy's gateway_key_generation can't go below 2, the "
        "generation gateway-key.json holds: that would bring back a retired key.\n",
    )
    assert not (state / "policy-anchor.json").exists()


def test_seed_refuses_what_the_gate_refuses(tmp_path: Path, master: dict[str, str]) -> None:
    """The policy given goes through the gate with this container's environment (C); a
    declarative one isn't a seed; none given is refused as the vault refuses it."""
    state = used(tmp_path, master)
    argv = ["policy", "seed", "--state", str(state), "--yes", "--config"]
    declarative = write(tmp_path, EXAMPLE_POLICY.read_text(encoding="utf-8"), "d.yaml")
    assert cli([*argv, declarative]) == (
        2,
        "zoeymcp policy seed: The policy given says mode: declarative, and a seed is managed "
        "mode's first revision: set mode: managed, check it, then seed.\n",
    )
    code, err = cli([*argv, write(tmp_path, "version: 1\nmode: [\n", "bad.yaml")])
    assert code == 2
    assert err.startswith("zoeymcp policy seed: The policy is refused: policy ")
    code, err = cli(["policy", "seed", "--state", str(state), "--yes"])
    assert (code, err) == (
        2,
        "zoeymcp policy seed: The policy is refused: policy (none) refused: (document): no "
        "policy given: use --config or set ZOEYMCP_CONFIG.\n",
    )
    assert not (state / "policy-anchor.json").exists()


ROOT_FORMS = [
    ["policy", "seed", "--yes"],
    ["policy", "import", "--reseed", "--from-env", "--new-ratchet", "--yes"],
]


@pytest.mark.parametrize("argv", ROOT_FORMS, ids=["seed", "reseed"])
def test_state_as_root(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    """OPS-5: every --state form refuses root, before it reads or writes anything."""
    monkeypatch.setattr(main_module, "running_as_root", lambda: True)
    state = tmp_path / "state"
    code, err = cli([*argv, "--state", str(state)])
    assert (code, err) == (
        2,
        f"zoeymcp policy {argv[1]}: This command won't run as root: the vault's uid couldn't "
        "read what it writes. Run it as the vault's uid: add --user 10001:10001.\n",
    )
    assert not state.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="the state lock is flock, which Windows lacks")
@pytest.mark.parametrize("argv", ROOT_FORMS, ids=["seed", "reseed"])
def test_state_locked_while_a_vault_runs(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    """OPS-6: the lock a running vault holds refuses every --state form, naming the stop in the
    host's own commands; each command lets the lock go when it ends."""
    state = used(tmp_path, master)
    monkeypatch.setenv("ZOEYMCP_CONFIG", managed_text())
    monkeypatch.setenv("ZOEYMCP_COMPOSE_CMD", "docker compose -f deploy/compose.yaml")
    monkeypatch.setenv("ZOEYMCP_EXEC_SERVICE", "zoeymcp")
    held = acquire_state_lock(state)
    assert held is not None
    try:
        code, err = cli([*argv, "--state", str(state)])
    finally:
        os.close(held)
    assert (code, err) == (
        2,
        f"zoeymcp policy {argv[1]}: The state directory is in use: stop the vault first (docker "
        "compose -f deploy/compose.yaml stop zoeymcp), then run this again.\n",
    )
    assert not (state / "policy-anchor.json").exists()
    assert cli([*argv, "--state", str(state)])[0] == 0
    again = acquire_state_lock(state)
    assert again is not None
    os.close(again)


# --- policy import --state --reseed (F.3, J16, T-8) ---------------------------------------------


def test_reseed_plans_against_the_ratchet(
    tmp_path: Path, master: dict[str, str], log_buffer: io.StringIO
) -> None:
    """T-8, OPS-20: with the old head verifying, the reseed is planned against it and its
    ratchet: bringing back a client revision 2 removed needs --allow-revive, named; granted, the
    plan names the revisions it undoes, the generations against their floors and every change,
    and the reseed is revision 3, with no parent, under the same deployment, the old files in
    quarantine, the ratchet the old one advanced; the vault starts from it."""
    state = with_two_revisions(tmp_path, master)
    before = reopened(state, master)
    assert isinstance(before.verdict, Ok)
    deployment = before.verdict.head.deployment
    source = write(tmp_path, managed_text(), "export.yaml")
    argv = ["policy", "import", source, "--state", str(state), "--reseed", "--yes"]
    code, err = cli(argv)
    assert (code, err) == (
        1,
        "zoeymcp policy import: This brings back client agent2, removed in revision 2: refused "
        "without --allow-revive client:NAME for each.\n"
        "  --allow-revive client:agent2\n",
    )
    assert reopened(state, master).head == before.head
    granted = ["--allow-revive", "client:agent2", "--accept-widening"]
    code, err = cli([*argv, *granted, "--reason", "back to 1"])
    assert code == 0, err
    lines = err.splitlines()
    assert lines[:4] == [
        "Reseeding as revision 3, its deployment kept, planned against revision 2 and what it "
        "retired:",
        "  Undoes: revision 2",
        "  gateway_key_generation: 1 (the store's floor 1, gateway-key.json 1)",
        "  egress_key_generation: 1 (the store's floor 1)",
    ]
    assert "  Granted by the host: revives_client: client:agent2" in lines
    assert any(line.startswith("  gateway.clients.agent2: ") for line in lines)
    assert lines[-3:] == [
        f"The old head and its revisions go to {state}/policy/quarantine/, never deleted.",
        "Reseeded as revision 3. Start the vault:",
        f"  {HARDENED} up -d vault",
    ]
    assert TOKEN not in err + log_buffer.getvalue()
    store = reopened(state, master)
    assert isinstance(store.verdict, Ok)
    head, header = store.verdict.head, store.verdict.top.header
    assert (head.revision, head.oldest, head.oldest_parent, head.deployment) == (
        3,
        3,
        None,
        deployment,
    )
    assert (header["origin"], header["parent"], header["base"], header["author"]) == (
        "reseed",
        None,
        2,
        OFFLINE,
    )
    assert store.verdict.top.body.reason == "back to 1"
    # The ratchet advanced from revision 2's: agent2's old token stays retired.
    assert store.verdict.ratchet.retired_clients == {hash_token(TOKEN)}
    assert store.anchor is not None
    assert (store.anchor.highest, store.anchor.deployment) == (3, deployment)
    quarantine = sorted(path.name for path in (state / "policy" / "quarantine").iterdir())
    assert quarantine == ["1.reseeded.json", "2.reseeded.json", "head.reseeded.json"]
    [line] = events(log_buffer, "policy_imported")[-1:]
    assert line == {
        "event": "policy_imported",
        "revision": 3,
        "write_kind": "policy.reseed",
        "origin": "reseed",
        "author": "host",
        "base": 2,
        "digest": head.digest.removeprefix("sha256:")[:8],
        "effects": [],
        "deployment": deployment[:8],
        "reseed": True,
        "new_ratchet": False,
        "from_env": False,
    }
    runtime = load_runtime(source, state, master)
    assert runtime.policy_store is not None
    assert runtime.policy_store.head == head
    assert runtime.policy.gateway is not None
    assert "agent2" in runtime.policy.gateway.clients


def test_reseed_new_ratchet_lists_what_it_forgets(
    tmp_path: Path, master: dict[str, str], log_buffer: io.StringIO
) -> None:
    """F.3: --new-ratchet drops the old ratchet for the document's own, listing every retired
    entry it forgets (a retired client only counted: the ratchet keeps its hash alone), so the
    revival needs no grant."""
    state = with_two_revisions(tmp_path, master)
    source = write(tmp_path, managed_text(), "export.yaml")
    argv = ["policy", "import", source, "--state", str(state), "--reseed", "--new-ratchet"]
    code, err = cli([*argv, "--yes"])
    assert code == 0, err
    lines = err.splitlines()
    assert lines[0] == (
        "Reseeding as revision 3, its deployment kept, with a new ratchet, replacing revision 2:"
    )
    assert "  Forgets: 1 retired client token(s)" in lines
    assert "  Client tokens written as their hash: 1" in lines
    store = reopened(state, master)
    assert isinstance(store.verdict, Ok)
    assert store.verdict.ratchet == initial(head_policy(store.verdict))
    assert events(log_buffer, "policy_imported")[-1]["new_ratchet"] is True


def broken(*args: Any) -> None:
    raise OSError(errno.ENOSPC, "No space left on device")


def test_a_reseed_that_fails_is_planned_again(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """A reseed whose head can't be written puts the old store back, so "nothing changed" is
    true and the next reseed is planned against the old head and its ratchet again (T-8), with
    no --new-ratchet. When even the way back fails, the refusal names each file still out of
    place."""
    state = with_two_revisions(tmp_path, master)
    source = write(tmp_path, managed_text(), "export.yaml")
    argv = ["policy", "import", source, "--state", str(state), "--reseed", "--yes"]
    granted = [*argv, "--allow-revive", "client:agent2", "--accept-widening"]
    real_head, real_move = policystore.write_head, policystore.move
    monkeypatch.setattr(policystore, "write_head", broken)
    code, err = cli(granted)
    assert code == 1
    assert err.endswith(
        "zoeymcp policy import: The revision couldn't be written; nothing changed.\n"
    )
    monkeypatch.setattr(policystore, "write_head", real_head)
    code, err = cli(granted)
    assert code == 0, err
    assert err.splitlines()[0] == (
        "Reseeding as revision 3, its deployment kept, planned against revision 2 and what it "
        "retired:"
    )

    def move_in_only(source: Path, target: Path) -> None:
        if source.parent.name == "quarantine":
            raise OSError(errno.EACCES, "Permission denied")
        real_move(source, target)

    monkeypatch.setattr(policystore, "write_head", broken)
    monkeypatch.setattr(policystore, "move", move_in_only)
    code, err = cli([*argv, "--new-ratchet"])
    assert code == 1
    assert err.endswith(
        "zoeymcp policy import: The reseed failed and couldn't put the old store back, so the "
        "vault won't start (revision 4 can't be written (OSError); policy/quarantine/"
        "3.reseeded.json goes back to policy/revisions/0000000003.json; policy/quarantine/"
        "head.reseeded.2.json goes back to policy/head.json). Put each file named back, then run "
        "the reseed again; if the old anchor can't be put back, run it with --new-ratchet.\n"
    )


def test_reseed_of_a_store_that_doesnt_verify(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """J16's way out: a head that doesn't verify leaves no ratchet to plan against, so the reseed
    needs --new-ratchet and says so; it keeps the deployment while the anchor verifies, and
    makes a new one when it doesn't; no revision number is used twice (Y4)."""
    rig = managed_start(tmp_path, managed_text(), key=master["ZOEYMCP_MASTER_KEY"], K="v")
    asyncio.run(rig.app.aclose())
    state = rig.state
    deployment = reopened(state, master).verdict
    assert isinstance(deployment, Ok)
    (state / "policy" / "head.json").write_bytes(b"{}")
    source = write(tmp_path, managed_text(agent2=False), "export.yaml")
    argv = ["policy", "import", source, "--state", str(state), "--reseed", "--yes"]
    code, err = cli(argv)
    assert (code, err) == (
        1,
        "zoeymcp policy import: The old policy head doesn't verify (tampered), so there is no "
        "ratchet to plan the reseed against: add --new-ratchet, which forgets what the old "
        "store retired.\n",
    )
    code, err = cli([*argv, "--new-ratchet"])
    assert code == 0, err
    assert err.splitlines()[0] == (
        "Reseeding as revision 2, its deployment kept, with a new ratchet, the old store "
        "doesn't verify (tampered):"
    )
    store = reopened(state, master)
    assert isinstance(store.verdict, Ok)
    assert (store.verdict.revision, store.verdict.head.deployment) == (
        2,
        deployment.head.deployment,
    )
    # Now the anchor doesn't verify either: a new deployment, from the compose policy.
    (state / "policy-anchor.json").write_bytes(b"x")
    monkeypatch.setenv("ZOEYMCP_CONFIG", managed_text())
    from_env = ["policy", "import", "--from-env", "--state", str(state), "--reseed"]
    code, err = cli([*from_env, "--new-ratchet", "--yes"])
    assert code == 0, err
    assert err.splitlines()[0] == (
        "Reseeding as revision 3, a new deployment, with a new ratchet, the old store doesn't "
        "verify (policy_anchor_tampered):"
    )
    store = reopened(state, master)
    assert isinstance(store.verdict, Ok)
    assert store.verdict.revision == 3
    assert store.verdict.head.deployment != deployment.head.deployment
    quarantine = sorted(path.name for path in (state / "policy" / "quarantine").iterdir())
    assert quarantine == [
        "1.reseeded.json",
        "2.reseeded.json",
        "head.reseeded.2.json",
        "head.reseeded.json",
    ]


def test_reseed_refuses_a_lower_generation_up_front(tmp_path: Path, master: dict[str, str]) -> None:
    """F.3: a source whose gateway key generation is below the gateway-key state is refused
    before anything moves, naming the field; a planned reseed below the ratchet's floor is the
    planner's generation_lowered, and --new-ratchet keeps the floor too (E1)."""
    rig = managed_start(
        tmp_path,
        managed_text().replace("gateway_key_generation: 1", "gateway_key_generation: 2"),
        key=master["ZOEYMCP_MASTER_KEY"],
        K="v",
    )
    asyncio.run(rig.app.aclose())
    state = rig.state
    before = reopened(state, master).head
    source = write(tmp_path, managed_text(), "export.yaml")
    argv = ["policy", "import", source, "--state", str(state), "--reseed", "--yes"]
    refused = (
        1,
        "zoeymcp policy import: The policy's gateway_key_generation can't go below 2, the "
        "generation gateway-key.json holds: that would bring back a retired key.\n",
    )
    assert cli(argv) == refused
    assert cli([*argv, "--new-ratchet"]) == refused
    (state / gatewaykeys.STATE_FILE).unlink()
    assert cli(argv) == (
        1,
        "zoeymcp policy import: The policy's gateway_key_generation can't go below 2: that "
        "would bring back a retired key.\n",
    )
    assert cli([*argv, "--new-ratchet"]) == (
        1,
        "zoeymcp policy import: The policy's gateway_key_generation can't go below 2: that "
        "would bring back a retired key.\n",
    )
    assert reopened(state, master).head == before
    assert not (state / "policy" / "quarantine").exists()


def test_reseed_asks_what_an_import_asks(tmp_path: Path, master: dict[str, str]) -> None:
    """13c's carry-in (I.1, G-17, Q41): a reseed planned against a head that verifies needs,
    with --yes, --accept-widening for a widening plan (import_widens) and --lockout-ok for a
    moved admin.listen (lockout_unconfirmed); without --yes the listen is typed."""
    state = with_two_revisions(tmp_path, master)
    moved = managed_text(agent2=False).replace("listen: 127.0.0.1:8081", "listen: 127.0.0.1:9091")
    widened = write(tmp_path, managed_text(), "widened.yaml")
    argv = ["policy", "import", "--state", str(state), "--reseed", "--yes"]
    code, err = cli([*argv, widened, "--allow-revive", "client:agent2"])
    assert (code, err.splitlines()[-1]) == (
        1,
        "zoeymcp policy import: This plan widens the policy (gateway.clients.agent2): with --yes "
        "it needs --accept-widening too, or run it without --yes to read the plan and confirm it.",
    )
    source = write(tmp_path, moved, "moved.yaml")
    code, err = cli([*argv, source, "--accept-widening"])
    assert "  Lockout: this moves the portal from 127.0.0.1:8081 to 127.0.0.1:9091" in err
    assert err.splitlines()[-1] == (
        "zoeymcp policy import: This change moves the portal from 127.0.0.1:8081 to "
        "127.0.0.1:9091: after the vault's restart it listens there: type the confirmation at "
        "the prompt, or pass --yes --lockout-ok."
    )
    asked = ["policy", "import", source, "--state", str(state), "--reseed"]
    code, err = cli(asked, "y\n127.0.0.1:8081\n")
    assert code == 1
    assert err.endswith("Type the address to continue: Nothing written.\n")
    code, err = cli(asked, "y\n127.0.0.1:9091\n")
    assert code == 0, err
    head = reopened(state, master).head
    assert head is not None
    assert head.revision == 3


def test_reseed_from_standard_input_prints_the_plan(tmp_path: Path, master: dict[str, str]) -> None:
    """J16's piped form: without --yes the plan is printed and nothing is written; with it, the
    reseed is written. A declarative document is no import."""
    state = with_two_revisions(tmp_path, master)
    before = reopened(state, master).head
    argv = ["policy", "import", "-", "--state", str(state), "--reseed"]
    code, err = cli([*argv, "--allow-revive", "client:agent2"], managed_text())
    assert code == 1
    assert err.endswith("Read the plan above, then run this again with --yes.\n")
    assert reopened(state, master).head == before
    declarative = EXAMPLE_POLICY.read_text(encoding="utf-8")
    assert cli([*argv, "--yes"], declarative) == (
        2,
        "zoeymcp policy import: An import is a managed revision; to go declarative, put an "
        "export made with --mode declarative in ZOEYMCP_CONFIG.\n",
    )
    granted = ["--allow-revive", "client:agent2", "--accept-widening", "--yes"]
    code, err = cli([*argv, *granted], managed_text())
    assert code == 0, err
    head = reopened(state, master).head
    assert head is not None
    assert head.revision == 3


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (
            ["import", "x.yaml", "--reseed"],
            "--reseed replaces the store with the vault stopped: add --state DIR",
        ),
        (
            ["import", "--state", "s", "--reseed"],
            "give the policy as FILE (- for standard input) or --from-env, one of them",
        ),
        (
            ["import", "x.yaml", "--from-env", "--state", "s", "--reseed"],
            "give the policy as FILE (- for standard input) or --from-env, one of them",
        ),
        (
            ["import", "x.yaml", "--state", "s", "--reseed", "--reason", ""],
            "--reason is 1 to 200 printable characters",
        ),
        (
            ["import", "x.yaml", "--state", "s", "--reseed", "--reason", "a\tb"],
            "--reason is 1 to 200 printable characters",
        ),
        (
            ["import", "x.yaml", "--state", "s", "--reseed", "--base", "3"],
            "--base isn't a reseed's: a reseed replaces the store whole",
        ),
        (["import", "x.yaml", "--new-ratchet"], "--new-ratchet goes with --reseed"),
        (["import", "x.yaml", "--baseline-only"], "--baseline-only goes with --from-env"),
        (["import", "--from-env", "--base", "2"], "--from-env is planned on the head: drop --base"),
        (
            ["import", "x.yaml", "--state", "s", "--revoke-removed"],
            "--revoke-removed needs the running vault: run it over the socket",
        ),
        (
            ["rollback", "2", "--state", "s", "--revoke-removed"],
            "--revoke-removed needs the running vault: run it over the socket",
        ),
        (["history", "--limit", "51"], "--limit is 1 to 50"),
    ],
    ids=[
        "reseed-no-state",
        "no-source",
        "two-sources",
        "empty-reason",
        "tab-reason",
        "reseed-base",
        "new-ratchet",
        "baseline-only",
        "from-env-base",
        "offline-import-revoke",
        "offline-rollback-revoke",
        "limit",
    ],
)
def test_usage(master: dict[str, str], argv: list[str], said: str) -> None:
    """M.6: what each form takes. An import without --reseed is the next revision, over the
    socket or with --state (this step); --revoke-removed needs the running vault."""
    assert cli(["policy", *argv]) == (2, f"zoeymcp policy {argv[0]}: {said}\n")


# --- the host's commands over the socket (H, M.6) ------------------------------------------------


@pytest.fixture
def portal() -> Iterator[BlockingPortal]:
    with start_blocking_portal() as found:
        yield found


class Terminal(io.StringIO):
    """A stdout that is a terminal."""

    def isatty(self) -> bool:
        return True


def run_cli(
    argv: list[str], stdin: str = "", out: io.StringIO | None = None
) -> tuple[int, str, str]:
    """``zoeymcp <argv>``: its exit code, stdout and stderr."""
    out = out or io.StringIO()
    err = io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def socket_rig(
    tmp_path: Path,
    master: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    portal: BlockingPortal,
    *,
    holder: Holder | None = None,
) -> PolicyRig:
    """A managed vault seeded with agent2, its admin socket served to the CLI in process."""
    rig = PolicyRig(
        tmp_path, managed_text(), holder=holder, key=master["ZOEYMCP_MASTER_KEY"], K="v"
    )
    serve(monkeypatch, lambda: rig.admin.app, portal)
    return rig


def test_head_history_and_diff(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """M.6, H.1, H.2, D-171: the head, history and a diff in text and in JSON, hidden fields
    hidden; the deployment and digest by their first 8."""
    rig = socket_rig(tmp_path, master, monkeypatch, portal)
    code, out, err = run_cli(["policy"])
    assert (code, err) == (0, "")
    store = rig.vault.store
    assert store.head is not None
    lines = out.splitlines()
    assert lines[0] == "Mode: managed"
    assert lines[1].startswith("Revision 1, saved ")
    assert lines[1].endswith(" by the seed, policy.seed")
    assert lines[2:] == [
        f"Deployment {store.head.deployment[:8]}, digest "
        f"{store.head.digest.removeprefix('sha256:')[:8]}",
        "Gateway: unknown (no status report yet)",
        "Witness: unknown (no status report yet)",
    ]
    code, out, _ = run_cli(["policy", "head", "--format", "json"])
    assert json.loads(out)["revision"] == 1
    removed = import_(rig.vault, edited(lambda data: data["gateway"]["clients"].pop("agent2")))
    assert isinstance(removed, Written)
    code, out, _ = run_cli(["policy", "history"])
    assert code == 0
    history = out.splitlines()
    assert history[0].startswith("2  policy.import  saved ")
    assert history[0].endswith(" by the host (socket)  base 1")
    assert history[1].startswith("1  policy.seed  saved ")
    code, out, _ = run_cli(["policy", "history", "--format", "json", "--limit", "1"])
    page = json.loads(out)
    assert ([entry["revision"] for entry in page["revisions"]], page["next"]) == ([2], 2)
    code, out, _ = run_cli(["policy", "diff", "2"])
    [said, row] = out.splitlines()
    assert said == "Revision 2 against revision 1:"
    assert row.startswith("  gateway.clients.agent2: removed {")
    assert row.endswith(" (narrower)")
    assert '"(set)"' in row
    assert hash_token(TOKEN) not in out
    code, out, _ = run_cli(["policy", "diff", "2", "--format", "json"])
    assert json.loads(out)["rows"][0]["op"] == "removed"
    code, _, err = run_cli(["policy", "diff", "9"])
    assert (code, err) == (1, "zoeymcp policy diff: Revision 9 is no longer kept, or never was.\n")


def test_export_to_stdout_and_its_notes(
    tmp_path: Path,
    master: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    portal: BlockingPortal,
    log_buffer: io.StringIO,
) -> None:
    """H.6, G-15, J10: the YAML alone on stdout, the notes on stderr; a terminal stdout is
    refused without --force-tty; the declarative compose form ends with the way back in the
    host's own commands."""
    socket_rig(tmp_path, master, monkeypatch, portal)
    code, out, err = run_cli(["policy", "export"], out=Terminal())
    assert (code, out) == (2, "")
    assert err == (
        "zoeymcp policy export: the export holds placeholders and client token hashes: redirect "
        "it to a file (> policy.yaml), or pass --force-tty to print it here\n"
    )
    code, out, err = run_cli(["policy", "export"])
    assert code == 0, err
    assert out.startswith("# zoeymcp policy export: revision 1 of deployment ")
    assert hash_token(TOKEN) in out
    assert TOKEN not in out
    assert err.startswith("Exported revision 1 of deployment ")
    code, out, err = run_cli(["policy", "export", "--mode", "declarative", "--for", "compose"])
    assert code == 0, err
    assert '        mode: "declarative"' in out
    assert err.splitlines()[1:] == [
        "gateway_key_generation is now a literal 1: put ${ZOEYMCP_GATEWAY_KEY_GENERATION:-1} "
        "back if you rotate by the variable.",
        "admin.origins is now the literal http://localhost:8081: put "
        "${ZOEYMCP_ADMIN_PORT:-8081} back if you move the port by the variable.",
        "Next: replace the policy under ZOEYMCP_CONFIG in your compose file with it, then:",
        f"  {HARDENED} run --rm --no-deps vault check",
        f"  {HARDENED} up -d vault",
    ]
    code, out, err = run_cli(["policy", "export", "--force-tty"], out=Terminal())
    assert code == 0, err


def exported(edit: Callable[[dict[str, Any]], None]) -> str:
    """The head exported by the CLI, its document edited as the operator would."""
    code, out, err = run_cli(["policy", "export"])
    assert code == 0, err
    first, _, rest = out.partition("\n")
    data = yaml.safe_load(rest)
    edit(data)
    return first + "\n" + json.dumps(data) + "\n"


def add_reports(data: dict[str, Any]) -> None:
    data["gateway"]["clients"]["reports"] = {"token_sha256": hash_token("reports-token-0001")}


def test_import_an_edited_export(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """J7, H.5, OPS-8, Q41: the base comes from the export's header; the plan goes to stderr,
    the widening first; [y/N] writes it; on standard input with --yes a widening needs
    --accept-widening (import_widens); the vault's answer names the way on."""
    rig = socket_rig(tmp_path, master, monkeypatch, portal)
    text = exported(add_reports)
    path = write(tmp_path, text, "edited.yaml")
    code, _, err = run_cli(["policy", "import", path], "n\n")
    assert code == 1
    assert err.splitlines()[:3] == [
        "Planned on revision 1 (from the export's header):",
        "  Revision: 2, from 1",
        "  gateway.clients.reports: added (wider)",
    ]
    assert err.endswith("Write revision 2? [y/N] Nothing written.\n")
    code, _, err = run_cli(["policy", "import", "-", "--yes"], text)
    assert (code, err.splitlines()[-1]) == (
        1,
        "zoeymcp policy import: This plan widens the policy (gateway.clients.reports): with --yes "
        "it needs --accept-widening too, or run it without --yes to read the plan and confirm it.",
    )
    code, _, err = run_cli(["policy", "import", "-"], text)
    assert code == 1
    assert err.endswith("Read the plan above, then run this again with --yes.\n")
    assert rig.vault.managed.revision == 1
    code, _, err = run_cli(
        ["policy", "import", "-", "--yes", "--accept-widening", "--reason", "reports"], text
    )
    assert code == 0, err
    assert err.splitlines()[-3:] == [
        "Imported as revision 2.",
        "Next:",
        "  The gateway takes the new view within seconds",
    ]
    assert rig.vault.managed.revision == 2
    # MISS-9, FM-16: run again after its answer was lost, the same import made the head.
    code, _, err = run_cli(["policy", "import", path, "--yes", "--accept-widening"])
    assert (code, err) == (0, "This was already written as revision 2.\n")
    assert rig.vault.managed.revision == 2
    # Another edit of the same export meets the moved head: export again (OPS-8).
    first, _, rest = text.partition("\n")
    other = {**yaml.safe_load(rest), "egress_key_generation": 2}
    code, _, err = run_cli(
        ["policy", "import", "-", "--yes", "--accept-widening"],
        first + "\n" + json.dumps(other) + "\n",
    )
    said = err.splitlines()[-1]
    assert code == 1
    assert said.startswith(
        "zoeymcp policy import: Nothing was written: the policy moved to revision 2, saved "
    )
    assert said.endswith(
        " by the host (socket) since you started. For an import, export again and redo your "
        "edit; for a rollback, run it again."
    )


def test_base_required_and_another_deployment(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """OPS-8: a document with no export header and no --base is base_required; a header from
    another deployment is refused; --base names it instead."""
    socket_rig(tmp_path, master, monkeypatch, portal)
    text = exported(add_reports)
    bare = text.partition("\n")[2]
    code, _, err = run_cli(["policy", "import", "-", "--yes"], bare)
    assert (code, err) == (
        1,
        "zoeymcp policy import: Say which revision this change is planned on: pass --base N "
        "(the revision you exported; zoeymcp policy head shows the current one).\n",
    )
    deployment = text.split(" of deployment ", 1)[1][:8]
    other = text.replace(f" of deployment {deployment},", " of deployment 00000000,", 1)
    code, _, err = run_cli(["policy", "import", "-", "--yes"], other)
    assert (code, err) == (
        1,
        "zoeymcp policy import: This export is from deployment 00000000, not this one: export "
        "from this deployment and redo your edit there.\n",
    )
    code, _, err = run_cli(
        ["policy", "import", "-", "--yes", "--accept-widening", "--base", "1"], bare
    )
    assert code == 0, err
    assert err.startswith("Planned on revision 1 (--base):\n")


def test_lockout_needs_typed_confirmation(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """Y17, I.1, G-17: an import that drops the origin a passkey was enrolled through asks,
    after [y/N], for the origin typed; a wrong one writes nothing; without a terminal it needs
    --yes --lockout-ok (lockout_unconfirmed)."""
    rig = socket_rig(tmp_path, master, monkeypatch, portal, holder=Holder(["localhost"]))

    def drop(data: dict[str, Any]) -> None:
        data["admin"]["origins"] = ["https://zoeymcp.tailnet.example"]

    path = write(tmp_path, exported(drop), "drop.yaml")
    code, _, err = run_cli(["policy", "import", path], "y\nhttp://localhost:9999\n")
    assert code == 1
    assert (
        "  Lockout: this removes http://localhost:8081, where 1 passkey was enrolled: it stops "
        "working\n"
    ) in err
    assert err.endswith(
        "Write revision 2? [y/N] This removes http://localhost:8081, where 1 passkey was "
        "enrolled: it stops working. Type the origin to continue: Nothing written.\n"
    )
    code, _, err = run_cli(["policy", "import", path, "--yes", "--accept-widening"])
    assert (code, err.splitlines()[-1]) == (
        1,
        "zoeymcp policy import: This change removes http://localhost:8081, where 1 passkey was "
        "enrolled: it stops working: type the confirmation at the prompt, or pass --yes "
        "--lockout-ok.",
    )
    assert rig.vault.managed.revision == 1
    code, _, err = run_cli(["policy", "import", path], "y\nhttp://localhost:8081\n")
    assert code == 0, err
    assert rig.vault.managed.policy.admin is not None
    assert rig.vault.managed.policy.admin.origins == ["https://zoeymcp.tailnet.example"]


def test_rollback_over_the_socket(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """J6's socket half, H.3, E3: a rollback that brings back a client a later revision removed
    is refused naming the grant; granted, it is written with the target's content."""
    rig = socket_rig(tmp_path, master, monkeypatch, portal)
    removed = import_(rig.vault, edited(lambda data: data["gateway"]["clients"].pop("agent2")))
    assert isinstance(removed, Written)
    code, _, err = run_cli(["policy", "rollback", "1", "--yes"])
    assert (code, err.splitlines()[-2:]) == (
        1,
        [
            "zoeymcp policy rollback: This brings back client agent2, removed in revision 2: "
            "refused without --allow-revive client:NAME for each.",
            "  --allow-revive client:agent2",
        ],
    )
    argv = ["policy", "rollback", "1", "--allow-revive", "client:agent2"]
    code, _, err = run_cli(argv, "y\n")
    assert code == 0, err
    assert err.splitlines()[:2] == [
        "Planned on revision 2 (the head):",
        "  Revision: 3, from 2: the content of revision 1",
    ]
    assert "Rolled back as revision 3." in err
    assert rig.vault.managed.policy.gateway is not None
    assert "agent2" in rig.vault.managed.policy.gateway.clients


def test_a_declarative_vault_has_no_managed_commands(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """G.9's mode source: GET /policy says declarative; a write is policy_not_managed."""
    rig = socket_rig(tmp_path, master, monkeypatch, portal)
    declarative = Policy.model_validate({"version": 1, "mode": "declarative"})
    rig.admin = AdminApp(
        rig.vault.runtime.store,
        rig.vault.runtime.keys,
        lambda: declarative,
        SetupCodes(rig.vault.state, rig.vault.runtime.keys.portal_key),
    )
    code, out, _ = run_cli(["policy"])
    assert (code, out) == (
        0,
        "Mode: declarative: the policy is the file or ZOEYMCP_CONFIG the vault was given.\n",
    )
    code, _, err = run_cli(["policy", "rollback", "1", "--yes"])
    assert (code, err) == (
        1,
        "zoeymcp policy rollback: This deployment's policy is declarative: commit a fragment "
        "instead.\n",
    )
    code, _, err = run_cli(["policy", "history"])
    assert code == 1
    assert "declarative" in err


def test_no_socket_is_said(master: dict[str, str], tmp_path: Path) -> None:
    """A vault that can't be reached: exit 2, naming the socket."""
    code, _, err = run_cli(["policy", "head", "--socket", str(tmp_path / "none.sock")])
    assert code == 2
    assert err.startswith("zoeymcp policy head: can't reach the vault's admin socket at ")


# --- the offline forms (I.1's recovery without a socket, COV-5) --------------------------------


def test_offline_reads(tmp_path: Path, master: dict[str, str], log_buffer: io.StringIO) -> None:
    """COV-5: history, a diff and an export with --state, the vault stopped: as over the socket,
    and the export logged via offline."""
    state = str(with_two_revisions(tmp_path, master))
    code, out, err = run_cli(["policy", "history", "--state", state])
    assert code == 0, err
    assert [line.split("  ")[0] for line in out.splitlines()] == ["2", "1"]
    code, out, err = run_cli(["policy", "diff", "2", "--state", state])
    assert code == 0, err
    assert out.splitlines()[0] == "Revision 2 against revision 1:"
    code, out, err = run_cli(["policy", "export", "--revision", "1", "--state", state])
    assert code == 0, err
    assert out.startswith("# zoeymcp policy export: revision 1 of deployment ")
    assert events(log_buffer, "policy_exported") == [
        {"event": "policy_exported", "revision": 1, "via": "offline"}
    ]


def test_offline_reads_keep_log_lines_off_stdout(
    tmp_path: Path, master: dict[str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """A read's stdout is its answer alone: the store's housekeeping lines as it opens (a stray
    file in the policy directory) go to stderr, so --format json parses."""
    state = with_two_revisions(tmp_path, master)
    (state / "policy" / "notes.txt").write_bytes(b"stray\n")
    capsys.readouterr()
    for argv in (["history"], ["diff", "2"]):
        code, out, err = run_cli(["policy", *argv, "--state", str(state), "--format", "json"])
        assert code == 0, err
        assert isinstance(json.loads(out), dict), argv
        assert "policy_stray_file" in err, argv
        assert capsys.readouterr().out == "", argv


def test_offline_import(tmp_path: Path, master: dict[str, str], log_buffer: io.StringIO) -> None:
    """J8 without a socket: a broken admin fixed by an export, an edit and an import with the
    vault stopped (--lockout-ok where a passkey's origin goes); written by the host offline,
    the store's next revision, and the vault starts from it."""
    state = with_two_revisions(tmp_path, master)
    code, out, err = run_cli(["policy", "export", "--state", str(state)])
    assert code == 0, err
    first, _, rest = out.partition("\n")
    data = yaml.safe_load(rest)
    data["admin"]["listen"] = "127.0.0.1:9091"
    text = first + "\n" + json.dumps(data) + "\n"
    argv = ["policy", "import", "-", "--state", str(state), "--yes", "--accept-widening"]
    code, _, err = run_cli(argv, text)
    assert (code, err.splitlines()[-1]) == (
        1,
        "zoeymcp policy import: This change moves the portal from 127.0.0.1:8081 to "
        "127.0.0.1:9091: after the vault's restart it listens there: type the confirmation at "
        "the prompt, or pass --yes --lockout-ok.",
    )
    code, _, err = run_cli([*argv, "--lockout-ok"], text)
    assert code == 0, err
    assert err.splitlines()[-3:] == [
        "Imported as revision 3.",
        "Start the vault:",
        f"  {HARDENED} up -d vault",
    ]
    store = reopened(state, master)
    assert isinstance(store.verdict, Ok)
    header = store.verdict.top.header
    assert (header["revision"], header["kind"], header["author"]) == (
        3,
        "policy.import",
        OFFLINE,
    )
    [line] = events(log_buffer, "policy_imported")[-1:]
    assert (line["revision"], line["author"], line["from_env"]) == (3, "host", False)
    runtime = load_runtime(write(tmp_path, managed_text()), state, master)
    assert runtime.policy.admin is not None
    assert runtime.policy.admin.listen == "127.0.0.1:9091"


def test_offline_rollback(tmp_path: Path, master: dict[str, str]) -> None:
    """J8's other way: a rollback with --state to the revision before, its grant given, the
    target's admin taken (a host rollback's, H.4); a moved base is refused."""
    state = with_two_revisions(tmp_path, master)
    argv = ["policy", "rollback", "1", "--state", str(state), "--yes"]
    code, _, err = run_cli(argv)
    assert code == 1
    assert err.splitlines()[-1] == "  --allow-revive client:agent2"
    code, _, err = run_cli([*argv, "--base", "1", "--allow-revive", "client:agent2"])
    said = err.splitlines()[-1]
    assert code == 1
    assert said.startswith(
        "zoeymcp policy rollback: Nothing was written: the policy moved to revision 2, saved "
    )
    assert said.endswith(
        " by the host (socket) since you started. For an import, export again and redo your "
        "edit; for a rollback, run it again."
    )
    code, _, err = run_cli([*argv, "--allow-revive", "client:agent2", "--accept-widening"])
    assert code == 0, err
    assert "Rolled back as revision 3." in err
    store = reopened(state, master)
    assert isinstance(store.verdict, Ok)
    assert store.verdict.top.header["target"] == 1


def test_offline_refuses_a_parked_or_missing_store(tmp_path: Path, master: dict[str, str]) -> None:
    """A store a declarative start parked is read, never written offline; a volume with no store
    names the seed."""
    state = with_two_revisions(tmp_path, master)
    declarative = EXAMPLE_POLICY.read_text(encoding="utf-8")
    load_runtime(write(tmp_path, declarative, "declarative.yaml"), state, master)
    code, _, err = run_cli(["policy", "history", "--state", str(state)])
    assert code == 0, err
    code, _, err = run_cli(["policy", "rollback", "1", "--state", str(state), "--yes"])
    assert (code, err) == (
        1,
        "zoeymcp policy rollback: This deployment's policy is declarative: commit a fragment "
        "instead.\n",
    )
    empty = tmp_path / "empty"
    empty.mkdir(mode=0o700)
    code, _, err = run_cli(["policy", "history", "--state", str(empty)])
    # A read's log lines go to stderr too (the state lock's, where there is no flock).
    assert (code, err.splitlines()[-1]) == (
        2,
        f"zoeymcp policy history: there is no policy store in {empty}: seed it with zoeymcp "
        f"policy seed --state {empty}",
    )


OFFLINE_FORMS = [
    ["policy", "history"],
    ["policy", "diff", "1"],
    ["policy", "export"],
    ["policy", "import", "-", "--yes"],
    ["policy", "rollback", "1", "--yes"],
]
OFFLINE_IDS = ["history", "diff", "export", "import", "rollback"]


@pytest.mark.parametrize("argv", OFFLINE_FORMS, ids=OFFLINE_IDS)
def test_every_offline_form_refuses_root(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, argv: list[str]
) -> None:
    """OPS-5: each --state form refuses root before it reads or writes anything."""
    monkeypatch.setattr(main_module, "running_as_root", lambda: True)
    state = tmp_path / "state"
    code, _, err = run_cli([*argv, "--state", str(state)])
    assert (code, err) == (
        2,
        f"zoeymcp policy {argv[1]}: This command won't run as root: the vault's uid couldn't "
        "read what it writes. Run it as the vault's uid: add --user 10001:10001.\n",
    )
    assert not state.exists()


@pytest.mark.skipif(sys.platform == "win32", reason="the state lock is flock, which Windows lacks")
@pytest.mark.parametrize("argv", OFFLINE_FORMS, ids=OFFLINE_IDS)
def test_every_offline_form_waits_for_the_vault(
    tmp_path: Path, master: dict[str, str], argv: list[str]
) -> None:
    """OPS-6: while a vault holds the state lock, each --state form refuses, naming the stop."""
    state = with_two_revisions(tmp_path, master)
    held = acquire_state_lock(state)
    assert held is not None
    try:
        code, _, err = run_cli([*argv, "--state", str(state)], managed_text())
    finally:
        os.close(held)
    assert (code, err) == (
        2,
        f"zoeymcp policy {argv[1]}: The state directory is in use: stop the vault first ("
        f"{HARDENED} stop vault), then run this again.\n",
    )


# --- policy acknowledge-restore (K.3, J11, T-4) --------------------------------------------------

WITNESS_OTHER = "fedcba9876543210" * 2


def test_acknowledge_over_the_socket(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """J11's acknowledgment: the number and where it comes from (the gateway's claim), typed to
    write it; a mistyped one, or a --to other than the vault's, writes nothing; the head names
    the witness."""
    rig = socket_rig(tmp_path, master, monkeypatch, portal)
    code, _, err = run_cli(["policy", "acknowledge-restore"])
    assert (code, err) == (
        1,
        "zoeymcp policy acknowledge-restore: There is nothing to record: the gateway reports no "
        "revision of this deployment above the head, and no other deployment it hasn't passed.\n",
    )
    deployment = deployment_of(rig)
    witness_of(rig, {deployment: 31})
    code, out, _ = run_cli(["policy"])
    assert out.splitlines()[-2:] == [
        "Witness: the gateway has seen revision 31",
        "The gateway's witness shows a restore: see zoeymcp health, then zoeymcp policy "
        "acknowledge-restore (revision 32).",
    ]
    jump = (
        "Revision 1 jumps to 32: one above the gateway's claim of 31; the number comes from the "
        "gateway."
    )
    code, _, err = run_cli(["policy", "acknowledge-restore"], "31\n")
    assert (code, err) == (1, f"{jump}\nType 32 to write it: Nothing written.\n")
    code, _, err = run_cli(["policy", "acknowledge-restore", "--to", "30", "--yes"])
    assert (code, err) == (1, f"{jump}\nNothing written: the vault plans revision 32, not 30.\n")
    code, _, err = run_cli(["policy", "acknowledge-restore", "--to", "10000000000", "--yes"])
    assert (code, err) == (
        1,
        "zoeymcp policy acknowledge-restore: A revision can't go above 9,999,999,999.\n",
    )
    code, _, err = run_cli(["policy", "acknowledge-restore"], "000000000000\n")
    assert (code, err) == (1, f"{jump}\nType 32 to write it: Nothing written.\n")
    assert rig.vault.managed.revision == 1
    code, _, err = run_cli(["policy", "acknowledge-restore"], "32\n")
    assert code == 0, err
    assert err.splitlines()[:5] == [
        jump,
        "Type 32 to write it: Planned on revision 1 (the head):",
        "  Revision: 32, from 1, past 2-31, which are never written",
        "Acknowledged the restore as revision 32.",
        "Next:",
    ]
    assert rig.vault.managed.revision == 32
    code, out, _ = run_cli(["policy"])
    assert out.splitlines()[-1] == "Witness: the gateway has seen revision 31"


def test_acknowledge_another_deployment_with_to(
    tmp_path: Path, master: dict[str, str], monkeypatch: pytest.MonkeyPatch, portal: BlockingPortal
) -> None:
    """T-5: the claim is another deployment's, which the line names; --to the vault's number
    asks [y/N], and --yes writes it."""
    rig = socket_rig(tmp_path, master, monkeypatch, portal)
    witness_of(rig, {WITNESS_OTHER: 31, deployment_of(rig): 1})
    code, _, err = run_cli(["policy", "acknowledge-restore", "--to", "32"], "n\n")
    assert code == 1
    assert err.splitlines()[0] == (
        "Revision 1 jumps to 32: one above the gateway's claim of 31 for another deployment of "
        "this vault (fedcba98); the number comes from the gateway."
    )
    assert err.splitlines()[-1] == "Write revision 32? [y/N] Nothing written."
    code, _, err = run_cli(["policy", "acknowledge-restore", "--to", "32", "--yes"])
    assert code == 0, err
    assert "Acknowledged the restore as revision 32." in err.splitlines()
    store = rig.vault.store
    assert store.header is not None
    assert (store.header["revision"], store.header["jumped_from"]) == (32, 1)


def test_acknowledge_offline(
    tmp_path: Path, master: dict[str, str], log_buffer: io.StringIO
) -> None:
    """With the vault stopped there is no claim to read: the number is the host's, typed or
    --to, above the head and at most 9,999,999,999; then the vault's start."""
    state = with_two_revisions(tmp_path, master)
    argv = ["policy", "acknowledge-restore", "--state", str(state)]
    code, _, err = run_cli([*argv, "--to", "2", "--yes"])
    assert (code, err.splitlines()[-1]) == (
        1,
        "zoeymcp policy acknowledge-restore: There is nothing to record: revision 2 isn't above "
        "the head, revision 2.",
    )
    code, _, err = run_cli(argv, "x\n")
    assert code == 1
    assert err.endswith("the one zoeymcp health named: Nothing written.\n")
    # K.3: a number above 9,999,999,999, given or typed, is revision_out_of_range.
    out_of_range = "zoeymcp policy acknowledge-restore: A revision can't go above 9,999,999,999.\n"
    code, _, err = run_cli([*argv, "--to", "10000000000", "--yes"])
    assert (code, err) == (1, out_of_range)
    code, _, err = run_cli(argv, "10000000000\n")
    assert (code, err.endswith(f"the one zoeymcp health named: {out_of_range}")) == (1, True)
    code, _, err = run_cli(argv, "9\n")
    assert code == 0, err
    lines = err.splitlines()
    assert lines[0] == (
        "The vault is stopped, so its witness can't be read here. Type the revision to jump to, "
        "the one zoeymcp health named: Revision 2 jumps to 9: the number you gave."
    )
    assert lines[1:] == [
        "Planned on revision 2 (the head):",
        "  Revision: 9, from 2, past 3-8, which are never written",
        "Acknowledged the restore as revision 9.",
        "Start the vault:",
        f"  {HARDENED} up -d vault",
    ]
    store = reopened(state, master)
    assert isinstance(store.verdict, Ok)
    header = store.verdict.top.header
    assert (header["revision"], header["origin"], header["jumped_from"]) == (9, "acknowledge", 2)
    assert header["author"] == OFFLINE
    [line] = events(log_buffer, "policy_acknowledged")
    assert (line["revision"], line["jumped_from"], line["author"]) == (9, 2, "host")
    code, _, err = run_cli([*argv, "--to", "10", "--yes"])
    assert code == 0, err


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (["--yes"], "with --yes, give the revision with --to N: the number is never taken unseen"),
        (["--to", "0"], "--to is a revision, 1 to 9,999,999,999"),
    ],
    ids=["yes-without-to", "to-zero"],
)
def test_acknowledge_usage(master: dict[str, str], argv: list[str], said: str) -> None:
    assert cli(["policy", "acknowledge-restore", *argv]) == (
        2,
        f"zoeymcp policy acknowledge-restore: {said}\n",
    )
