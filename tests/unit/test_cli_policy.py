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
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.cli import main as main_module
from zoeymcp.cli.main import main
from zoeymcp.common.policy.ratchet import initial
from zoeymcp.common.policy.schema import hash_token
from zoeymcp.vault import gatewaykeys, logs, policystore
from zoeymcp.vault.keys import KeySet, generate_master_key
from zoeymcp.vault.managed import head_policy
from zoeymcp.vault.policystart import Ok
from zoeymcp.vault.policystore import PolicyStore
from zoeymcp.vault.server import acquire_state_lock, load_runtime

from .conftest import EXAMPLE_POLICY
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
    code, err = cli([*argv, "--allow-revive", "client:agent2", "--reason", "back to 1"])
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
    granted = [*argv, "--allow-revive", "client:agent2"]
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
    code, err = cli([*argv, "--allow-revive", "client:agent2", "--yes"], managed_text())
    assert code == 0, err
    head = reopened(state, master).head
    assert head is not None
    assert head.revision == 3


@pytest.mark.parametrize(
    ("argv", "said"),
    [
        (
            ["x.yaml", "--reseed"],
            "this version imports only offline, with the vault stopped: --state DIR --reseed",
        ),
        (
            ["x.yaml", "--state", "s"],
            "this version imports only offline, with the vault stopped: --state DIR --reseed",
        ),
        (
            ["--state", "s", "--reseed"],
            "give the policy as FILE (- for standard input) or --from-env, one of them",
        ),
        (
            ["x.yaml", "--from-env", "--state", "s", "--reseed"],
            "give the policy as FILE (- for standard input) or --from-env, one of them",
        ),
        (
            ["x.yaml", "--state", "s", "--reseed", "--reason", ""],
            "--reason is 1 to 200 printable characters",
        ),
        (
            ["x.yaml", "--state", "s", "--reseed", "--reason", "a\tb"],
            "--reason is 1 to 200 printable characters",
        ),
    ],
    ids=["no-state", "no-reseed", "no-source", "two-sources", "empty-reason", "tab-reason"],
)
def test_import_usage(master: dict[str, str], argv: list[str], said: str) -> None:
    """Only the offline reseed is an import in this version (the socket's is step 14a's)."""
    assert cli(["policy", "import", *argv]) == (2, f"zoeymcp policy import: {said}\n")
