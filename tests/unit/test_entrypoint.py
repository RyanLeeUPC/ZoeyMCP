"""The standard tier's launcher: the environment split, the box checks, the directories, the
command lines and the supervisor (M3 design B.2, G21). The privilege drop itself needs root in a
container, so the image smoke test runs it.

M7 (design C.10, O.2, step 18d): bridges under the launcher. Every ``bridge_specs`` refusal, each
free of the value it refuses; each bridge's socket directory, a wrong one refusing that bridge
alone while the vault and the gateway start (FM-31); the bridge's command line and environment;
the vault's ``--bridge NAME=UID``; the supervisor's stop order, a bridge's exit leaving the
others running (FM-29), and a bridge started without its token hash (FM-30's launcher half).
"""

from __future__ import annotations

import errno
import io
import json
import os
import signal
import stat
import sys
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.cli.main import main
from zoeymcp.common import logs
from zoeymcp.entrypoint import env, launcher
from zoeymcp.entrypoint.env import Bridge, Found, ProcessStatus, StatusError
from zoeymcp.entrypoint.launcher import Child, LaunchError, Options, Supervisor

# --- the environment -----------------------------------------------------------------------------

ENVIRON = {
    "PATH": "/opt/zoeymcp/bin:/usr/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "LC_TIME": "en_GB.UTF-8",
    "TZ": "UTC",
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
    "ZOEYMCP_GATEWAY_ADMIN_SOCKET": "/run/zoeymcp-gateway/admin.sock",
    "ZOEYMCP_GATEWAY_KEY": "zgw1-secret",
    "ZOEYMCP_GATEWAY_KEY_FILE": "/run/secrets/gateway_key",
    "ZOEYMCP_GATEWAY_KEYS": "zgw1-secret",
    "ZOEYMCP_MASTER_KEY": "master",
    "ZOEYMCP_MASTER_KEY_PREVIOUS": "old-master",
    "ZOEYMCP_CONFIG": "version: 1",
    "ZOEYMCP_ADMIN_SOCKET": "/run/zoeymcp/admin.sock",
    "MUSIC_TOKEN": "an env: secret",
    "PYTHONPATH": "/var/evil",
    "PYTHONSTARTUP": "/var/evil.py",
    "LD_PRELOAD": "/var/evil.so",
    "HOME": "/root",
    "XLC_ALL": "not a locale",
}


def test_the_gateway_gets_only_the_allowlist() -> None:
    assert env.gateway_environment(ENVIRON) == {
        "PATH": "/opt/zoeymcp/bin:/usr/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LC_TIME": "en_GB.UTF-8",
        "TZ": "UTC",
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "ZOEYMCP_GATEWAY_ADMIN_SOCKET": "/run/zoeymcp-gateway/admin.sock",
    }


def test_the_vault_gets_everything() -> None:
    vault, gateway, bridges = env.split_environment(ENVIRON)
    assert vault == ENVIRON
    assert vault is not ENVIRON
    assert gateway == env.gateway_environment(ENVIRON)
    assert bridges == {}


# --- /proc/self/status ---------------------------------------------------------------------------

STATUS = """Name:\tzoeymcp
Umask:\t0022
State:\tR (running)
Pid:\t1
Uid:\t0\t0\t0\t0
Gid:\t0\t0\t0\t0
NoNewPrivs:\t1
CapInh:\t0000000000000000
CapPrm:\t00000000000000c0
CapEff:\t00000000000000c0
CapBnd:\t00000000000000c0
CapAmb:\t0000000000000000
Seccomp:\t2
"""


def test_parse_status() -> None:
    assert env.parse_status(STATUS) == ProcessStatus((0, 0, 0, 0), True, 0xC0, 0xC0)
    dropped = STATUS.replace("Uid:\t0\t0\t0\t0", "Uid:\t10003\t10003\t10003\t10003")
    dropped = dropped.replace("CapEff:\t00000000000000c0", "CapEff:\t0000000000000000")
    dropped = dropped.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")
    assert env.parse_status(dropped) == ProcessStatus((10003,) * 4, False, 0xC0, 0)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (("NoNewPrivs:\t1\n", ""), "no NoNewPrivs line"),
        (("CapBnd:\t00000000000000c0\n", ""), "no CapBnd line"),
        (("CapEff:\t00000000000000c0\n", ""), "no CapEff line"),
        (("Uid:\t0\t0\t0\t0\n", ""), "no Uid line"),
        (("CapBnd:\t00000000000000c0", "CapBnd:\tzz"), "a malformed line"),
        (("Uid:\t0\t0\t0\t0", "Uid:\t0\t0\t0"), "a malformed line"),
        (("Uid:\t0\t0\t0\t0", "Uid:\t0\t0\t0\t0\t0"), "a malformed line"),
        (("NoNewPrivs:\t1", "NoNewPrivs:\t2"), "a malformed line"),
        (("NoNewPrivs:\t1", "NoNewPrivs:\tyes"), "a malformed line"),
        # The name ends at the first colon: the rest of the line is its value.
        (("CapBnd:\t00000000000000c0", "CapBnd:\t00000000000000c0:1"), "a malformed line"),
    ],
)
def test_a_status_without_what_is_needed_is_refused(change: tuple[str, str], message: str) -> None:
    with pytest.raises(StatusError, match=f"^{message}$"):
        env.parse_status(STATUS.replace(*change))


def boxed(**changes: Any) -> ProcessStatus:
    base: dict[str, Any] = {
        "uids": (0, 0, 0, 0),
        "no_new_privs": True,
        "cap_bounding": env.ALLOWED_CAPS,
        "cap_effective": env.ALLOWED_CAPS,
    }
    return ProcessStatus(**{**base, **changes})


def test_the_right_box_passes() -> None:
    assert env.box_refusals(boxed(), 1) == []
    assert env.box_refusals(boxed(cap_bounding=1 << env.CAP_SETUID), 1) == []
    assert env.box_refusals(boxed(cap_bounding=0), 1) == []


def test_each_box_refusal() -> None:
    assert env.box_refusals(boxed(), 7) == ["the launcher must be the container's PID 1, not PID 7"]
    root = 'the launcher must start as root (user: "0:0"); it drops root itself'
    assert env.box_refusals(boxed(uids=(10001, 10001, 10001, 10001)), 1) == [root]
    assert env.box_refusals(boxed(uids=(0, 10001, 0, 0)), 1) == [root]
    assert env.box_refusals(boxed(uids=(10001, 0, 0, 0)), 1) == [root]
    assert env.box_refusals(boxed(uids=(0, 0, 10001, 10001)), 1) == []
    assert env.box_refusals(boxed(no_new_privs=False), 1) == [
        "NoNewPrivs is not set: add security_opt: [no-new-privileges:true], or a setuid binary "
        "could hand the gateway's uid privileges back"
    ]
    extra = env.ALLOWED_CAPS | 1 << 0 | 1 << 13 | 1 << 21
    assert env.box_refusals(boxed(cap_bounding=extra), 1) == [
        "capabilities beyond SETUID and SETGID are in the bounding set (cap_0, cap_13, cap_21): "
        "add cap_drop: [ALL] and cap_add: [SETUID, SETGID]"
    ]
    assert len(env.box_refusals(boxed(uids=(1, 1, 1, 1), no_new_privs=False), 2)) == 3


def test_cap_names() -> None:
    assert env.cap_names(0) == []
    assert env.cap_names(0b101) == ["cap_0", "cap_2"]
    assert env.cap_names(1 << 40) == ["cap_40"]


# --- the directories -----------------------------------------------------------------------------

GOOD = {d.path: Found(d.uid, d.gid, d.mode) for d in env.DIRECTORIES}


def test_the_directories_as_the_image_makes_them() -> None:
    assert [(d.path, d.uid, d.gid, d.mode) for d in env.DIRECTORIES] == [
        ("/state", 10001, 10001, 0o700),
        ("/state-gateway", 10002, 10002, 0o700),
        ("/run/zoeymcp", 10001, 10001, 0o700),
        ("/run/zoeymcp-link", 10001, 10002, 0o750),
        ("/run/zoeymcp-gateway", 10002, 10002, 0o700),
    ]
    assert env.directory_refusals(GOOD) == []


@pytest.mark.parametrize(
    ("found", "message"),
    [
        (None, "/run/zoeymcp-link (the link socket) is missing; it must be 10001:10002 0750"),
        (
            Found(10001, 10002, 0o750, is_dir=False),
            "/run/zoeymcp-link (the link socket) is missing; it must be 10001:10002 0750",
        ),
        (
            Found(10001, 10002, 0o2750),
            "/run/zoeymcp-link (the link socket) is 10001:10002 2750; it must be 10001:10002 0750",
        ),
        (
            Found(10001, 10001, 0o750),
            "/run/zoeymcp-link (the link socket) is 10001:10001 0750; it must be 10001:10002 0750",
        ),
        (
            Found(10002, 10002, 0o750),
            "/run/zoeymcp-link (the link socket) is 10002:10002 0750; it must be 10001:10002 0750",
        ),
        (
            Found(10001, 10002, 0o755),
            "/run/zoeymcp-link (the link socket) is 10001:10002 0755; it must be 10001:10002 0750",
        ),
    ],
)
def test_a_wrong_directory_is_refused(found: Found | None, message: str) -> None:
    assert env.directory_refusals({**GOOD, "/run/zoeymcp-link": found}) == [message]


def test_every_wrong_directory_is_named() -> None:
    found = {**GOOD, "/state": None, "/run/zoeymcp-link": Found(10001, 10002, 0o755)}
    assert env.directory_refusals(found) == [
        "/state (the vault's state (a volume)) is missing; it must be 10001:10001 0700",
        "/run/zoeymcp-link (the link socket) is 10001:10002 0755; it must be 10001:10002 0750",
    ]


def test_a_mode_with_the_file_type_bits_still_compares() -> None:
    assert env.directory_refusals({**GOOD, "/state": Found(10001, 10001, 0o40700)}) == []
    assert env.directory_refusals({k: v for k, v in GOOD.items() if k != "/state"}) == [
        "/state (the vault's state (a volume)) is missing; it must be 10001:10001 0700"
    ]


# --- command lines -------------------------------------------------------------------------------


VAULT_TAIL = [
    "vault",
    "--gateway-socket",
    "/run/zoeymcp-link/vault.sock",
    "--gateway-uid",
    "10002",
    "--listen",
    "none",
    "--control-fd",
    "5",
]


def test_the_vault_listens_on_the_link_only_by_default() -> None:
    assert launcher.vault_argv(Options(), 5) == [
        sys.executable,
        "-I",
        "-m",
        "zoeymcp",
        "vault",
        "--gateway-socket",
        "/run/zoeymcp-link/vault.sock",
        "--gateway-uid",
        "10002",
        "--listen",
        "none",
        "--control-fd",
        "5",
    ]
    argv = launcher.vault_argv(Options(vault_listens=("0.0.0.0:8080", "[::]:8080")), 5)
    assert argv[9:13] == ["--listen", "0.0.0.0:8080", "--listen", "[::]:8080"]


def test_the_gateway_runs_in_its_own_environment(tmp_path: Path) -> None:
    python = tmp_path / "python"
    tail = [
        "-I",
        "-m",
        "zoeymcp",
        "gateway",
        "--vault",
        "unix:/run/zoeymcp-link/vault.sock",
        "--listen",
        "127.0.0.1:9000",
        "--control-fd",
        "6",
    ]
    options = Options(gateway_listen="127.0.0.1:9000")
    assert launcher.gateway_argv(options, 6, str(python)) == [sys.executable, *tail]
    python.write_text("")
    assert launcher.gateway_argv(options, 6, str(python)) == [str(python), *tail]
    assert launcher.GATEWAY_PYTHON == "/opt/zoeymcp-gateway/bin/python"


def test_parse_supervised() -> None:
    assert launcher.parse_supervised(["vault=12:4", "gateway=13:5"]) == [
        Child("vault", 12, 4),
        Child("gateway", 13, 5),
    ]
    # A bridge beside them; a refused bridge is simply absent.
    assert launcher.parse_supervised(
        ["vault=12:4", "gateway=13:5", "bridge:fetch=14:6", "bridge:n0tes=15:7"]
    ) == [
        Child("vault", 12, 4),
        Child("gateway", 13, 5),
        Child("bridge:fetch", 14, 6),
        Child("bridge:n0tes", 15, 7),
    ]
    for bad, message in (
        (["vault=12:4"], "needs the vault and the gateway"),
        (["gateway=13:5", "bridge:fetch=14:6"], "needs the vault and the gateway"),
        (["vault=12:4", "vault=13:5"], "names vault twice"),
        (["vault=12:4", "gateway=13:5", "bridge:a=14:6", "bridge:a=15:7"], "names bridge:a twice"),
        (["vault=x:4", "gateway=13:5"], "bad --supervise value"),
        (["vault=12:", "gateway=13:5"], "bad --supervise value"),
        # Any other name, a bridge's malformed one included.
        (["vault=12:4", "gateway=13:5", "other=14:6"], "bad --supervise value"),
        (["vault=12:4", "gateway=13:5", "bridge:=14:6"], "bad --supervise value"),
        (["vault=12:4", "gateway=13:5", "bridge:Fetch=14:6"], "bad --supervise value"),
        (["vault=12:4", "gateway=13:5", "bridge:fetch=14:x"], "bad --supervise value"),
        (["vault=12:4", "gateway=13:5", "fetch=14:6"], "bad --supervise value"),
        (["vault=12:4", "gateway=13:5", "xbridge:fetch=14:6"], "bad --supervise value"),
    ):
        with pytest.raises(LaunchError, match=message):
            launcher.parse_supervised(bad)


@pytest.mark.skipif(sys.platform == "linux", reason="checks the refusal off Linux")
def test_the_standard_tier_needs_linux() -> None:
    with pytest.raises(LaunchError, match="only in a Linux container"):
        launcher.check(Options())


@pytest.mark.skipif(sys.platform != "linux", reason="reads a status file on Linux")
def test_check_reads_the_status_and_the_directories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status = tmp_path / "status"
    status.write_text(STATUS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"))
    monkeypatch.setattr(launcher, "STATUS_FILE", str(status))
    monkeypatch.setattr(launcher, "found_directories", lambda: GOOD)
    with pytest.raises(LaunchError) as raised:
        launcher.check(Options())
    assert "PID 1" in str(raised.value)
    assert "NoNewPrivs is not set" in str(raised.value)
    launcher.check(Options(unsafe_skip_checks=True))
    monkeypatch.setattr(launcher, "found_directories", dict)
    with pytest.raises(LaunchError, match=r"/state .* is missing"):
        launcher.check(Options(unsafe_skip_checks=True))
    monkeypatch.setattr(launcher, "STATUS_FILE", str(tmp_path / "nothing"))
    with pytest.raises(LaunchError, match="can't read"):
        launcher.check(Options())


def test_found_directories_stats_each(tmp_path: Path) -> None:
    here = tmp_path / "d"
    here.mkdir()
    (tmp_path / "f").write_text("")

    def fake_stat(path: str) -> os.stat_result:
        if path == "/state":
            return os.stat(here)
        if path == "/run/zoeymcp":
            return os.stat(tmp_path / "f")
        raise FileNotFoundError(path)

    found = launcher.found_directories(fake_stat)
    assert found["/state-gateway"] is None
    assert found["/state"] == Found(
        os.stat(here).st_uid, os.stat(here).st_gid, os.stat(here).st_mode & 0o7777, True
    )
    run_dir = found["/run/zoeymcp"]
    assert run_dir is not None
    assert not run_dir.is_dir


# --- the supervisor ------------------------------------------------------------------------------


class System:
    """Children that end when told to stop (or when the test says), and a clock."""

    def __init__(self, *, obey: bool = True) -> None:
        self.now = 0.0
        self.obey = obey
        self.written: list[tuple[int, bytes]] = []
        self.ended: list[tuple[int, int]] = []  # (pid, wait status) still to be reaped
        self.closed: set[int] = set()

    def waitpid(self, pid: int, options: int) -> tuple[int, int]:
        assert (pid, options) == (-1, launcher.WNOHANG)
        if not self.ended:
            return 0, 0
        return self.ended.pop(0)

    def write(self, fd: int, data: bytes) -> int:
        if fd in self.closed:
            raise BrokenPipeError(32, "Broken pipe")
        self.written.append((fd, data))
        if data == b"TERM\n" and self.obey:
            self.ended.append((100 + fd, 0))
            self.closed.add(fd)
        return len(data)

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def supervisor(system: System) -> Supervisor:
    return Supervisor(
        [Child("vault", 104, 4), Child("gateway", 105, 5)],
        waitpid=system.waitpid,
        write=system.write,
        clock=system.clock,
        sleep=system.sleep,
    )


def run(sup: Supervisor, system: System, rounds: int = 1000) -> int:
    for _ in range(rounds):
        code = sup.step()
        if code is not None:
            return code
        system.sleep(launcher.POLL)
    raise AssertionError("the supervisor didn't finish")


def test_sigterm_stops_the_gateway_then_the_vault_and_exits_0() -> None:
    system = System()
    sup = supervisor(system)
    assert sup.step() is None
    sup.on_signal(signal.SIGTERM)
    assert run(sup, system) == 0
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n")]
    assert [child.status for child in sup.children] == [0, 0]


def test_sighup_reloads_both() -> None:
    system = System()
    sup = supervisor(system)
    sup.on_signal(launcher.SIGHUP)
    assert sup.step() is None
    assert system.written == [(4, b"HUP\n"), (5, b"HUP\n")]
    assert sup.stopping_since is None


def test_a_child_exiting_stops_the_other_and_exits_1() -> None:
    system = System()
    sup = supervisor(system)
    system.ended.append((105, 3 << 8))  # the gateway exited with 3
    assert run(sup, system) == 1
    assert system.written == [(4, b"TERM\n")]
    assert [child.status for child in sup.children] == [0, 3]


def test_a_child_that_wont_stop_is_left_after_the_wait() -> None:
    system = System(obey=False)
    sup = supervisor(system)
    sup.on_signal(signal.SIGINT)
    assert run(sup, system, rounds=5000) == 1
    assert system.now == pytest.approx(launcher.STOP_WAIT + launcher.POLL, abs=launcher.POLL)
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n")]


def test_the_vault_outlives_the_gateway() -> None:
    system = System(obey=False)
    sup = supervisor(system)
    sup.on_signal(signal.SIGTERM)
    while system.now < 300:  # an approved call still runs in the gateway
        assert sup.step() is None
        system.sleep(launcher.POLL)
    assert system.written == [(5, b"TERM\n")]
    system.ended.append((105, 0))  # the gateway is done
    assert sup.step() is None
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n")]
    # The vault is told once, however long it takes.
    sup.stop("signal")
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n")]


def test_the_vault_is_told_after_the_gateways_wait() -> None:
    system = System(obey=False)
    sup = supervisor(system)
    sup.stop("signal")
    system.now = launcher.GATEWAY_STOP_WAIT
    assert sup.step() is None
    assert system.written == [(5, b"TERM\n")]
    system.now = launcher.GATEWAY_STOP_WAIT + 0.1
    assert sup.step() is None
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n")]
    assert launcher.STOP_WAIT == (
        launcher.GATEWAY_STOP_WAIT + launcher.VAULT_STOP_WAIT + launcher.BRIDGE_STOP_WAIT
    )


def test_orphans_are_reaped_and_a_dead_childs_pipe_is_ignored() -> None:
    system = System()
    sup = supervisor(system)
    system.ended += [(999, 0), (104, 0)]
    system.closed.add(4)
    assert run(sup, system) == 1  # the vault ended on its own
    assert system.written == [(5, b"TERM\n")]


def test_no_children_left_to_wait_for() -> None:
    def none_left(pid: int, options: int) -> tuple[int, int]:
        raise ChildProcessError

    sup = Supervisor([Child("vault", 1, 4), Child("gateway", 2, 5)], waitpid=none_left)
    sup.reap()
    assert [child.status for child in sup.children] == [None, None]


def test_a_second_stop_doesnt_restart_the_wait() -> None:
    system = System(obey=False)
    sup = supervisor(system)
    sup.stop("signal")
    system.now = 10
    sup.stop("signal")
    assert sup.stopping_since == 0


def test_run_installs_the_signal_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    installed: list[int] = []
    monkeypatch.setattr(signal, "signal", lambda signum, handler: installed.append(signum))
    system = System()
    sup = supervisor(system)
    system.ended += [(104, 0), (105, 0)]
    assert sup.run() == 1
    assert installed == [signal.SIGTERM, signal.SIGINT, launcher.SIGHUP]


# --- bridges: their specs (M7 design C.10, O.2) --------------------------------------------------

FETCH_ARGS = ["--era", "legacy", "--", "/opt/stdio-server/venv/bin/fetch-server"]
NOTES_ARGS = ["--era=modern", "--secret-env", "NOTES_KEY", "--", "notes", "--listen", "x"]
FETCH_HASH = "sha256:" + "a" * 64
BRIDGE_ENVIRON = {
    **ENVIRON,
    "ZOEYMCP_BRIDGE_FETCH_ARGS": json.dumps(FETCH_ARGS),
    "ZOEYMCP_BRIDGE_FETCH_TOKEN_SHA256": FETCH_HASH,
    "ZOEYMCP_BRIDGE_FETCH_ENV_BASE_URL": "http://127.0.0.1:8080/fetch",
    "ZOEYMCP_BRIDGE_NOTES_ARGS": json.dumps(NOTES_ARGS),
    "ZOEYMCP_BRIDGE_NOTES_TOKEN_SHA256": "sha256:" + "b" * 64,
    "ZOEYMCP_BRIDGE_NOTES_ENV_NOTES_KEY": "a notes secret",
}


def specs(args: object, **environ: str) -> list[Bridge]:
    """Bridge fetch's spec with ``args`` as its ARGS (a list is written as JSON)."""
    raw = args if isinstance(args, str) else json.dumps(args)
    return env.bridge_specs({"ZOEYMCP_BRIDGE_FETCH_ARGS": raw, **environ}, ["fetch"])


def refusals(args: object, **environ: str) -> list[str]:
    [spec] = specs(args, **environ)
    assert spec.args == ()
    return list(spec.refusals)


def test_the_constants() -> None:
    assert (env.BRIDGE_UID_BASE, env.MAX_BRIDGES) == (10100, 8)
    assert env.BRIDGE_TOKEN == "ZOEYMCP_BRIDGE_TOKEN_SHA256"
    assert env.LAUNCHER_OPTIONS == ("--listen", "--peer-uid", "--control-fd", "--work-dir")
    assert env.bridge_variable("fetch", "ARGS") == "ZOEYMCP_BRIDGE_FETCH_ARGS"
    assert env.bridge_variable("n0tes", "ENV_") == "ZOEYMCP_BRIDGE_N0TES_ENV_"


def test_a_bridges_spec_is_its_args() -> None:
    assert env.bridge_specs(BRIDGE_ENVIRON, ["fetch", "notes"]) == [
        Bridge("fetch", 0, tuple(FETCH_ARGS)),
        Bridge("notes", 1, tuple(NOTES_ARGS)),
    ]
    assert env.bridge_specs(BRIDGE_ENVIRON, []) == []
    # The command's own words after the -- aren't looked at, an option's name included.
    assert specs(["--era", "legacy", "--", "x", "--", "--listen=y", "--egress-proxy"]) == [
        Bridge("fetch", 0, ("--era", "legacy", "--", "x", "--", "--listen=y", "--egress-proxy"))
    ]


@pytest.mark.parametrize(
    ("args", "reasons"),
    [
        (
            ["--era", "legacy", "x"],
            ["ZOEYMCP_BRIDGE_FETCH_ARGS has no --: the command goes after it"],
        ),
        (["--era", "legacy", "--"], ["ZOEYMCP_BRIDGE_FETCH_ARGS has no command after --"]),
        (["--", "x"], ["ZOEYMCP_BRIDGE_FETCH_ARGS has no --era"]),
        # --era after the -- is the command's.
        (["--", "x", "--era", "legacy"], ["ZOEYMCP_BRIDGE_FETCH_ARGS has no --era"]),
        (["--eras", "legacy", "--", "x"], ["ZOEYMCP_BRIDGE_FETCH_ARGS has no --era"]),
        (
            [],
            [
                "ZOEYMCP_BRIDGE_FETCH_ARGS has no --: the command goes after it",
                "ZOEYMCP_BRIDGE_FETCH_ARGS has no --era",
            ],
        ),
    ],
)
def test_args_need_an_era_and_a_command(args: list[str], reasons: list[str]) -> None:
    assert refusals(args) == reasons


@pytest.mark.parametrize("option", ["--listen", "--peer-uid", "--control-fd", "--work-dir"])
def test_the_launchers_options_are_refused_in_args(option: str) -> None:
    reason = f"ZOEYMCP_BRIDGE_FETCH_ARGS[2]: {option} is the launcher's"
    assert refusals(["--era", "legacy", option, "v", "--", "x"]) == [reason]
    assert refusals(["--era", "legacy", f"{option}=v", "--", "x"]) == [reason]
    assert refusals(["--era", "legacy", f"{option}=", "--", "x"]) == [reason]
    # After the -- it is the command's word.
    assert specs(["--era", "legacy", "--", "x", option, f"{option}=v"])[0].refusals == ()
    # A longer option is the bridge's parser's to refuse (allow_abbrev=False).
    assert specs(["--era", "legacy", f"{option}s", "--", "x"])[0].refusals == ()


def test_egress_proxy_is_refused_in_args() -> None:
    reason = (
        "ZOEYMCP_BRIDGE_FETCH_ARGS[0]: --egress-proxy: nothing in the standard tier enforces egress"
    )
    assert refusals(["--egress-proxy", "http://p:3128", "--era", "legacy", "--", "x"]) == [reason]
    assert refusals(["--egress-proxy=http://p:3128", "--era", "legacy", "--", "x"]) == [reason]
    assert specs(["--era", "legacy", "--", "x", "--egress-proxy=http://p:3128"])[0].refusals == ()


def test_every_args_refusal_is_named_at_once() -> None:
    args = ["--listen=a", "--work-dir", "b", "--egress-proxy", "c", "--peer-uid=1"]
    assert refusals(args) == [
        "ZOEYMCP_BRIDGE_FETCH_ARGS has no --: the command goes after it",
        "ZOEYMCP_BRIDGE_FETCH_ARGS has no --era",
        "ZOEYMCP_BRIDGE_FETCH_ARGS[0]: --listen is the launcher's",
        "ZOEYMCP_BRIDGE_FETCH_ARGS[1]: --work-dir is the launcher's",
        "ZOEYMCP_BRIDGE_FETCH_ARGS[3]: --egress-proxy: nothing in the standard tier enforces "
        "egress",
        "ZOEYMCP_BRIDGE_FETCH_ARGS[5]: --peer-uid is the launcher's",
    ]


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not json",
        "{}",
        '"--era"',
        "[1]",
        '["--era", null]',
        "[[]]",
        # Deep enough that the parser gives up (RecursionError).
        pytest.param("[" * 100000, id="nested"),
    ],
)
def test_args_that_arent_a_json_array_of_strings(raw: str) -> None:
    assert refusals(raw) == ["ZOEYMCP_BRIDGE_FETCH_ARGS is not a JSON array of strings"]


@pytest.mark.parametrize(
    "word", ["x\x00y", "\x00", "\ud800", "a\udfffb"], ids=["nul", "lone-nul", "high", "low"]
)
def test_a_word_no_command_line_can_hold_is_refused(word: str) -> None:
    """Popen would raise in PID 1 after the vault and the gateway started, whether the word is an
    option's or the command's."""
    reason = "no command line can hold this word (a NUL or a lone surrogate)"
    assert refusals(["--era", "legacy", "--", "x", word]) == [
        f"ZOEYMCP_BRIDGE_FETCH_ARGS[4]: {reason}"
    ]
    assert refusals(["--era", word, "--", "x"]) == [f"ZOEYMCP_BRIDGE_FETCH_ARGS[1]: {reason}"]


def test_a_word_the_filesystem_encoding_carries_is_taken() -> None:
    """``os.environ`` and ``os.fsdecode`` give an undecodable byte as \\udc80-\\udcff, which
    ``exec`` takes back as that byte."""
    assert specs(["--era", "legacy", "--", "x", "caf\udce9", "é\U0001f600"])[0].refusals == ()


def test_args_unset() -> None:
    assert env.bridge_specs({}, ["fetch"]) == [
        Bridge("fetch", 0, refusals=("ZOEYMCP_BRIDGE_FETCH_ARGS is not set",))
    ]


def test_env_variables_must_be_names_the_program_may_get() -> None:
    good = ["--era", "legacy", "--", "x"]
    assert specs(good, ZOEYMCP_BRIDGE_FETCH_ENV_api_Key2="v")[0].refusals == ()
    assert refusals(
        good,
        ZOEYMCP_BRIDGE_FETCH_ENV_="v",
        ZOEYMCP_BRIDGE_FETCH_ENV_2X="v",
        ZOEYMCP_BRIDGE_FETCH_ENV_ZOEYMCP_CONFIG="v",
        ZOEYMCP_BRIDGE_FETCH_ENV_zoeymcp_x="v",
    ) == [
        "ZOEYMCP_BRIDGE_FETCH_ENV_: the part after ENV_ isn't a variable name",
        "ZOEYMCP_BRIDGE_FETCH_ENV_2X: the part after ENV_ isn't a variable name",
        "ZOEYMCP_BRIDGE_FETCH_ENV_ZOEYMCP_CONFIG: a ZOEYMCP_ variable never reaches the bridge's "
        "program",
        "ZOEYMCP_BRIDGE_FETCH_ENV_zoeymcp_x: a ZOEYMCP_ variable never reaches the bridge's "
        "program",
    ]
    long = "A" * 128
    assert specs(good, **{f"ZOEYMCP_BRIDGE_FETCH_ENV_{long}": "v"})[0].refusals == ()
    assert refusals(good, **{f"ZOEYMCP_BRIDGE_FETCH_ENV_{long}A": "v"}) == [
        f"ZOEYMCP_BRIDGE_FETCH_ENV_{long}A: the part after ENV_ isn't a variable name"
    ]
    # Another bridge's variables are its own.
    assert specs(good, ZOEYMCP_BRIDGE_NOTES_ENV_ZOEYMCP_X="v")[0].refusals == ()
    # ARGS and ENV refusals together.
    assert refusals(["--era", "legacy"], ZOEYMCP_BRIDGE_FETCH_ENV_ZOEYMCP_X="v") == [
        "ZOEYMCP_BRIDGE_FETCH_ARGS has no --: the command goes after it",
        "ZOEYMCP_BRIDGE_FETCH_ENV_ZOEYMCP_X: a ZOEYMCP_ variable never reaches the bridge's "
        "program",
    ]
    assert refusals("x", ZOEYMCP_BRIDGE_FETCH_ENV_="v") == [
        "ZOEYMCP_BRIDGE_FETCH_ARGS is not a JSON array of strings",
        "ZOEYMCP_BRIDGE_FETCH_ENV_: the part after ENV_ isn't a variable name",
    ]


def test_bridge_names() -> None:
    environ = {
        env.bridge_variable(name, "ARGS"): json.dumps(["--era", "legacy", "--", "x"])
        for name in ("a", "b", "c", "d", "e", "f", "g", "h", "i", "fetch")
    }
    found = env.bridge_specs(environ, ["a", "Fetch", "fetch-1", "", "a", "x" * 17, "1" * 16, "b"])
    assert [(s.name, s.index, s.refusals) for s in found] == [
        ("a", 0, ()),
        ("Fetch", 1, ("--bridge [1]: a bridge's name is 1 to 16 lower-case letters or digits",)),
        ("fetch-1", 2, ("--bridge [2]: a bridge's name is 1 to 16 lower-case letters or digits",)),
        ("", 3, ("--bridge [3]: a bridge's name is 1 to 16 lower-case letters or digits",)),
        ("a", 4, ("--bridge a is given twice",)),
        ("x" * 17, 5, ("--bridge [5]: a bridge's name is 1 to 16 lower-case letters or digits",)),
        ("1" * 16, 6, ("ZOEYMCP_BRIDGE_1111111111111111_ARGS is not set",)),
        ("b", 7, ()),
    ]
    nine = env.bridge_specs(environ, ["a", "b", "c", "d", "e", "f", "g", "h", "i"])
    assert [s.refusals for s in nine[:8]] == [()] * 8
    assert nine[8].refusals == ("--bridge i: at most 8 bridges run in one container",)
    # A ninth name given twice is refused as given twice.
    again = env.bridge_specs(environ, ["a", "b", "c", "d", "e", "f", "g", "h", "a"])
    assert again[8].refusals == ("--bridge a is given twice",)


def test_the_vault_is_told_every_bridge_name_it_can_read() -> None:
    """Refused ones included, past the eighth too; never a malformed name or a repeat, which
    the vault's ``parse_bridges`` refuses."""
    names = ["fetch", "Bad", "notes", "fetch", "c", "d", "e", "f", "g", "h", "g"]
    assert env.bridge_uids(names) == {
        "fetch": 10100,
        "notes": 10102,
        "c": 10104,
        "d": 10105,
        "e": 10106,
        "f": 10107,
        "g": 10108,
        "h": 10109,
    }
    assert env.bridge_uids([]) == {}


def test_a_bridges_uid_and_directory_follow_its_place() -> None:
    bridge = Bridge("notes", 3)
    assert bridge.uid == 10103
    assert bridge.directory == env.Directory(
        "/run/zoeymcp-bridge-notes", 10103, 10001, 0o750, "bridge notes's socket and work directory"
    )
    assert env.bridge_directory("fetch", 0) == env.Directory(
        "/run/zoeymcp-bridge-fetch", 10100, 10001, 0o750, "bridge fetch's socket and work directory"
    )


SENTINEL = "bridge-value-sentinel"


def test_no_reason_holds_the_value_it_refuses() -> None:
    """A sentinel in every field each refusal reads: ARGS (refused whole, and at a position),
    the token hash and an ENV value."""
    environ = {
        "ZOEYMCP_BRIDGE_A_ARGS": f'["{SENTINEL}"',
        "ZOEYMCP_BRIDGE_B_ARGS": json.dumps(
            [f"--listen={SENTINEL}", "--work-dir", SENTINEL, "--egress-proxy", SENTINEL]
        ),
        "ZOEYMCP_BRIDGE_B_TOKEN_SHA256": SENTINEL,
        "ZOEYMCP_BRIDGE_B_ENV_ZOEYMCP_X": SENTINEL,
        "ZOEYMCP_BRIDGE_B_ENV_": SENTINEL,
        "ZOEYMCP_BRIDGE_C_ARGS": json.dumps([SENTINEL, "--era", SENTINEL, "--", SENTINEL]),
        "ZOEYMCP_BRIDGE_C_TOKEN_SHA256": SENTINEL,
        "ZOEYMCP_BRIDGE_C_ENV_X": SENTINEL,
    }
    found = env.bridge_specs(environ, ["a", "b", "c", f"{SENTINEL}!"])
    assert [len(s.refusals) for s in found] == [1, 7, 0, 1]
    for spec in found:
        for reason in spec.refusals:
            assert SENTINEL not in reason


def test_holds_secret_env() -> None:
    def holds(args: list[str] | str) -> bool:
        raw = args if isinstance(args, str) else json.dumps(args)
        return env.holds_secret_env({"ZOEYMCP_BRIDGE_FETCH_ARGS": raw}, "fetch")

    assert holds(["--era", "legacy", "--secret-env", "KEY", "--", "x"])
    assert holds(["--secret-env=KEY", "--era", "legacy", "--", "x"])
    assert holds(["--secret-env=KEY"])
    assert not holds(["--era", "legacy", "--env", "KEY", "--", "x"])
    assert not holds(["--era", "legacy", "--", "x", "--secret-env", "KEY"])
    assert not holds(["--era", "legacy", "--secret-envs", "KEY", "--", "x"])
    assert not holds("not json")
    assert not holds('{"--secret-env": 1}')
    assert not env.holds_secret_env({}, "fetch")
    assert env.holds_secret_env(BRIDGE_ENVIRON, "notes")
    assert not env.holds_secret_env(BRIDGE_ENVIRON, "fetch")


# --- bridges: their environments ------------------------------------------------------------------

BRIDGE_BASE = {
    "PATH": "/opt/zoeymcp/bin:/usr/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "LC_TIME": "en_GB.UTF-8",
    "TZ": "UTC",
    "PYTHONUNBUFFERED": "1",
    "PYTHONDONTWRITEBYTECODE": "1",
}


def test_each_bridge_gets_its_allowlist_its_hash_and_its_env() -> None:
    vault, gateway, bridges = env.split_environment(BRIDGE_ENVIRON, ["fetch", "notes"])
    assert vault == BRIDGE_ENVIRON
    # The gateway's allowlist is unchanged: ZOEYMCP_BRIDGE_* is never ZOEYMCP_GATEWAY_*.
    assert gateway == env.gateway_environment(ENVIRON)
    assert bridges == {
        "fetch": {
            **BRIDGE_BASE,
            "ZOEYMCP_BRIDGE_TOKEN_SHA256": FETCH_HASH,
            "BASE_URL": "http://127.0.0.1:8080/fetch",
        },
        "notes": {
            **BRIDGE_BASE,
            "ZOEYMCP_BRIDGE_TOKEN_SHA256": "sha256:" + "b" * 64,
            "NOTES_KEY": "a notes secret",
        },
    }
    for own in bridges.values():
        for name in ("ZOEYMCP_MASTER_KEY", "ZOEYMCP_CONFIG", "ZOEYMCP_GATEWAY_KEY", "HOME"):
            assert name not in own
        assert not any(key.startswith("ZOEYMCP_BRIDGE_") and key != env.BRIDGE_TOKEN for key in own)
    assert "a notes secret" not in bridges["fetch"].values()


def test_a_bridge_without_its_hash_gets_none() -> None:
    environ = {"ZOEYMCP_BRIDGE_FETCH_ARGS": "[]", "ZOEYMCP_BRIDGE_TOKEN_SHA256": FETCH_HASH}
    assert env.bridge_environment(environ, "fetch") == {}
    environ["ZOEYMCP_BRIDGE_FETCH_TOKEN_SHA256"] = ""
    assert env.bridge_environment(environ, "fetch") == {"ZOEYMCP_BRIDGE_TOKEN_SHA256": ""}


# --- bridges: their directories and command lines (FM-31) ----------------------------------------


def directory(
    uid: int = 10100, gid: int = 10001, mode: int = 0o750, kind: int = stat.S_IFDIR
) -> os.stat_result:
    return os.stat_result((kind | mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))


def stats(found: Mapping[str, os.stat_result | None]) -> Callable[[str], os.stat_result]:
    def stat_path(path: str) -> os.stat_result:
        result = found.get(path)
        if result is None:
            raise FileNotFoundError(path)
        return result

    return stat_path


GOOD_BRIDGES = {
    "/run/zoeymcp-bridge-fetch": directory(10100),
    "/run/zoeymcp-bridge-notes": directory(10101),
}


@pytest.fixture
def lines() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def events(buffer: io.StringIO, kind: str) -> list[dict[str, Any]]:
    records = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [
        {k: v for k, v in r.items() if k not in ("ts", "role", "event")}
        for r in records
        if r["event"] == kind
    ]


def test_bridge_argv() -> None:
    bridge = Bridge("fetch", 0, tuple(FETCH_ARGS))
    assert launcher.bridge_argv(bridge, 7) == [
        sys.executable,
        "-I",
        "-m",
        "zoeymcp",
        "bridge",
        "--control-fd",
        "7",
        "--listen",
        "unix:/run/zoeymcp-bridge-fetch/mcp.sock",
        "--peer-uid",
        "10001",
        "--work-dir",
        "/run/zoeymcp-bridge-fetch/work",
        *FETCH_ARGS,
    ]


def test_the_vault_gets_bridge_only_with_bridges() -> None:
    options = Options(bridges=("fetch", "Bad", "notes"))
    assert launcher.vault_argv(options, 5) == [
        sys.executable,
        "-I",
        "-m",
        "zoeymcp",
        *VAULT_TAIL,
        "--bridge",
        "fetch=10100",
        "--bridge",
        "notes=10102",
    ]
    assert launcher.vault_argv(Options(), 5)[4:] == VAULT_TAIL


@pytest.mark.parametrize(
    ("found", "seen"),
    [
        (None, "is missing"),
        (directory(kind=stat.S_IFREG), "is missing"),
        (directory(uid=10101), "is 10101:10001 0750"),
        (directory(uid=0), "is 0:10001 0750"),
        (directory(gid=10100), "is 10100:10100 0750"),
        (directory(gid=10002), "is 10100:10002 0750"),
        (directory(mode=0o700), "is 10100:10001 0700"),
        (directory(mode=0o755), "is 10100:10001 0755"),
        (directory(mode=0o770), "is 10100:10001 0770"),
        (directory(mode=0o1750), "is 10100:10001 1750"),
    ],
)
def test_a_wrong_bridge_directory_refuses_that_bridge(
    found: os.stat_result | None, seen: str, lines: io.StringIO
) -> None:
    """FM-31: the vault and the gateway start, and the other bridge too."""
    started = Started()
    options = Options(bridges=("fetch", "notes"))
    found_bridges = {**GOOD_BRIDGES, "/run/zoeymcp-bridge-fetch": found}
    launcher.start(options, BRIDGE_ENVIRON, spawn=started.spawn, stat_path=stats(found_bridges))
    assert started.names() == ["vault", "gateway", "bridge:notes"]
    reason = (
        f"/run/zoeymcp-bridge-fetch (bridge fetch's socket and work directory) {seen}; it must be "
        "10100:10001 0750"
    )
    assert events(lines, "launcher_bridge_refused") == [{"name": "fetch", "reasons": [reason]}]
    # The vault is told of the refused bridge too: its routes fail the connect.
    assert started.argv("vault")[-4:] == ["--bridge", "fetch=10100", "--bridge", "notes=10101"]


def test_a_reordered_bridge_list_refuses_both() -> None:
    """The mounts were made for fetch, notes; --bridge names them the other way round."""
    started = Started()
    options = Options(bridges=("notes", "fetch"))
    launcher.start(options, BRIDGE_ENVIRON, spawn=started.spawn, stat_path=stats(GOOD_BRIDGES))
    assert started.names() == ["vault", "gateway"]


def test_found_directories_takes_the_bridges() -> None:
    wanted = [env.bridge_directory("fetch", 0), env.bridge_directory("notes", 1)]
    found = launcher.found_directories(stats(GOOD_BRIDGES), wanted)
    assert found == {
        "/run/zoeymcp-bridge-fetch": Found(10100, 10001, 0o750, True),
        "/run/zoeymcp-bridge-notes": Found(10101, 10001, 0o750, True),
    }


class Started:
    """A fake ``spawn``: what each child would be started with."""

    def __init__(self, failing: Mapping[str, Exception] | None = None) -> None:
        self.children: list[tuple[str, list[str], int, dict[str, str]]] = []
        # What Popen raises for a child, after building its command line.
        self.failing = failing or {}

    def spawn(
        self,
        name: str,
        argv: Callable[[int], list[str]],
        uid: int,
        environ: Mapping[str, str],
    ) -> Child:
        fd = 4 + len(self.children)
        command = argv(fd)
        if name in self.failing:
            raise self.failing[name]
        self.children.append((name, command, uid, dict(environ)))
        return Child(name, 100 + fd, fd)

    def names(self) -> list[str]:
        return [name for name, _, _, _ in self.children]

    def argv(self, name: str) -> list[str]:
        return next(argv for child, argv, _, _ in self.children if child == name)

    def environ(self, name: str) -> dict[str, str]:
        return next(environ for child, _, _, environ in self.children if child == name)


def test_bridges_start_after_the_vault_and_the_gateway(lines: io.StringIO) -> None:
    started = Started()
    options = Options(bridges=("fetch", "notes"))
    children = launcher.start(
        options, BRIDGE_ENVIRON, spawn=started.spawn, stat_path=stats(GOOD_BRIDGES)
    )
    assert children == [
        Child("vault", 104, 4),
        Child("gateway", 105, 5),
        Child("bridge:fetch", 106, 6),
        Child("bridge:notes", 107, 7),
    ]
    assert [(name, uid) for name, _, uid, _ in started.children] == [
        ("vault", 10001),
        ("gateway", 10002),
        ("bridge:fetch", 10100),
        ("bridge:notes", 10101),
    ]
    assert started.argv("bridge:fetch") == launcher.bridge_argv(
        Bridge("fetch", 0, tuple(FETCH_ARGS)), 6
    )
    assert started.argv("bridge:notes")[-len(NOTES_ARGS) :] == NOTES_ARGS
    vault, gateway, bridges = env.split_environment(BRIDGE_ENVIRON, ["fetch", "notes"])
    assert started.environ("vault") == vault
    assert started.environ("gateway") == gateway
    assert started.environ("bridge:fetch") == bridges["fetch"]
    assert started.environ("bridge:notes") == bridges["notes"]
    assert events(lines, "launcher_bridge_refused") == []
    assert events(lines, "launcher_started") == [{"vault_uid": 10001, "gateway_uid": 10002}]


def test_a_refused_spec_is_logged_and_not_started(lines: io.StringIO) -> None:
    started = Started()
    environ = {**BRIDGE_ENVIRON, "ZOEYMCP_BRIDGE_FETCH_ARGS": '["--listen=x"]'}
    options = Options(bridges=("fetch", "Bad", "notes"))
    launcher.start(options, environ, spawn=started.spawn, stat_path=stats(GOOD_BRIDGES))
    # notes is the third: its directory is checked as 10102's.
    assert started.names() == ["vault", "gateway"]
    assert events(lines, "launcher_bridge_refused") == [
        {
            "name": "fetch",
            "reasons": [
                "ZOEYMCP_BRIDGE_FETCH_ARGS has no --: the command goes after it",
                "ZOEYMCP_BRIDGE_FETCH_ARGS has no --era",
                "ZOEYMCP_BRIDGE_FETCH_ARGS[0]: --listen is the launcher's",
            ],
        },
        {
            "name": None,
            "reasons": ["--bridge [1]: a bridge's name is 1 to 16 lower-case letters or digits"],
        },
        {
            "name": "notes",
            "reasons": [
                "/run/zoeymcp-bridge-notes (bridge notes's socket and work directory) is "
                "10101:10001 0750; it must be 10102:10001 0750"
            ],
        },
    ]
    assert started.argv("vault")[-4:] == ["--bridge", "fetch=10100", "--bridge", "notes=10102"]


@pytest.mark.parametrize(
    ("error", "reason"),
    [
        (
            OSError(errno.E2BIG, "Argument list too long"),
            "it couldn't be started: Argument list too long",
        ),
        (ValueError(f"embedded null byte in {SENTINEL}"), "it couldn't be started (ValueError)"),
        (
            UnicodeEncodeError("utf-8", f"{SENTINEL}\ud800", 21, 22, "surrogates not allowed"),
            "it couldn't be started (UnicodeEncodeError)",
        ),
        (OSError(SENTINEL), "it couldn't be started (OSError)"),
    ],
    ids=["e2big", "nul", "surrogate", "no-strerror"],
)
def test_a_bridge_that_cant_be_spawned_stops_only_itself(
    error: Exception, reason: str, lines: io.StringIO
) -> None:
    """C.10: a bridge's configuration never stops the trust root, even one ``bridge_specs``
    can't see (a command line too long for ``exec``); the reason holds no value."""
    started = Started({"bridge:fetch": error})
    environ = {
        **BRIDGE_ENVIRON,
        "ZOEYMCP_BRIDGE_FETCH_ARGS": json.dumps(["--era", "legacy", "--", "x", SENTINEL]),
    }
    options = Options(bridges=("fetch", "notes"))
    children = launcher.start(options, environ, spawn=started.spawn, stat_path=stats(GOOD_BRIDGES))
    assert [child.name for child in children] == ["vault", "gateway", "bridge:notes"]
    assert events(lines, "launcher_bridge_refused") == [{"name": "fetch", "reasons": [reason]}]
    assert SENTINEL not in lines.getvalue()


def test_bridge_without_hash(lines: io.StringIO) -> None:
    """FM-30's launcher half: a missing hash is the bridge's own refusal, so the launcher starts
    it without one, and it refuses to start (``test_bridge_process.py::test_no_token_hash``)."""
    started = Started()
    environ = {
        key: value for key, value in BRIDGE_ENVIRON.items() if not key.endswith("TOKEN_SHA256")
    }
    launcher.start(
        Options(bridges=("fetch",)), environ, spawn=started.spawn, stat_path=stats(GOOD_BRIDGES)
    )
    assert started.names() == ["vault", "gateway", "bridge:fetch"]
    assert "ZOEYMCP_BRIDGE_TOKEN_SHA256" not in started.environ("bridge:fetch")
    assert events(lines, "launcher_bridge_refused") == []


def test_no_bridge_starts_as_today(lines: io.StringIO) -> None:
    """The same children, arguments and environments as before bridges."""
    started = Started()

    def no_stat(path: str) -> os.stat_result:
        raise AssertionError(path)

    options = Options(vault_listens=("0.0.0.0:8080",))
    launcher.start(options, BRIDGE_ENVIRON, spawn=started.spawn, stat_path=no_stat)
    assert started.children == [
        ("vault", launcher.vault_argv(options, 4), 10001, BRIDGE_ENVIRON),
        ("gateway", launcher.gateway_argv(options, 5), 10002, env.gateway_environment(ENVIRON)),
    ]
    assert "--bridge" not in started.argv("vault")
    assert lines.getvalue().count('"event":') == 1  # launcher_started


# --- bridges: supervising (FM-29) ---------------------------------------------------------------


def bridged(system: System) -> Supervisor:
    return Supervisor(
        [
            Child("vault", 104, 4),
            Child("gateway", 105, 5),
            Child("bridge:fetch", 106, 6),
            Child("bridge:notes", 107, 7),
        ],
        waitpid=system.waitpid,
        write=system.write,
        clock=system.clock,
        sleep=system.sleep,
    )


def test_the_bridges_stop_after_the_vault() -> None:
    system = System()
    sup = bridged(system)
    sup.on_signal(signal.SIGTERM)
    assert run(sup, system) == 0
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n"), (6, b"TERM\n"), (7, b"TERM\n")]
    assert [child.status for child in sup.children] == [0, 0, 0, 0]


def test_the_bridges_outlive_the_vault_for_its_wait() -> None:
    system = System(obey=False)
    sup = bridged(system)
    sup.stop("signal")
    system.now = 10
    system.ended.append((105, 0))  # the gateway is done; the vault is told
    assert sup.step() is None
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n")]
    system.now = 10 + launcher.VAULT_STOP_WAIT
    assert sup.step() is None
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n")]
    system.now = 10 + launcher.VAULT_STOP_WAIT + 0.1
    assert sup.step() is None
    bridges = [(6, b"TERM\n"), (7, b"TERM\n")]
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n"), *bridges]
    # Told once.
    assert sup.step() is None
    assert system.written[4:] == []


def test_the_bridges_are_told_once_the_vault_has_exited() -> None:
    system = System(obey=False)
    sup = bridged(system)
    sup.stop("signal")
    system.ended.append((105, 0))
    assert sup.step() is None
    system.ended.append((104, 0))
    assert sup.step() is None
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n"), (6, b"TERM\n"), (7, b"TERM\n")]


def test_bridges_that_wont_stop_are_left_at_stop_wait() -> None:
    system = System(obey=False)
    sup = bridged(system)
    sup.on_signal(signal.SIGTERM)
    assert run(sup, system, rounds=5000) == 1
    assert system.now == pytest.approx(launcher.STOP_WAIT + launcher.POLL, abs=launcher.POLL)
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n"), (6, b"TERM\n"), (7, b"TERM\n")]
    assert launcher.BRIDGE_STOP_WAIT == 10
    assert launcher.STOP_WAIT == 415 < 420


def test_hup_reaches_the_vault_and_the_gateway_only() -> None:
    system = System()
    sup = bridged(system)
    sup.on_signal(launcher.SIGHUP)
    assert sup.step() is None
    assert system.written == [(4, b"HUP\n"), (5, b"HUP\n")]


def test_bridge_exit_keeps_the_vault(lines: io.StringIO) -> None:
    """FM-29: logged, not restarted, nothing else told; a later TERM still stops the rest in
    order, and the launcher exits 0."""
    system = System()
    sup = bridged(system)
    system.ended.append((106, 3 << 8))  # bridge fetch exited with 3
    for _ in range(10):
        assert sup.step() is None
        system.sleep(launcher.POLL)
    assert system.written == []
    assert sup.stopping_since is None
    assert [child.status for child in sup.children] == [None, None, 3, None]
    records = [json.loads(line) for line in lines.getvalue().splitlines()]
    assert [(r["event"], r.get("child"), r.get("name"), r["status"]) for r in records] == [
        ("child_exited", "bridge:fetch", None, 3),
        ("launcher_bridge_down", None, "fetch", 3),
    ]
    sup.on_signal(signal.SIGTERM)
    assert run(sup, system) == 0
    assert system.written == [(5, b"TERM\n"), (4, b"TERM\n"), (7, b"TERM\n")]


def test_a_vault_exit_stops_the_bridges_too() -> None:
    system = System()
    sup = bridged(system)
    system.ended.append((104, 1 << 8))
    assert run(sup, system) == 1
    assert system.written == [(5, b"TERM\n"), (6, b"TERM\n"), (7, b"TERM\n")]


def test_a_bridge_exiting_while_stopping_is_not_down(lines: io.StringIO) -> None:
    system = System(obey=False)
    sup = bridged(system)
    sup.stop("signal")
    system.ended.append((107, 0))
    assert sup.step() is None
    assert events(lines, "launcher_bridge_down") == []
    assert sup.children[3].status == 0


# --- the CLI -------------------------------------------------------------------------------------


def test_the_cli_reports_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Options] = []

    def refuse(options: Options, environ: object) -> None:
        seen.append(options)
        raise LaunchError("NoNewPrivs is not set")

    monkeypatch.setattr(launcher, "launch", refuse)
    err = io.StringIO()
    argv = ["standard", "--gateway-listen", "127.0.0.1:1", "--vault-listen", "0.0.0.0:8080"]
    assert main(argv, out=io.StringIO(), err=err) == 2
    assert err.getvalue() == "zoeymcp standard: NoNewPrivs is not set\n"
    assert seen == [Options("127.0.0.1:1", ("0.0.0.0:8080",), False)]


def test_the_cli_supervises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(Supervisor, "run", lambda self: len(self.children) + 40)
    argv = ["standard", "--supervise", "vault=1:4", "--supervise", "gateway=2:5"]
    assert main(argv, out=io.StringIO(), err=io.StringIO()) == 42
    argv += ["--supervise", "bridge:fetch=3:6"]
    assert main(argv, out=io.StringIO(), err=io.StringIO()) == 43


def test_the_cli_names_the_bridges(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[Options] = []

    def refuse(options: Options, environ: object) -> None:
        seen.append(options)
        raise LaunchError("NoNewPrivs is not set")

    monkeypatch.setattr(launcher, "launch", refuse)
    argv = ["standard", "--bridge", "fetch", "--bridge", "notes"]
    assert main(argv, out=io.StringIO(), err=io.StringIO()) == 2
    assert seen == [Options(bridges=("fetch", "notes"))]
