"""The standard tier's launcher: the environment split, the box checks, the directories, the
command lines and the supervisor (M3 design B.2, G21). The privilege drop itself needs root in a
container, so the image smoke test runs it."""

from __future__ import annotations

import io
import os
import signal
import sys
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.cli.main import main
from zoeymcp.entrypoint import env, launcher
from zoeymcp.entrypoint.env import Found, ProcessStatus, StatusError
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
    vault, gateway = env.split_environment(ENVIRON)
    assert vault == ENVIRON
    assert vault is not ENVIRON
    assert gateway == env.gateway_environment(ENVIRON)


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


def test_a_mode_with_the_file_type_bits_still_compares() -> None:
    assert env.directory_refusals({**GOOD, "/state": Found(10001, 10001, 0o40700)}) == []
    assert env.directory_refusals({k: v for k, v in GOOD.items() if k != "/state"}) == [
        "/state (the vault's state (a volume)) is missing; it must be 10001:10001 0700"
    ]


# --- command lines -------------------------------------------------------------------------------


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
    for bad in (
        ["vault=12:4"],
        ["vault=12:4", "vault=13:5"],
        ["vault=x:4", "gateway=13:5"],
        ["vault=12:", "gateway=13:5"],
        ["other=12:4", "gateway=13:5"],
    ):
        with pytest.raises(LaunchError):
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


def test_sigterm_stops_both_and_exits_0() -> None:
    system = System()
    sup = supervisor(system)
    assert sup.step() is None
    sup.on_signal(signal.SIGTERM)
    assert run(sup, system) == 0
    assert system.written == [(4, b"TERM\n"), (5, b"TERM\n")]
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
    assert run(sup, system) == 1
    assert system.now == pytest.approx(launcher.STOP_WAIT + launcher.POLL, abs=launcher.POLL)


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
