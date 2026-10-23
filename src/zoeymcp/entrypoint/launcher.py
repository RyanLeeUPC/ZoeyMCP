"""``zoeymcp standard``: the standard tier's launcher (M3 design B.2).

1. **Check the box** (:mod:`.env`): PID 1, root, ``NoNewPrivs``, and no capability beyond
   ``SETUID`` and ``SETGID``. Then the state and socket directories' owners and modes. Then each
   bridge (``--bridge NAME``, M7 design C.10): its spec, from the environment, and its socket
   directory, ``/run/zoeymcp-bridge-<name>``, before any child starts. A bridge refused here is
   logged ``launcher_bridge_refused`` and not started; the vault and the gateway start anyway.
2. **Split the environment**: the vault gets all of it, the gateway an allowlist, each bridge
   an allowlist with its own token hash and ``ENV_*`` values.
3. **Start the vault** as 10001 and **the gateway** as 10002, then **each bridge** as
   10100 + its place in ``--bridge`` order, no supplementary groups, umask 077, each with the
   read end of its own control pipe. The vault listens on the link socket only (or also on
   ``--vault-listen`` addresses, for direct routes), and is told each bridge's name and uid
   (``--bridge NAME=UID``, refused bridges included). The gateway answers 503 until it has a
   view, so it isn't made to wait. A bridge creates its own socket in its own directory: the
   launcher binds, holds and passes no listener.
4. **Drop PID 1** to 10003, which owns no files, and re-exec as ``zoeymcp standard
   --supervise`` with an empty environment: the master key is then gone from PID 1's memory and
   from ``/proc/1/environ``, and PID 1 holds no capability.
5. **Supervise**. PID 1 can't signal other uids, so ``SIGTERM`` and ``SIGINT`` become ``TERM``
   on the control pipes and ``SIGHUP`` becomes ``HUP`` on the vault's and the gateway's (a bridge
   has nothing to reload). The gateway is told to stop first: an approved call it is still
   forwarding goes through the vault (M4 design B.6). The vault is told once the gateway has
   exited, or after :data:`GATEWAY_STOP_WAIT` seconds, and the bridges once the vault has
   exited, or :data:`VAULT_STOP_WAIT` seconds after it was told, so a call through a bridge
   finishes inside the vault's window. If the vault or the gateway exits on its own, the others
   are told to stop. A bridge that exits on its own is logged ``launcher_bridge_down`` and isn't
   restarted (PID 1 can't start a process as another uid any more); the others keep running.
   After at most :data:`STOP_WAIT` seconds the launcher exits non-zero, so the container
   restarts. PID 1 reaps every process that ends, orphans included.

The launcher uses the standard library only.
"""

from __future__ import annotations

import contextlib
import os
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from functools import partial
from typing import NoReturn

from ..common.logs import Log
from . import env

# The image's second environment, the only one with the gateway's dependencies (B.5).
GATEWAY_PYTHON = "/opt/zoeymcp-gateway/bin/python"
# Seconds the gateway gets to stop: an approved call accepted just before may run for the default
# call_timeout (300 s), and its outcome is written after (M4 design B.6).
GATEWAY_STOP_WAIT = 330.0
# Seconds the vault gets after that: more than an SMTP send's 60 s.
VAULT_STOP_WAIT = 75.0
# Seconds each bridge gets after that: its children's 4 s stop (M7 design C.3, C.10).
BRIDGE_STOP_WAIT = 10.0
# compose's stop_grace_period is 420 s.
STOP_WAIT = GATEWAY_STOP_WAIT + VAULT_STOP_WAIT + BRIDGE_STOP_WAIT
POLL = 0.2
STATUS_FILE = "/proc/self/status"
# A bridge child's name: bridge:<its --bridge name>.
BRIDGE_CHILD = "bridge:"
# POSIX constants, looked up so the module still imports (and type-checks) on Windows.
SIGHUP: int = getattr(signal, "SIGHUP", 1)
WNOHANG: int = getattr(os, "WNOHANG", 1)

log = Log("launcher").event


class LaunchError(RuntimeError):
    """The launcher won't start; the message says why."""


@dataclass(frozen=True)
class Options:
    gateway_listen: str = "0.0.0.0:8090"
    vault_listens: tuple[str, ...] = ()
    unsafe_skip_checks: bool = False
    bridges: tuple[str, ...] = ()


def python_command(module_argv: Sequence[str], python: str | None = None) -> list[str]:
    """``zoeymcp <argv>``, isolated: no PYTHON* variables, no user site, no current directory.
    ``python`` defaults to this interpreter."""
    return [python or sys.executable, "-I", "-m", "zoeymcp", *module_argv]


def vault_argv(options: Options, control_fd: int) -> list[str]:
    listens = [arg for address in options.vault_listens for arg in ("--listen", address)]
    bridges = [
        arg
        for name, uid in env.bridge_uids(options.bridges).items()
        for arg in ("--bridge", f"{name}={uid}")
    ]
    return python_command(
        [
            "vault",
            "--gateway-socket",
            env.LINK_SOCKET,
            "--gateway-uid",
            str(env.GATEWAY_UID),
            *(listens or ["--listen", "none"]),
            "--control-fd",
            str(control_fd),
            *bridges,
        ]
    )


def gateway_argv(options: Options, control_fd: int, python: str = GATEWAY_PYTHON) -> list[str]:
    """The gateway in its own environment; in this one when that doesn't exist (a checkout)."""
    argv = [
        "gateway",
        "--vault",
        f"unix:{env.LINK_SOCKET}",
        "--listen",
        options.gateway_listen,
        "--control-fd",
        str(control_fd),
    ]
    return python_command(argv, python if os.path.isfile(python) else None)


def bridge_argv(bridge: env.Bridge, control_fd: int) -> list[str]:
    """A bridge from this interpreter (no SDK), on its socket in its own directory, with only the
    vault's uid let in; the launcher's options first, the operator's ARGS (the command last)
    after, so none of them can be given again (C.8)."""
    directory = bridge.directory.path
    return python_command(
        [
            "bridge",
            "--control-fd",
            str(control_fd),
            "--listen",
            f"unix:{directory}/mcp.sock",
            "--peer-uid",
            str(env.VAULT_UID),
            "--work-dir",
            f"{directory}/work",
            *bridge.args,
        ]
    )


def found_directories(
    stat_path: Callable[[str], os.stat_result] = os.stat,
    directories: Iterable[env.Directory] = env.DIRECTORIES,
) -> dict[str, env.Found | None]:
    found: dict[str, env.Found | None] = {}
    for wanted in directories:
        try:
            info = stat_path(wanted.path)
        except OSError:
            found[wanted.path] = None
            continue
        found[wanted.path] = env.Found(
            info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), stat.S_ISDIR(info.st_mode)
        )
    return found


def check(options: Options) -> None:
    """Step 1's box and directories, or :class:`LaunchError` with every reason."""
    if sys.platform != "linux":
        raise LaunchError("the standard tier runs only in a Linux container")
    refusals: list[str] = []
    if not options.unsafe_skip_checks:
        try:
            with open(STATUS_FILE, encoding="ascii") as handle:
                status = env.parse_status(handle.read())
        except (OSError, env.StatusError) as exc:
            raise LaunchError(f"can't read {STATUS_FILE}: {exc}") from exc
        refusals += env.box_refusals(status, os.getpid())
    refusals += env.directory_refusals(found_directories())
    if refusals:
        raise LaunchError("; ".join(refusals))


def check_bridges(
    options: Options,
    environ: Mapping[str, str],
    stat_path: Callable[[str], os.stat_result] = os.stat,
) -> list[env.Bridge]:
    """Step 1's bridges: each spec, then each accepted one's directory, refusing that bridge
    alone (FM-31). Each refused one is logged with its reasons, which hold no value."""
    specs = env.bridge_specs(environ, options.bridges)
    found = found_directories(stat_path, [s.directory for s in specs if not s.refusals])
    checked = []
    for spec in specs:
        if not spec.refusals:
            refusal = env.directory_refusal(spec.directory, found[spec.directory.path])
            if refusal is not None:
                spec = replace(spec, args=(), refusals=(refusal,))
        if spec.refusals:
            named = spec.name if env.BRIDGE_NAME.fullmatch(spec.name) else None
            log("launcher_bridge_refused", name=named, reasons=list(spec.refusals))
        checked.append(spec)
    return checked


@dataclass
class Child:
    name: str
    pid: int
    control: int  # the write end of its control pipe
    status: int | None = None  # the exit code, once it has ended


# What starts a child: its name, its command line from its control pipe's number, its uid and
# its environment (:func:`spawn`; tests record instead).
Spawn = Callable[[str, Callable[[int], list[str]], int, Mapping[str, str]], Child]


def spawn(
    name: str, argv: Callable[[int], list[str]], uid: int, environ: Mapping[str, str]
) -> Child:  # pragma: no cover - needs root; the image smoke test runs it
    """Start a child as ``uid`` with the read end of a new control pipe, whose number
    ``argv`` puts on its command line (``pass_fds`` keeps the number)."""
    read, write = os.pipe()
    try:
        process = subprocess.Popen(  # noqa: S603 - a fixed interpreter and arguments, no shell
            argv(read),
            env=dict(environ),
            user=uid,
            group=uid,
            extra_groups=[],
            umask=0o077,
            pass_fds=(read,),
            stdin=subprocess.DEVNULL,
        )
    finally:
        os.close(read)
    log("child_started", child=name, pid=process.pid, uid=uid)
    return Child(name, process.pid, write)


def drop_and_supervise(children: Sequence[Child]) -> NoReturn:  # pragma: no cover - image smoke
    """Step 4: become 10003 and re-exec with an empty environment and only the control pipes."""
    if sys.platform == "win32":
        raise LaunchError("the standard tier runs only in a Linux container")
    os.setgroups([])
    os.setresgid(env.INIT_UID, env.INIT_UID, env.INIT_UID)
    os.setresuid(env.INIT_UID, env.INIT_UID, env.INIT_UID)
    if os.getresuid() != (env.INIT_UID,) * 3 or os.getgroups():
        raise LaunchError("dropping root didn't take")
    argv = python_command(["standard"])
    for child in children:
        os.set_inheritable(child.control, True)
        argv += ["--supervise", f"{child.name}={child.pid}:{child.control}"]
    os.execve(sys.executable, argv, {})  # noqa: S606 - this interpreter, no shell


def start(
    options: Options,
    environ: Mapping[str, str],
    *,
    spawn: Spawn = spawn,
    stat_path: Callable[[str], os.stat_result] = os.stat,
) -> list[Child]:
    """Steps 1 (the bridges) to 3: every bridge checked before any child starts, then the vault,
    the gateway and each bridge that passed. A bridge that can't be spawned (a command line too
    long for ``exec``, say) is refused as a checked one is, and the others start (C.10)."""
    bridges = [
        bridge for bridge in check_bridges(options, environ, stat_path) if not bridge.refusals
    ]
    vault_env, gateway_env, bridge_envs = env.split_environment(
        environ, [bridge.name for bridge in bridges]
    )
    log("launcher_started", vault_uid=env.VAULT_UID, gateway_uid=env.GATEWAY_UID)
    children = [
        spawn("vault", partial(vault_argv, options), env.VAULT_UID, vault_env),
        spawn("gateway", partial(gateway_argv, options), env.GATEWAY_UID, gateway_env),
    ]
    for bridge in bridges:
        argv = partial(bridge_argv, bridge)
        try:
            children.append(
                spawn(f"{BRIDGE_CHILD}{bridge.name}", argv, bridge.uid, bridge_envs[bridge.name])
            )
        except (OSError, ValueError) as exc:
            log("launcher_bridge_refused", name=bridge.name, reasons=[spawn_refusal(exc)])
    return children


def spawn_refusal(exc: OSError | ValueError) -> str:
    """Why a bridge couldn't be spawned, without a value: an error's message may quote its
    command line (``UnicodeEncodeError`` does), so only ``strerror`` or the error's type."""
    if isinstance(exc, OSError) and exc.strerror:
        return f"it couldn't be started: {exc.strerror}"
    return f"it couldn't be started ({type(exc).__name__})"


def launch(options: Options, environ: Mapping[str, str]) -> NoReturn:  # pragma: no cover
    """Steps 1 to 4. Raises :class:`LaunchError` before anything starts."""
    try:
        check(options)
    except LaunchError as exc:
        log("launcher_refused", reason=str(exc))
        raise
    drop_and_supervise(start(options, environ))


# --- supervising ---------------------------------------------------------------------------------


def parse_supervised(values: Sequence[str]) -> list[Child]:
    """``--supervise NAME=PID:FD`` values, as the launcher wrote them: the vault and the gateway
    once each, and any ``bridge:<name>`` once (a refused bridge is simply absent)."""
    children: list[Child] = []
    for value in values:
        name, _, rest = value.partition("=")
        pid, _, fd = rest.partition(":")
        bridge = name.removeprefix(BRIDGE_CHILD)
        known = name in ("vault", "gateway") or (
            name.startswith(BRIDGE_CHILD) and env.BRIDGE_NAME.fullmatch(bridge) is not None
        )
        if not known or not pid.isdigit() or not fd.isdigit():
            raise LaunchError(f"bad --supervise value {value!r}")
        if name in (child.name for child in children):
            raise LaunchError(f"--supervise names {name} twice")
        children.append(Child(name, int(pid), int(fd)))
    if not {"vault", "gateway"} <= {child.name for child in children}:
        raise LaunchError("--supervise needs the vault and the gateway")
    return children


@dataclass
class Supervisor:
    """Step 5. The system calls are parameters, so tests drive it with fakes."""

    children: list[Child]
    waitpid: Callable[[int, int], tuple[int, int]] = os.waitpid
    write: Callable[[int, bytes], int] = os.write
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    pending: list[str] = field(default_factory=list)  # commands from signal handlers
    stopping_since: float | None = None
    failed: bool = False
    vault_told: float | None = None  # when the vault was told to stop
    bridges_told: bool = False

    def on_signal(self, signum: int, _frame: object = None) -> None:
        self.pending.append("HUP" if signum == SIGHUP else "TERM")

    def tell(self, command: str, names: Iterable[str] = ("vault", "gateway")) -> None:
        wanted = set(names)
        for child in self.children:
            if child.status is None and child.name in wanted:
                with contextlib.suppress(OSError):  # a child that just ended
                    self.write(child.control, command.encode() + b"\n")

    def _child(self, name: str) -> Child:
        return next(child for child in self.children if child.name == name)

    def _bridges(self) -> list[str]:
        return [child.name for child in self.children if child.name.startswith(BRIDGE_CHILD)]

    def stop(self, reason: str) -> None:
        if self.stopping_since is None:
            self.stopping_since = self.clock()
            log("launcher_stopping", reason=reason)
        self.tell("TERM", ("gateway",))
        self._stop_vault_when_due()

    def _stop_vault_when_due(self) -> None:
        """The vault outlives the gateway, up to :data:`GATEWAY_STOP_WAIT`."""
        if self.stopping_since is None or self.vault_told is not None:
            return
        waited = self.clock() - self.stopping_since
        if self._child("gateway").status is not None or waited > GATEWAY_STOP_WAIT:
            self.vault_told = self.clock()
            self.tell("TERM", ("vault",))

    def _stop_bridges_when_due(self) -> None:
        """The bridges outlive the vault, up to :data:`VAULT_STOP_WAIT` after it was told."""
        if self.vault_told is None or self.bridges_told:
            return
        waited = self.clock() - self.vault_told
        if self._child("vault").status is not None or waited > VAULT_STOP_WAIT:
            self.bridges_told = True
            self.tell("TERM", self._bridges())

    def reap(self) -> None:
        while True:
            try:
                pid, status = self.waitpid(-1, WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                return
            for child in self.children:
                if child.pid == pid and child.status is None:
                    child.status = os.waitstatus_to_exitcode(status)
                    log("child_exited", child=child.name, status=child.status)
                    if self.stopping_since is not None:
                        continue
                    if child.name.startswith(BRIDGE_CHILD):
                        # Not restarted, and nothing else is stopped (Q44).
                        name = child.name.removeprefix(BRIDGE_CHILD)
                        log("launcher_bridge_down", name=name, status=child.status)
                    else:
                        self.failed = True
                        self.stop(f"{child.name} exited")

    def step(self) -> int | None:
        """One round: act on signals, reap, and say whether to exit (with which code)."""
        while self.pending:
            command = self.pending.pop(0)
            if command == "HUP":
                log("launcher_reload")
                self.tell("HUP")
            else:
                self.stop("signal")
        self.reap()
        self._stop_vault_when_due()
        self._stop_bridges_when_due()
        if all(child.status is not None for child in self.children):
            return 1 if self.failed else 0
        if self.stopping_since is not None and self.clock() - self.stopping_since > STOP_WAIT:
            log("launcher_stop_timeout", waited_s=STOP_WAIT)
            return 1
        return None

    def run(self) -> int:
        for signum in (signal.SIGTERM, signal.SIGINT, SIGHUP):
            signal.signal(signum, self.on_signal)
        while True:
            code = self.step()
            if code is not None:
                return code
            self.sleep(POLL)
