"""``zoeymcp bridge``: the bridge's process (M7 design C.3, C.5, C.8, N; FM-30).

Before anything listens, the start refuses (``StartupError``, printed, exit 2):

- an option out of range, a ``--listen`` of none of its three forms, ``--peer-uid`` without a
  ``unix:`` listen or a ``unix:`` listen without it, a ``--egress-proxy`` that isn't
  ``http://host:port``, an ``--env`` or ``--secret-env`` name that is ZoeyMCP's or isn't a
  variable name, ``--stderr text`` with a ``--secret-env`` (TI-13), no command after ``--``;
- ``ZOEYMCP_BRIDGE_TOKEN_SHA256`` unset or not ``sha256:`` and 64 lower-case hex digits, read
  before the socket is created (FM-30): a bridge without its hash never listens;
- a ``--secret-env`` variable that is unset or empty;
- ``--work-dir`` that exists and isn't this uid's own directory with mode 0700 (it is created
  0700 when it doesn't exist): a directory another uid made first could be a trap (C.3);
- a ``--control-fd`` that isn't an open pipe it can read;
- for ``unix:``, a socket directory that isn't its own or grants others any access or its group
  write, or an entry at the socket's path that isn't a stale socket (C.8).

Then, before its first child, it lowers its own ``RLIMIT_NPROC`` (soft and hard) to
``--max-procs`` and raises its ``oom_score_adj`` to 1000 (C.3): neither needs a privilege, and
the children inherit both and can't undo them. It logs ``bridge_started`` (its era, caps and the
command's first word, never its arguments), serves, and probes for readiness.

``SIGTERM`` and ``SIGINT`` stop it, or with ``--control-fd`` a ``TERM`` line on the launcher's
pipe (or the pipe's end), as the vault and the gateway in the standard tier; there is nothing to
reload, so a ``HUP`` line is ignored. Stopping ends every stream and stops every child (at most
4 s, C.3), then the server.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
import stat
import sys
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Final

import uvicorn

from ..common import control
from . import childenv, event, listen
from .admit import BridgeTokenHash
from .child import Spec
from .framing import KEEPALIVE_INTERVAL, MESSAGE_MAX, Era, StderrMode, check_stderr_mode
from .server import START_TIMEOUT, Bridge, Settings
from .sessions import IDLE_TIMEOUT, SESSIONS_MAX

TOKEN_ENV: Final = "ZOEYMCP_BRIDGE_TOKEN_SHA256"  # noqa: S105 - a variable name, not a secret
# M7 design C.3 and M.6.
MAX_PROCS: Final = 64
OOM_SCORE_ADJ: Final = 1000
OOM_SCORE_PATH: Final = "/proc/self/oom_score_adj"
# How long the server waits for its connections once every stream has ended.
CLOSE_WAIT: Final = 5
# A Unix socket's path, with its NUL, fits sun_path (108 bytes on Linux).
SOCKET_PATH_MAX: Final = 107


class StartupError(Exception):
    """The bridge can't start; the message says why and is safe to print (it names options and
    variables, never a value)."""


@dataclass(frozen=True)
class Options:
    listen: str
    era: Era
    command: tuple[str, ...]
    peer_uid: int | None = None
    egress_proxy: str | None = None
    env: tuple[str, ...] = ()
    secret_env: tuple[str, ...] = ()
    stderr: StderrMode = "counts"
    max_sessions: int = SESSIONS_MAX
    max_message_bytes: int = MESSAGE_MAX
    idle_timeout: float = IDLE_TIMEOUT
    start_timeout: float = START_TIMEOUT
    keepalive: float = KEEPALIVE_INTERVAL
    max_procs: int = MAX_PROCS
    work_dir: str = childenv.WORK_DIR
    control_fd: int | None = None


@dataclass(frozen=True)
class Prepared:
    """A bridge that passed every start-up check: where it listens and what it serves with."""

    options: Options
    listen: listen.Listen
    settings: Settings


@contextlib.contextmanager
def _refused() -> Iterator[None]:
    """Each check's own error, as the start's refusal."""
    try:
        yield
    except (ValueError, listen.ListenError) as exc:
        raise StartupError(str(exc)) from exc


def check_options(options: Options) -> listen.Listen:
    """The options alone: ranges, forms and pairings."""
    if not options.command:
        raise StartupError("give the program to run after --, as: zoeymcp bridge ... -- <command>")
    if options.era not in ("legacy", "modern"):
        raise StartupError("--era is legacy or modern")
    if options.stderr not in ("counts", "text"):
        raise StartupError("--stderr is counts or text")
    for name, value, low in (
        ("--max-sessions", options.max_sessions, 1),
        ("--max-message-bytes", options.max_message_bytes, 1024),
        ("--max-procs", options.max_procs, 1),
    ):
        if value < low:
            raise StartupError(f"{name} is at least {low}")
    for name, seconds in (
        ("--idle-timeout", options.idle_timeout),
        ("--start-timeout", options.start_timeout),
        ("--keepalive", options.keepalive),
    ):
        if not seconds > 0:
            raise StartupError(f"{name} is a positive number of seconds")
    with _refused():
        where = listen.parse(options.listen)
        listen.check_peer_uid(where, options.peer_uid)
        if isinstance(where, listen.Unix) and len(where.path.encode()) > SOCKET_PATH_MAX:
            raise StartupError(f"--listen unix: takes a path of at most {SOCKET_PATH_MAX} bytes")
        check_stderr_mode(options.stderr, bool(options.secret_env))
        childenv.check_names(options.env, options.secret_env)
        if options.egress_proxy is not None:
            childenv.proxy_url(options.egress_proxy)
        childenv.work_paths(options.work_dir)
    return where


def load_token(environ: Mapping[str, str]) -> BridgeTokenHash:
    """``ZOEYMCP_BRIDGE_TOKEN_SHA256``, the only form of the token the bridge holds (X14)."""
    value = environ.get(TOKEN_ENV)
    if not value:
        raise StartupError(
            f"{TOKEN_ENV} is unset: generate the token in the vault's container with zoeymcp "
            "secret set <the route credential's secret> --generate, and set the sha256: line it "
            "prints"
        )
    with _refused():
        return BridgeTokenHash(value)


def prepare_work(paths: childenv.WorkPaths) -> None:
    """Create ``<work>`` 0700, or accept it as this uid's own with 0700 (C.3), then the child's
    home, temporary and working directories in it, and drop a ``ready`` left from a run before."""
    if sys.platform == "win32":
        raise StartupError("the bridge needs a POSIX platform")
    try:
        os.mkdir(paths.root, 0o700)
        os.chmod(paths.root, 0o700)
    except FileExistsError:
        info = os.lstat(paths.root)
        own = stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
        if not own or stat.S_IMODE(info.st_mode) != 0o700:
            raise StartupError(
                f"--work-dir {paths.root} exists and isn't this uid's own directory with mode 0700"
            ) from None
    except OSError as exc:
        raise StartupError(f"--work-dir {paths.root} can't be made: {exc}") from exc
    try:
        for directory in (paths.home, paths.tmp, paths.cwd):
            with contextlib.suppress(FileExistsError):
                os.mkdir(directory, 0o700)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(paths.ready)
    except OSError as exc:
        raise StartupError(f"--work-dir {paths.root} can't be used: {exc}") from exc


def check_control_fd(fd: int) -> None:
    """An open pipe or socket this process can read (the launcher's)."""
    if sys.platform == "win32":
        raise StartupError("--control-fd needs a POSIX platform")
    try:
        mode = os.fstat(fd).st_mode
    except OSError as exc:
        raise StartupError(f"--control-fd {fd} is not open: {exc}") from exc
    if not (stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)):
        raise StartupError(f"--control-fd {fd} is not a pipe")


def set_limits(max_procs: int) -> None:
    """``RLIMIT_NPROC`` to ``max_procs`` (no higher than the hard limit it has) and
    ``oom_score_adj`` to 1000, before the first child (C.3)."""
    if sys.platform == "win32":
        raise StartupError("the bridge needs a POSIX platform")
    import resource

    _, hard = resource.getrlimit(resource.RLIMIT_NPROC)
    limit = max_procs if hard == resource.RLIM_INFINITY else min(max_procs, hard)
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (limit, limit))
    except (OSError, ValueError) as exc:
        raise StartupError(f"can't set RLIMIT_NPROC to {limit}: {exc}") from exc
    if os.path.exists(OOM_SCORE_PATH):
        try:
            with open(OOM_SCORE_PATH, "w", encoding="ascii") as adjust:
                adjust.write(str(OOM_SCORE_ADJ))
        except OSError as exc:
            raise StartupError(f"can't raise oom_score_adj to {OOM_SCORE_ADJ}: {exc}") from exc


def prepare(options: Options, environ: Mapping[str, str]) -> Prepared:
    """Every start-up check, in the order of this module's docstring, and the limits."""
    where = check_options(options)
    token = load_token(environ)
    paths = childenv.work_paths(options.work_dir)
    with _refused():
        env = childenv.build(
            environ,
            paths,
            egress_proxy=options.egress_proxy,
            env=options.env,
            secret_env=options.secret_env,
        )
    prepare_work(paths)
    if options.control_fd is not None:
        check_control_fd(options.control_fd)
    if isinstance(where, listen.Unix):
        with _refused():
            listen.prepare_socket(where)
    set_limits(options.max_procs)
    spec = Spec(options.command, env, paths.cwd, options.max_message_bytes, options.stderr)
    settings = Settings(
        options.era,
        spec,
        token,
        paths.ready,
        max_sessions=options.max_sessions,
        idle_timeout=options.idle_timeout,
        start_timeout=options.start_timeout,
        keepalive=options.keepalive,
    )
    return Prepared(options, where, settings)


def ready_check(work_dir: str) -> bool:
    """``--ready-check``: whether the probe passed (``<work>/ready``, C.5)."""
    try:
        return os.path.isfile(childenv.work_paths(work_dir).ready)
    except childenv.ChildEnvError:
        return False


class _Server(uvicorn.Server):
    """A uvicorn server that leaves signal handling to the bridge."""

    def install_signal_handlers(self) -> None:
        pass

    @contextlib.contextmanager
    def capture_signals(self) -> Iterator[None]:
        yield


def _config(
    bridge: Bridge,
    *,
    uds: str | None = None,
    http: type[asyncio.Protocol] | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
) -> uvicorn.Config:
    """uvicorn's settings: no proxy headers (nothing is read from them), no server or date
    header, no access log, and a bounded wait for connections once the streams have ended."""
    return uvicorn.Config(
        bridge,
        uds=uds,
        http=http or "h11",
        host=host,  # unused with a socket given or uds=; kept so the config names its address
        port=port,
        proxy_headers=False,
        server_header=False,
        date_header=False,
        access_log=False,
        log_level="warning",
        lifespan="off",
        timeout_graceful_shutdown=CLOSE_WAIT,
    )


async def serve(
    prepared: Prepared, *, stopper: Callable[[Callable[[], None]], None] | None = None
) -> None:
    """Serve until a stop. ``stopper`` is for a caller off the main thread (tests): it is handed
    the stop function, and no signal handler is installed."""
    options = prepared.options
    bridge = Bridge(prepared.settings)
    sockets: list[socket.socket] | None = None
    where = prepared.listen
    if isinstance(where, listen.Unix):
        assert options.peer_uid is not None  # noqa: S101 - check_peer_uid refused it otherwise
        config = _config(bridge, uds=where.path, http=listen.peer_checked(options.peer_uid))
        shown = where.text
    else:
        try:
            address = await listen.resolve(where)
        except listen.ListenError as exc:
            raise StartupError(str(exc)) from exc
        try:
            sockets = [listen.bind_tcp(address, where.port)]
        except listen.ListenError as exc:
            raise StartupError(str(exc)) from exc
        config = _config(bridge, host=address, port=where.port)
        shown = listen.Tcp(address, where.port).text
    server = _Server(config)
    stopping = asyncio.Event()
    loop = asyncio.get_running_loop()
    if stopper is not None:
        stopper(stopping.set)
    elif sys.platform != "win32":
        loop.add_signal_handler(signal.SIGTERM, stopping.set)
        loop.add_signal_handler(signal.SIGINT, stopping.set)
    tasks: list[asyncio.Task[None]] = []
    pipe = None
    try:
        if options.control_fd is not None:
            reader, pipe = await control.open_control(options.control_fd)
            tasks.append(
                asyncio.create_task(
                    control.read_control(
                        reader, reload=lambda: None, stop=stopping.set, event=event
                    )
                )
            )
        event(
            "bridge_started",
            era=options.era,
            listen=shown,
            command=options.command[0],
            max_sessions=options.max_sessions,
            max_message_bytes=options.max_message_bytes,
            idle_timeout=options.idle_timeout,
            start_timeout=options.start_timeout,
            keepalive=options.keepalive,
            max_procs=options.max_procs,
            stderr=options.stderr,
        )
        bridge.start()
        serving = asyncio.create_task(server.serve(sockets=sockets))
        stop = asyncio.create_task(stopping.wait())
        await asyncio.wait((serving, stop), return_when=asyncio.FIRST_COMPLETED)
        await bridge.close()
        server.should_exit = True
        stop.cancel()
        await serving
    finally:
        for socket_ in sockets or []:
            socket_.close()
        for task in tasks:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        if pipe is not None:
            pipe.close()
        await bridge.close()
        event("bridge_stopped")


def run(options: Options, environ: Mapping[str, str]) -> None:
    prepared = prepare(options, environ)
    asyncio.run(serve(prepared))
