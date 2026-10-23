"""The standard tier's decisions, pure (M3 design B.2, G21).

The launcher runs both roles in one container: the vault as uid 10001, the gateway as uid 10002,
and itself, once both are started, as uid 10003, which owns no files. It refuses to start unless
the container is a box the gateway uid can't climb out of:

- it is PID 1, as root;
- ``NoNewPrivs`` is set (``no-new-privileges``): without it, a setuid binary could give the
  gateway uid the whole bounding set back;
- the bounding set holds nothing beyond ``SETUID`` and ``SETGID`` (``cap_drop: [ALL]``), which
  the launcher needs to start its children and the CLI needs to reach their admin sockets.

The vault gets the whole environment: the master key, ``ZOEYMCP_CONFIG``, and ``env:`` secrets
with any names. The gateway gets an allowlist, so no secret reaches it by accident (G1).

Each bridge named by ``--bridge NAME`` (M7 design C.10, Q46) is one more child, unconfined: bridge
*i* in ``--bridge`` order runs as :data:`BRIDGE_UID_BASE` + *i*, and listens on
``/run/zoeymcp-bridge-<name>/mcp.sock`` in a tmpfs of its own, its uid's, group the vault's, mode
0750, which the launcher checks as it checks its own directories (:func:`bridge_directory`). Its
configuration is the container's environment: ``ZOEYMCP_BRIDGE_<NAME>_ARGS``, a JSON array of its
``zoeymcp bridge`` arguments, which every process in the container can read on its command line;
``ZOEYMCP_BRIDGE_<NAME>_TOKEN_SHA256``; and ``ZOEYMCP_BRIDGE_<NAME>_ENV_<VAR>``, handed to it as
``<VAR>``, which only its own uid can read. :func:`bridge_specs` refuses a bridge's spec with
reasons that name a variable or a position, never a value; a refused bridge isn't started, and
the vault and the gateway start regardless. A missing or malformed token hash is the bridge's own
refusal, since on a cold start the hash exists only after the vault has run.

Everything here takes its inputs as values, so it is tested without a container.
"""

from __future__ import annotations

import json
import re
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass

VAULT_UID = 10001
GATEWAY_UID = 10002
INIT_UID = 10003

CAP_SETGID = 6
CAP_SETUID = 7
ALLOWED_CAPS = (1 << CAP_SETGID) | (1 << CAP_SETUID)

# The gateway's environment: exactly these names, LC_*, and ZOEYMCP_GATEWAY_* but its key.
GATEWAY_NAMES = frozenset({"PATH", "LANG", "TZ", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE"})
GATEWAY_PREFIX = "ZOEYMCP_GATEWAY_"
GATEWAY_KEY_PREFIX = "ZOEYMCP_GATEWAY_KEY"

LINK_SOCKET = "/run/zoeymcp-link/vault.sock"

# The standard tier's bridges (M7 design C.10, M.6): bridge i runs as BRIDGE_UID_BASE + i.
BRIDGE_UID_BASE = 10100
MAX_BRIDGES = 8
BRIDGE_NAME = re.compile(r"[a-z0-9]{1,16}")
BRIDGE_PREFIX = "ZOEYMCP_BRIDGE_"
# The name a bridge reads its own token hash under.
BRIDGE_TOKEN = "ZOEYMCP_BRIDGE_TOKEN_SHA256"  # noqa: S105 - a variable name, not a secret
# A bridge's environment: exactly these names, LC_*, its token hash and its own ENV_* values.
BRIDGE_NAMES = GATEWAY_NAMES
# The bridge's options the launcher sets itself (C.8), refused in ARGS.
LAUNCHER_OPTIONS = ("--listen", "--peer-uid", "--control-fd", "--work-dir")
# A variable an ENV_<VAR> may name: the bridge's own rule for --env (bridge/childenv.py).
_VARIABLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")


@dataclass(frozen=True)
class Directory:
    path: str
    uid: int
    gid: int
    mode: int
    holds: str


# Set at build time or by tmpfs options, so no CHOWN or DAC_OVERRIDE is ever needed.
DIRECTORIES = (
    Directory("/state", VAULT_UID, VAULT_UID, 0o700, "the vault's state (a volume)"),
    Directory("/state-gateway", GATEWAY_UID, GATEWAY_UID, 0o700, "the gateway's state (a volume)"),
    Directory("/run/zoeymcp", VAULT_UID, VAULT_UID, 0o700, "the vault's admin socket"),
    Directory("/run/zoeymcp-link", VAULT_UID, GATEWAY_UID, 0o750, "the link socket"),
    Directory(
        "/run/zoeymcp-gateway", GATEWAY_UID, GATEWAY_UID, 0o700, "the gateway's admin socket"
    ),
)


def gateway_environment(environ: Mapping[str, str]) -> dict[str, str]:
    """The allowlisted part of ``environ`` the gateway may see."""
    return {
        name: value
        for name, value in environ.items()
        if name in GATEWAY_NAMES
        or name.startswith("LC_")
        or (name.startswith(GATEWAY_PREFIX) and not name.startswith(GATEWAY_KEY_PREFIX))
    }


def bridge_variable(name: str, suffix: str) -> str:
    """``ZOEYMCP_BRIDGE_<NAME>_<suffix>``. A bridge's name holds no ``_``, so no bridge's
    variables are another's."""
    return f"{BRIDGE_PREFIX}{name.upper()}_{suffix}"


def bridge_environment(environ: Mapping[str, str], name: str) -> dict[str, str]:
    """Bridge ``name``'s environment: the allowlist, its token hash under the plain name, and
    its own ``ENV_<VAR>`` values as ``<VAR>``. Never the master key, ``ZOEYMCP_CONFIG``, a
    gateway key or another bridge's variables."""
    own = bridge_variable(name, "ENV_")
    found = {
        key: value for key, value in environ.items() if key in BRIDGE_NAMES or key.startswith("LC_")
    }
    token = environ.get(bridge_variable(name, "TOKEN_SHA256"))
    if token is not None:
        found[BRIDGE_TOKEN] = token
    for key, value in environ.items():
        if key.startswith(own):
            found[key.removeprefix(own)] = value
    return found


def split_environment(
    environ: Mapping[str, str], bridges: Sequence[str] = ()
) -> tuple[dict[str, str], dict[str, str], dict[str, dict[str, str]]]:
    """``(vault, gateway, {bridge: its environment})``: the vault gets everything, the gateway
    the allowlist, each bridge in ``bridges`` its own (:func:`bridge_environment`)."""
    return (
        dict(environ),
        gateway_environment(environ),
        {name: bridge_environment(environ, name) for name in bridges},
    )


@dataclass(frozen=True)
class ProcessStatus:
    """What the launcher reads from ``/proc/self/status``."""

    uids: tuple[int, ...]  # real, effective, saved, filesystem
    no_new_privs: bool
    cap_bounding: int
    cap_effective: int


class StatusError(ValueError):
    """``/proc/self/status`` lacks a line the launcher needs, or has a malformed one."""


def parse_status(text: str) -> ProcessStatus:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition(":")
        if separator:
            fields[name.strip()] = value.strip()
    try:
        uids = tuple(int(part) for part in fields["Uid"].split())
        no_new_privs = int(fields["NoNewPrivs"])
        bounding = int(fields["CapBnd"], 16)
        effective = int(fields["CapEff"], 16)
    except KeyError as exc:
        raise StatusError(f"no {exc.args[0]} line") from exc
    except ValueError as exc:
        raise StatusError("a malformed line") from exc
    if len(uids) != 4 or no_new_privs not in (0, 1):
        raise StatusError("a malformed line")
    return ProcessStatus(uids, no_new_privs == 1, bounding, effective)


def cap_names(mask: int) -> list[str]:
    """Capability numbers in ``mask``, as ``cap_<n>`` (names aren't needed to refuse them)."""
    return [f"cap_{bit}" for bit in range(mask.bit_length()) if mask >> bit & 1]


def box_refusals(status: ProcessStatus, pid: int) -> list[str]:
    """Why this process may not launch the standard tier; empty when it may."""
    refusals = []
    if pid != 1:
        refusals.append(f"the launcher must be the container's PID 1, not PID {pid}")
    if status.uids[:2] != (0, 0):
        refusals.append('the launcher must start as root (user: "0:0"); it drops root itself')
    if not status.no_new_privs:
        refusals.append(
            "NoNewPrivs is not set: add security_opt: [no-new-privileges:true], or a setuid "
            "binary could hand the gateway's uid privileges back"
        )
    extra = status.cap_bounding & ~ALLOWED_CAPS
    if extra:
        refusals.append(
            "capabilities beyond SETUID and SETGID are in the bounding set "
            f"({', '.join(cap_names(extra))}): add cap_drop: [ALL] and cap_add: [SETUID, SETGID]"
        )
    return refusals


@dataclass(frozen=True)
class Found:
    """A directory as it is: owner, group and permission bits, or None if it is missing."""

    uid: int
    gid: int
    mode: int
    is_dir: bool = True


def directory_refusal(wanted: Directory, actual: Found | None) -> str | None:
    """Why ``actual`` isn't ``wanted``: a directory with exactly its owner, group and mode."""
    expected = f"{wanted.uid}:{wanted.gid} {wanted.mode:04o}"
    if actual is None or not actual.is_dir:
        return f"{wanted.path} ({wanted.holds}) is missing; it must be {expected}"
    if (actual.uid, actual.gid, actual.mode & 0o7777) != (wanted.uid, wanted.gid, wanted.mode):
        return (
            f"{wanted.path} ({wanted.holds}) is {actual.uid}:{actual.gid} "
            f"{actual.mode & 0o7777:04o}; it must be {expected}"
        )
    return None


def directory_refusals(found: Mapping[str, Found | None]) -> list[str]:
    """Each directory of :data:`DIRECTORIES` that doesn't have exactly its owner and mode."""
    refusals = []
    for wanted in DIRECTORIES:
        refusal = directory_refusal(wanted, found.get(wanted.path))
        if refusal is not None:
            refusals.append(refusal)
    return refusals


# --- bridges (M7 design C.10) --------------------------------------------------------------------


def bridge_directory(name: str, index: int) -> Directory:
    """Bridge ``name``'s tmpfs, the ``index``-th in ``--bridge`` order: its uid's, group the
    vault's, 0750, so only the vault can reach its socket and only the bridge create one there."""
    return Directory(
        f"/run/zoeymcp-bridge-{name}",
        BRIDGE_UID_BASE + index,
        VAULT_UID,
        0o750,
        f"bridge {name}'s socket and work directory",
    )


@dataclass(frozen=True)
class Bridge:
    """A ``--bridge`` name as the launcher reads it: its place in ``--bridge`` order, which
    gives its uid and directory, its ``zoeymcp bridge`` arguments, and why it can't start
    (empty when it can; a refused one has no arguments)."""

    name: str
    index: int
    args: tuple[str, ...] = ()
    refusals: tuple[str, ...] = ()

    @property
    def uid(self) -> int:
        return BRIDGE_UID_BASE + self.index

    @property
    def directory(self) -> Directory:
        return bridge_directory(self.name, self.index)


def _name_refusal(name: str, index: int, taken: Collection[str]) -> str | None:
    """Why the ``index``-th ``--bridge`` can't be a bridge at all: a malformed name (named by
    its position, not repeated), one given before, or one past :data:`MAX_BRIDGES`."""
    if not BRIDGE_NAME.fullmatch(name):
        return f"--bridge [{index}]: a bridge's name is 1 to 16 lower-case letters or digits"
    if name in taken:
        return f"--bridge {name} is given twice"
    if index >= MAX_BRIDGES:
        return f"--bridge {name}: at most {MAX_BRIDGES} bridges run in one container"
    return None


def bridge_uids(names: Sequence[str]) -> dict[str, int]:
    """Each ``--bridge`` name with its uid, refused ones included (one past :data:`MAX_BRIDGES`
    too): the vault's ``--bridge NAME=UID`` list, so a route to a refused one fails its connect.
    Only a malformed name and a repeat are left out, which the vault's own parser refuses."""
    found: dict[str, int] = {}
    for index, name in enumerate(names):
        if BRIDGE_NAME.fullmatch(name) and name not in found:
            found[name] = BRIDGE_UID_BASE + index
    return found


def _arguments(raw: str) -> list[str] | None:
    """ARGS as a list of strings, or None for anything else."""
    try:
        args = json.loads(raw)
    except (ValueError, RecursionError):
        return None
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        return None
    return args


def _passable(word: str) -> bool:
    """Whether a command line can hold ``word``: no NUL, and nothing the filesystem encoding
    can't write (a lone surrogate), either of which fails the bridge's spawn in PID 1."""
    if "\x00" in word:
        return False
    try:
        word.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:
        return False
    return True


def _options(args: Sequence[str]) -> Sequence[str]:
    """The words before the first ``--``: after it they are the command's."""
    return args[: args.index("--")] if "--" in args else args


def _option(word: str) -> str:
    """The option a word gives, alone or as ``--<option>=<value>``."""
    return word.partition("=")[0]


def _args_refusals(variable: str, args: Sequence[str]) -> list[str]:
    refusals = []
    if "--" not in args:
        refusals.append(f"{variable} has no --: the command goes after it")
    elif args.index("--") == len(args) - 1:
        refusals.append(f"{variable} has no command after --")
    options = _options(args)
    if "--era" not in map(_option, options):
        refusals.append(f"{variable} has no --era")
    for position, word in enumerate(options):
        option = _option(word)
        if option in LAUNCHER_OPTIONS:
            refusals.append(f"{variable}[{position}]: {option} is the launcher's")
        elif option == "--egress-proxy":
            refusals.append(
                f"{variable}[{position}]: --egress-proxy: nothing in the standard tier enforces "
                "egress"
            )
    # The command's words too: every word ends up on the command line.
    for position, word in enumerate(args):
        if not _passable(word):
            refusals.append(
                f"{variable}[{position}]: no command line can hold this word (a NUL or a lone "
                "surrogate)"
            )
    return refusals


def _env_refusals(environ: Mapping[str, str], name: str) -> list[str]:
    own = bridge_variable(name, "ENV_")
    refusals = []
    for key in sorted(environ):
        if not key.startswith(own):
            continue
        var = key.removeprefix(own)
        if not _VARIABLE.fullmatch(var):
            refusals.append(f"{key}: the part after ENV_ isn't a variable name")
        elif var.upper().startswith("ZOEYMCP_"):
            refusals.append(f"{key}: a ZOEYMCP_ variable never reaches the bridge's program")
    return refusals


def bridge_specs(environ: Mapping[str, str], names: Sequence[str]) -> list[Bridge]:
    """Each ``--bridge`` name, in order, with its arguments or every reason it is refused. A
    reason names a variable, a position in ARGS or a ``--bridge`` position, never a value."""
    specs = []
    taken: list[str] = []
    for index, name in enumerate(names):
        refusal = _name_refusal(name, index, taken)
        if refusal is not None:
            specs.append(Bridge(name, index, refusals=(refusal,)))
            continue
        taken.append(name)
        variable = bridge_variable(name, "ARGS")
        raw = environ.get(variable)
        args = None if raw is None else _arguments(raw)
        if raw is None:
            refusals = [f"{variable} is not set"]
        elif args is None:
            refusals = [f"{variable} is not a JSON array of strings"]
        else:
            refusals = _args_refusals(variable, args)
        refusals += _env_refusals(environ, name)
        if args is None or refusals:
            specs.append(Bridge(name, index, refusals=tuple(refusals)))
        else:
            specs.append(Bridge(name, index, tuple(args)))
    return specs


def holds_secret_env(environ: Mapping[str, str], name: str) -> bool:
    """Whether bridge ``name``'s ARGS give it a ``--secret-env`` before the ``--`` (health's
    ``program_secret_unflagged``, M7 design J), read from the vault's environment, which is the
    container's. ARGS that can't be read hold none: that bridge is refused anyway."""
    raw = environ.get(bridge_variable(name, "ARGS"))
    args = None if raw is None else _arguments(raw)
    if args is None:
        return False
    return "--secret-env" in map(_option, _options(args))
