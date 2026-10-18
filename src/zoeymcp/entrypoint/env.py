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

Everything here takes its inputs as values, so it is tested without a container.
"""

from __future__ import annotations

from collections.abc import Mapping
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


def split_environment(environ: Mapping[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    """``(vault, gateway)``: the vault gets everything, the gateway the allowlist."""
    return dict(environ), gateway_environment(environ)


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


def directory_refusals(found: Mapping[str, Found | None]) -> list[str]:
    """Each directory of :data:`DIRECTORIES` that doesn't have exactly its owner and mode."""
    refusals = []
    for wanted in DIRECTORIES:
        actual = found.get(wanted.path)
        expected = f"{wanted.uid}:{wanted.gid} {wanted.mode:04o}"
        if actual is None or not actual.is_dir:
            refusals.append(f"{wanted.path} ({wanted.holds}) is missing; it must be {expected}")
            continue
        if (actual.uid, actual.gid, actual.mode & 0o7777) != (wanted.uid, wanted.gid, wanted.mode):
            refusals.append(
                f"{wanted.path} ({wanted.holds}) is {actual.uid}:{actual.gid} "
                f"{actual.mode & 0o7777:04o}; it must be {expected}"
            )
    return refusals
