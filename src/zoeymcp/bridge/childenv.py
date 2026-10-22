"""The child's environment and its work directory's paths (M7 design C.3, X14, R35). Pure and
mutation-tested; :mod:`.child` starts the child with them.

The environment is built, never inherited (:func:`build`): exactly ``PATH`` (the bridge's own,
which is the image's), ``HOME`` and ``TMPDIR`` inside the work directory, and ``LANG``,
``LC_ALL`` and ``TZ`` where the bridge has them; with ``--egress-proxy``, ``HTTPS_PROXY``,
``HTTP_PROXY``, ``ALL_PROXY`` and their lower-case forms set to it, ``NO_PROXY`` empty and
``NODE_USE_ENV_PROXY=1`` (fold-in C6); then each ``--env`` and ``--secret-env`` name copied
from the bridge's own environment. A ``ZOEYMCP_*`` name is refused, so the token's hash and
anything else of ZoeyMCP's stays with the bridge, and so is a ``--secret-env`` name that is unset
or empty, rather than starting a program without the secret it was given. Proxy variables
confine only in the hardened placement, where the bridge's networks have no other way out.

Every path is under ``<work>``, ``--work-dir`` (:data:`WORK_DIR` by default, on tmpfs;
``/run/zoeymcp-bridge-<name>/work`` in the standard tier), which the bridge makes 0700 or
accepts as its own with 0700 (:func:`work_paths`).
"""

from __future__ import annotations

import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

WORK_DIR: Final = "/tmp/zoeymcp-bridge"  # noqa: S108 - the bridge's own tmpfs (C.3)
COPIED: Final = ("LANG", "LC_ALL", "TZ")
PROXY_NAMES: Final = (
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "https_proxy",
    "http_proxy",
    "all_proxy",
)
RESERVED_PREFIX: Final = "ZOEYMCP_"
PROXY_FORM: Final = "--egress-proxy is http://host:port, the egress role's listener"

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_PROXY = re.compile(r"http://(?:[A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\]):([0-9]{1,5})")


class ChildEnvError(ValueError):
    """A refusal to start: the message names an option and a variable, never a value."""


@dataclass(frozen=True)
class WorkPaths:
    """``<work>`` and what lies in it: the child's ``HOME``, ``TMPDIR`` and working directory,
    and the readiness file (C.5)."""

    root: str
    home: str
    tmp: str
    cwd: str
    ready: str


def work_paths(work: str) -> WorkPaths:
    """The paths under ``--work-dir``, which must be an absolute, normalized path other than
    ``/``."""
    if not work.startswith("/") or work == "/" or posixpath.normpath(work) != work:
        raise ChildEnvError("--work-dir is an absolute path such as /tmp/zoeymcp-bridge")
    tmp = f"{work}/tmp"  # noqa: S108 - inside <work>, not the shared /tmp
    return WorkPaths(work, f"{work}/home", tmp, f"{work}/work", f"{work}/ready")


def proxy_url(value: str) -> str:
    """``--egress-proxy``: ``http://host:port`` exactly, with no credentials, path or query."""
    found = _PROXY.fullmatch(value)
    if found is None or not 0 < int(found.group(1)) < 65536:
        raise ChildEnvError(PROXY_FORM)
    return value


def check_names(env: Sequence[str], secret_env: Sequence[str]) -> None:
    """Every ``--env`` and ``--secret-env`` name is a variable name and not ZoeyMCP's own."""
    for option, names in (("--env", env), ("--secret-env", secret_env)):
        for name in names:
            if not _NAME.fullmatch(name):
                raise ChildEnvError(f"{option} {name!a} isn't a variable name")
            if name.upper().startswith(RESERVED_PREFIX):
                raise ChildEnvError(f"{option} {name}: a ZOEYMCP_ variable never reaches the child")


def build(
    environ: Mapping[str, str],
    paths: WorkPaths,
    *,
    egress_proxy: str | None = None,
    env: Sequence[str] = (),
    secret_env: Sequence[str] = (),
) -> dict[str, str]:
    """The child's whole environment, from the bridge's own (``environ``)."""
    check_names(env, secret_env)
    for name in secret_env:
        if not environ.get(name):
            raise ChildEnvError(f"--secret-env {name} is unset or empty")
    child: dict[str, str] = {}
    if "PATH" in environ:
        child["PATH"] = environ["PATH"]
    child["HOME"] = paths.home
    child["TMPDIR"] = paths.tmp
    child.update({name: environ[name] for name in COPIED if name in environ})
    if egress_proxy is not None:
        url = proxy_url(egress_proxy)
        child.update(dict.fromkeys(PROXY_NAMES, url))
        child["NO_PROXY"] = ""
        child["NODE_USE_ENV_PROXY"] = "1"
    child.update({name: environ[name] for name in (*env, *secret_env) if name in environ})
    return child
