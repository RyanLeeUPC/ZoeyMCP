"""Import guards between the vault's and the gateway's virtual environments.

The image has two environments from one lock. The vault's has none of the gateway extra's
packages: Python runs every ``.pth`` file in site-packages at start, so they must not be installed
there at all. The vault's code must therefore never need them, and the gateway's code must never
load the vault's.
"""

from __future__ import annotations

import ast
import importlib.metadata
import json
import re
import subprocess
import sys
import tomllib
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

import pytest

import zoeymcp

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = Path(zoeymcp.__file__).resolve().parent

# Code that runs in the vault's environment and never reaches the gateway's code.
VAULT_SIDE = ("vault", "common", "selftest", "entrypoint")
# The CLI runs in both environments. It may start the gateway's code, but never needs its packages.
# The top-level package and ``python -m zoeymcp`` are its entry points.
CLI = "cli"
ENTRY_POINTS = ("__init__.py", "__main__.py")
# Code the gateway's process runs (common is shared) and that never reaches the vault's code.
GATEWAY_SIDE = ("gateway", "common")
# The gateway extra's own packages, named here so that no guard can pass vacuously.
ALWAYS_GATEWAY_ONLY = frozenset({"mcp", "mcp_types", "httpx2", "httpcore2", "jsonschema", "regex"})
# Every distribution only the gateway's environment has, on any platform, by normalized name.
GATEWAY_ONLY = frozenset(
    {
        "attrs",
        "httpcore2",
        "httpx2",
        "httpx2-jsfetch",
        "jsonschema",
        "jsonschema-specifications",
        "mcp",
        "mcp-types",
        "opentelemetry-api",
        "pyjwt",
        "python-multipart",
        "pywin32",
        "referencing",
        "regex",
        "rpds-py",
        "sse-starlette",
        "truststore",
    }
)


# --- the lock -----------------------------------------------------------------------------------


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _lock() -> dict[str, Any]:
    with (ROOT / "uv.lock").open("rb") as file:
        return tomllib.load(file)


def _closure(lock: Mapping[str, Any], roots: Iterable[Mapping[str, Any]]) -> set[str]:
    """Every package the roots need, by normalized name. Markers are ignored, so any platform
    counts."""
    packages: dict[str, list[Mapping[str, Any]]] = {}
    for package in lock["package"]:
        packages.setdefault(_normalize(package["name"]), []).append(package)
    seen: set[tuple[str, str]] = set()
    pending = list(roots)
    while pending:
        dependency = pending.pop()
        name = _normalize(dependency["name"])
        for extra in ["", *dependency.get("extra", [])]:
            if (name, extra) in seen:
                continue
            seen.add((name, extra))
            for package in packages[name]:
                if extra:
                    pending.extend(package.get("optional-dependencies", {}).get(extra, []))
                else:
                    pending.extend(package.get("dependencies", []))
    return {name for name, _ in seen}


def _project(lock: Mapping[str, Any]) -> Mapping[str, Any]:
    projects: list[Mapping[str, Any]] = [p for p in lock["package"] if p["name"] == "zoeymcp"]
    (project,) = projects
    return project


def environments() -> tuple[set[str], set[str]]:
    """The packages of the vault's environment, and those only the gateway's has."""
    lock = _lock()
    project = _project(lock)
    vault = _closure(lock, project["dependencies"])
    extra = project["optional-dependencies"]["gateway"]
    gateway = _closure(lock, [*project["dependencies"], *extra])
    return vault, gateway - vault


def test_the_gateway_extra_is_exact() -> None:
    with (ROOT / "pyproject.toml").open("rb") as file:
        extra = tomllib.load(file)["project"]["optional-dependencies"]["gateway"]
    assert "mcp==2.3.0" in extra
    assert "mcp-types==2.3.0" in extra
    versions = {p["name"]: p["version"] for p in _lock()["package"]}
    assert versions["mcp"] == "2.3.0"
    assert versions["mcp-types"] == "2.3.0"


def test_every_locked_package_has_hashes() -> None:
    lock = _lock()
    # Only the project itself comes from somewhere other than the registry (a git, URL or path
    # source would carry no hashes).
    assert [p["name"] for p in lock["package"] if "registry" not in p["source"]] == ["zoeymcp"]
    unhashed = []
    for package in lock["package"]:
        if "registry" not in package["source"]:
            continue
        files = [*package.get("wheels", []), *([package["sdist"]] if "sdist" in package else [])]
        if not files or not all(f.get("hash", "").startswith("sha256:") for f in files):
            unhashed.append(package["name"])
    assert unhashed == []


def smoke_gateway_only() -> set[str]:
    """The gateway-only distributions the image smoke test names."""
    script = (ROOT / "scripts" / "smoke-image.sh").read_text(encoding="utf-8")
    lines = re.findall(r'^gateway_only_dists="([^"]*)"$', script, flags=re.MULTILINE)
    return {name for line in lines for name in line.replace("$gateway_only_dists", "").split()}


def test_the_vault_environment_has_none_of_the_gateway_packages() -> None:
    vault, gateway_only = environments()
    assert {_normalize(m) for m in ALWAYS_GATEWAY_ONLY} <= gateway_only
    # Exact, so that a package moving into the vault's environment fails here. A relock that
    # changes this updates the smoke test's list too.
    assert gateway_only == GATEWAY_ONLY
    assert smoke_gateway_only() == GATEWAY_ONLY
    assert {"httpx", "starlette", "uvicorn", "pydantic", "anyio", "cryptography"} <= vault


def test_the_shared_stack_has_one_version() -> None:
    lock = _lock()
    project = _project(lock)
    gateway = _closure(
        lock, [*project["dependencies"], *project["optional-dependencies"]["gateway"]]
    )
    counts = Counter(_normalize(p["name"]) for p in lock["package"])
    assert sorted(name for name in gateway if counts[name] != 1) == []


def test_no_opentelemetry_sdk_or_exporter_is_locked() -> None:
    names = {_normalize(p["name"]) for p in _lock()["package"]}
    assert {n for n in names if n.startswith("opentelemetry")} == {"opentelemetry-api"}


# --- what the source imports --------------------------------------------------------------------


def module_name(path: Path, root: Path) -> str:
    parts = list(path.relative_to(root).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def imported_modules(path: Path, module: str) -> Iterator[str]:
    """Every module an import in this file names, wherever the import is, relative ones resolved."""
    tree = ast.parse(path.read_bytes(), filename=str(path))
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                parts = package.split(".")
                parts = parts[: len(parts) - (node.level - 1)]
                base = ".".join([*parts, base] if base else parts)
            yield base
            yield from (f"{base}.{alias.name}" for alias in node.names)


def violations(root: Path, subpackages: Iterable[str], forbidden: Iterable[str]) -> list[str]:
    """``file: module`` for each import under these subpackages (or in these files) of
    ``root/zoeymcp`` that names a forbidden module or one inside it."""
    forbidden = tuple(forbidden)
    found = []
    for sub in subpackages:
        target = root / "zoeymcp" / sub
        paths = sorted(target.rglob("*.py")) if target.is_dir() else [target]
        for path in (p for p in paths if p.is_file()):
            for name in imported_modules(path, module_name(path, root)):
                if any(name == f or name.startswith(f + ".") for f in forbidden):
                    found.append(f"{path.relative_to(root).as_posix()}: {name}")
    return found


def gateway_only_modules() -> set[str]:
    """Top-level modules of the gateway-only packages installed here, and the named few."""
    _, gateway_only = environments()
    installed = {
        top
        for top, dists in importlib.metadata.packages_distributions().items()
        if any(_normalize(d) in gateway_only for d in dists)
    }
    return installed | ALWAYS_GATEWAY_ONLY


def test_the_scanner_sees_every_kind_of_import(tmp_path: Path) -> None:
    common = tmp_path / "zoeymcp" / "common"
    (common / "policy").mkdir(parents=True)
    (common / "__init__.py").write_bytes(b"from .policy import check\n")
    (common / "policy" / "__init__.py").write_bytes(b"")
    (common / "policy" / "x.py").write_bytes(
        b"import os, zoeymcp.vault.store\n"
        b"from ...vault import keys\n"
        b"from zoeymcp import vault\n"
        b"from .. import logs\n"
        b"def lazy() -> None:\n"
        b"    import mcp.client\n"
        b"    from httpx2 import Client\n"
    )
    x = common / "policy" / "x.py"
    assert module_name(x, tmp_path) == "zoeymcp.common.policy.x"
    assert module_name(common / "__init__.py", tmp_path) == "zoeymcp.common"
    assert list(imported_modules(x, "zoeymcp.common.policy.x")) == [
        "os",
        "zoeymcp.vault.store",
        "zoeymcp.vault",
        "zoeymcp.vault.keys",
        "zoeymcp",
        "zoeymcp.vault",
        "zoeymcp.common",
        "zoeymcp.common.logs",
        "mcp.client",
        "httpx2",
        "httpx2.Client",
    ]
    assert list(imported_modules(common / "__init__.py", "zoeymcp.common")) == [
        "zoeymcp.common.policy",
        "zoeymcp.common.policy.check",
    ]
    assert violations(tmp_path, ["common", "absent"], ["zoeymcp.vault"]) == [
        "zoeymcp/common/policy/x.py: zoeymcp.vault.store",
        "zoeymcp/common/policy/x.py: zoeymcp.vault",
        "zoeymcp/common/policy/x.py: zoeymcp.vault.keys",
        "zoeymcp/common/policy/x.py: zoeymcp.vault",
    ]
    # A module whose name only starts the same way is a different module.
    assert violations(tmp_path, ["common"], ["mcp", "httpx", "zoeymcp.vaults"]) == [
        "zoeymcp/common/policy/x.py: mcp.client"
    ]
    # A single file is scanned too; a missing one is skipped.
    (tmp_path / "zoeymcp" / "__main__.py").write_bytes(b"from .cli.main import main\n")
    assert violations(tmp_path, ["__main__.py", "absent.py"], ["zoeymcp.cli"]) == [
        "zoeymcp/__main__.py: zoeymcp.cli.main",
        "zoeymcp/__main__.py: zoeymcp.cli.main.main",
    ]


def test_vault_code_never_imports_gateway_code_or_packages() -> None:
    forbidden = ["zoeymcp.gateway", *sorted(gateway_only_modules())]
    assert violations(PACKAGE.parent, VAULT_SIDE, forbidden) == []


def test_the_cli_never_imports_gateway_packages() -> None:
    forbidden = sorted(gateway_only_modules())
    assert violations(PACKAGE.parent, [CLI, *ENTRY_POINTS], forbidden) == []


def test_gateway_code_never_imports_vault_code() -> None:
    assert violations(PACKAGE.parent, GATEWAY_SIDE, ["zoeymcp.vault"]) == []


def test_the_launcher_uses_the_standard_library_only() -> None:
    """PID 1 of the standard tier: nothing beyond the stdlib, the shared log writer and itself."""
    allowed = ("zoeymcp.entrypoint", "zoeymcp.common.logs")
    found = []
    for path in sorted((PACKAGE / "entrypoint").rglob("*.py")):
        for name in imported_modules(path, module_name(path, PACKAGE.parent)):
            top = name.partition(".")[0]
            if top == "zoeymcp":
                if name != "zoeymcp.common" and not any(
                    name == a or name.startswith(a + ".") for a in allowed
                ):
                    found.append(f"{path.name}: {name}")
            elif top and top not in sys.stdlib_module_names and top != "__future__":
                found.append(f"{path.name}: {name}")
    assert found == []


# --- what importing it loads --------------------------------------------------------------------

# Imports every module of the named packages (a missing package is skipped) in a fresh
# interpreter where the blocked top-level modules can't be found, as in the vault's environment.
# Prints the names of every module loaded.
PROBE = """
import importlib, importlib.abc, json, pkgutil, sys

class Blocked(importlib.abc.MetaPathFinder):
    def __init__(self, names):
        self.names = names

    def find_spec(self, fullname, path, target=None):
        if fullname.partition(".")[0] in self.names:
            raise ModuleNotFoundError(f"No module named {fullname!r}", name=fullname)
        return None

packages, blocked = json.loads(sys.argv[1]), frozenset(json.loads(sys.argv[2]))
sys.meta_path.insert(0, Blocked(blocked))
for name in packages:
    try:
        package = importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name != name:
            raise
        continue
    for info in pkgutil.walk_packages(package.__path__, name + "."):
        importlib.import_module(info.name)
print(json.dumps(sorted(sys.modules)))
"""


def loaded_modules(packages: Iterable[str], blocked: Iterable[str] = ()) -> set[str]:
    result = subprocess.run(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-I", "-c", PROBE, json.dumps(list(packages)), json.dumps(list(blocked))],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    return set(json.loads(result.stdout))


def _within(loaded: set[str], package: str) -> set[str]:
    return {name for name in loaded if name == package or name.startswith(package + ".")}


def test_the_probe_blocks_and_skips() -> None:
    loaded = loaded_modules(["zoeymcp.absent", "zoeymcp.common"])
    assert "zoeymcp.common.logs" in loaded
    assert not _within(loaded, "zoeymcp.absent")
    # A blocked import inside a package that exists is an error, not a skipped package.
    result = subprocess.run(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-I", "-c", PROBE, json.dumps(["zoeymcp.common"]), json.dumps(["yaml"])],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode != 0
    assert "No module named 'yaml'" in result.stderr


def test_vault_code_loads_without_the_gateway_packages() -> None:
    # A shared library may try an optional gateway package (Starlette tries python_multipart);
    # the block makes that attempt fail as it does in the vault's environment.
    blocked = gateway_only_modules()
    loaded = loaded_modules([f"zoeymcp.{sub}" for sub in (*VAULT_SIDE, CLI)], sorted(blocked))
    assert {"zoeymcp.vault.server", "zoeymcp.selftest.runner", "zoeymcp.cli.main"} <= loaded
    assert not _within(loaded, "zoeymcp.gateway")
    # Nothing loaded before the block went in (a .pth file runs at start) gets past it either.
    assert not {name.partition(".")[0] for name in loaded} & blocked


def test_loading_gateway_code_loads_no_vault_code() -> None:
    loaded = loaded_modules([f"zoeymcp.{sub}" for sub in GATEWAY_SIDE])
    assert {"zoeymcp.common.logs", "zoeymcp.common.policy.view"} <= loaded
    assert not _within(loaded, "zoeymcp.vault")


# Runs ``python -m zoeymcp gateway --help`` as the image's exec does, then prints its exit status
# and the names of every module loaded. Its output is captured so that it can't mix with these.
ENTRY_PROBE = """
import contextlib, io, json, runpy, sys

sys.argv = ["zoeymcp", "gateway", "--help"]
status = None
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    try:
        runpy.run_module("zoeymcp", run_name="__main__", alter_sys=True)
    except SystemExit as exc:
        status = exc.code
print(json.dumps({"status": status, "modules": sorted(sys.modules)}))
"""


@pytest.mark.xfail(
    strict=True,
    reason="step 13: python -m zoeymcp gateway goes through cli/main.py, which imports vault code",
)
def test_the_gateway_entry_path_loads_no_vault_code() -> None:
    result = subprocess.run(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-I", "-c", ENTRY_PROBE],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    probe = json.loads(result.stdout)
    # The entry point ran to its exit: argparse's error for now, the gateway's help in step 13.
    assert isinstance(probe["status"], int)
    assert not _within(set(probe["modules"]), "zoeymcp.vault")
