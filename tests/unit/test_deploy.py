"""The compose files: their inline policies pass ``check``, and the standard tier's container is
the box its launcher insists on (M3 design B.2, B.3)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from zoeymcp.common.policy import check_policy, parse_policy
from zoeymcp.entrypoint import env

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
COMPOSE_FILES = sorted(DEPLOY.glob("compose*.yaml"))


_VARIABLE = re.compile(r"\$\{([A-Z_]+)(?::-([^}]*)|:\?[^}]*)?\}")


def interpolated(text: str) -> str:
    """``text`` as compose would interpolate it with nothing set: ``${NAME:-default}`` is the
    default, and every other variable is ``set-by-the-operator``."""
    return _VARIABLE.sub(
        lambda m: m.group(2) if m.group(2) is not None else "set-by-the-operator", text
    )


def compose(name: str) -> dict[str, Any]:
    document = yaml.safe_load(interpolated((DEPLOY / name).read_text(encoding="utf-8")))
    assert isinstance(document, dict)
    return document


def unprivileged(service: dict[str, Any], cap_add: list[str] | None = None) -> None:
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service.get("cap_add") == cap_add
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert not service["user"].startswith("0:")


def test_there_are_both_tiers() -> None:
    assert [path.name for path in COMPOSE_FILES] == ["compose.hardened.yaml", "compose.yaml"]


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda path: path.name)
def test_inline_policies_pass_check(path: Path) -> None:
    services = compose(path.name)["services"]
    policies = [
        service["environment"]["ZOEYMCP_CONFIG"]
        for service in services.values()
        if "ZOEYMCP_CONFIG" in service.get("environment", {})
    ]
    assert policies
    for text in policies:
        findings = check_policy(parse_policy(text, path.name))
        assert [f for f in findings if f.level == "error"] == []


def test_the_standard_container_is_the_launchers_box() -> None:
    service = compose("compose.yaml")["services"]["zoeymcp"]
    assert service["command"][0] == "standard"
    assert service["user"] == "0:0"
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert sorted(service["cap_add"]) == ["SETGID", "SETUID"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    # Loopback only: a client token on a port without TLS is readable on the network.
    assert service["ports"] == ["127.0.0.1:8090:8090"]
    tmpfs = {entry.split(":")[0]: entry.split(":", 1)[1] for entry in service["tmpfs"]}
    for directory in env.DIRECTORIES:
        if not directory.path.startswith("/run/"):
            continue
        options = dict(option.split("=") for option in tmpfs[directory.path].split(","))
        assert (options["uid"], options["gid"], options["mode"]) == (
            str(directory.uid),
            str(directory.gid),
            f"{directory.mode:04o}",
        )
    volumes = {entry.split(":")[1] for entry in service["volumes"]}
    assert volumes == {"/state", "/state-gateway"}
    # The vault's environment holds the master key; the launcher keeps it from the gateway.
    assert "ZOEYMCP_MASTER_KEY" in service["environment"]
