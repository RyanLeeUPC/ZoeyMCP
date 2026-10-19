"""The compose files: their inline policies pass ``check``, and the standard tier's container is
the box its launcher insists on (M3 design B.2, B.3)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from zoeymcp.common.policy import check_policy, parse_policy
from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.entrypoint import env, launcher

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
COMPOSE_FILES = sorted(DEPLOY.glob("compose*.yaml"))


# An innermost ${...}: its default holds no other variable.
_VARIABLE = re.compile(r"\$\{([A-Z_]+)(?::-([^}$]*)|:\?[^}$]*)?\}")


def interpolated(text: str, environ: dict[str, str] | None = None) -> str:
    """``text`` as compose would interpolate it with ``environ`` set (nothing, by default):
    ``${NAME:-default}`` is the default, and every other unset variable is
    ``set-by-the-operator``. Nested defaults are resolved from the inside out."""
    given = environ or {}

    def value(match: re.Match[str]) -> str:
        if match.group(1) in given:
            return given[match.group(1)]
        return match.group(2) if match.group(2) is not None else "set-by-the-operator"

    while True:
        replaced = _VARIABLE.sub(value, text)
        if replaced == text:
            return text
        text = replaced


def compose(name: str, environ: dict[str, str] | None = None) -> dict[str, Any]:
    text = (DEPLOY / name).read_text(encoding="utf-8")
    document = yaml.safe_load(interpolated(text, environ))
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
        policy = parse_policy(text, path.name)
        # No portal until its listener, alias and published port come in together.
        assert policy.admin is None
        findings = check_policy(policy)
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


def test_the_hardened_gateway_has_no_egress() -> None:
    document = compose("compose.hardened.yaml")
    networks = document["networks"]
    gateway = document["services"]["gateway"]
    unprivileged(gateway)
    assert gateway["user"] == "10002:10002"
    assert gateway["command"][:3] == ["gateway", "--vault", "http://vault:8080"]
    assert sorted(gateway["networks"]) == ["agents", "internal"]
    assert all(networks[name]["internal"] is True for name in gateway["networks"])
    assert "ports" not in gateway
    assert "ZOEYMCP_MASTER_KEY" not in gateway["environment"]
    assert "ZOEYMCP_CONFIG" not in gateway["environment"]
    assert "egress" in document["services"]["vault"]["networks"]


@pytest.mark.parametrize(
    ("path", "upstream"),
    [("compose.yaml", "zoeymcp:8090"), ("compose.hardened.yaml", "gateway:8090")],
)
def test_the_lan_profile(path: str, upstream: str) -> None:
    document = compose(path)
    lan, init = document["services"]["lan"], document["services"]["lan-init"]
    assert lan["profiles"] == init["profiles"] == ["lan"]
    # Only for exec: the caddy binary has the file capability.
    unprivileged(lan, ["NET_BIND_SERVICE"])
    assert lan["image"] == init["image"]
    assert "@sha256:" in lan["image"]
    assert lan["ports"] == ["0.0.0.0:8443:8443"]
    # The one-shot chown has only CHOWN, and no network.
    assert (init["cap_drop"], init["cap_add"], init["network_mode"]) == (["ALL"], ["CHOWN"], "none")
    caddyfile = lan["environment"]["ZOEYMCP_CADDYFILE"]
    assert "https://zoeymcp.lan.example:8443 {" in caddyfile
    assert "tls internal" in caddyfile
    assert f"reverse_proxy {upstream} {{" in caddyfile
    assert "flush_interval -1" in caddyfile
    assert "admin off" in caddyfile
    # The gateway must accept the LAN name, or it answers 421.
    policy = next(
        service["environment"]["ZOEYMCP_CONFIG"]
        for service in document["services"].values()
        if "ZOEYMCP_CONFIG" in service.get("environment", {})
    )
    assert "zoeymcp.lan.example" in yaml.safe_load(policy)["gateway"]["hosts"]


def _seconds(value: str) -> float:
    match = re.fullmatch(r"([0-9]+)s", value)
    assert match is not None, value
    return float(match.group(1))


def test_the_stop_windows_let_approved_calls_finish() -> None:
    # M4 design B.6: a stop waits for an approved call already running, which goes through the
    # vault, so the gateway stops first and the windows cover the default call_timeout.
    standard = compose("compose.yaml")["services"]["zoeymcp"]
    assert _seconds(standard["stop_grace_period"]) > launcher.STOP_WAIT
    hardened = compose("compose.hardened.yaml")["services"]
    assert _seconds(hardened["gateway"]["stop_grace_period"]) >= launcher.GATEWAY_STOP_WAIT
    assert _seconds(hardened["vault"]["stop_grace_period"]) >= launcher.VAULT_STOP_WAIT
    assert hardened["gateway"]["depends_on"] == {"vault": {"condition": "service_started"}}
    assert GatewayLimits().call_timeout + 30 <= launcher.GATEWAY_STOP_WAIT


def test_a_derived_gateway_image_runs_beside_the_official_vault() -> None:
    """M4 design I.3: the gateway's image can differ; unset, both run ZOEYMCP_IMAGE."""
    services = compose("compose.hardened.yaml")["services"]
    assert services["gateway"]["image"] == services["vault"]["image"] == "zoeymcp:local"
    official = {"ZOEYMCP_IMAGE": "zoeymcp@sha256:" + "1" * 64}
    services = compose("compose.hardened.yaml", official)["services"]
    assert services["gateway"]["image"] == services["vault"]["image"] == official["ZOEYMCP_IMAGE"]
    derived = {**official, "ZOEYMCP_GATEWAY_IMAGE": "zoeymcp-derived@sha256:" + "2" * 64}
    services = compose("compose.hardened.yaml", derived)["services"]
    assert services["vault"]["image"] == official["ZOEYMCP_IMAGE"]
    assert services["gateway"]["image"] == derived["ZOEYMCP_GATEWAY_IMAGE"]


def test_interpolation_resolves_nested_defaults() -> None:
    assert interpolated("${A:-${B:-x}}") == "x"
    assert interpolated("${A:-${B:-x}}", {"B": "b"}) == "b"
    assert interpolated("${A:-${B:-x}}", {"A": "a"}) == "a"
    assert interpolated("${A:?say so}") == "set-by-the-operator"
