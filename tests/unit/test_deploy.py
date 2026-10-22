"""The compose files: their inline policies pass ``check``, the standard tier's container is the
box its launcher insists on (M3 design B.2, B.3), and the portal is published on the host's
loopback only, on the hardened vault's ``egress`` network alone (M5 design B.1, B.2)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from zoeymcp.cli import onboard as onboard_cli
from zoeymcp.common.policy import check_policy, parse_policy
from zoeymcp.common.policy.schema import GatewayLimits, Policy
from zoeymcp.entrypoint import env, launcher
from zoeymcp.portal import listen

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


def inline_policy(document: dict[str, Any], name: str) -> Policy:
    """The one inline policy in a compose ``document``."""
    policies = [
        service["environment"]["ZOEYMCP_CONFIG"]
        for service in document["services"].values()
        if "ZOEYMCP_CONFIG" in service.get("environment", {})
    ]
    assert len(policies) == 1
    return parse_policy(policies[0], name)


def published(entry: str) -> tuple[str, int, int]:
    """A ``ports`` entry, ``ip:host_port:container_port``, as its three parts."""
    ip, host_port, container_port = entry.rsplit(":", 2)
    return ip, int(host_port), int(container_port)


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
    # Loopback only: a client token on a port without TLS is readable on the network, and the
    # portal is for a browser on the host (or at the end of a tunnel to it).
    assert service["ports"] == ["127.0.0.1:8090:8090", "127.0.0.1:8081:8081"]
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


PORTAL_SERVICES = [("compose.yaml", "zoeymcp"), ("compose.hardened.yaml", "vault")]


@pytest.mark.parametrize(("path", "name"), PORTAL_SERVICES)
@pytest.mark.parametrize("admin_port", [None, "9000"])
def test_the_portal_is_published_on_the_hosts_loopback_only(
    path: str, name: str, admin_port: str | None
) -> None:
    environ = {} if admin_port is None else {"ZOEYMCP_ADMIN_PORT": admin_port}
    document = compose(path, environ)
    policy = inline_policy(document, path)
    assert policy.admin is not None
    port = listen.split(policy.admin.listen)[1]
    host_port = int(admin_port or port)
    # The browser's origin carries the port the host publishes, not the container's.
    assert policy.admin.origins == [f"http://localhost:{host_port}"]
    portal = [
        published(entry)
        for service in document["services"].values()
        for entry in service.get("ports", [])
        if published(entry)[2] == port
    ]
    assert portal == [("127.0.0.1", host_port, port)]
    assert f"127.0.0.1:{host_port}:{port}" in document["services"][name]["ports"]
    # Every port of the container holding the vault is on the host's loopback.
    assert all(published(entry)[0] == "127.0.0.1" for entry in document["services"][name]["ports"])


def test_the_standard_portal_listens_on_every_address_in_its_container() -> None:
    policy = inline_policy(compose("compose.yaml"), "compose.yaml")
    assert policy.admin is not None
    # A container's loopback can't be published, so the listener takes every address there.
    assert policy.admin.listen == "0.0.0.0:8081"


def test_the_hardened_portal_listens_on_egress_alone() -> None:
    document = compose("compose.hardened.yaml")
    networks, services = document["networks"], document["services"]
    policy = inline_policy(document, "compose.hardened.yaml")
    assert policy.admin is not None
    host, port = listen.split(policy.admin.listen)
    # A name, resolved at start to exactly one address, never a literal or a wildcard.
    assert listen.literal(host) is None
    assert (host, port) == ("vault-portal", 8081)
    vault = services["vault"]["networks"]
    assert isinstance(vault, dict)
    aliases = {network: (vault[network] or {}).get("aliases", []) for network in vault}
    assert aliases == {"internal": [], "direct": [], "egress": ["vault-portal"]}
    # Docker publishes a port only through a non-internal network: egress must be the vault's
    # only one, so the published port lands on the address the portal listens on.
    assert [n for n in vault if networks[n].get("internal") is not True] == ["egress"]
    # Whatever joins egress reaches the portal: it holds the vault alone (an egress proxy gets
    # a network of its own).
    joined = {name for name, service in services.items() if "egress" in service.get("networks", [])}
    assert joined == {"vault"}
    # Nor does anything share a network namespace with the vault.
    assert all(service.get("network_mode", "none") == "none" for service in services.values())
    # No other service answers to the alias.
    for name, service in services.items():
        if name != "vault" and isinstance(service.get("networks"), dict):
            for settings in service["networks"].values():
                assert "vault-portal" not in (settings or {}).get("aliases", [])


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


@pytest.mark.parametrize(
    ("name", "command", "services"),
    [
        (
            "compose.hardened.yaml",
            "docker compose -f deploy/compose.hardened.yaml",
            {"vault": ("vault", "gateway"), "gateway": ("gateway", None)},
        ),
        (
            "compose.yaml",
            "docker compose -f deploy/compose.yaml",
            {"zoeymcp": ("zoeymcp", "zoeymcp")},
        ),
    ],
)
def test_the_printed_commands_name_the_tier_and_its_services(
    name: str, command: str, services: dict[str, tuple[str, str | None]]
) -> None:
    """M7 design M.7 (OPS-17): ``login --mcp`` prints its commands after ZOEYMCP_COMPOSE_CMD,
    this file's own command unless .env sets another, and the services each service names."""
    found = compose(name)["services"]
    for service, (own, review) in services.items():
        environment = found[service]["environment"]
        assert environment[onboard_cli.EXEC_SERVICE_ENV] == own
        assert environment.get(onboard_cli.REVIEW_SERVICE_ENV) == review
        has_command = onboard_cli.COMPOSE_CMD_ENV in environment
        assert has_command == (review is not None)
        if has_command:
            assert environment[onboard_cli.COMPOSE_CMD_ENV] == command
    given = compose(name, {onboard_cli.COMPOSE_CMD_ENV: "docker compose -f a.yaml -p mine"})
    commands = [
        service["environment"][onboard_cli.COMPOSE_CMD_ENV]
        for service in given["services"].values()
        if onboard_cli.COMPOSE_CMD_ENV in service.get("environment", {})
    ]
    assert commands == ["docker compose -f a.yaml -p mine"]
    # The CLI's own default is the hardened file's, as M.7 says.
    if name == "compose.hardened.yaml":
        assert command == onboard_cli.DEFAULT_COMPOSE_CMD
