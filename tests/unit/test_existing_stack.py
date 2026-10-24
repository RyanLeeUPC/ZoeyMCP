"""``examples/existing-stack/``: the declared shape of the existing-stack recipe (M7 design J6,
L, P.2 step 3b). Its inline policy passes ``check``; the vault has no network that Compose
would create with a route out; the gateway and the agents reach ZoeyMCP by aliases only it uses;
only the portal relay publishes, on the host's loopback, from a network of its own; the relay
holds no secret, keeps no access or error log and changes no header; and the committed Squid
snippet is what the emitter prints for the policy.

An external network's real setting is outside the file, so these tests can only refuse a
network the file *declares* non-internal; the README's ``docker inspect`` probe checks the
running containers, and the image smoke's contract 54 runs it.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any

import pytest
import yaml

from zoeymcp.cli import onboard as onboard_cli
from zoeymcp.cli.main import EXIT_OK, main
from zoeymcp.common.policy import check_policy
from zoeymcp.portal import listen

from .test_deploy import compose as deploy_compose
from .test_deploy import inline_policy, interpolated, published, unprivileged

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "existing-stack"


def compose(environ: dict[str, str] | None = None) -> dict[str, Any]:
    text = (EXAMPLE / "compose.yaml").read_text(encoding="utf-8")
    document = yaml.safe_load(interpolated(text, environ))
    assert isinstance(document, dict)
    return document


def members(document: dict[str, Any], network: str) -> set[str]:
    """The services that join ``network``."""
    return {
        name
        for name, service in document["services"].items()
        if network in service.get("networks", [])
    }


def test_the_inline_policy_passes_check_and_names_the_stacks_proxy() -> None:
    policy = inline_policy(compose(), "compose.yaml")
    assert [f for f in check_policy(policy) if f.level == "error"] == []
    assert policy.egress_proxy == "http://stack-proxy:3128"
    assert policy.egress_proxy_acls == {"vault": "stack_vault_net"}


def test_every_vault_network_is_internal_or_external() -> None:
    document = compose()
    networks, vault = document["networks"], document["services"]["vault"]
    assert sorted(vault["networks"]) == ["internal", "portal", "stack-proxy"]
    for name in vault["networks"]:
        declared = networks[name]
        assert declared.get("internal") is True or declared.get("external") is True, name
    # The stack's proxy network is the stack's own: Compose creates nothing for it.
    assert networks["stack-proxy"]["external"] is True
    assert "ports" not in vault
    # Hardened as in compose.hardened.yaml: the one container holding the master key.
    unprivileged(vault)
    assert vault["user"] == "10001:10001"
    assert "/run/zoeymcp:size=1m,mode=0700,uid=10001,gid=10001" in vault["tmpfs"]


def test_the_gateways_declared_networks_include_none_declared_non_internal() -> None:
    document = compose()
    networks, gateway = document["networks"], document["services"]["gateway"]
    unprivileged(gateway)
    assert gateway["user"] == "10002:10002"
    assert gateway["command"][:3] == ["gateway", "--vault", "http://zoeymcp-vault:8080"]
    assert sorted(gateway["networks"]) == ["internal", "stack-agents"]
    for name in gateway["networks"]:
        assert networks[name].get("internal") is True or networks[name].get("external") is True
    assert networks["stack-agents"]["external"] is True
    assert "ports" not in gateway
    assert "ZOEYMCP_MASTER_KEY" not in gateway["environment"]
    assert "ZOEYMCP_CONFIG" not in gateway["environment"]


def aliases(service: dict[str, Any]) -> dict[str, list[str]]:
    """Each of ``service``'s networks with its aliases there."""
    return {
        name: (settings or {}).get("aliases", []) for name, settings in service["networks"].items()
    }


def test_zoeymcp_is_reached_by_aliases_only_it_uses() -> None:
    # A bare service name is resolved on the stack's networks too, where the stack's own `vault`
    # or `gateway` could answer and be sent the gateway key or a client token.
    document = compose()
    services = document["services"]
    assert aliases(services["vault"])["internal"] == ["zoeymcp-vault"]
    assert aliases(services["gateway"]) == {"stack-agents": ["zoeymcp-gateway"], "internal": []}
    assert services["gateway"]["command"][2] == "http://zoeymcp-vault:8080"
    policy = inline_policy(document, "compose.yaml")
    assert policy.gateway is not None
    assert policy.gateway.hosts == ["zoeymcp-gateway"]
    readme = (EXAMPLE / "README.md").read_text(encoding="utf-8")
    assert "`http://zoeymcp-gateway:8090/s/<server>/mcp`" in readme
    for text in (readme, (EXAMPLE / "compose.yaml").read_text(encoding="utf-8")):
        assert "http://gateway:8090" not in text
        assert "http://vault:8080" not in text


def test_the_stacks_networks_take_their_names_from_the_environment() -> None:
    networks = compose()["networks"]
    assert (networks["stack-agents"]["name"], networks["stack-proxy"]["name"]) == (
        "stack-agents",
        "stack-proxy",
    )
    environ = {"ZOEYMCP_STACK_AGENTS": "agents-net", "ZOEYMCP_STACK_PROXY": "proxy-net"}
    networks = compose(environ)["networks"]
    assert (networks["stack-agents"]["name"], networks["stack-proxy"]["name"]) == (
        "agents-net",
        "proxy-net",
    )


@pytest.mark.parametrize("admin_port", [None, "9000"])
def test_only_the_relay_publishes_and_on_the_hosts_loopback(admin_port: str | None) -> None:
    environ = {} if admin_port is None else {"ZOEYMCP_ADMIN_PORT": admin_port}
    document = compose(environ)
    host_port = int(admin_port or 8081)
    ports = {
        name: [published(entry) for entry in service["ports"]]
        for name, service in document["services"].items()
        if "ports" in service
    }
    assert ports == {"portal-relay": [("127.0.0.1", host_port, 8081)]}
    # The relay passes Host on, so the vault sees the browser's address, port included.
    policy = inline_policy(document, "compose.yaml")
    assert policy.admin is not None
    assert policy.admin.origins == [f"http://localhost:{host_port}"]


def test_the_portal_network_holds_the_vault_and_the_relay_alone() -> None:
    document = compose()
    networks, services = document["networks"], document["services"]
    assert networks["portal"] == {"internal": True}
    assert members(document, "portal") == {"vault", "portal-relay"}
    # Docker publishes only through a non-internal network: portal-pub is one, with the relay
    # alone on it, and the only non-internal network the file creates.
    assert members(document, "portal-pub") == {"portal-relay"}
    assert sorted(services["portal-relay"]["networks"]) == ["portal", "portal-pub"]
    created = {name for name, network in networks.items() if not network.get("external")}
    assert [n for n in sorted(created) if networks[n].get("internal") is not True] == ["portal-pub"]
    # The portal listens on the vault's portal address alone: a name, not a wildcard.
    policy = inline_policy(document, "compose.yaml")
    assert policy.admin is not None
    host, port = listen.split(policy.admin.listen)
    assert listen.literal(host) is None
    assert (host, port) == ("vault-portal", 8081)
    assert aliases(services["vault"]) == {
        "internal": ["zoeymcp-vault"],
        "stack-proxy": [],
        "portal": ["vault-portal"],
    }
    for name, service in services.items():
        if name != "vault" and isinstance(service.get("networks"), dict):
            for settings in service["networks"].values():
                assert "vault-portal" not in (settings or {}).get("aliases", [])
    assert all("network_mode" not in service for service in services.values())


def test_the_relays_capability_and_tmpfs_mounts() -> None:
    relay = compose()["services"]["portal-relay"]
    # Only for exec: the caddy binary carries the file capability cap_net_bind_service.
    unprivileged(relay, ["NET_BIND_SERVICE"])
    assert relay["user"] == "10007:10007"
    tmpfs = {entry.split(":")[0]: entry.split(":", 1)[1] for entry in relay["tmpfs"]}
    assert sorted(tmpfs) == ["/config", "/data"]
    for options in tmpfs.values():
        settings = dict(option.split("=") for option in options.split(",") if "=" in option)
        assert (settings["uid"], settings["gid"], settings["mode"]) == ("10007", "10007", "0700")
    assert "volumes" not in relay
    assert relay["depends_on"] == {"vault": {"condition": "service_started"}}


def test_the_relay_holds_no_secret_keeps_no_log_and_changes_no_header() -> None:
    relay = compose()["services"]["portal-relay"]
    # Its environment is the Caddyfile alone: no key, no token, no policy.
    assert list(relay["environment"]) == ["ZOEYMCP_CADDYFILE"]
    caddyfile = relay["environment"]["ZOEYMCP_CADDYFILE"]
    assert "--config /config/Caddyfile" in relay["command"][0]
    # Caddy writes an access log only for a log directive, and rewrites a request header only
    # for header_up or a header directive: none is there, so Host, Origin and Sec-Fetch-* pass.
    # Its error log and the proxy handler's log record a 5xx's URI and headers (the callback's
    # query, X-ZoeyMCP-Session): the global log options exclude both.
    lines = [line.strip() for line in caddyfile.splitlines() if line.strip()]
    assert lines == [
        "{",
        "admin off",
        "auto_https off",
        "log default {",
        "exclude http.log.error http.handlers.reverse_proxy",
        "}",
        "}",
        ":8081 {",
        "reverse_proxy vault-portal:8081",
        "}",
    ]


def test_the_relays_caddy_image_is_the_hardened_files() -> None:
    relay = compose()["services"]["portal-relay"]
    hardened = deploy_compose("compose.hardened.yaml")
    assert "@sha256:" in relay["image"]
    assert relay["image"] == hardened["x-caddy"] == hardened["services"]["lan"]["image"]


def test_the_committed_squid_file_is_the_emitters_output(tmp_path: Path) -> None:
    document = compose()
    policy = document["services"]["vault"]["environment"]["ZOEYMCP_CONFIG"]
    snippet = EXAMPLE / "zoeymcp-squid.conf"
    out, err = io.StringIO(), io.StringIO()
    argv = ["check", "--config", "-", "--emit-egress-allowlist", "--allowlist-format", "squid"]
    code = main([*argv, "--check", str(snippet)], stdin=io.StringIO(policy), out=out, err=err)
    assert code == EXIT_OK, out.getvalue()
    assert out.getvalue() == f"{snippet}: matches the policy's egress allowlist\n"
    # Line endings aside, as --check compares: the file is committed with LF.
    assert b"\r" not in snippet.read_bytes()
    # The control: a destination the policy doesn't name makes --check fail.
    stale = tmp_path / "stale.conf"
    stale.write_bytes(snippet.read_bytes().replace(b"mcp.notes.example", b"mcp.other.example"))
    code = main([*argv, "--check", str(stale)], stdin=io.StringIO(policy), out=io.StringIO())
    assert code != EXIT_OK


def test_the_readme_probes_both_containers_networks() -> None:
    readme = (EXAMPLE / "README.md").read_text(encoding="utf-8")
    assert "must be `internal: true`" in readme
    assert "for service in vault gateway; do" in readme
    assert "docker network inspect -f '{{.Internal}}'" in readme


def test_the_printed_commands_name_this_file() -> None:
    """M7 design M.7 (OPS-17): the commands ``login --mcp`` prints start with this file's own
    compose command unless .env sets another, and name its services."""
    services = compose()["services"]
    vault, gateway = services["vault"]["environment"], services["gateway"]["environment"]
    assert vault[onboard_cli.COMPOSE_CMD_ENV] == (
        "docker compose -f examples/existing-stack/compose.yaml"
    )
    assert vault[onboard_cli.EXEC_SERVICE_ENV] == "vault"
    assert "ZOEYMCP_REVIEW_SERVICE" not in vault  # no printed command used it (D-201)
    assert gateway[onboard_cli.EXEC_SERVICE_ENV] == "gateway"
    given = compose({onboard_cli.COMPOSE_CMD_ENV: "docker compose -f stack.yaml"})
    assert given["services"]["vault"]["environment"][onboard_cli.COMPOSE_CMD_ENV] == (
        "docker compose -f stack.yaml"
    )
