"""The compose files: their inline policies pass ``check``, are managed and say what the seed
reads (M6 design Q2 (a), step 23), the standard tier's container is the
box its launcher insists on (M3 design B.2, B.3), the portal is published on the host's
loopback only, on the hardened vault's ``egress`` network alone (M5 design B.1, B.2), the
egress role is a profile of the hardened tier alone, on networks of its own (M7 design I.5, L),
and the bridge example's overrides add a confined bridge to the hardened tier and an unconfined
one to the standard tier's box, leaving the rest as it was (M7 design C.9, C.10, L)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

from zoeymcp.bridge import listen as bridge_listen
from zoeymcp.cli import main as cli_main
from zoeymcp.cli import onboard as onboard_cli
from zoeymcp.common import egresslist
from zoeymcp.common.policy import check as policy_check
from zoeymcp.common.policy import check_policy, fields, parse_policy
from zoeymcp.common.policy.schema import GatewayLimits, Policy
from zoeymcp.egress import allowlist as egress_allowlist
from zoeymcp.egress import listen as egress_listen
from zoeymcp.egress.main import Options as EgressOptions
from zoeymcp.egress.main import StartupError as EgressStartupError
from zoeymcp.egress.main import build as build_egress
from zoeymcp.entrypoint import env, launcher
from zoeymcp.portal import listen

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy"
COMPOSE_FILES = sorted(DEPLOY.glob("compose*.yaml"))
EGRESS_UID = 10006


# An innermost ${...}: its default holds no other variable.
_VARIABLE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-([^}$]*)|:\?[^}$]*)?\}")


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


# --- the shipped default: managed (M6 design Q2 (a), step 23; OPS-3, J14, J15, Q36) ------------

SEED_COMMENT = (
    "It seeds revision 1 of the managed policy on a fresh volume and is ignored afterwards"
)
# What a managed compose file's comments no longer say (OPS-3).
STALE_COMMENTS = (
    "commit the pins",
    "review notes --add",
    "recreate the container for this inline one",
    "Leave this block out for no portal",
    "The commands `zoeymcp login --mcp` prints start with this compose command",
)


def comments(text: str) -> str:
    """Every comment of a YAML file, the inline policy's included, as one line of words, so a
    comment wrapped over several lines reads as one."""
    found = [line.split("#", 1)[1] for line in text.splitlines() if line.lstrip().startswith("#")]
    return " ".join(" ".join(found).split())


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda path: path.name)
def test_the_shipped_policies_are_managed(path: Path) -> None:
    """Q2 (a): both compose files say ``mode: managed``, so the inline policy seeds revision 1
    and is ignored afterwards; ``check`` says so in exactly one warning, row 7's."""
    policy = inline_policy(compose(path.name), path.name)
    assert policy.mode == "managed"
    findings = check_policy(policy)
    assert [(f.level, f.path) for f in findings] == [("warning", "mode")]
    assert findings[0].message.startswith(
        "the vault seeds its first revision from this document and ignores it afterwards"
    )


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda path: path.name)
def test_the_comments_say_what_the_seed_reads(path: Path) -> None:
    """OPS-3, J14, Q36: the comments say the inline policy seeds revision 1 and is ignored
    afterwards, what to set before the first ``up -d``, that the admin port's origin is read only
    at the seed, and that a later change is a host import; none says to commit a fragment or to
    recreate for an edit, that the managed policy may go without its portal, or that the compose
    command is only for what ``login --mcp`` prints."""
    said = comments((DEPLOY / path.name).read_text(encoding="utf-8"))
    assert SEED_COMMENT in said
    assert "so set agent1's token_sha256, the server's URL" in said
    assert "here before the first `up -d`" in said
    assert "change the policy in the portal, or export, edit and `zoeymcp policy import` it" in said
    assert "ZOEYMCP_ADMIN_PORT is read only at the seed" in said
    assert "a port change after it is a host import first (docs/operations.md §30)" in said
    assert "replace it before the first `up -d`, since no portal change sets a token" in said
    for stale in STALE_COMMENTS:
        assert stale not in said


def test_the_hardened_rotation_is_a_host_import() -> None:
    """J15, E-8: the generation the compose file interpolates is read only at the seed, so the
    rotation comment says to raise it with an import (an edited export, or ``--from-env`` when the
    compose policy is the one kept), not with the variable and a recreate alone, and the field's
    own comment says the same."""
    said = comments((DEPLOY / "compose.hardened.yaml").read_text(encoding="utf-8"))
    assert (
        "ZOEYMCP_GATEWAY_KEY_GENERATION is read only at the seed, so raising it and recreating "
        "the vault changes no generation. Raise gateway_key_generation with a host import"
    ) in said
    assert "raise ZOEYMCP_GATEWAY_KEY_GENERATION and recreate the vault" not in said
    assert (
        "if this file is the policy you keep, raise the variable, recreate the vault, and run "
        "`zoeymcp policy import --from-env` in it, whose plan shows the rotation"
    ) in said
    vault = compose("compose.hardened.yaml")["services"]["vault"]
    assert (
        "# Read only at the seed: a rotation later is a host import (docs/operations.md §14).\n"
        "gateway_key_generation: 1\n"
    ) in vault["environment"]["ZOEYMCP_CONFIG"]


def launchers_box(service: dict[str, Any]) -> None:
    """The standard container as its launcher insists on it (M3 design B.2, B.3)."""
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


def test_the_standard_container_is_the_launchers_box() -> None:
    launchers_box(compose("compose.yaml")["services"]["zoeymcp"])


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
    # egress-ctl since M7 (design L): the egress role fetches its lists from the vault there.
    assert aliases == {"internal": [], "direct": [], "egress": ["vault-portal"], "egress-ctl": []}
    assert networks["egress-ctl"]["internal"] is True
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
    # The standard tier's bridges get their 10 s after the vault's 75 s, still inside compose's
    # 420 s (M7 design C.10, CR-B5).
    assert launcher.BRIDGE_STOP_WAIT == 10
    assert launcher.STOP_WAIT == 330 + 75 + 10 < _seconds(standard["stop_grace_period"]) == 420
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
            {"vault": ("vault", True), "gateway": ("gateway", False)},
        ),
        (
            "compose.yaml",
            "docker compose -f deploy/compose.yaml",
            {"zoeymcp": ("zoeymcp", True)},
        ),
    ],
)
def test_the_printed_commands_name_the_tier_and_its_services(
    name: str, command: str, services: dict[str, tuple[str, bool]]
) -> None:
    """M7 design M.7 (OPS-17): ``login --mcp`` prints its commands after ZOEYMCP_COMPOSE_CMD,
    this file's own command unless .env sets another, and the service it runs in. No service
    sets ZOEYMCP_REVIEW_SERVICE, which no printed command used (D-201)."""
    found = compose(name)["services"]
    for service, (own, prints) in services.items():
        environment = found[service]["environment"]
        assert environment[onboard_cli.EXEC_SERVICE_ENV] == own
        assert "ZOEYMCP_REVIEW_SERVICE" not in environment
        has_command = onboard_cli.COMPOSE_CMD_ENV in environment
        assert has_command == prints
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


# --- the egress role (M7 design I.5, L) ---------------------------------------------------------

# A policy line the hardened file and the SMTP profiles leave commented, for the egress role.
_ROLE_LINE = re.compile(r"^ *# (egress_proxy(?:_kind)?: \S+)$", re.MULTILINE)


def _on(services: dict[str, Any], network: str) -> set[str]:
    """The services on ``network``."""
    return {name for name, service in services.items() if network in service.get("networks", [])}


def test_the_egress_role_is_a_profile_on_networks_of_its_own() -> None:
    document = compose("compose.hardened.yaml")
    networks, services = document["networks"], document["services"]
    role = services["egress-proxy"]
    assert role["profiles"] == ["egress-proxy"]
    # It listens on 3128, so it needs no NET_BIND_SERVICE: no capability at all.
    unprivileged(role)
    assert role["user"] == f"{EGRESS_UID}:{EGRESS_UID}"
    # The official image, as the vault's: never a derived gateway image.
    assert role["image"] == services["vault"]["image"]
    assert role["command"] == [
        "egress", "--vault", "http://vault:8080", "--listen", "vault=egress-vault:3128",
    ]  # fmt: skip
    assert "ports" not in role
    # The vault's side, internal, and its own way out; never egress, which reaches the portal.
    assert role["networks"] == {"egress-ctl": {"aliases": ["egress-vault"]}, "egress-out": {}}
    assert networks["egress-ctl"] == {"internal": True}
    assert networks["egress-out"].get("internal") is not True
    assert _on(services, "egress-ctl") == {"vault", "egress-proxy"}
    assert _on(services, "egress-out") == {"egress-proxy"}
    assert _on(services, "egress") == {"vault"}
    # Its one listener is the alias egress-ctl gives it, and nothing else answers to that name.
    [spec] = egress_listen.parse_all(role["command"][4:])
    assert (spec.source, spec.host, spec.port) == ("vault", "egress-vault", 3128)
    for name, service in services.items():
        if name != "egress-proxy" and isinstance(service.get("networks"), dict):
            for settings in service["networks"].values():
                assert "egress-vault" not in (settings or {}).get("aliases", [])
    # --vault is the vault's own listener, reached on egress-ctl.
    vault = services["vault"]
    assert vault["command"] == ["vault", "--listen", "0.0.0.0:8080"]
    assert role["command"][2] == f"http://vault:{listen.split(vault['command'][2])[1]}"
    # Its environment holds its key and nothing else: no master key, gateway key or policy.
    assert list(role["environment"]) == [egress_allowlist.KEY_ENV]
    assert _seconds(role["stop_grace_period"]) == 15
    # With the profile off, nothing waits on it.
    for service in services.values():
        assert "egress-proxy" not in service.get("depends_on", {})


def test_the_egress_roles_uid_is_the_images_egress_user() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert f" && groupadd --gid {EGRESS_UID} egress \\\n" in dockerfile
    assert (
        f" && useradd --uid {EGRESS_UID} --gid {EGRESS_UID} --no-create-home "
        "--home-dir /nonexistent --shell /usr/sbin/nologin egress \\\n"
    ) in dockerfile
    # One uid per container, root aside (lan-init's one-shot chown).
    services = compose("compose.hardened.yaml")["services"].values()
    users = [s["user"] for s in services if not s["user"].startswith("0:")]
    assert len(set(users)) == len(users)


def test_the_egress_key_is_needed_only_when_the_role_runs() -> None:
    """M7 design I.5 (GR-8): ``:-`` rather than ``:?``, so ``docker compose config`` passes with
    the key unset and the profile off; with the profile on and no key, the role refuses to start
    and names ``zoeymcp egress-key``."""
    text = (DEPLOY / "compose.hardened.yaml").read_text(encoding="utf-8")
    assert "ZOEYMCP_EGRESS_KEY: ${ZOEYMCP_EGRESS_KEY:-}\n" in text
    assert "${ZOEYMCP_EGRESS_KEY:?" not in text
    role = compose("compose.hardened.yaml")["services"]["egress-proxy"]
    # Compose interpolates after parsing, so the role gets an empty string where this text-level
    # interpolation leaves YAML's null.
    environ = {name: value or "" for name, value in role["environment"].items()}
    assert environ == {egress_allowlist.KEY_ENV: ""}
    options = EgressOptions(vault=role["command"][2], listens=(role["command"][4],))
    with pytest.raises(EgressStartupError, match="zoeymcp egress-key"):
        build_egress(options, environ)
    given = {egress_allowlist.KEY_ENV: "zeg1-" + "k" * 43}
    role = compose("compose.hardened.yaml", given)["services"]["egress-proxy"]
    assert role["environment"] == given


def test_the_standard_tier_has_no_egress_role() -> None:
    """X21: confinement is hardened-only. Nothing in the standard tier could make a program use
    the role."""
    services = compose("compose.yaml")["services"]
    assert "egress-proxy" not in services
    assert all(service.get("command", [""])[0] != "egress" for service in services.values())
    assert "ZOEYMCP_EGRESS_KEY" not in (DEPLOY / "compose.yaml").read_text(encoding="utf-8")


def test_the_vaults_policy_names_the_role_commented() -> None:
    """The hardened file's inline policy and the SMTP profiles carry the same two commented
    lines; uncommented, they name the role's vault listener as the role, and pass ``check``."""
    document = compose("compose.hardened.yaml")
    text = document["services"]["vault"]["environment"]["ZOEYMCP_CONFIG"]
    lines = _ROLE_LINE.findall(text)
    assert lines == ["egress_proxy: http://egress-vault:3128", "egress_proxy_kind: role"]
    for profile in ("smtp-implicit-tls.yaml", "smtp-starttls.yaml"):
        assert (
            _ROLE_LINE.findall((ROOT / "profiles" / profile).read_text(encoding="utf-8")) == lines
        )
    policy = parse_policy(_ROLE_LINE.sub(r"\1", text), "compose.hardened.yaml")
    assert (policy.egress_proxy, policy.egress_proxy_kind) == ("http://egress-vault:3128", "role")
    assert [f for f in check_policy(policy) if f.level == "error"] == []
    # The address is the role's vault listener, as its --listen names it.
    [spec] = egress_listen.parse_all(document["services"]["egress-proxy"]["command"][4:])
    assert policy.egress_proxy == f"http://{spec.host}:{spec.port}"
    # As shipped the lines stay comments: no proxy, so nothing needs the profile.
    shipped = inline_policy(document, "compose.hardened.yaml")
    assert (shipped.egress_proxy, shipped.egress_proxy_kind) == (None, "own")


# --- the bridge's compose overrides (M7 design C.7, C.9, C.10, L) -------------------------------

BRIDGE_EXAMPLE = ROOT / "examples" / "bridge"
BRIDGE_PROFILE = ROOT / "profiles" / "stdio-bridge.yaml"
BRIDGE_UID = 10005
# Where a hardened bridge must never be: every network the base file has.
NOT_A_BRIDGES = {"internal", "agents", "direct", "egress", "egress-ctl", "egress-out", "lan"}
_UV_STAGE = re.compile(r"^FROM (ghcr\.io/astral-sh/uv:\S+) AS uv$", re.MULTILINE)
_BRIDGE_LISTEN_VARIABLE = re.compile(r"ZOEYMCP_BRIDGE_\w*_LISTEN")


def override(name: str, environ: dict[str, str] | None = None) -> dict[str, Any]:
    text = (BRIDGE_EXAMPLE / name).read_text(encoding="utf-8")
    document = yaml.safe_load(interpolated(text, environ))
    assert isinstance(document, dict)
    return document


def _mapping(value: Any) -> dict[str, Any]:
    """A compose mapping that may be written as a list of names (``networks: [a, b]``)."""
    if value is None:
        return {}
    if isinstance(value, list):
        return dict.fromkeys(value)
    assert isinstance(value, dict)
    return value


def _merged_service(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """One service of ``extra`` merged onto ``base`` as compose merges an override file, for the
    keys the bridge's overrides use: a mapping (``environment``, ``networks``, ``depends_on``)
    merged by key, ``tmpfs`` concatenated, anything else (``command`` included) replaced."""
    found = dict(base)
    for key, value in extra.items():
        if key in ("environment", "networks", "depends_on"):
            found[key] = {**_mapping(base.get(key)), **_mapping(value)}
        elif key == "tmpfs":
            found[key] = [*base.get(key, []), *[v for v in value if v not in base.get(key, [])]]
        else:
            found[key] = value
    return found


def merged(
    base_name: str, override_name: str, environ: dict[str, str] | None = None
) -> dict[str, Any]:
    """``deploy/<base_name>`` with ``examples/bridge/<override_name>`` merged onto it."""
    base, extra = compose(base_name, environ), override(override_name, environ)
    services = dict(base["services"])
    for name, service in extra["services"].items():
        services[name] = _merged_service(services[name], service) if name in services else service
    networks = {**base.get("networks", {}), **extra.get("networks", {})}
    return {**base, "networks": networks, "services": services}


def _listens(command: list[str]) -> list[str]:
    """The egress role's ``--listen`` values, in order."""
    return [word for i, word in enumerate(command) if i and command[i - 1] == "--listen"]


def _bridge_args(command: list[str]) -> Any:
    """A ``zoeymcp bridge`` command line, as the bridge's own parser reads it."""
    args = cli_main._build_parser().parse_args(command)
    assert args.command == "bridge"
    return args


def with_bridge(policy_text: str, *, upstream: str | None = None) -> Policy:
    """The inline policy with the shipped S11 profile's credential, route and server added; with
    ``upstream``, the route's upstream swapped as the profile's comment says for a standard-tier
    bridge (no ``allow_insecure_upstream``, no ``program``)."""
    document = yaml.safe_load(policy_text)
    fragment = yaml.safe_load(BRIDGE_PROFILE.read_text(encoding="utf-8"))
    [route] = fragment["routes"]
    if upstream is not None:
        route["upstream"] = upstream
        del route["allow_insecure_upstream"], route["program"]
    document.setdefault("credentials", {}).update(fragment["credentials"])
    document.setdefault("routes", []).append(route)
    document["gateway"]["servers"].update(fragment["gateway"]["servers"])
    return Policy.model_validate(document)


def _errors(policy: Policy) -> list[str]:
    return [f"{f.path}: {f.message}" for f in check_policy(policy) if f.level == "error"]


def test_the_hardened_bridge_is_a_container_on_networks_of_its_own() -> None:
    """C.9, L (CR-B3, CR-4): each bridge service the override adds is unprivileged, has an init,
    and sits on internal networks of its own only, its alias on its vault network alone."""
    base = compose("compose.hardened.yaml")
    document = merged("compose.hardened.yaml", "compose.bridge.yaml")
    networks, services = document["networks"], document["services"]
    added = sorted(set(services) - set(base["services"]))
    assert added == ["bridge-fetch"]
    bridge = services["bridge-fetch"]
    unprivileged(bridge)
    assert bridge["user"] == f"{BRIDGE_UID}:{BRIDGE_UID}"
    # PID 1 reaps the program's orphans (contract 48's other half runs in the image smoke).
    assert bridge["init"] is True
    assert bridge["restart"] == "unless-stopped"
    assert bridge["image"] == "zoeymcp-bridge-fetch:local"
    image = {"ZOEYMCP_BRIDGE_IMAGE": "zoeymcp-bridge-fetch@sha256:" + "3" * 64}
    pinned = merged("compose.hardened.yaml", "compose.bridge.yaml", image)["services"]
    assert pinned["bridge-fetch"]["image"] == image["ZOEYMCP_BRIDGE_IMAGE"]
    assert bridge["tmpfs"] == ["/tmp:size=64m,mode=1777"]  # noqa: S108 - the container's own tmpfs
    assert bridge["healthcheck"]["test"] == ["CMD", "zoeymcp", "bridge", "--ready-check"]
    assert "ports" not in bridge
    # Its environment holds its token's hash and nothing else; `:-`, so compose config passes
    # before the vault has made the token.
    assert list(bridge["environment"]) == [env.BRIDGE_TOKEN]
    text = (BRIDGE_EXAMPLE / "compose.bridge.yaml").read_text(encoding="utf-8")
    assert "ZOEYMCP_BRIDGE_TOKEN_SHA256: ${ZOEYMCP_BRIDGE_FETCH_TOKEN_SHA256:-}\n" in text
    # Internal networks of its own, never one the base file has.
    assert sorted(bridge["networks"]) == ["bridge-fetch", "egress-fetch"]
    assert all(networks[name] == {"internal": True} for name in bridge["networks"])
    assert not set(bridge["networks"]) & NOT_A_BRIDGES
    assert _on(services, "bridge-fetch") == {"vault", "bridge-fetch"}
    assert _on(services, "egress-fetch") == {"bridge-fetch", "egress-proxy"}
    # It listens on an alias declared on bridge-fetch alone, which no other service carries and
    # which is neither a service's nor a network's name (CR-4).
    args = _bridge_args(bridge["command"])
    listen = bridge_listen.parse(args.listen)
    assert isinstance(listen, bridge_listen.Tcp)
    assert (listen.host, listen.port) == ("bridge-fetch-mcp", 9000)
    assert bridge["networks"]["bridge-fetch"] == {"aliases": [listen.host]}
    assert not (bridge["networks"]["egress-fetch"] or {}).get("aliases")
    assert listen.host not in services
    assert listen.host not in networks
    for name, service in services.items():
        if name != "bridge-fetch" and isinstance(service.get("networks"), dict):
            for settings in service["networks"].values():
                assert listen.host not in (settings or {}).get("aliases", [])
    assert (args.era, args.program) == ("legacy", ["/opt/stdio-server/venv/bin/fetch-server"])


def test_the_hardened_override_adds_only_its_own_to_the_vault_and_the_role() -> None:
    """C.9, L (CR-B3, OPS-10): the vault gains exactly its bridge network and the depends_on, and
    keeps egress as its one network with a route out; the role gains exactly the bridge's egress
    network, with its alias, and a whole command that keeps the vault's listener."""
    base = compose("compose.hardened.yaml")["services"]
    document = merged("compose.hardened.yaml", "compose.bridge.yaml")
    networks, services = document["networks"], document["services"]
    vault, before = services["vault"], base["vault"]
    assert vault["networks"] == {**before["networks"], "bridge-fetch": {}}
    assert vault["depends_on"] == {"bridge-fetch": {"condition": "service_started"}}
    assert {k: v for k, v in vault.items() if k not in ("networks", "depends_on")} == {
        k: v for k, v in before.items() if k not in ("networks", "depends_on")
    }
    assert [n for n in vault["networks"] if networks[n].get("internal") is not True] == ["egress"]
    assert _on(services, "egress") == {"vault"}
    role, before = services["egress-proxy"], base["egress-proxy"]
    assert role["networks"] == {**before["networks"], "egress-fetch": {"aliases": ["egress-fetch"]}}
    assert _on(services, "egress-out") == {"egress-proxy"}
    assert role["command"][:4] == before["command"][:4]
    specs = egress_listen.parse_all(_listens(role["command"]))
    assert [(s.source, s.host, s.port) for s in specs] == [
        ("vault", "egress-vault", 3128),
        ("bridge-fetch", "egress-fetch", 3128),
    ]
    assert {k: v for k, v in role.items() if k not in ("networks", "command")} == {
        k: v for k, v in before.items() if k not in ("networks", "command")
    }
    # The bridge's child goes through that listener, on the network it shares with the role.
    args = _bridge_args(services["bridge-fetch"]["command"])
    assert args.egress_proxy == f"http://{specs[1].host}:{specs[1].port}"
    # One uid per container, root aside: the bridge's is the image's bridge user.
    users = [s["user"] for s in services.values() if not s["user"].startswith("0:")]
    assert len(set(users)) == len(users)


def test_the_hardened_bridges_route_passes_check_and_names_its_listeners() -> None:
    """C.9: the merged inline policy with the S11 profile's route and server added passes check;
    the route reaches the bridge's alias, and its name is the role's listener source."""
    services = merged("compose.hardened.yaml", "compose.bridge.yaml")["services"]
    policy = with_bridge(services["vault"]["environment"]["ZOEYMCP_CONFIG"])
    assert _errors(policy) == []
    [route] = [r for r in policy.routes if r.name == "bridge-fetch"]
    args = _bridge_args(services["bridge-fetch"]["command"])
    assert route.upstream == f"http://{args.listen}"
    assert route.name in policy_check.local_mcp_routes(policy)
    role = egress_listen.parse_all(_listens(services["egress-proxy"]["command"]))
    assert [s.source for s in role if s.source != "vault"] == [route.name]
    lists = egresslist.derive(policy)
    assert [(d.host, d.port) for d in lists[route.name]] == [("docs.example.org", 443)]
    # The vault reaches its bridge directly, never through a proxy (I.2).
    assert ("bridge-fetch-mcp", 9000) not in {(d.host, d.port) for d in lists["vault"]}


def test_compose_stops_a_hardened_bridge_after_the_vault() -> None:
    """BP-14's static half: compose stops a service before what it depends on, so the gateway,
    then the vault, then the bridge; a call in flight through the bridge finishes inside the
    vault's window, and the bridge's own stop (its children's 4 s) fits its grace period."""
    services = merged("compose.hardened.yaml", "compose.bridge.yaml")["services"]
    assert services["gateway"]["depends_on"] == {"vault": {"condition": "service_started"}}
    assert services["vault"]["depends_on"] == {"bridge-fetch": {"condition": "service_started"}}
    assert _seconds(services["vault"]["stop_grace_period"]) >= launcher.VAULT_STOP_WAIT
    assert _seconds(services["bridge-fetch"]["stop_grace_period"]) >= launcher.BRIDGE_STOP_WAIT
    assert "depends_on" not in services["bridge-fetch"]


def test_the_hardened_bridges_uid_is_the_images_bridge_user() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert f" && groupadd --gid {BRIDGE_UID} bridge \\\n" in dockerfile
    assert (
        f" && useradd --uid {BRIDGE_UID} --gid {BRIDGE_UID} --no-create-home "
        "--home-dir /nonexistent --shell /usr/sbin/nologin bridge \\\n"
    ) in dockerfile
    # Below the standard tier's bridge uids, and none of the other roles'.
    assert BRIDGE_UID < env.BRIDGE_UID_BASE
    assert BRIDGE_UID not in {env.VAULT_UID, env.GATEWAY_UID, env.INIT_UID, EGRESS_UID}


def test_the_official_image_drops_the_distrusted_root() -> None:
    """Q42, TI-9: the official image disables emSign ECC Root CA - G3 in Debian's store, and the
    build fails unless the line was there to disable and the root is gone afterwards; the image
    smoke and verify.sh --bridge check the built store."""
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "grep -qx 'mozilla/emSign_ECC_Root_CA_-_G3.crt' /etc/ca-certificates.conf" in dockerfile
    assert "s|^mozilla/emSign_ECC_Root_CA_-_G3\\.crt$|!&|" in dockerfile
    assert "update-ca-certificates --fresh" in dockerfile
    assert "test ! -e /etc/ssl/certs/emSign_ECC_Root_CA_-_G3.pem" in dockerfile
    verify = (BRIDGE_EXAMPLE / "verify.sh").read_text(encoding="utf-8")
    assert 'name = "emSign_ECC_Root_CA_-_G3"' in verify


def test_the_example_images_pin_the_same_uv() -> None:
    """D-162: Dependabot bumps the root's uv stage and the examples' copies in one group."""
    [root] = _UV_STAGE.findall((ROOT / "Dockerfile").read_text(encoding="utf-8"))
    assert "@sha256:" in root
    dependabot = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert "directories: [/, /examples/bridge, /examples/derived-image]" in dependabot
    for example in ("bridge", "derived-image"):
        path = ROOT / "examples" / example / "Dockerfile"
        assert _UV_STAGE.findall(path.read_text(encoding="utf-8")) == [root]


def _bridge_names(command: list[str]) -> list[str]:
    return [command[i + 1] for i, word in enumerate(command) if word == "--bridge"]


def test_the_standard_bridge_override_keeps_the_launchers_box() -> None:
    """C.10, L (Q46, CR-B9): the merged container is still the launcher's box, each bridge's
    arguments leave the launcher's options alone, and each bridge's tmpfs is exactly its uid's,
    group the vault's, 0750, in --bridge order."""
    service = merged("compose.yaml", "compose.standard.yaml")["services"]["zoeymcp"]
    launchers_box(service)
    assert service["image"] == "zoeymcp-bridge-fetch:local"
    assert service["pids_limit"] == 1024
    names = _bridge_names(service["command"])
    assert names == ["fetch"]
    assert service["command"][:3] == compose("compose.yaml")["services"]["zoeymcp"]["command"]
    environ = {name: value or "" for name, value in service["environment"].items()}
    specs = env.bridge_specs(environ, names)
    assert [(s.name, s.refusals) for s in specs] == [("fetch", ())]
    for spec in specs:
        options = spec.args[: spec.args.index("--")]
        for option in (*env.LAUNCHER_OPTIONS, "--egress-proxy"):
            assert not any(word.partition("=")[0] == option for word in options)
        command = spec.args[spec.args.index("--") + 1 :]
        assert command == ("/opt/stdio-server/venv/bin/fetch-server",)
    tmpfs = {entry.split(":")[0]: entry.split(":", 1)[1] for entry in service["tmpfs"]}
    for spec in specs:
        wanted = env.bridge_directory(spec.name, spec.index)
        assert tmpfs[wanted.path] == (
            f"size=64m,mode={wanted.mode:04o},uid={wanted.uid},gid={wanted.gid}"
        )
        assert (wanted.uid, wanted.gid, wanted.mode) == (10100 + spec.index, 10001, 0o750)
    # The socket's path is the launcher's alone: no variable names it.
    for path in (BRIDGE_EXAMPLE / "compose.standard.yaml", *COMPOSE_FILES):
        assert not _BRIDGE_LISTEN_VARIABLE.search(path.read_text(encoding="utf-8"))
    # Its token hash, `:-`, so compose config passes before the vault has made the token.
    assert environ[env.bridge_variable("fetch", "TOKEN_SHA256")] == ""


def test_the_standard_bridges_route_is_its_socket() -> None:
    """C.10: the merged policy's route for each bridge is exactly the socket the launcher has
    that bridge listen on, and passes check without allow_insecure_upstream or program.egress."""
    service = merged("compose.yaml", "compose.standard.yaml")["services"]["zoeymcp"]
    environ = {name: value or "" for name, value in service["environment"].items()}
    for spec in env.bridge_specs(environ, _bridge_names(service["command"])):
        upstream = f"unix:{spec.directory.path}/mcp.sock"
        assert upstream == "unix:/run/zoeymcp-bridge-fetch/mcp.sock"
        assert fields.unix_upstream(upstream) == upstream
        argv = launcher.bridge_argv(spec, 7)
        assert argv[argv.index("--listen") + 1] == upstream
        policy = with_bridge(service["environment"]["ZOEYMCP_CONFIG"], upstream=upstream)
        assert _errors(policy) == []
        [route] = [r for r in policy.routes if r.name == "bridge-fetch"]
        assert route.upstream == upstream
        assert route.name in policy_check.local_mcp_routes(policy)


def test_the_standard_override_says_unconfined_first() -> None:
    """X21: the override's header says the program is unconfined, what it shares, that no secret
    goes in ARGS, and that the image must pass verify.sh --bridge."""
    text = (BRIDGE_EXAMPLE / "compose.standard.yaml").read_text(encoding="utf-8")
    header = text.split("\nservices:", 1)[0].splitlines()
    assert header[2].startswith(
        "# UNCONFINED: this program shares the container with the vault and the gateway."
    )
    joined = " ".join(line.removeprefix("# ") for line in header)
    for phrase in (
        "can ignore proxy settings",
        "memory, processes and CPU",
        "so no secret goes in ..._ARGS",
        "This image must pass examples/bridge/verify.sh --bridge.",
    ):
        assert phrase in joined


def test_the_example_policys_bridge_block_passes_check() -> None:
    """examples/policy.yaml's commented bridge block, uncommented into the policy, passes check;
    as shipped it stays a comment, so the example keeps its one warning."""
    text = (ROOT / "examples" / "policy.yaml").read_text(encoding="utf-8")
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("# A stdio MCP server"))
    body = lines[lines.index("#", start) + 1 :]
    assert body
    assert all(line.startswith("# ") for line in body)
    fragment = yaml.safe_load("\n".join(line[2:] for line in body))
    document = yaml.safe_load(text)
    assert "bridge-fetch" not in document["credentials"]
    document["credentials"].update(fragment["credentials"])
    document["routes"] += fragment["routes"]
    document["gateway"]["servers"].update(fragment["gateway"]["servers"])
    policy = Policy.model_validate(document)
    assert _errors(policy) == []
    assert "bridge-fetch" in policy_check.local_mcp_routes(policy)
