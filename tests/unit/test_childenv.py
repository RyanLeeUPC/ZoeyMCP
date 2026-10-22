"""The bridge child's environment and work paths (M7 design C.3, X14, R35; O.2
``test_childenv.py``).

The environment is exactly the listed names: nothing inherited, no ``ZOEYMCP_*`` name, proxy
variables only with ``--egress-proxy``, and ``--secret-env`` refused when unset or empty. Every
path is under ``<work>``.
"""

from __future__ import annotations

import pytest

from zoeymcp.bridge import childenv
from zoeymcp.bridge.childenv import (
    PROXY_FORM,
    WORK_DIR,
    ChildEnvError,
    WorkPaths,
    build,
    check_names,
    proxy_url,
    work_paths,
)

PATHS = work_paths("/run/zoeymcp-bridge-fetch/work")
ENVIRON = {
    "PATH": "/opt/stdio-server/venv/bin:/usr/bin",
    "HOME": "/home/bridge",
    "TMPDIR": "/somewhere",
    "LANG": "C.UTF-8",
    "TZ": "UTC",
    "ZOEYMCP_BRIDGE_TOKEN_SHA256": "sha256:" + "0" * 64,
    "ZOEYMCP_CONFIG": "/etc/zoeymcp/policy.yaml",
    "HTTPS_PROXY": "http://inherited:1",
    "SSH_AUTH_SOCK": "/run/agent.sock",
    "API_BASE": "http://vault:8080/notes",
    "API_KEY": "secret-value",
    "EMPTY": "",
}


def test_the_constants() -> None:
    assert WORK_DIR == "/tmp/zoeymcp-bridge"  # noqa: S108 - C.3's default, on tmpfs
    assert childenv.COPIED == ("LANG", "LC_ALL", "TZ")
    assert childenv.PROXY_NAMES == (
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
    )


def test_every_path_is_under_work() -> None:
    assert work_paths(WORK_DIR) == WorkPaths(
        WORK_DIR,
        WORK_DIR + "/home",
        WORK_DIR + "/tmp",  # noqa: S108 - inside <work>
        WORK_DIR + "/work",
        WORK_DIR + "/ready",
    )
    assert PATHS.cwd == "/run/zoeymcp-bridge-fetch/work/work"
    assert work_paths("/w").home == "/w/home"


@pytest.mark.parametrize(
    "work", ["", "/", "run/x", "./x", "/run/x/", "/run//x", "/run/../etc", "/run/./x"]
)
def test_a_work_dir_is_absolute_and_normalized(work: str) -> None:
    with pytest.raises(
        ChildEnvError, match=r"^--work-dir is an absolute path such as /tmp/zoeymcp-bridge$"
    ):
        work_paths(work)


def test_the_environment_is_built_not_inherited() -> None:
    assert build(ENVIRON, PATHS) == {
        "PATH": "/opt/stdio-server/venv/bin:/usr/bin",
        "HOME": "/run/zoeymcp-bridge-fetch/work/home",
        "TMPDIR": "/run/zoeymcp-bridge-fetch/work/tmp",
        "LANG": "C.UTF-8",
        "TZ": "UTC",
    }
    assert build({"LC_ALL": "C"}, PATHS) == {"HOME": PATHS.home, "TMPDIR": PATHS.tmp, "LC_ALL": "C"}


def test_listed_names_are_copied() -> None:
    child = build(ENVIRON, PATHS, env=["API_BASE", "UNSET", "EMPTY"], secret_env=["API_KEY"])
    assert child["API_BASE"] == "http://vault:8080/notes"
    assert child["API_KEY"] == "secret-value"
    assert child["EMPTY"] == ""
    assert "UNSET" not in child
    assert not any(name.startswith("ZOEYMCP_") for name in child)
    assert "SSH_AUTH_SOCK" not in child
    # A listed name comes last, so it is what the operator asked for.
    assert build(ENVIRON, PATHS, env=["HOME"])["HOME"] == "/home/bridge"


def test_the_egress_proxy() -> None:
    """Fold-in C6: every common spelling, NO_PROXY empty, and Node told to use them."""
    url = "http://egress-fetch:3128"
    child = build(ENVIRON, PATHS, egress_proxy=url)
    for name in (
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "https_proxy",
        "http_proxy",
        "all_proxy",
    ):
        assert child[name] == url
    assert (child["NO_PROXY"], child["NODE_USE_ENV_PROXY"]) == ("", "1")
    assert len(child) == len(build(ENVIRON, PATHS)) + 8
    assert "HTTPS_PROXY" not in build(ENVIRON, PATHS)


@pytest.mark.parametrize(
    "url",
    [
        "http://egress-fetch:3128",
        "http://10.0.0.5:3128",
        "http://[fd00::5]:1",
        "http://[" + "0" * 45 + "]:1",
        "http://e:65535",
        "http://" + "e" * 253 + ":3128",
        "http://e:00080",
    ],
)
def test_a_proxy_url(url: str) -> None:
    assert proxy_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        "egress-fetch:3128",
        "https://egress-fetch:3128",
        "http://egress-fetch",
        "http://egress-fetch:",
        "http://egress-fetch:0",
        "http://egress-fetch:65536",
        "http://egress-fetch:123456",
        "http://user:pass@egress-fetch:3128",
        "http://egress-fetch:3128/",
        "http://egress-fetch:3128?x=1",
        "http://egress fetch:3128",
        "http://egress-fetch:3128\n",
        "HTTP://egress-fetch:3128",
        "http://" + "e" * 254 + ":3128",
        "http://[" + "0" * 46 + "]:1",
        "http://[1]:1",
        "http://_e:3128",
    ],
)
def test_a_proxy_url_refused(url: str) -> None:
    with pytest.raises(ChildEnvError, match=f"^{PROXY_FORM}$"):
        proxy_url(url)
    with pytest.raises(ChildEnvError, match=f"^{PROXY_FORM}$"):
        build(ENVIRON, PATHS, egress_proxy=url)


@pytest.mark.parametrize(
    "name", ["ZOEYMCP_CONFIG", "ZOEYMCP_BRIDGE_TOKEN_SHA256", "zoeymcp_x", "ZOEYMCP_"]
)
def test_a_zoeymcp_name_is_refused(name: str) -> None:
    """X14: nothing of ZoeyMCP's reaches the child, by either option."""
    with pytest.raises(
        ChildEnvError, match=f"^--env {name}: a ZOEYMCP_ variable never reaches the child$"
    ):
        build(ENVIRON, PATHS, env=[name])
    with pytest.raises(ChildEnvError, match=f"^--secret-env {name}: a ZOEYMCP_ variable"):
        build(ENVIRON, PATHS, secret_env=[name])


@pytest.mark.parametrize("name", ["", "1A", "A-B", "A=B", "A B", "\u00c9", "A" * 129])
def test_a_name_must_be_a_variable_name(name: str) -> None:
    with pytest.raises(ChildEnvError, match=r"^--env .* isn't a variable name$"):
        check_names([name], [])
    with pytest.raises(ChildEnvError, match=r"^--secret-env .* isn't a variable name$"):
        check_names([], [name])
    # Shown escaped, so the message holds nothing hidden.
    with pytest.raises(ChildEnvError, match=r"^--env '\\xc9' isn't"):
        check_names(["\u00c9"], [])


def test_names_that_pass() -> None:
    check_names(["_", "a", "A_1", "A" * 128, "ZOEYMCPX", "X_ZOEYMCP_"], ["B"])


@pytest.mark.parametrize("name", ["UNSET", "EMPTY"])
def test_a_secret_env_must_be_set(name: str) -> None:
    """R35: the program isn't started without the secret it was given."""
    with pytest.raises(ChildEnvError, match=f"^--secret-env {name} is unset or empty$"):
        build(ENVIRON, PATHS, secret_env=[name])
