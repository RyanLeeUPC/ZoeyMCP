from __future__ import annotations

import contextlib
import getpass
import inspect
import io
import json
import os
import re
import shlex
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from anyio.from_thread import BlockingPortal, start_blocking_portal
from mcp.types import Tool

from tests.fakes.oauth_server import AuthSwitch, FakeAuthServer
from tests.unit import onboard_model
from zoeymcp.cli import admin_client
from zoeymcp.cli import main as main_module
from zoeymcp.cli import onboard as onboard_cli
from zoeymcp.cli import review as review_view
from zoeymcp.cli.main import (
    EXIT_FINDINGS,
    EXIT_OK,
    EXIT_UNREADABLE,
    GATEWAY_ENVIRONMENT,
    NOT_PERSISTED,
    counted,
    dollar_flags,
    duration,
    exec_gateway_environment,
    format_status,
    gateway_command,
    health_action,
    listed,
    main,
    merge_summary,
    new_client_token,
)
from zoeymcp.common import egresslist, netguard
from zoeymcp.common.adminsocket import SOCKET_ENV
from zoeymcp.common.policy import Finding, Policy, parse_policy
from zoeymcp.common.policy import change as policy_change
from zoeymcp.common.policy import emit as policy_emit
from zoeymcp.common.policy.merge import Merged, merge, replace_paths
from zoeymcp.common.policy.schema import GatewayLimits, hash_token
from zoeymcp.common.policy.view import ViewRemoteServer, ViewToolkitServer, build_view
from zoeymcp.common.reviewreport import fit
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway import pins as gateway_pins
from zoeymcp.gateway import review as gateway_review
from zoeymcp.vault import admin as admin_module
from zoeymcp.vault.admin import AdminApp, SetupCodes
from zoeymcp.vault.bindings import derive_binding
from zoeymcp.vault.netclient import RESOLVE_TIMEOUT
from zoeymcp.vault.oauth import fetch
from zoeymcp.vault.oauth.dcr import NOTES
from zoeymcp.vault.oauth.tokens import TokenManager
from zoeymcp.vault.onboarding import INLINE_SOURCE, allow_hosts, next_for, onboard_again
from zoeymcp.vault.reviewjobs import Job, JobTable, Owner, ServerKind, read_result
from zoeymcp.vault.store import SecretStore

from .conftest import EXAMPLE_POLICY
from .test_admin import KEYS as ADMIN_KEYS
from .test_admin import AdminRig
from .test_deploy import compose, inline_policy
from .test_netclient import bridges_policy
from .test_oauth_tokens import KEYS
from .test_onboarding import staged as onboarding_staged
from .test_policy_change import notes_change, review_change
from .test_review import policy as review_server


def run(argv: list[str], stdin: str = "") -> tuple[int, str]:
    out = io.StringIO()
    code = main(argv, stdin=io.StringIO(stdin), out=out)
    return code, out.getvalue()


def test_check_example_file() -> None:
    code, out = run(["check", "--config", str(EXAMPLE_POLICY)])
    assert code == EXIT_OK
    assert out.strip().endswith("ok (0 error(s), 1 warning(s))")


def test_check_from_stdin(example_text: str) -> None:
    code, out = run(["check", "--config", "-"], stdin=example_text)
    assert code == EXIT_OK
    assert out.splitlines()[-1] == "<stdin>: ok (0 error(s), 1 warning(s))"


def test_check_from_env(example_text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ZOEYMCP_CONFIG", example_text)
    code, out = run(["check"])
    assert code == EXIT_OK
    assert out.splitlines()[-1] == "$ZOEYMCP_CONFIG: ok (0 error(s), 1 warning(s))"


def test_check_reports_errors_as_json(example_text: str) -> None:
    bad = example_text.replace(
        "callers: [gateway] # the gateway only", "callers: [{placeholder: ph-sandbox-0123456789}]"
    )
    code, out = run(["check", "--config", "-", "--format", "json"], stdin=bad)
    assert code == EXIT_FINDINGS
    report = json.loads(out)
    assert report["ok"] is False
    assert report["readable"] is True
    assert report["errors"] == 1
    found = [f["path"] for f in report["findings"] if f["level"] == "error"]
    assert found == ["routes[1].callers"]


def test_schema_errors_exit_with_findings() -> None:
    code, out = run(["check", "--config", "-"], stdin="version: 1\n")
    assert code == EXIT_FINDINGS
    assert "mode: Field required" in out


def test_resolve_env_flag(example_text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    text = example_text.replace("secret: store:music-stats", "secret: env:ZMCP_TEST_STATS")
    monkeypatch.delenv("ZMCP_TEST_STATS", raising=False)
    assert run(["check", "--config", "-"], stdin=text)[0] == EXIT_OK
    code, out = run(["check", "--config", "-", "--resolve-env"], stdin=text)
    assert code == EXIT_FINDINGS
    assert "env var ZMCP_TEST_STATS is not set" in out


def test_missing_file_is_unreadable(tmp_path: Path) -> None:
    code, out = run(["check", "--config", str(tmp_path / "absent.yaml")])
    assert code == EXIT_UNREADABLE
    assert "can't read" in out


def test_no_policy_at_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ZOEYMCP_CONFIG", raising=False)
    code, out = run(["check"])
    assert code == EXIT_UNREADABLE
    assert "no policy given" in out


# --- check --emit-egress-allowlist (M7 design I.6, J5) ------------------------------------------

EMIT_POLICY = """\
version: 1
mode: declarative
egress_private: ["files.lan.example:8080"]
routes:
  - name: zeta
    prefix: /zeta
    upstream: https://zeta.example
    callers: [{placeholder: ph-zeta-0123456789abcdef}]
    rules: [{methods: [GET], paths: [/v1/**]}]
  - name: files
    prefix: /files
    upstream: http://files.lan.example:8080
    allow_insecure_upstream: true
    callers: [{placeholder: ph-files-0123456789abcdef}]
    rules: [{methods: [GET], paths: [/v1/**]}]
  - name: alpha
    prefix: /alpha
    upstream: https://Alpha.example:8443
    callers: [{placeholder: ph-alpha-0123456789abcdef}]
    rules: [{methods: [GET], paths: [/v1/**]}]
"""
EMIT_FINDINGS = [
    "warning routes[1].upstream: plain http upstream",
    "<stdin>: ok (0 error(s), 1 warning(s))",
]


def emit(*flags: str, policy: str = EMIT_POLICY) -> tuple[int, str, str]:
    return cli(["check", "--config", "-", "--emit-egress-allowlist", *flags], io.StringIO(policy))


def lists_digest(policy: str = EMIT_POLICY) -> str:
    return egresslist.digest(egresslist.derive(parse_policy(policy, "test")))


def test_emit_text_byte_for_byte_and_sorted() -> None:
    code, out, err = emit()
    assert code == EXIT_OK
    # Sorted by host then port, whatever the policy's order; host names in lower case.
    assert out == (
        f"# zoeymcp egress allowlist, lists {lists_digest()}\n"
        "vault alpha.example:8443\n"
        "vault files.lan.example:8080  # plain http: refused by a CONNECT-only proxy\n"
        "vault zeta.example:443\n"
    )
    # Findings on stderr only, so stdout can be redirected into the proxy's configuration.
    assert err.splitlines() == EMIT_FINDINGS
    assert emit("--allowlist-format", "text")[1] == out


def test_emit_json_byte_for_byte() -> None:
    code, out, err = emit("--allowlist-format", "json")
    assert code == EXIT_OK
    assert out == (
        "{\n"
        '  "v": 1,\n'
        f'  "digest": "{lists_digest()}",\n'
        '  "sources": {\n'
        '    "vault": [\n'
        "      {\n"
        '        "host": "alpha.example",\n'
        '        "port": 8443,\n'
        '        "private": false\n'
        "      },\n"
        "      {\n"
        '        "host": "files.lan.example",\n'
        '        "port": 8080,\n'
        '        "private": true\n'
        "      },\n"
        "      {\n"
        '        "host": "zeta.example",\n'
        '        "port": 443,\n'
        '        "private": false\n'
        "      }\n"
        "    ]\n"
        "  }\n"
        "}\n"
    )
    assert err.splitlines() == EMIT_FINDINGS


def squid_text(src: str = "zoeymcp_src_vault") -> str:
    return (
        f"# zoeymcp egress allowlist, lists {lists_digest()}; regenerate with zoeymcp check "
        "--emit-egress-allowlist; keep your own final deny\n"
        "# expects your squid.conf to define: acl CONNECT method CONNECT, and "
        f"acl {src} src <the vault's network>\n"
        f"acl zoeymcp_private_dst dst {' '.join(netguard.squid_private_dst())}\n"
        "acl zoeymcp_port_443 port 443\n"
        "acl zoeymcp_port_8080 port 8080\n"
        "acl zoeymcp_port_8443 port 8443\n"
        "acl zoeymcp_vault_1 dstdomain -n alpha.example\n"
        f"http_access allow {src} CONNECT zoeymcp_vault_1 zoeymcp_port_8443 !zoeymcp_private_dst\n"
        "acl zoeymcp_vault_2 dstdomain -n files.lan.example\n"
        f"http_access allow {src} CONNECT zoeymcp_vault_2 zoeymcp_port_8080\n"
        "acl zoeymcp_vault_3 dstdomain -n zeta.example\n"
        f"http_access allow {src} CONNECT zoeymcp_vault_3 zoeymcp_port_443 !zoeymcp_private_dst\n"
    )


def test_emit_squid_byte_for_byte() -> None:
    code, out, err = emit("--allowlist-format", "squid")
    assert code == EXIT_OK
    assert out == squid_text()
    assert err.splitlines() == EMIT_FINDINGS


def test_emit_squid_names_the_policys_acl_and_squid_src_overrides_it() -> None:
    policy = EMIT_POLICY + "egress_proxy_acls: {vault: stack_vault_net}\n"
    assert emit("--allowlist-format", "squid", policy=policy)[1] == squid_text("stack_vault_net")
    code, out, _ = emit(
        "--allowlist-format", "squid", "--squid-src", "vault=other_net", policy=policy
    )
    assert code == EXIT_OK
    assert out == squid_text("other_net")
    assert emit("--allowlist-format", "squid", "--squid-src", "vault=x1")[1] == squid_text("x1")


@pytest.mark.parametrize("value", ["vault", "vault=", "vault=a-b", "=net"])
def test_a_bad_squid_src_is_a_usage_error(value: str) -> None:
    code, out, err = emit("--allowlist-format", "squid", "--squid-src", value)
    assert code == EXIT_UNREADABLE
    assert out == ""
    assert f"--squid-src {value}: write SOURCE=ACL, ACL 1 to 64 letters" in err
    # Checked before the policy is read: still a usage error, and the only line, when the
    # policy has errors or can't be parsed.
    for policy in (EMIT_POLICY.replace("allow_insecure_upstream: true\n", ""), "version: 1\n"):
        code, out, err = emit("--allowlist-format", "squid", "--squid-src", value, policy=policy)
        assert (code, out) == (EXIT_UNREADABLE, "")
        assert err.splitlines() == [
            f"zoeymcp check: --squid-src {value}: write SOURCE=ACL, ACL 1 to 64 letters, "
            "digits or underscores"
        ]


def test_a_squid_src_naming_no_source_is_a_usage_error() -> None:
    code, out, err = emit("--allowlist-format", "squid", "--squid-src", "bridge-fetch=net")
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert (
        err.splitlines()[-1]
        == "zoeymcp check: --squid-src bridge-fetch=net: SOURCE is one of vault"
    )


@pytest.mark.parametrize(
    "flags",
    [
        ["--allowlist-format", "json"],
        ["--allowlist-format", "squid"],
        ["--squid-src", "vault=net"],
        ["--check", "zoeymcp.conf"],
    ],
)
def test_emitter_flags_without_emit_are_a_usage_error(flags: list[str]) -> None:
    code, out, err = cli(["check", "--config", "-", *flags], io.StringIO(EMIT_POLICY))
    assert code == EXIT_UNREADABLE
    assert out == ""
    assert err == (
        "zoeymcp check: --allowlist-format, --squid-src and --check go with "
        "--emit-egress-allowlist\n"
    )


@pytest.mark.parametrize("flags", [[], ["--allowlist-format", "json"]])
def test_squid_src_without_the_squid_form_is_a_usage_error(flags: list[str]) -> None:
    code, out, err = emit(*flags, "--squid-src", "vault=net")
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err == "zoeymcp check: --squid-src goes with --allowlist-format squid\n"


def test_emit_check_exits_0_when_equal_and_1_listing_the_differences(tmp_path: Path) -> None:
    conf = tmp_path / "zoeymcp.conf"
    conf.write_bytes(squid_text().replace("\n", "\r\n").encode())  # line endings aside
    code, out, err = emit("--allowlist-format", "squid", "--check", str(conf))
    assert code == EXIT_OK
    assert out == f"{conf}: matches the policy's egress allowlist\n"
    assert err.splitlines() == EMIT_FINDINGS
    stale = squid_text().replace("zoeymcp_vault_3 dstdomain -n zeta.example", "zoeymcp_vault_3 x")
    conf.write_bytes(stale.encode())
    code, out, _ = emit("--allowlist-format", "squid", "--check", str(conf))
    assert code == EXIT_FINDINGS
    assert out.splitlines() == [
        "missing: acl zoeymcp_vault_3 dstdomain -n zeta.example",
        "unexpected: acl zoeymcp_vault_3 x",
        f"{conf}: out of date (2 difference(s)); regenerate it with check --emit-egress-allowlist",
    ]
    # The source ACL name is part of the comparison: --squid-src changes what is expected.
    conf.write_bytes(squid_text().encode())
    code, out, _ = emit(
        "--allowlist-format", "squid", "--squid-src", "vault=n", "--check", str(conf)
    )
    assert code == EXIT_FINDINGS
    # The header's expects line and the three rules, each missing once and unexpected once.
    assert len(out.splitlines()) == 9
    assert "missing: http_access allow n CONNECT zoeymcp_vault_3 zoeymcp_port_443" in out


def test_emit_check_of_a_missing_file_is_unreadable(tmp_path: Path) -> None:
    code, out, err = emit("--check", str(tmp_path / "absent.conf"))
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert f"zoeymcp check: can't read {tmp_path / 'absent.conf'}" in err


def test_emit_prints_nothing_for_a_policy_with_errors() -> None:
    bad = EMIT_POLICY.replace("allow_insecure_upstream: true\n", "")
    code, out, err = emit(policy=bad)
    assert (code, out) == (EXIT_FINDINGS, "")
    assert "FAILED" in err
    code, out, err = emit(policy="version: 1\n")
    assert (code, out) == (EXIT_FINDINGS, "")
    assert "mode: Field required" in err


def test_emit_findings_on_stderr_as_json() -> None:
    code, out, err = emit("--format", "json", "--allowlist-format", "squid")
    assert code == EXIT_OK
    assert out == squid_text()
    assert json.loads(err)["warnings"] == 1


def test_emit_output_is_unchanged_by_an_unrelated_edit() -> None:
    # GR-20: the digest covers the lists alone, so --check keeps passing.
    edited = EMIT_POLICY.replace("paths: [/v1/**]", "paths: [/v2/**]").replace(
        "ph-zeta-0123456789abcdef", "ph-zeta-fedcba9876543210"
    )
    for fmt in ("text", "json", "squid"):
        assert (
            emit("--allowlist-format", fmt, policy=edited)[1] == emit("--allowlist-format", fmt)[1]
        )
    moved = EMIT_POLICY.replace("https://zeta.example", "https://zeta.example:9443")
    assert emit(policy=moved)[1] != emit()[1]


def test_emit_reads_the_policy_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    # OPS-9: the container forms of J5 read the service's inline policy; --config is optional.
    monkeypatch.setenv("ZOEYMCP_CONFIG", EMIT_POLICY)
    code, out, err = cli(["check", "--emit-egress-allowlist", "--allowlist-format", "squid"])
    assert code == EXIT_OK
    assert out == squid_text()
    assert err.splitlines()[-1] == "$ZOEYMCP_CONFIG: ok (0 error(s), 1 warning(s))"


def test_emit_the_example_policy() -> None:
    code, out, _ = cli(["check", "--config", str(EXAMPLE_POLICY), "--emit-egress-allowlist"])
    assert code == EXIT_OK
    assert out.splitlines()[1:] == [
        "vault api.stats.example:443",
        "vault auth.broker.example:443",
        "vault mcp.broker.example:443",
        "vault smtp.mail.example:465",
    ]


# --- check --with (M7 design H.4, E.5; GR-1, OPS-6, OPS-17, TI-1) -------------------------------

PIN_C = "sha256:" + "c" * 64


def fragment_file(tmp_path: Path, text: str, name: str = "onboard-notes-1.yaml") -> str:
    path = tmp_path / name
    path.write_bytes(text.encode("utf-8"))
    return str(path)


def notes_fragment(tmp_path: Path) -> str:
    return fragment_file(tmp_path, policy_emit.emit(notes_change(private=False)))


ADDS_NOTES = (
    "with onboard-notes-1.yaml merged: 0 errors, 2 warnings; it adds credentials.notes, routes "
    "notes and gateway.servers.notes and changes nothing that exists"
)


def test_check_with_a_policy_file(tmp_path: Path) -> None:
    fragment = notes_fragment(tmp_path)
    code, out, err = cli(["check", "--config", str(EXAMPLE_POLICY), "--with", fragment])
    assert (code, err) == (EXIT_OK, "")
    size = len(EXAMPLE_POLICY.read_bytes())
    lines = out.splitlines()
    assert lines[0] == f"policy from {EXAMPLE_POLICY}, {size:,} bytes"
    assert lines[1] == ADDS_NOTES
    assert lines[-1] == (
        f"{EXAMPLE_POLICY} with onboard-notes-1.yaml merged: ok (0 error(s), 2 warning(s))"
    )
    assert "warning gateway.servers.notes: not assigned to any client" in lines


def test_check_with_stdin(tmp_path: Path, example_text: str) -> None:
    fragment = notes_fragment(tmp_path)
    code, out, _ = cli(["check", "--config", "-", "--with", fragment], io.StringIO(example_text))
    assert code == EXIT_OK
    assert out.splitlines()[0] == f"policy from <stdin>, {len(example_text.encode()):,} bytes"
    assert out.splitlines()[1] == ADDS_NOTES


def test_check_with_the_inline_policy(
    tmp_path: Path, example_text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """J1's line: the one-off run reads the service's own ZOEYMCP_CONFIG."""
    monkeypatch.setenv("ZOEYMCP_CONFIG", example_text)
    code, out, _ = cli(["check", "--with", notes_fragment(tmp_path)])
    assert code == EXIT_OK
    lines = out.splitlines()
    assert lines[0] == f"policy from ZOEYMCP_CONFIG, {len(example_text.encode()):,} bytes"
    assert lines[1] == ADDS_NOTES
    assert lines[-1] == (
        "$ZOEYMCP_CONFIG with onboard-notes-1.yaml merged: ok (0 error(s), 2 warning(s))"
    )


INLINE_NOTE = (
    "zoeymcp check: ZOEYMCP_CONFIG is read as compose substituted it, so a value it took from a "
    "variable (gateway_key_generation, the portal's origin port) is printed as its current "
    "value; restore each ${...} reference before replacing the block"
)


def test_print_merged_of_the_inline_policy_says_compose_substituted_it(
    tmp_path: Path, example_text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """E.5's "replace the whole block": compose has already written its variables' values, so
    stderr says to restore the ${...} references (operations.md's gateway-key rotation)."""
    monkeypatch.setenv("ZOEYMCP_CONFIG", example_text)
    code, out, err = cli(["check", "--with", notes_fragment(tmp_path), "--print-merged"])
    assert code == EXIT_OK
    assert out
    assert err.splitlines()[-1] == INLINE_NOTE
    # A file or stdin is the operator's own text, read as written: no such note.
    fragment = notes_fragment(tmp_path)
    code, _, err = cli(
        ["check", "--config", str(EXAMPLE_POLICY), "--with", fragment, "--print-merged"]
    )
    assert code == EXIT_OK
    assert INLINE_NOTE not in err


def test_check_with_two_fragments_lists_what_each_replaces(tmp_path: Path) -> None:
    first = notes_fragment(tmp_path)
    second = fragment_file(tmp_path, policy_emit.emit(review_change()), "review-2.yaml")
    code, out, _ = cli(
        ["check", "--config", str(EXAMPLE_POLICY), "--with", first, "--with", second]
    )
    assert code == EXIT_OK
    assert out.splitlines()[1] == (
        "with onboard-notes-1.yaml and review-2.yaml merged: 0 errors, 2 warnings; it adds "
        "credentials.notes, routes notes and gateway.servers.notes and replaces "
        "gateway.servers.broker-read.tools and gateway.servers.broker-read.review"
    )


def test_check_with_merges_a_review_as_the_vault_does(tmp_path: Path) -> None:
    """The header's replace paths: the dropped tool's pin goes (CR-14), so --print-merged holds
    exactly the vault's merged policy."""
    fragment = fragment_file(tmp_path, policy_emit.emit(review_change()), "review-2.yaml")
    code, out, err = cli(
        ["check", "--config", str(EXAMPLE_POLICY), "--with", fragment, "--print-merged"]
    )
    assert code == EXIT_OK
    assert "list_positions" not in out
    merged = parse_policy(out, "merged")
    assert merged == policy_change.apply(
        parse_policy(EXAMPLE_POLICY.read_text(), "x"), review_change()
    )
    assert err.splitlines()[1] == (
        "with review-2.yaml merged: 0 errors, 1 warning; it adds nothing and replaces "
        "gateway.servers.broker-read.tools and gateway.servers.broker-read.review"
    )
    assert err.splitlines()[-1] == (
        "zoeymcp check: the merged policy is printed whole, so the comments of the policy and "
        "the fragments are dropped"
    )


def test_print_merged_writes_the_whole_merged_policy(tmp_path: Path, example_raw: Any) -> None:
    code, out, err = cli(
        [
            "check",
            "--config",
            str(EXAMPLE_POLICY),
            "--with",
            notes_fragment(tmp_path),
            "--print-merged",
        ]
    )
    assert code == EXIT_OK
    assert out == policy_emit.document(load_mapping(out))
    loaded = load_mapping(out)
    assert loaded["credentials"]["music-stats"] == example_raw["credentials"]["music-stats"]
    assert loaded["credentials"]["notes"] == notes_change().data()["credentials"]["notes"]
    assert ADDS_NOTES in err
    assert err.splitlines()[0].startswith("policy from ")


@pytest.mark.parametrize(
    ("flags", "spaces"), [(["--indent", "4"], 4), (["--for", "compose"], 8), ([], 0)]
)
def test_print_merged_indents_and_takes_the_compose_form(
    tmp_path: Path, flags: list[str], spaces: int
) -> None:
    policy = (
        "version: 1\nmode: declarative\ncredentials:\n"
        '  a: {kind: header, secret: "store:a", format: "Bearer {secret} $X"}\n'
    )
    fragment = fragment_file(tmp_path, "{}\n")
    code, out, _ = cli(
        ["check", "--config", "-", "--with", fragment, "--print-merged", *flags],
        io.StringIO(policy),
    )
    assert code == EXIT_OK
    assert out.splitlines()[0] == " " * spaces + "version: 1"
    dollar = "$$X" if flags == ["--for", "compose"] else "$X"
    assert f'format: "Bearer {{secret}} {dollar}"' in out


def test_a_dollar_in_a_fragment_is_a_warning_with_its_line(tmp_path: Path) -> None:
    fragment = fragment_file(
        tmp_path, '# zoeymcp: t\negress_private: ["a.lan.example:443"]\n# $ZOEYMCP_MASTER_KEY\n'
    )
    code, out, _ = cli(["check", "--config", str(EXAMPLE_POLICY), "--with", fragment])
    assert code == EXIT_OK
    assert (
        f"warning {fragment} line 3: holds a $, which compose reads as a variable in an inline "
        "ZOEYMCP_CONFIG; merge the compose form (--for compose) there"
    ) in out.splitlines()
    assert dollar_flags("f", "a\nb$\n$c$") == [
        Finding("f line 2", "warning", dollar_flags("f", "$")[0].message),
        Finding("f line 3", "warning", dollar_flags("f", "$")[0].message),
    ]


def test_check_with_errors_in_the_merged_policy_exits_1(tmp_path: Path) -> None:
    # A server on a route that doesn't exist: a check error.
    server = '{"gateway": {"servers": {"orphan": {"kind": "remote", "route": "absent"}}}}\n'
    code, out, _ = cli(
        ["check", "--config", str(EXAMPLE_POLICY), "--with", fragment_file(tmp_path, server)]
    )
    assert code == EXIT_FINDINGS
    assert out.splitlines()[1].startswith("with onboard-notes-1.yaml merged: 1 error, ")
    assert out.splitlines()[-1].endswith("merged: FAILED (1 error(s), 2 warning(s))")


def test_print_merged_prints_nothing_for_a_merged_policy_with_errors(tmp_path: Path) -> None:
    server = '{"gateway": {"servers": {"orphan": {"kind": "remote", "route": "absent"}}}}\n'
    fragment = fragment_file(tmp_path, server)
    code, out, err = cli(
        ["check", "--config", str(EXAMPLE_POLICY), "--with", fragment, "--print-merged"]
    )
    assert (code, out) == (EXIT_FINDINGS, "")
    assert "FAILED" in err


def test_check_with_a_schema_error_exits_1(tmp_path: Path) -> None:
    fragment = fragment_file(tmp_path, "credentials: {notes: {kind: oauth2}}\n")
    code, out, _ = cli(["check", "--config", str(EXAMPLE_POLICY), "--with", fragment])
    assert code == EXIT_FINDINGS
    # What the fragment added is said before the schema's findings too (H.4).
    lines = out.splitlines()
    assert lines[1] == (
        "with onboard-notes-1.yaml merged: 2 errors, 0 warnings; it adds credentials.notes and "
        "changes nothing that exists"
    )
    assert "error   credentials.notes.oauth2.token_url: Field required" in out
    assert lines[-1].startswith(f"{EXAMPLE_POLICY} with onboard-notes-1.yaml merged: ")


def test_check_with_a_conflicting_route_exits_1(tmp_path: Path) -> None:
    route = '{"routes": [{"name": "stats", "prefix": "/other"}]}\n'
    code, out, _ = cli(
        ["check", "--config", str(EXAMPLE_POLICY), "--with", fragment_file(tmp_path, route)]
    )
    assert code == EXIT_FINDINGS
    assert "error   routes stats: route stats is in the policy already" in out


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("a: 1\na: 2\n", "duplicate key 'a'"),
        ("[1]\n", "the top level must be a mapping"),
        ("# zoeymcp replace: routes\n{}\n", "the header names routes, which a fragment can't"),
    ],
)
def test_check_with_a_fragment_that_wont_load_exits_1(
    tmp_path: Path, text: str, message: str
) -> None:
    fragment = fragment_file(tmp_path, text)
    code, out, _ = cli(["check", "--config", str(EXAMPLE_POLICY), "--with", fragment])
    assert code == EXIT_FINDINGS
    assert message in out
    assert out.splitlines()[-1].startswith(f"{fragment}: FAILED")


def test_check_with_a_base_that_wont_load_exits_1(tmp_path: Path) -> None:
    code, out, _ = cli(
        ["check", "--config", "-", "--with", notes_fragment(tmp_path)], io.StringIO("a: [\n")
    )
    assert code == EXIT_FINDINGS
    assert out.splitlines()[-1] == "<stdin>: FAILED (1 error(s), 0 warning(s))"


def test_check_with_unreadable_files_exits_2(tmp_path: Path) -> None:
    code, out, err = cli(["check", "--config", str(EXAMPLE_POLICY), "--with", str(tmp_path / "x")])
    assert code == EXIT_UNREADABLE
    assert err.startswith(f"zoeymcp check: can't read {tmp_path / 'x'}: ")
    code, out, _ = cli(["check", "--config", str(tmp_path / "x"), "--with", str(tmp_path / "y")])
    assert code == EXIT_UNREADABLE
    assert "can't read" in out


def test_check_with_as_json_keeps_stdout_one_document(tmp_path: Path) -> None:
    code, out, err = cli(
        [
            "check",
            "--config",
            str(EXAMPLE_POLICY),
            "--with",
            notes_fragment(tmp_path),
            "--format",
            "json",
        ]
    )
    assert code == EXIT_OK
    report = json.loads(out)
    assert (report["ok"], report["errors"], report["warnings"]) == (True, 0, 2)
    assert err.splitlines()[1] == ADDS_NOTES


@pytest.mark.parametrize(
    ("flags", "message"),
    [
        (["--print-merged"], "--print-merged goes with --with"),
        (["--indent", "2"], "--indent and --for go with --print-merged"),
        (["--for", "compose"], "--indent and --for go with --print-merged"),
        (
            ["--with", "f", "--emit-egress-allowlist"],
            "--with and --emit-egress-allowlist are separate",
        ),
        (["--with", "f", "--print-merged", "--indent", "17"], "--indent is 0 to 16"),
        (["--with", "f", "--print-merged", "--indent", "-1"], "--indent is 0 to 16"),
    ],
)
def test_check_with_usage_errors(flags: list[str], message: str) -> None:
    code, out, err = cli(["check", "--config", str(EXAMPLE_POLICY), *flags])
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err == f"zoeymcp check: {message}\n" or message in err


def test_indent_and_for_compose_exclude_each_other() -> None:
    with pytest.raises(SystemExit) as info:
        cli(["check", "--with", "f", "--print-merged", "--indent", "2", "--for", "compose"])
    assert info.value.code == 2


@pytest.mark.parametrize(
    ("items", "said"),
    [([], ""), (["a"], "a"), (["a", "b"], "a and b"), (["a", "b", "c"], "a, b and c")],
)
def test_listed(items: list[str], said: str) -> None:
    assert listed(items) == said


def test_counted_and_merge_summary() -> None:
    assert (counted(0, "error"), counted(1, "error"), counted(2, "warning")) == (
        "0 errors",
        "1 error",
        "2 warnings",
    )
    assert merge_summary([], []) == "it adds nothing and changes nothing that exists"
    assert merge_summary([("routes", "a")], [("credentials", "b")]) == (
        "it adds routes a and replaces credentials.b"
    )


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0
    assert capsys.readouterr().out.startswith("zoeymcp ")


def test_keygen_prints_a_matching_pair() -> None:
    from zoeymcp.vault.keys import KeySet

    code, out = run(["keygen"])
    assert code == EXIT_OK
    lines = dict(line.split("=", 1) for line in out.splitlines())
    assert set(lines) == {"ZOEYMCP_MASTER_KEY", "ZOEYMCP_GATEWAY_KEY"}
    assert (
        KeySet.from_text(lines["ZOEYMCP_MASTER_KEY"]).gateway_key(1) == lines["ZOEYMCP_GATEWAY_KEY"]
    )
    assert run(["keygen"])[1] != out


def test_client_token_prints_a_token_and_its_hash() -> None:
    import hashlib

    out, err = io.StringIO(), io.StringIO()
    assert main(["client-token"], out=out, err=err) == EXIT_OK
    lines = dict(line.split(": ", 1) for line in out.getvalue().splitlines())
    assert list(lines) == ["client_token", "token_sha256"]
    token = lines["client_token"]
    assert re.fullmatch(r"zgc1-[A-Za-z0-9_-]{43}", token)
    assert len(token) == 48
    assert lines["token_sha256"] == "sha256:" + hashlib.sha256(token.encode()).hexdigest()
    assert token not in err.getvalue()
    assert "token_sha256" in err.getvalue()
    assert run(["client-token"])[1] != out.getvalue()


def test_a_client_token_passes_the_policy_schema(example_text: str) -> None:
    out = io.StringIO()
    main(["client-token"], out=out, err=io.StringIO())
    lines = dict(line.split(": ", 1) for line in out.getvalue().splitlines())
    pattern = r"token_sha256: \S+"
    hashed, count = re.subn(pattern, f"token_sha256: {lines['token_sha256']}", example_text)
    assert count == 1
    assert f"token_sha256: {lines['token_sha256']}" in hashed
    assert run(["check", "--config", "-"], stdin=hashed)[0] == EXIT_OK
    literal, count = re.subn(pattern, f"token: {lines['client_token']}", example_text)
    assert count == 1
    code, report = run(["check", "--config", "-"], stdin=literal)
    assert code == EXIT_OK
    assert "gateway.clients.agent1.token: anyone who reads the policy" in report
    assert "easy to guess" not in report


def test_new_client_tokens_are_random(monkeypatch: pytest.MonkeyPatch) -> None:
    import secrets

    monkeypatch.setattr(secrets, "token_bytes", lambda n: bytes(range(n)))
    assert new_client_token() == "zgc1-AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"


@pytest.mark.parametrize(
    ("binding", "text"),
    [
        (
            {"origins": ["https://a.example:443", "https://b.example:443"]},
            "origins https://a.example:443, https://b.example:443",
        ),
        (
            {
                "oauth": {
                    "token": "https://accounts.example:443",
                    "resources": ["https://api.example:443", "https://files.example:443"],
                }
            },
            "token endpoint https://accounts.example:443, "
            "access tokens to https://api.example:443, https://files.example:443",
        ),
        (
            {
                "smtp": {
                    "host": "smtp.mail.example",
                    "port": 465,
                    "from": "a@mail.example",
                    "to": ["b@mail.example", "c@mail.example"],
                }
            },
            "SMTP smtp.mail.example:465 from a@mail.example to b@mail.example, c@mail.example",
        ),
        # A login's issuer terms, changed by a reload before its answer (M7 D.6).
        (
            {"issuer": "https://accounts.example", "require_iss": True},
            "issuer https://accounts.example, iss required",
        ),
        ({"issuer": None, "require_iss": False}, "no issuer, iss not required"),
        ({"other": 1}, '{"other": 1}'),
    ],
    ids=["origins", "oauth", "smtp", "issuer", "no-issuer", "unknown"],
)
def test_describe_binding(binding: dict[str, Any], text: str) -> None:
    assert admin_client.describe_binding(binding) == text


# --- login and oauth, against a canned admin socket --------------------------------------------

BINDING = {
    "oauth": {"token": "https://accounts.example:443", "resources": ["https://api.example:443"]}
}
AUTHORIZE = "https://accounts.example/authorize?response_type=code&client_id=example-client"
PASTED = "http://127.0.0.1/callback?code=fake-code-1&state=fake-state-1"
STARTED: dict[str, Any] = {
    "flow": "flow-0001",
    "authorize_url": AUTHORIZE,
    "redirect_uri": "http://127.0.0.1/callback",
    "expires": 1_800_000_600,
    "requested_scopes": ["read"],
    "expected_scopes": ["read"],
    "client_auth": "none",
    "rotates": True,
    "binding": BINDING,
    "binding_change": None,
}
COMPLETED: dict[str, Any] = {
    "slot": "oauth.music.live",
    "binding": BINDING,
    "granted_scopes": ["read", "admin"],
    "unexpected_scopes": ["admin"],
    "missing_scopes": [],
    "access_expires_in": 3600,
    "refresh_expires_at": None,
    "consented_at": "2026-10-17T09:00:00Z",
    "grant_expires_at": "2027-04-15T09:00:00Z",
    "persisted": True,
    "seed_note": "The env seed MUSIC_REFRESH is now ignored (reseed: never). You may remove it.",
}
HEADER = (
    "Credential   music (public client, PKCE S256, rotating refresh tokens)\n"
    "Binding      token endpoint https://accounts.example:443\n"
    "             access tokens to https://api.example:443\n"
    "Scopes       read\n"
    "\n"
    "Open this URL in a browser and approve:\n"
    f"  {AUTHORIZE}\n"
)
STORED = (
    "Stored the refresh token for music as oauth.music.live.\n"
    "Granted: read admin\n"
    "The grant ends at 2027-04-15T09:00:00Z; run login again before then.\n"
    "The env seed MUSIC_REFRESH is now ignored (reseed: never). You may remove it.\n"
)


def paste_text(how: str) -> str:
    return (
        "\nYour browser will then try to open http://127.0.0.1/callback?... and fail to load. "
        "That is\nexpected. Copy the full address from the address bar and paste it here "
        f"({how}, 10 minutes):\n"
    )


class FakeAdmin:
    """The admin socket, answering each method and path with a canned answer."""

    def __init__(self) -> None:
        self.answers: dict[tuple[str, str], tuple[int, dict[str, Any]]] = {
            ("POST", "/oauth/music/login"): (200, STARTED),
            ("POST", "/oauth/music/complete"): (200, COMPLETED),
            ("DELETE", "/oauth/flows/flow-0001"): (200, {"cancelled": True}),
        }
        self.requests: list[tuple[str, str, Any]] = []
        self.timeouts: list[float] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.requests.append((request.method, request.url.raw_path.decode(), body))
        self.timeouts.append(request.extensions["timeout"]["read"])
        status, data = self.answers[(request.method, request.url.raw_path.decode())]
        return httpx.Response(status, json=data)


@pytest.fixture
def admin(monkeypatch: pytest.MonkeyPatch) -> FakeAdmin:
    fake = FakeAdmin()
    monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: httpx.MockTransport(fake.handle))
    return fake


class TTY(io.StringIO):
    """A terminal: the paste must come from getpass. Its stdin is empty, so reading it fails."""

    def isatty(self) -> bool:
        return True


def cli(argv: list[str], stdin: io.StringIO | None = None) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    code = main(argv, stdin=stdin or io.StringIO(), out=out, err=err)
    return code, out.getvalue(), err.getvalue()


def test_login_reads_one_stdin_line_off_a_terminal(admin: FakeAdmin) -> None:
    code, out, err = cli(["login", "music", "--socket", "x"], io.StringIO(PASTED + "\r\nmore\n"))
    assert code == EXIT_OK
    assert out == HEADER + paste_text("one line on stdin") + STORED
    assert err == "UNEXPECTED: admin\n"
    assert admin.requests == [
        ("POST", "/oauth/music/login", {"rebind": False}),
        ("POST", "/oauth/music/complete", {"flow": "flow-0001", "redirect_url": PASTED}),
    ]
    # A login may wait for the token endpoint, and then for a refresh in flight.
    assert admin.timeouts == [76.0, 76.0]
    assert admin_client.LOGIN_TIMEOUT == 20.0 + 41.0 + 15
    assert "fake-code-1" not in out + err
    assert "fake-state-1" not in out + err


def test_login_says_where_a_callback_address_lands(admin: FakeAdmin) -> None:
    """M5 H.6, review finding R16: a credential registered with the portal's callback address
    sends the browser there, and the callback takes no command-line login, so the CLI says to
    paste the address from that tab. ``callback`` is null on every CLI start."""
    callback = "http://localhost:8081/oauth/callback/music"
    started = {**STARTED, "redirect_uri": callback, "callback": None, "callback_address": True}
    admin.answers[("POST", "/oauth/music/login")] = (200, started)
    code, out, _ = cli(["login", "music", "--socket", "x"], io.StringIO(PASTED + "\n"))
    assert code == EXIT_OK
    assert (
        out
        == HEADER
        + (
            "\nYour browser will land on the portal's callback, which doesn't take a command-line "
            "login:\ncopy the full address from that tab's address bar and paste it here (one line "
            "on stdin, 10 minutes):\n"
        )
        + STORED
    )
    # Without the key (an older vault) or with it false, the loopback text as before.
    for value in (False, None):
        started = {**STARTED, "callback": None, "callback_address": value}
        admin.answers[("POST", "/oauth/music/login")] = (200, started)
        _, out, _ = cli(["login", "music", "--socket", "x"], io.StringIO(PASTED + "\n"))
        assert out == HEADER + paste_text("one line on stdin") + STORED


def test_login_reads_the_paste_hidden_on_a_terminal(
    admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompts: list[str] = []

    def hidden(prompt: str) -> str:
        prompts.append(prompt)
        return f"  {PASTED}  "

    monkeypatch.setattr(getpass, "getpass", hidden)
    code, out, err = cli(["login", "music", "--socket", "x"], TTY())
    assert code == EXIT_OK
    assert prompts == ["> "]
    assert out == HEADER + paste_text("input hidden") + STORED
    assert admin.requests[-1] == (
        "POST",
        "/oauth/music/complete",
        {"flow": "flow-0001", "redirect_url": PASTED},
    )
    assert PASTED not in out + err


def test_login_start_prints_the_url_and_the_flow(admin: FakeAdmin) -> None:
    code, out, err = cli(["login", "music", "--start", "--rebind", "--socket", "x"])
    assert code == EXIT_OK
    assert out == HEADER + (
        "\nThen, within 10 minutes, run: zoeymcp login music --flow=flow-0001\n"
        "and give it the address your browser was sent to.\n"
    )
    assert err == ""
    assert admin.requests == [("POST", "/oauth/music/login", {"rebind": True})]


def test_login_flow_completes_from_stdin(admin: FakeAdmin) -> None:
    argv = ["login", "music", "--flow", "flow-0001", "--socket", "x"]
    code, out, err = cli(argv, io.StringIO(PASTED))
    assert code == EXIT_OK
    assert out == STORED
    assert err == "UNEXPECTED: admin\n"
    assert admin.requests == [
        ("POST", "/oauth/music/complete", {"flow": "flow-0001", "redirect_url": PASTED})
    ]
    assert admin.timeouts == [76.0]


def test_a_flow_id_may_start_with_a_dash(admin: FakeAdmin) -> None:
    """Flow IDs are URL-safe base64, so one in 64 starts with a dash. The command --start
    prints still parses."""
    admin.answers[("POST", "/oauth/music/login")] = (200, {**STARTED, "flow": "-flow-0001"})
    code, out, _ = cli(["login", "music", "--start", "--socket", "x"])
    assert code == EXIT_OK
    [printed] = re.findall(r"run: zoeymcp (login .*)$", out, re.MULTILINE)
    code, out, _ = cli([*shlex.split(printed), "--socket", "x"], io.StringIO(PASTED))
    assert (code, out) == (EXIT_OK, STORED)
    assert admin.requests[-1] == (
        "POST",
        "/oauth/music/complete",
        {"flow": "-flow-0001", "redirect_url": PASTED},
    )


def test_login_start_and_flow_exclude_each_other() -> None:
    with pytest.raises(SystemExit) as info:
        main(["login", "music", "--start", "--flow", "f"], out=io.StringIO(), err=io.StringIO())
    assert info.value.code == 2


def test_login_shows_a_rebinding(admin: FakeAdmin) -> None:
    old = {"origins": ["https://old.example:443"]}
    started = {**STARTED, "binding_change": {"old": old, "new": BINDING}}
    admin.answers[("POST", "/oauth/music/login")] = (200, started)
    code, out, _ = cli(["login", "music", "--start", "--rebind", "--socket", "x"])
    assert code == EXIT_OK
    assert "Rebinding    was origins https://old.example:443\nScopes       read\n" in out


@pytest.mark.parametrize(
    ("replaced", "first"),
    [("portal", "Replaced a login pending in the portal.\n"), ("cli", ""), (None, "")],
)
def test_login_says_it_replaced_a_portal_login(
    admin: FakeAdmin, replaced: str | None, first: str
) -> None:
    admin.answers[("POST", "/oauth/music/login")] = (200, {**STARTED, "replaced": replaced})
    code, out, err = cli(["login", "music", "--start", "--socket", "x"])
    assert code == EXIT_OK
    assert err == ""
    assert out.startswith(first + HEADER)


def test_login_describes_a_confidential_client_without_scopes(admin: FakeAdmin) -> None:
    started = {**STARTED, "client_auth": "post", "rotates": False, "requested_scopes": []}
    admin.answers[("POST", "/oauth/music/login")] = (200, started)
    _, out, _ = cli(["login", "music", "--start", "--socket", "x"])
    assert out.startswith(
        "Credential   music (confidential client, PKCE S256, non-rotating refresh tokens)\n"
    )
    assert "Scopes       (none requested)\n" in out


@pytest.mark.parametrize("stdin", ["", "\n", "   \n"])
def test_login_without_a_paste_cancels_the_flow(admin: FakeAdmin, stdin: str) -> None:
    code, _, err = cli(["login", "music", "--socket", "x"], io.StringIO(stdin))
    assert code == EXIT_FINDINGS
    assert err == "zoeymcp login: no address given\n"
    assert admin.requests[-1] == ("DELETE", "/oauth/flows/flow-0001", None)


@pytest.mark.parametrize("raised", [KeyboardInterrupt, EOFError])
def test_ctrl_c_cancels_the_flow(
    admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch, raised: type[BaseException]
) -> None:
    def interrupted(prompt: str) -> str:
        raise raised

    monkeypatch.setattr(getpass, "getpass", interrupted)
    code, _, err = cli(["login", "music", "--socket", "x"], TTY())
    assert code == EXIT_FINDINGS
    assert err == "zoeymcp login: cancelled\n"
    assert admin.requests[-1] == ("DELETE", "/oauth/flows/flow-0001", None)
    assert len(admin.requests) == 2


@pytest.mark.parametrize("raised", [KeyboardInterrupt, EOFError])
def test_ctrl_c_cancels_a_flow_given_by_id(
    admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch, raised: type[BaseException]
) -> None:
    def interrupted(prompt: str) -> str:
        raise raised

    monkeypatch.setattr(getpass, "getpass", interrupted)
    code, out, err = cli(["login", "music", "--flow", "flow-0001", "--socket", "x"], TTY())
    assert (code, out, err) == (EXIT_FINDINGS, "", "zoeymcp login: cancelled\n")
    assert admin.requests == [("DELETE", "/oauth/flows/flow-0001", None)]


def test_no_paste_cancels_a_flow_given_by_id(admin: FakeAdmin) -> None:
    code, _, err = cli(["login", "music", "--flow", "flow-0001", "--socket", "x"])
    assert (code, err) == (EXIT_FINDINGS, "zoeymcp login: no address given\n")
    assert admin.requests == [("DELETE", "/oauth/flows/flow-0001", None)]


def test_a_failed_cancel_still_reports_the_interruption(
    admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(prompt: str) -> str:
        raise KeyboardInterrupt

    monkeypatch.setattr(getpass, "getpass", interrupted)
    admin.answers[("DELETE", "/oauth/flows/flow-0001")] = (500, {"error": "boom"})
    code, _, err = cli(["login", "music", "--socket", "x"], TTY())
    assert (code, err) == (EXIT_FINDINGS, "zoeymcp login: cancelled\n")


def test_a_login_kept_only_in_memory_exits_1(admin: FakeAdmin) -> None:
    completed = {**COMPLETED, "persisted": False, "seed_note": None, "grant_expires_at": None}
    completed |= {"unexpected_scopes": [], "missing_scopes": ["write", "delete"]}
    completed |= {"refresh_expires_at": "2026-10-18T09:00:00Z"}
    admin.answers[("POST", "/oauth/music/complete")] = (200, completed)
    argv = ["login", "music", "--flow", "flow-0001", "--socket", "x"]
    code, out, err = cli(argv, io.StringIO(PASTED))
    assert code == EXIT_FINDINGS
    assert out == (
        "Stored the refresh token for music as oauth.music.live.\n"
        "Granted: read admin\n"
        "The refresh token expires at 2026-10-18T09:00:00Z; run login again before then.\n"
    )
    assert err == f"missing: write delete\nzoeymcp login: {NOT_PERSISTED}\n"
    assert NOT_PERSISTED == (
        "kept in memory, not on disk; fix the state volume; "
        "zoeymcp oauth status shows when it is saved"
    )


def test_a_login_with_no_scopes_says_so(admin: FakeAdmin) -> None:
    completed = {**COMPLETED, "granted_scopes": [], "unexpected_scopes": []}
    admin.answers[("POST", "/oauth/music/complete")] = (200, completed)
    argv = ["login", "music", "--flow", "flow-0001", "--socket", "x"]
    _, out, err = cli(argv, io.StringIO(PASTED))
    assert "Granted: (no scopes)\n" in out
    assert err == ""


def test_login_errors(admin: FakeAdmin) -> None:
    old = {"origins": ["https://old.example:443"]}
    refusal = {
        "error": "the policy binds this grant differently; pass --rebind to accept",
        "reason": "binding_changed",
        "old": old,
        "new": BINDING,
    }
    admin.answers[("POST", "/oauth/music/login")] = (409, refusal)
    code, out, err = cli(["login", "music", "--socket", "x"])
    assert (code, out) == (EXIT_FINDINGS, "")
    assert err == (
        "zoeymcp login: the policy binds this grant differently; pass --rebind to accept\n"
        "  old: origins https://old.example:443\n"
        "  new: token endpoint https://accounts.example:443, "
        "access tokens to https://api.example:443\n"
    )
    provider = {
        "error": "the provider refused the authorization: access_denied",
        "reason": "provider_error",
        "provider_error": "access_denied",
        "description": "The user said no",
    }
    admin.answers[("POST", "/oauth/music/complete")] = (400, provider)
    code, _, err = cli(["login", "music", "--flow", "f", "--socket", "x"], io.StringIO(PASTED))
    assert code == EXIT_FINDINGS
    assert err == (
        "zoeymcp login: the provider refused the authorization: access_denied\n"
        "  the provider says: The user said no\n"
    )
    admin.answers[("POST", "/oauth/music/complete")] = (400, {**provider, "description": None})
    _, _, err = cli(["login", "music", "--flow", "f", "--socket", "x"], io.StringIO(PASTED))
    assert err == "zoeymcp login: the provider refused the authorization: access_denied\n"
    plain = {"error": "no such login is pending", "reason": "flow_unknown"}
    admin.answers[("POST", "/oauth/music/complete")] = (404, plain)
    _, _, err = cli(["login", "music", "--flow", "f", "--socket", "x"], io.StringIO(PASTED))
    assert err == "zoeymcp login: no such login is pending\n"


def test_a_mixed_up_answer_shows_no_provider_text(admin: FakeAdmin) -> None:
    """M7 D.6: a mismatched or missing iss carries nothing from the answer's error, and a reload
    between start and paste names the issuer terms the flow and the policy hold."""
    for reason, text in (
        ("iss_mismatch", "the response came from a different issuer"),
        ("iss_missing", "the answer has no iss, which this server always sends"),
    ):
        admin.answers[("POST", "/oauth/music/complete")] = (400, {"error": text, "reason": reason})
        _, _, err = cli(["login", "music", "--flow", "f", "--socket", "x"], io.StringIO(PASTED))
        assert err == f"zoeymcp login: {text}\n"
    moved = {
        "error": "the policy changed this credential's issuer or require_iss since the login "
        "started; run login again",
        "reason": "binding_changed",
        "old": {"issuer": "https://accounts.example", "require_iss": True},
        "new": {"issuer": None, "require_iss": True},
    }
    admin.answers[("POST", "/oauth/music/complete")] = (409, moved)
    _, _, err = cli(["login", "music", "--flow", "f", "--socket", "x"], io.StringIO(PASTED))
    assert err == (
        f"zoeymcp login: {moved['error']}\n"
        "  old: issuer https://accounts.example, iss required\n"
        "  new: no issuer, iss required\n"
    )


def test_admin_errors_keep_their_answer(admin: FakeAdmin) -> None:
    admin.answers[("POST", "/oauth/music/login")] = (404, {"error": "nope", "reason": "not_oauth"})
    with pytest.raises(admin_client.AdminUnavailable) as caught:
        admin_client.oauth_login("x", "music", rebind=False)
    assert str(caught.value) == "nope"
    assert caught.value.reason == "not_oauth"
    assert caught.value.data == {"error": "nope", "reason": "not_oauth"}
    admin.answers[("POST", "/oauth/music/login")] = (500, {"reason": 7})
    with pytest.raises(admin_client.AdminUnavailable) as caught:
        admin_client.oauth_login("x", "music", rebind=False)
    assert str(caught.value) == "HTTP 500"
    assert caught.value.reason is None
    assert admin_client.AdminUnavailable("x").data == {}


def test_client_credentials_login_is_a_test_fetch(admin: FakeAdmin) -> None:
    fetched = {**COMPLETED, "slot": "cc:music", "granted_scopes": ["read"]}
    fetched |= {"unexpected_scopes": [], "missing_scopes": ["write"], "access_expires_in": 600}
    admin.answers[("POST", "/oauth/music/login")] = (200, fetched)
    code, out, err = cli(["login", "music", "--socket", "x"])
    assert code == EXIT_OK
    assert out == (
        "The client credentials of music work: the token endpoint issued an access token "
        "for 600 s. Nothing was stored.\nGranted: read\n"
    )
    assert err == "missing: write\n"
    assert len(admin.requests) == 1


def test_read_redirect_url() -> None:
    assert admin_client.read_redirect_url(io.StringIO(" x \r\nsecond\n"), "> ") == "x"
    with pytest.raises(admin_client.AdminUnavailable, match="no address given"):
        admin_client.read_redirect_url(io.StringIO(""), "> ")


def test_secret_set_and_delete_wait_for_a_refresh_in_flight(admin: FakeAdmin) -> None:
    admin.answers[("PUT", "/secrets/music-secret")] = (200, {"name": "music-secret"})
    admin.answers[("DELETE", "/secrets/music-secret")] = (200, {"deleted": True})
    admin_client.secret_set("x", "music-secret", "value", None)
    admin_client.secret_delete("x", "music-secret")
    # The vault may wait for a refresh of a credential that uses the secret.
    assert admin.timeouts == [56.0, 56.0]
    assert admin_client.SECRET_TIMEOUT == 41.0 + 15


def test_the_admin_timeout_defaults_to_10_s(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/oauth")] = (200, {"credentials": []})
    admin.answers[("POST", "/oauth/music/reset")] = (200, {"credential": "music", "reset": True})
    admin_client.oauth_status("x")
    admin_client.oauth_reset("x", "music")
    admin_client.oauth_cancel("x", "flow-0001")
    assert admin.timeouts == [10.0, 10.0, 10.0]
    assert [r[:2] for r in admin.requests] == [
        ("GET", "/oauth"),
        ("POST", "/oauth/music/reset"),
        ("DELETE", "/oauth/flows/flow-0001"),
    ]


def test_path_segments_are_quoted(admin: FakeAdmin) -> None:
    admin.answers[("DELETE", "/oauth/flows/a%2Fb")] = (200, {"cancelled": False})
    admin_client.oauth_cancel("x", "a/b")
    assert admin.requests == [("DELETE", "/oauth/flows/a%2Fb", None)]


STATUS: dict[str, Any] = {
    "credential": "music",
    "grant": "refresh_token",
    "slot": "oauth.music.live",
    "state": "terminal",
    "refreshing": True,
    "code": "oauth_reconsent_needed",
    "error": "invalid_grant",
    "failures": 1,
    "retry_in": 90.5,
    "access_expires_in": 1500.0,
    "persisted": False,
    "meta": None,
    "upstream": {"code": "upstream_insufficient_scope", "at": "2026-10-17T09:01:00Z"},
    "hint": "run: zoeymcp login music",
    "last_ok_ago": 7200,
    "reconsent_due": "2026-10-20T09:00:00Z",
    "scopes": {"unexpected": ["admin", "root"], "missing": ["read"]},
    "last_failure": {"code": None, "at": "2026-10-16T09:00:00Z"},
    "idle": {"days": 171, "limit": 180},
}
QUIET: dict[str, Any] = {
    **STATUS,
    "state": "ok",
    "refreshing": False,
    "code": None,
    "retry_in": None,
    "access_expires_in": None,
    "persisted": True,
    "upstream": None,
    "hint": None,
    "last_ok_ago": None,
    "reconsent_due": None,
    "scopes": None,
    "last_failure": None,
    "idle": None,
}


# --- gateway-key -------------------------------------------------------------------------------

GATEWAY_KEY = "zgw1-fake-gateway-key-0002"


def gateway_answer(previous: dict[str, Any] | None, **extra: Any) -> dict[str, Any]:
    return {"generation": 2, "key": GATEWAY_KEY, "previous": previous, **extra}


def test_gateway_key_prints_the_key(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/gateway-key")] = (200, gateway_answer(None))
    code, out, err = cli(["gateway-key", "--socket", "x"])
    assert code == EXIT_OK
    assert out == f"ZOEYMCP_GATEWAY_KEY={GATEWAY_KEY}\n"
    assert err == "Generation 2.\n"
    assert admin.requests == [("GET", "/gateway-key", None)]
    assert admin.timeouts == [10.0]


def test_egress_key_prints_the_key(admin: FakeAdmin) -> None:
    """M7 design G.3 (step 17b): the role's key as the compose file reads it, the generation on
    stderr; there is no previous key to show."""
    key = "zeg1-" + "k" * 43
    admin.answers[("GET", "/egress-key")] = (200, {"key": key, "generation": 3})
    code, out, err = cli(["egress-key", "--socket", "x"])
    assert code == EXIT_OK
    assert out == f"ZOEYMCP_EGRESS_KEY={key}\n"
    assert err == "Generation 3.\n"
    assert admin.requests == [("GET", "/egress-key", None)]


def test_egress_key_without_the_vault(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/egress-key")] = (503, {"error": "unavailable"})
    code, out, err = cli(["egress-key", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert out == ""
    assert err.startswith("zoeymcp egress-key: ")


def test_a_stale_egress_role_is_worded() -> None:
    assert main_module.health_action({"kind": "check_egress_role"}) == (
        "check that the egress role runs, reaches the vault, and has the key zoeymcp egress-key "
        "prints"
    )


@pytest.mark.parametrize(
    ("generation", "master_key", "line"),
    [
        (1, "current", "rotation pending: generation 1 accepted until 2026-10-05T21:14:27Z\n"),
        (
            2,
            "previous",
            "rotation pending: generation 2 (previous master key) accepted until "
            "2026-10-05T21:14:27Z\n",
        ),
        (
            1,
            "previous",
            "rotation pending: generations 1 and 2 (previous master key) accepted until "
            "2026-10-05T21:14:27Z\n",
        ),
    ],
)
def test_gateway_key_shows_a_pending_rotation(
    admin: FakeAdmin, generation: int, master_key: str, line: str
) -> None:
    previous = {"generation": generation, "until": 1_791_234_867, "master_key": master_key}
    admin.answers[("GET", "/gateway-key")] = (200, gateway_answer(previous))
    code, out, err = cli(["gateway-key", "--socket", "x"])
    assert code == EXIT_OK
    assert out == f"ZOEYMCP_GATEWAY_KEY={GATEWAY_KEY}\n"
    assert err == "Generation 2.\n" + line


@pytest.mark.parametrize(
    ("retired", "line"),
    [
        (1, "Retired generation 1: only this key is accepted now.\n"),
        (None, "No previous key was accepted.\n"),
    ],
)
def test_gateway_key_retire_previous(admin: FakeAdmin, retired: int | None, line: str) -> None:
    path = "/gateway-key/retire-previous"
    admin.answers[("POST", path)] = (200, gateway_answer(None, retired=retired))
    code, out, err = cli(["gateway-key", "--retire-previous", "--socket", "x"])
    assert code == EXIT_OK
    assert out == f"ZOEYMCP_GATEWAY_KEY={GATEWAY_KEY}\n"
    assert err == "Generation 2.\n" + line
    assert admin.requests == [("POST", path, None)]
    assert admin.timeouts == [10.0]


def test_gateway_key_retire_previous_not_written(admin: FakeAdmin) -> None:
    error = {"error": "kept in memory, not written to disk; check the state volume"}
    admin.answers[("POST", "/gateway-key/retire-previous")] = (500, error)
    code, out, err = cli(["gateway-key", "--retire-previous", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert out == ""
    assert err == (
        "zoeymcp gateway-key: kept in memory, not written to disk; check the state volume\n"
    )


def test_format_status() -> None:
    assert format_status(STATUS) == [
        "music: terminal oauth_reconsent_needed (refreshing)",
        "  hint: run: zoeymcp login music",
        "  retry in 90 s",
        "  access token expires in 25 min",
        "  last success 2 h ago",
        "  WARNING re-consent due by 2026-10-20T09:00:00Z",
        "  UNEXPECTED scopes: admin root",
        "  missing scopes: read",
        "  WARNING an upstream said upstream_insufficient_scope at 2026-10-17T09:01:00Z",
        "  WARNING last attempt failed: no code at 2026-10-16T09:00:00Z (from stored metadata)",
        "  WARNING unused for 171 days; the provider drops unused grants after 180 "
        "(from stored metadata)",
        "  degraded (not persisted): the store can't be written; check the state volume",
    ]
    assert format_status(QUIET) == ["music: ok"]
    failed = {**QUIET, "last_failure": {"code": "oauth_unavailable", "at": "2026-10-16T09:00:00Z"}}
    assert format_status(failed) == [
        "music: ok",
        "  WARNING last attempt failed: oauth_unavailable at 2026-10-16T09:00:00Z "
        "(from stored metadata)",
    ]
    # An older vault's answer has neither.
    older = {k: v for k, v in QUIET.items() if k not in ("last_failure", "idle")}
    assert format_status(older) == ["music: ok"]
    assert format_status({**QUIET, "scopes": {"unexpected": [], "missing": []}}) == ["music: ok"]
    assert format_status({**QUIET, "last_ok_ago": 0}) == ["music: ok", "  last success 0 s ago"]
    assert format_status({**QUIET, "retry_in": 0.0, "access_expires_in": 0.0}) == [
        "music: ok",
        "  retry in 0 s",
        "  access token expires in 0 s",
    ]


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (0, "0 s"),
        (119.9, "119 s"),
        (120, "2 min"),
        (7199, "119 min"),
        (7200, "2 h"),
        (172799, "47 h"),
        (172800, "2 days"),
    ],
)
def test_duration(seconds: float, text: str) -> None:
    assert duration(seconds) == text


def test_oauth_status_lists_or_filters(admin: FakeAdmin) -> None:
    other = {**QUIET, "credential": "files"}
    admin.answers[("GET", "/oauth")] = (200, {"credentials": [STATUS, other]})
    code, out, err = cli(["oauth", "status", "--socket", "x"])
    assert (code, err) == (EXIT_OK, "")
    assert out == "\n".join([*format_status(STATUS), "files: ok"]) + "\n"
    code, out, _ = cli(["oauth", "status", "files", "--socket", "x"])
    assert (code, out) == (EXIT_OK, "files: ok\n")
    code, out, err = cli(["oauth", "status", "nope", "--socket", "x"])
    assert (code, out) == (EXIT_FINDINGS, "")
    assert err == "zoeymcp oauth status: no oauth2 credential named 'nope'\n"
    admin.answers[("GET", "/oauth")] = (200, {"credentials": []})
    assert cli(["oauth", "status", "--socket", "x"]) == (EXIT_OK, "no oauth2 credentials\n", "")


def test_oauth_reset(admin: FakeAdmin) -> None:
    admin.answers[("POST", "/oauth/music/reset")] = (200, {"credential": "music", "reset": True})
    assert cli(["oauth", "reset", "music", "--socket", "x"]) == (
        EXIT_OK,
        "reset music: the next request that needs a token tries once\n",
        "",
    )
    refusal = {"error": "no oauth2 credential named 'nope'", "reason": "not_oauth"}
    admin.answers[("POST", "/oauth/nope/reset")] = (404, refusal)
    assert cli(["oauth", "reset", "nope", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp oauth reset: no oauth2 credential named 'nope'\n",
    )
    admin.answers[("GET", "/oauth")] = (503, {"error": "OAuth needs the vault's token manager"})
    assert cli(["oauth", "status", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp oauth status: OAuth needs the vault's token manager\n",
    )


# --- health ------------------------------------------------------------------------------------


def health_report(**changes: Any) -> dict[str, Any]:
    """What the vault's GET /health answers for a small deployment, from :mod:`health` itself."""
    from zoeymcp.vault.health import Inputs, Sends, assess
    from zoeymcp.vault.store import origin_binding

    from .test_health import (
        API,
        MAIL,
        MAIL_BINDING,
        OTHER,
        SPOTIFY_ENTRIES,
        entry,
        header,
        make_policy,
        spotify,
        status,
    )

    policy = make_policy({"notes": header(), "music": spotify()}, connectors={"mail": MAIL})
    entries = [
        entry("notes-key", origin_binding([API, OTHER])),
        *SPOTIFY_ENTRIES[:2],
        entry("mail-pass", MAIL_BINDING),
        entry("old-key", origin_binding([API])),
    ]
    failure = {"code": "oauth_unavailable", "at": "2026-10-16T09:00:00Z"}
    last = {"state": "sent", "at": "2026-10-17T08:00:00Z", "smtp_code": 250}
    inputs = Inputs(
        policy,
        entries,
        frozenset({"MAIL_USER"}),
        [status(last_failure=failure)],
        {"mail": Sends(17, 0, last)},
    )
    return {**assess(inputs), **changes}


HEALTH_LINES = [
    "notes (header): info",
    "  info    binding_wider: store:notes-key is bound to more than the policy uses; it works",
    "          run: zoeymcp secret set notes-key",
    "music (oauth2): error",
    "  error   missing: store:music-refresh has no entry",
    "          run: zoeymcp login music",
    "  warning last_failure: last attempt failed: oauth_unavailable at 2026-10-16T09:00:00Z "
    "(from stored metadata)",
    "          run: zoeymcp oauth reset music",
    "connector mail: warning (17 of 20 sends in 24 h)",
    "  warning near_limit: 17 of 20 sends in the last 24 hours",
    "          wait: it clears with time",
    "store: info (5 entries)",
    "  info    unreferenced: nothing in the policy uses store:old-key",
    "          run: zoeymcp secret delete old-key",
    "health: FAILED (1 error(s), 2 warning(s), 2 info)",
]


def test_health_text(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/health")] = (200, health_report())
    text = "".join(f"{line}\n" for line in HEALTH_LINES)
    assert cli(["health", "--socket", "x"]) == (EXIT_FINDINGS, text, "")
    assert admin.requests == [("GET", "/health", None)]
    assert admin.timeouts == [10.0]


def test_health_json(admin: FakeAdmin) -> None:
    report = health_report()
    admin.answers[("GET", "/health")] = (200, report)
    code, out, err = cli(["health", "--json", "--socket", "x"])
    assert (code, err) == (EXIT_FINDINGS, "")
    assert out == json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


@pytest.mark.parametrize(
    ("counts", "plain", "strict"),
    [
        ({"error": 0, "warning": 0, "info": 3}, EXIT_OK, EXIT_OK),
        ({"error": 0, "warning": 1, "info": 0}, EXIT_OK, EXIT_FINDINGS),
        ({"error": 1, "warning": 0, "info": 0}, EXIT_FINDINGS, EXIT_FINDINGS),
    ],
)
def test_health_exit_codes(
    admin: FakeAdmin, counts: dict[str, int], plain: int, strict: int
) -> None:
    empty = {"entries": 0, "level": "ok", "findings": []}
    report = {"summary": counts, "credentials": [], "connectors": [], "store": empty}
    admin.answers[("GET", "/health")] = (200, report)
    verdict = "ok" if plain == EXIT_OK else "FAILED"
    tail = f"({counts['error']} error(s), {counts['warning']} warning(s), {counts['info']} info)"
    assert cli(["health", "--socket", "x"]) == (
        plain,
        f"store: ok (0 entries)\nhealth: {verdict} {tail}\n",
        "",
    )
    assert cli(["health", "--strict", "--socket", "x"])[0] == strict
    assert cli(["health", "--strict", "--json", "--socket", "x"])[0] == strict


def test_health_when_the_vault_cant_be_asked(admin: FakeAdmin, tmp_path: Path) -> None:
    admin.answers[("GET", "/health")] = (503, {"error": "starting"})
    assert cli(["health", "--socket", "x"]) == (EXIT_UNREADABLE, "", "zoeymcp health: starting\n")


def test_health_with_no_vault_at_all(tmp_path: Path) -> None:
    code, out, err = cli(["health", "--socket", str(tmp_path / "admin.sock")])
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err.startswith("zoeymcp health: can't reach the vault's admin socket at ")


@pytest.mark.parametrize(
    ("action", "text"),
    [
        (None, None),
        ({"kind": "connect", "credential": "music"}, "run: zoeymcp login music"),
        ({"kind": "reset", "credential": "music"}, "run: zoeymcp oauth reset music"),
        (
            {"kind": "set_secret", "credential": "music", "ref": "store:music-id"},
            "run: zoeymcp secret set music-id",
        ),
        (
            {"kind": "restart", "connector": "mail", "ref": "env:MAIL_USER"},
            "set env MAIL_USER and restart the vault",
        ),
        ({"kind": "delete_secret", "secret": "old"}, "run: zoeymcp secret delete old"),
        ({"kind": "fix_policy", "credential": "music"}, "fix the policy"),
        ({"kind": "wait", "connector": "mail"}, "wait: it clears with time"),
        ({"kind": "check_volume"}, "check the state volume"),
        (
            {"kind": "check_mailbox", "connector": "mail"},
            "check the mailbox for the sends with an unknown outcome",
        ),
        (
            {"kind": "add_passkey"},
            "run: zoeymcp setup-code, and enrol a second passkey with it",
        ),
        (
            {"kind": "review_passkeys"},
            "run: zoeymcp passkeys, and remove any you don't recognize",
        ),
        ({"kind": "reset_passkeys"}, "run: zoeymcp setup-code --reset"),
        (
            {
                "kind": "onboard_again",
                "credential": "notes",
                "command": "zoeymcp login --mcp https://mcp.notes.example/mcp --reregister",
            },
            "run: zoeymcp login --mcp https://mcp.notes.example/mcp --reregister",
        ),
        (
            {
                "kind": "widen_scope",
                "credential": "notes",
                "scope": "notes.read notes.write",
                "fragment": "# zoeymcp: widen the scope of notes\n",
            },
            'merge credentials.notes.scope: "notes.read notes.write" (the fragment is in health '
            "--json), check and reload the policy, then run: zoeymcp login notes",
        ),
        # A newer vault's action: its kind.
        ({"kind": "enrol_elsewhere"}, "enrol_elsewhere"),
    ],
)
def test_health_actions_in_the_clis_words(action: dict[str, str] | None, text: str | None) -> None:
    assert health_action(action) == text


def test_health_shows_hidden_characters(admin: FakeAdmin) -> None:
    """Store entry names and meta are shown as text, never as terminal controls."""
    finding = {
        "code": "unreferenced",
        "level": "info",
        "advisory": False,
        "text": "nothing in the policy uses store:x" + chr(27) + "[2J",
        "action": None,
    }
    store = {"entries": 1, "level": "info", "findings": [finding]}
    report = {
        "summary": {"error": 0, "warning": 0, "info": 1},
        "credentials": [],
        "connectors": [],
        "store": store,
    }
    admin.answers[("GET", "/health")] = (200, report)
    code, out, _ = cli(["health", "--socket", "x"])
    assert code == EXIT_OK
    assert chr(27) not in out
    assert (
        out.splitlines()[1]
        == "  info    unreferenced: nothing in the policy uses store:x[U+001B][2J"
    )


# --- the gateway's environment -----------------------------------------------------------------


def _environment(tmp_path: Path) -> Path:
    environment = tmp_path / "zoeymcp-gateway"
    (environment / "bin").mkdir(parents=True)
    (environment / "bin" / "python").write_bytes(b"")
    return environment


def test_gateway_command_moves_into_the_gateway_environment(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    command = gateway_command(
        ["gateway", "--listen", "0.0.0.0:8090"],
        environment=environment,
        prefix=str(tmp_path / "zoeymcp"),
    )
    python = str(environment / "bin" / "python")
    assert command == [python, "-I", "-m", "zoeymcp", "gateway", "--listen", "0.0.0.0:8090"]


def test_gateway_command_runs_here_inside_the_gateway_environment(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    assert gateway_command(["gateway"], environment=environment, prefix=str(environment)) is None
    # The same directory, spelled another way.
    other_spelling = str(environment / "bin" / "..")
    assert gateway_command(["gateway"], environment=environment, prefix=other_spelling) is None
    (tmp_path / "x").mkdir()
    other_environment = tmp_path / "x" / ".." / "zoeymcp-gateway"
    assert (
        gateway_command(["gateway"], environment=other_environment, prefix=str(environment)) is None
    )


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_gateway_command_runs_here_through_a_symlink(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(environment)
    assert gateway_command(["gateway"], environment=link, prefix=str(environment)) is None
    assert gateway_command(["gateway"], environment=environment, prefix=str(link)) is None


def test_gateway_command_runs_here_without_the_environment(tmp_path: Path) -> None:
    # A development checkout has no second environment.
    absent = tmp_path / "absent"
    assert gateway_command(["gateway"], environment=absent, prefix=str(tmp_path)) is None
    # A directory where the interpreter should be isn't one.
    broken = tmp_path / "broken"
    (broken / "bin" / "python").mkdir(parents=True)
    assert gateway_command(["gateway"], environment=broken, prefix=str(tmp_path)) is None


def test_gateway_command_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert Path("/opt/zoeymcp-gateway") == GATEWAY_ENVIRONMENT
    parameters = inspect.signature(gateway_command).parameters
    assert parameters["environment"].default == Path("/opt/zoeymcp-gateway")
    assert parameters["prefix"].default is None
    # Without a prefix, this interpreter's is used.
    environment = _environment(tmp_path)
    monkeypatch.setattr(sys, "prefix", str(environment))
    assert gateway_command(["gateway"], environment=environment) is None
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    assert gateway_command(["gateway"], environment=environment) is not None


def test_exec_gateway_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, list[str]]] = []
    monkeypatch.setattr(os, "execv", lambda path, args: calls.append((path, args)))
    monkeypatch.setattr(
        main_module, "gateway_command", lambda argv: ["/env/bin/python", "-m", "zoeymcp", *argv]
    )
    exec_gateway_environment(["gateway", "--state", "/state-gateway"])
    assert calls == [
        (
            "/env/bin/python",
            ["/env/bin/python", "-m", "zoeymcp", "gateway", "--state", "/state-gateway"],
        )
    ]
    calls.clear()
    monkeypatch.setattr(main_module, "gateway_command", lambda argv: None)
    exec_gateway_environment(["gateway"])
    assert calls == []


class _Moved(Exception):
    pass


def test_main_moves_only_the_gateway_command(monkeypatch: pytest.MonkeyPatch) -> None:
    moved: list[list[str]] = []

    def move(argv: list[str]) -> None:
        moved.append(list(argv))
        raise _Moved

    monkeypatch.setattr(main_module, "exec_gateway_environment", move)
    with pytest.raises(_Moved):
        main(["gateway", "--listen", "0.0.0.0:8090"])
    assert moved == [["gateway", "--listen", "0.0.0.0:8090"]]
    monkeypatch.setattr(sys, "argv", ["zoeymcp", "gateway"])
    with pytest.raises(_Moved):
        main()
    assert moved[-1] == ["gateway"]
    moved.clear()
    # Other commands run here, even with "gateway" as an argument.
    assert run(["keygen"])[0] == EXIT_OK
    assert run(["check", "--config", "gateway"])[0] == EXIT_UNREADABLE
    with pytest.raises(SystemExit):
        main([])
    assert moved == []


# --- ledger --vault (M5 design J.4, J.5) ---------------------------------------------------------

HEAD = "sha256:" + "a" * 64
ARCHIVED = {
    "name": "archive-1767276000000",
    "first_seq": 0,
    "head_seq": 9,
    "head_hash": HEAD,
    "received_ms": 1_767_276_000_000,
    "size": 5450,
}
CALL_ROW = {
    "kind": "call",
    "seq": 12,
    "ref": "3f9c0000000000aa",
    "at": "2026-10-19T09:12:03Z",
    "client": "agent1",
    "server": "mail",
    "tool": "send" + chr(27) + "[2J",
    "era": "modern",
    "decision": "accept",
    "waited_ms": 8123,
    "outcome": "ok",
    "detail": "sent",
    "writes": 1,
    "writes_sent": 1,
    "writes_unknown": 0,
    "writers": {"asked": "gateway"},
    "not_in_policy": ["client"],
    "journal": [
        {
            "key": "3f9c0000000000aa.1",
            "state": "sent",
            "smtp_code": 250,
            "at": "2026-10-19T09:12:05Z",
        }
    ],
}
LEDGER_ROW = {
    "kind": "recovered",
    "seq": 11,
    "at": "2026-10-19T09:00:00Z",
    "writer": "gateway",
    "fields": {"abandoned": 1, "not_sent": 0, "unknown": 0},
}
PAGE = {
    "state": {
        "state": "ok",
        "head_seq": 12,
        "head_hash": HEAD,
        "start_seq": 0,
        "reported_ago": 12,
        "broken_at": None,
    },
    "rows": [CALL_ROW, LEDGER_ROW],
    "orphans": [
        {
            "connector": "mail",
            "key": "a1b2000000000000.1",
            "state": "sent",
            "at": "2026-10-19T08:01:00Z",
            "flag": "no_ledger_record",
        },
        {
            "connector": "mail",
            "key": "a1b3000000000000.1",
            "state": "sent",
            "at": "2026-10-19T07:01:00Z",
            "flag": "older_than_copy",
        },
        {
            "connector": "mail",
            "key": "a1b4000000000000.1",
            "state": "sending",
            "at": "2026-10-19T06:01:00Z",
            "flag": "not_yet_reported",
        },
        {
            "connector": "mail",
            "key": "a1b5000000000000.1",
            "state": "sent",
            "at": "2026-10-19T05:01:00Z",
            "flag": "a_later_flag",
        },
    ],
    "next": 11,
    "refused": None,
    "archives": [{**ARCHIVED, "dropped": False}],
}
PAGE_LINES = [
    f"copy: ok, head seq 12 ({HEAD}), chain from seq 0, head moved 12 s ago",
    "2026-10-19T09:00:00Z ledger recovered abandoned=1 not_sent=0 unknown=0",
    "2026-10-19T09:12:03Z 3f9c0000000000aa agent1 mail/send[U+001B][2J modern accept ok (sent)",
    "  not in the current policy: client",
    "  send 3f9c0000000000aa.1 sent 250 2026-10-19T09:12:05Z",
    "orphan send a1b2000000000000.1 on mail: sent at 2026-10-19T08:01:00Z "
    "(no_ledger_record: no ledger record holds its call)",
    "orphan send a1b3000000000000.1 on mail: sent at 2026-10-19T07:01:00Z "
    "(older_than_copy: older than the ledger copy: can't be checked)",
    "orphan send a1b4000000000000.1 on mail: sending at 2026-10-19T06:01:00Z "
    "(not_yet_reported: not reported yet)",
    "orphan send a1b5000000000000.1 on mail: sent at 2026-10-19T05:01:00Z (a_later_flag)",
    f"archived archive-1767276000000: seq 0-9 (head {HEAD}), last received "
    "2026-01-01 14:00:00Z, 5450 bytes",
    "older rows: zoeymcp ledger --vault --before 11",
    "each row is as reported by the gateway",
]


def test_ledger_vault_reads_the_copy(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/ledger/reported")] = (200, PAGE)
    code, out, err = cli(["ledger", "--vault", "--socket", "x"])
    assert (code, err) == (EXIT_OK, "")
    assert out.splitlines() == PAGE_LINES
    admin.answers[("GET", "/ledger/reported?before=11")] = (200, PAGE)
    assert cli(["ledger", "--vault", "--before", "11", "--socket", "x"])[0] == EXIT_OK
    assert [path for _, path, _ in admin.requests] == [
        "/ledger/reported",
        "/ledger/reported?before=11",
    ]


def test_ledger_vault_as_json(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/ledger/reported")] = (200, PAGE)
    code, out, _ = cli(["ledger", "--vault", "--format", "json", "--socket", "x"])
    assert code == EXIT_OK
    assert json.loads(out) == PAGE


def test_ledger_vault_says_what_is_wrong(admin: FakeAdmin) -> None:
    refused = {"reason": "fork", "held_seq": 9, "offered_seq": 3, "at": 1_767_276_000_000}
    state = {**PAGE["state"], "state": "fork", "head_seq": None, "broken_at": 4}  # type: ignore[dict-item]
    page = {**PAGE, "state": state, "rows": [], "orphans": [], "next": None}
    page |= {"refused": refused, "archives": [{**ARCHIVED, "dropped": True}]}
    admin.answers[("GET", "/ledger/reported")] = (200, page)
    code, out, _ = cli(["ledger", "--vault", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert out.splitlines() == [
        "copy: fork, nothing reported yet",
        "broken: the copy's files stop chaining at seq 4",
        "refused: fork at seq 3 (held seq 9, 2026-01-01 14:00:00Z); after deciding why, run: "
        "zoeymcp ledger --vault --restart-chain",
        f"archived archive-1767276000000: seq 0-9 (head {HEAD}), last received "
        "2026-01-01 14:00:00Z, 5450 bytes, files dropped",
    ]


def test_ledger_vault_when_the_vault_cant_be_asked(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/ledger/reported")] = (503, {"error": "no copy", "reason": "x"})
    assert cli(["ledger", "--vault", "--socket", "x"]) == (
        EXIT_UNREADABLE,
        "",
        "zoeymcp ledger: no copy\n",
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["--vault", "--verify"],
        ["--vault", "--since", "1d"],
        ["--vault", "--client", "agent1"],
        ["--vault", "check", "ref", "file"],
        ["--restart-chain"],
        ["--before", "3"],
    ],
)
def test_ledger_vault_flags_go_together(admin: FakeAdmin, argv: list[str]) -> None:
    code, out, err = cli(["ledger", *argv, "--socket", "x"])
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err.startswith("zoeymcp ledger: ")
    assert admin.requests == []


PLAN = {
    "state": "fork",
    "refused": {"reason": "fork", "held_seq": 9, "offered_seq": 3, "at": 1_767_276_000_000},
    "archive": {**ARCHIVED, "name": None},
    "drop": [{**ARCHIVED, "name": "archive-1767000000000"}],
}
PLAN_LINES = [
    "the copy is fork: fork at seq 3 (held seq 9, 2026-01-01 14:00:00Z)",
    f"archive: seq 0-9 (head {HEAD}), last received 2026-01-01 14:00:00Z, 5450 bytes",
    f"delete archive-1767000000000: seq 0-9 (head {HEAD}), last received 2026-01-01 14:00:00Z, "
    "5450 bytes; its head stays as an anchor",
    "the next report from the gateway then starts a new chain, on trust",
]
RESTART = "/ledger/reported/restart"


def test_restart_chain_shows_the_plan_and_asks(admin: FakeAdmin) -> None:
    admin.answers[("POST", RESTART)] = (200, {"plan": PLAN})
    code, out, err = cli(
        ["ledger", "--vault", "--restart-chain", "--socket", "x"], io.StringIO("n\n")
    )
    assert (code, err) == (EXIT_FINDINGS, "zoeymcp ledger: not restarted\n")
    assert out == "".join(f"{line}\n" for line in PLAN_LINES) + "Restart the chain? [y/N] "
    assert admin.requests == [("POST", RESTART, {"dry_run": True})]


def test_restart_chain_runs_exactly_the_plan_shown(admin: FakeAdmin) -> None:
    done = {"restarted": {**PLAN, "archive": ARCHIVED}, "head": {}}
    answers = iter([(200, {"plan": PLAN}), (200, done)])
    admin.answers = InTurn(answers)
    code, out, err = cli(
        ["ledger", "--vault", "--restart-chain", "--socket", "x"], io.StringIO("yes\n")
    )
    assert (code, err) == (EXIT_OK, "")
    assert out.endswith(
        "restarted: archived as archive-1767276000000; the next report starts a new chain\n"
    )
    assert admin.requests[1] == ("POST", RESTART, {"plan": PLAN})


def test_restart_chain_refuses_a_plan_that_changed(admin: FakeAdmin) -> None:
    changed = {"error": "changed", "reason": "changed", "plan": PLAN}
    admin.answers = InTurn(iter([(200, {"plan": PLAN}), (409, changed)]))
    code, _, err = cli(
        ["ledger", "--vault", "--restart-chain", "--socket", "x"], io.StringIO("y\n")
    )
    assert code == EXIT_FINDINGS
    assert err == "zoeymcp ledger: the copy changed since this plan; nothing was done; run again\n"


def test_restart_chain_when_nothing_is_refused(admin: FakeAdmin) -> None:
    refused = {"error": "the copy takes reports", "reason": "not_restartable"}
    admin.answers[("POST", RESTART)] = (409, refused)
    code, out, err = cli(["ledger", "--vault", "--restart-chain", "--socket", "x"])
    assert (code, out, err) == (EXIT_UNREADABLE, "", "zoeymcp ledger: the copy takes reports\n")


class InTurn(dict[tuple[str, str], tuple[int, dict[str, Any]]]):
    """Answers taken in turn, whatever the method and path."""

    def __init__(self, answers: Any) -> None:
        super().__init__()
        self.answers = answers

    def __getitem__(self, key: tuple[str, str]) -> tuple[int, dict[str, Any]]:
        answer: tuple[int, dict[str, Any]] = next(self.answers)
        return answer


def test_health_shows_the_ledger_copy(admin: FakeAdmin) -> None:
    finding = {
        "code": "ledger_copy_refused",
        "level": "error",
        "advisory": False,
        "text": "a fork",
        "action": {"kind": "read_ledger"},
    }
    empty = {"entries": 0, "level": "ok", "findings": []}
    copy = {"state": "fork", "head_seq": 9, "reported_ago": 3, "broken_at": None}
    report = {
        "summary": {"error": 1, "warning": 0, "info": 0},
        "credentials": [],
        "connectors": [],
        "store": empty,
        "ledger_copy": {**copy, "level": "error", "findings": [finding]},
    }
    admin.answers[("GET", "/health")] = (200, report)
    code, out, _ = cli(["health", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert out.splitlines()[1:4] == [
        "ledger copy: error (fork, head seq 9)",
        "  error   ledger_copy_refused: a fork",
        "          run: zoeymcp ledger --vault",
    ]
    assert health_action({"kind": "check_gateway"}) == (
        "check that the gateway runs and reaches the vault"
    )


def test_health_shows_the_egress_section_only_with_findings(admin: FakeAdmin) -> None:
    """A route with no credential that the guard refused (M7 design J); a quiet section is
    not printed."""
    finding = {
        "code": "address_refused",
        "level": "error",
        "advisory": False,
        "text": "route files's upstream at files.lan.example:443 was refused",
        "action": {"kind": "fix_policy", "route": "files"},
    }
    empty = {"entries": 0, "level": "ok", "findings": []}
    report = {
        "summary": {"error": 1, "warning": 0, "info": 0},
        "credentials": [],
        "connectors": [],
        "store": empty,
        "egress": {"level": "error", "findings": [finding]},
    }
    admin.answers[("GET", "/health")] = (200, report)
    code, out, _ = cli(["health", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert out.splitlines()[1:-1] == [
        "egress: error",
        "  error   address_refused: route files's upstream at files.lan.example:443 was refused",
        "          fix the policy",
    ]
    report.update(
        summary={"error": 0, "warning": 0, "info": 0}, egress={"level": "ok", "findings": []}
    )
    _, out, _ = cli(["health", "--socket", "x"])
    assert out.splitlines() == [
        "store: ok (0 entries)",
        "health: ok (0 error(s), 0 warning(s), 0 info)",
    ]


@pytest.mark.parametrize(
    ("state", "lines"),
    [
        (
            {"count": 1},
            [
                "passkeys: info (1 enrolled)",
                "  info    passkey_single: only one passkey is enrolled: add a second, so losing "
                "one doesn't lock you out",
                "          run: zoeymcp setup-code, and enrol a second passkey with it",
            ],
        ),
        (
            {"count": 2, "regressed_ago": 0.0},
            [
                "passkeys: warning (2 enrolled)",
                "  warning passkey_counter: a passkey's signature counter went back in the last "
                "30 days: the authenticator may have been copied",
                "          run: zoeymcp passkeys, and remove any you don't recognize",
            ],
        ),
        (
            {"count": 0, "unavailable": True},
            [
                "passkeys: error (can't be verified)",
                "  error   passkeys_unavailable: the passkey file can't be verified (edited, or "
                "written under another master key); portal login is off",
                "          run: zoeymcp setup-code --reset",
            ],
        ),
        ({"count": 3}, ["passkeys: ok (3 enrolled)"]),
    ],
)
def test_health_shows_the_passkeys(
    admin: FakeAdmin, state: dict[str, Any], lines: list[str]
) -> None:
    from zoeymcp.vault.health import PasskeyState, _passkeys

    empty = {"entries": 0, "level": "ok", "findings": []}
    report = {
        "summary": {"error": 0, "warning": 0, "info": 0},
        "credentials": [],
        "connectors": [],
        "store": empty,
        "passkeys": _passkeys(PasskeyState(**state)),
    }
    admin.answers[("GET", "/health")] = (200, report)
    _, out, _ = cli(["health", "--socket", "x"])
    assert out.splitlines()[1:-1] == lines


# --- setup-code, passkeys and sessions (M5 design E) -------------------------------------------

ORIGINS = ["http://localhost:8081", "https://zoeymcp.tailnet.example"]
SETUP_CODE = "AAAQEA-YEAUDA-OCAJBI-FQYDIO"
ISSUED: dict[str, Any] = {
    "code": SETUP_CODE,
    "expires": 1_760_000_900,
    "reset": False,
    "passkeys": 0,
    "origins": ORIGINS,
}
FIRST_LINE = (
    "One-time code, valid for 15 minutes. Open http://localhost:8081 or "
    "https://zoeymcp.tailnet.example and choose Set up.\n"
)
REFUSED_LINE = (
    "If the portal refuses this code before you have used it, someone else has: run zoeymcp "
    "setup-code --reset.\n"
)
TEST_MASTER = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"  # bytes(range(32))


def test_setup_code_prints_the_code_and_where_to_use_it(admin: FakeAdmin) -> None:
    admin.answers[("POST", "/setup-code")] = (200, ISSUED)
    assert cli(["setup-code", "--socket", "x"]) == (
        EXIT_OK,
        f"{SETUP_CODE}\n",
        FIRST_LINE + REFUSED_LINE,
    )
    assert admin.requests == [("POST", "/setup-code", {"reset": False})]
    assert admin.timeouts == [10.0]
    cli(["setup-code", "--reset", "--socket", "x"])
    assert admin.requests[-1] == ("POST", "/setup-code", {"reset": True})


@pytest.mark.parametrize(
    ("changes", "line"),
    [
        ({"passkeys": 1}, "1 passkey is enrolled; enrolling with this code adds one.\n"),
        ({"passkeys": 3}, "3 passkeys are enrolled; enrolling with this code adds one.\n"),
        (
            {"passkeys": 1, "reset": True},
            "1 passkey is enrolled; enrolling with this code removes all of them and ends every "
            "session.\n",
        ),
        (
            {"passkeys": 2, "reset": True},
            "2 passkeys are enrolled; enrolling with this code removes all of them and ends every "
            "session.\n",
        ),
        ({"passkeys": 0, "reset": True}, ""),
        (
            {"passkeys": None},
            "The passkey file can't be verified: only a code issued with --reset can enrol; run "
            "zoeymcp setup-code --reset.\n",
        ),
        (
            {"passkeys": None, "reset": True},
            "The passkey file can't be verified: enrolling with this code moves it aside, removes "
            "every passkey and ends every session.\n",
        ),
    ],
)
def test_setup_code_says_what_enrolling_does(
    admin: FakeAdmin, changes: dict[str, Any], line: str
) -> None:
    admin.answers[("POST", "/setup-code")] = (200, {**ISSUED, **changes})
    _, _, err = cli(["setup-code", "--socket", "x"])
    assert err == FIRST_LINE + line + REFUSED_LINE


@pytest.mark.parametrize(
    ("origins", "line"),
    [
        (["http://localhost:8081"], "Open http://localhost:8081 and choose Set up."),
        ([], "The policy has no admin block, so no portal takes it yet."),
    ],
)
def test_setup_code_names_the_origins(admin: FakeAdmin, origins: list[str], line: str) -> None:
    admin.answers[("POST", "/setup-code")] = (200, {**ISSUED, "origins": origins})
    _, _, err = cli(["setup-code", "--socket", "x"])
    assert err.splitlines()[0] == f"One-time code, valid for 15 minutes. {line}"


def test_setup_code_errors(admin: FakeAdmin) -> None:
    refusal = {"error": "the setup code couldn't be written", "reason": "not_written"}
    admin.answers[("POST", "/setup-code")] = (500, refusal)
    assert cli(["setup-code", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp setup-code: the setup code couldn't be written\n",
    )


STATUS_PATH = "/setup-code/status?wait=30"
WAITING = "Waiting until a passkey is enrolled with this code (Ctrl-C stops waiting).\n"
ENROLLED = {
    "fingerprint": "3f9a1c0e52d4b7a8",
    "origin": "http://localhost:8081",
    "name": "laptop",
    "created": 1_760_000_043,
}


def status_answer(state: str, **changes: Any) -> tuple[int, dict[str, Any]]:
    answer = {"state": state, "expires": 1_760_000_900, "reset": False, "origin": None}
    return 200, {**answer, "passkey": None, **changes}


def test_setup_code_wait_shows_the_enrolled_passkey(admin: FakeAdmin) -> None:
    origin = "http://localhost:8081"
    admin.answers = InTurn(
        iter(
            [
                (200, ISSUED),
                status_answer("pending"),
                status_answer("redeemed", origin=origin),
                status_answer("redeemed", origin=origin),
                status_answer("enrolled", origin=origin, passkey=ENROLLED),
            ]
        )
    )
    code, out, err = cli(["setup-code", "--wait", "--socket", "x"])
    assert code == EXIT_OK
    assert out == (
        f"{SETUP_CODE}\n"
        "enrolled: 3f9a1c0e52d4b7a8 on http://localhost:8081 as laptop at 08:54:03 UTC\n"
    )
    assert err == (
        FIRST_LINE
        + REFUSED_LINE
        + WAITING
        + "Redeemed on http://localhost:8081; waiting for the enrolment.\n"
    )
    assert [request[:2] for request in admin.requests[1:]] == [("GET", STATUS_PATH)] * 4
    assert admin.timeouts[1:] == [40.0] * 4


@pytest.mark.parametrize(
    ("answer", "line"),
    [
        (status_answer("expired"), "the code expired, or was withdrawn, unused; issue a new code"),
        (
            status_answer("expired", origin="http://localhost:8081"),
            "redeemed on http://localhost:8081, but no passkey was enrolled in time; issue a new "
            "code",
        ),
        (
            status_answer("none", expires=None),
            "the vault has a newer code, or restarted: nothing to wait for",
        ),
        (
            status_answer("pending", expires=1_760_000_901),
            "the vault has a newer code, or restarted: nothing to wait for",
        ),
        (
            status_answer("enrolled", expires=1_760_000_901, passkey=ENROLLED),
            "the vault has a newer code, or restarted: nothing to wait for",
        ),
    ],
)
def test_setup_code_wait_ends_without_an_enrolment(
    admin: FakeAdmin, answer: tuple[int, dict[str, Any]], line: str
) -> None:
    admin.answers = InTurn(iter([(200, ISSUED), status_answer("pending"), answer]))
    code, out, err = cli(["setup-code", "--wait", "--socket", "x"])
    assert (code, out) == (EXIT_FINDINGS, f"{SETUP_CODE}\n")
    assert err == FIRST_LINE + REFUSED_LINE + WAITING + f"zoeymcp setup-code: {line}\n"


def test_setup_code_wait_stops_on_ctrl_c(admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch) -> None:
    admin.answers[("POST", "/setup-code")] = (200, ISSUED)

    def interrupted(socket: str, *, wait: int) -> dict[str, Any]:
        raise KeyboardInterrupt

    monkeypatch.setattr(admin_client, "setup_code_status", interrupted)
    code, _, err = cli(["setup-code", "--wait", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert err.endswith(
        WAITING + "zoeymcp setup-code: stopped waiting; the code still works until it expires\n"
    )


def test_setup_code_wait_when_the_vault_goes_away(admin: FakeAdmin) -> None:
    admin.answers = InTurn(iter([(200, ISSUED), (503, {"error": "stopping"})]))
    code, _, err = cli(["setup-code", "--wait", "--socket", "x"])
    assert code == EXIT_FINDINGS
    assert err.endswith(WAITING + "zoeymcp setup-code: stopping\n")


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """``setup-code --state`` as the vault's user, with the test master key."""
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY", TEST_MASTER)
    monkeypatch.delenv("ZOEYMCP_MASTER_KEY_PREVIOUS", raising=False)
    monkeypatch.setattr(main_module, "running_as_root", lambda: False)


def test_setup_code_offline_writes_a_record_the_vault_redeems(
    tmp_path: Path, offline: None
) -> None:
    import asyncio

    from zoeymcp.portal import setupcode
    from zoeymcp.vault.admin import SetupCodes
    from zoeymcp.vault.keys import KeySet

    code, out, err = cli(["setup-code", "--state", str(tmp_path), "--reset"])
    assert code == EXIT_OK
    assert err == "One-time code, valid for 15 minutes. Open the portal and choose Set up.\n" + (
        REFUSED_LINE
    )
    typed = out.strip()
    key = KeySet.from_text(TEST_MASTER).portal_key
    record = setupcode.unseal((tmp_path / "setup.json").read_bytes(), key)
    assert record is not None
    assert (record.sha256, record.reset) == (setupcode.digest(typed), True)
    redeemed = asyncio.run(SetupCodes(tmp_path, key).redeem(typed, origin="http://localhost:8081"))
    assert redeemed == setupcode.Redeemed(record.expires, True)


def test_setup_code_offline_counts_the_passkeys(
    tmp_path: Path, offline: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    from zoeymcp.portal.passkeys import seal

    from .test_passkeys import KEY, OLD, made

    portal = tmp_path / "portal"
    portal.mkdir(mode=0o700)
    (portal / "passkeys.json").write_bytes(seal(made(1, 2), KEY))
    _, _, err = cli(["setup-code", "--state", str(tmp_path)])
    assert err.splitlines()[1] == "2 passkeys are enrolled; enrolling with this code adds one."
    # Under the previous master key during a rotation.
    (portal / "passkeys.json").write_bytes(seal(made(1), OLD))
    _, _, err = cli(["setup-code", "--state", str(tmp_path)])
    assert err.splitlines()[1].startswith("The passkey file can't be verified")
    old_master = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"  # bytes(range(1, 33))
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY_PREVIOUS", old_master)
    _, _, err = cli(["setup-code", "--state", str(tmp_path)])
    assert err.splitlines()[1] == "1 passkey is enrolled; enrolling with this code adds one."
    (portal / "passkeys.json").write_bytes(b"edited")
    _, _, err = cli(["setup-code", "--state", str(tmp_path), "--reset"])
    assert err.splitlines()[1].startswith("The passkey file can't be verified: enrolling")
    (portal / "passkeys.json").unlink()
    (portal / "passkeys.json").mkdir(mode=0o700)
    _, _, err = cli(["setup-code", "--state", str(tmp_path)])
    assert err.splitlines()[1].startswith("The passkey file can't be verified")


def test_setup_code_offline_refusals(
    tmp_path: Path, offline: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = str(tmp_path / "state")
    assert cli(["setup-code", "--state", state, "--wait"]) == (
        EXIT_UNREADABLE,
        "",
        "zoeymcp setup-code: --wait asks the vault, so it can't go with --state\n",
    )
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY", "")
    assert cli(["setup-code", "--state", state]) == (
        EXIT_UNREADABLE,
        "",
        "zoeymcp setup-code: --state needs the vault's master key in ZOEYMCP_MASTER_KEY\n",
    )
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY", "too-short")
    code, out, err = cli(["setup-code", "--state", state])
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err == "zoeymcp setup-code: the master key isn't valid base64url\n"
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY", TEST_MASTER)
    monkeypatch.setenv("ZOEYMCP_MASTER_KEY_PREVIOUS", "too-short")
    assert cli(["setup-code", "--state", state])[0] == EXIT_UNREADABLE
    monkeypatch.delenv("ZOEYMCP_MASTER_KEY_PREVIOUS")
    monkeypatch.setattr(main_module, "running_as_root", lambda: True)
    assert cli(["setup-code", "--state", state]) == (
        EXIT_UNREADABLE,
        "",
        "zoeymcp setup-code: --state won't run as root: the vault's uid couldn't read the file. "
        "Run it as the vault's user.\n",
    )
    assert not (tmp_path / "state").exists()
    monkeypatch.setattr(main_module, "running_as_root", lambda: False)
    (tmp_path / "file").write_bytes(b"")
    code, out, err = cli(["setup-code", "--state", str(tmp_path / "file")])
    assert (code, out) == (EXIT_FINDINGS, "")
    assert err.startswith(f"zoeymcp setup-code: can't write {tmp_path / 'file' / 'setup.json'}: ")


@pytest.mark.parametrize(("uid", "root"), [(0, True), (10001, False), (None, False)])
def test_running_as_root(monkeypatch: pytest.MonkeyPatch, uid: int | None, root: bool) -> None:
    if uid is None:
        monkeypatch.delattr(os, "geteuid", raising=False)
    else:
        monkeypatch.setattr(os, "geteuid", lambda: uid, raising=False)
    assert main_module.running_as_root() is root


LISTED: list[dict[str, Any]] = [
    {
        "fingerprint": "3f9a1c0e52d4b7a8",
        "name": "laptop",
        "rp_id": "localhost",
        "alg": "ES256",
        "synced": True,
        "transports": ["hybrid", "internal"],
        "via": "setup_code",
        "origin": "http://localhost:8081",
        "created": 1_760_000_043,
        "last_used": 1_760_054_400,
    },
    {
        "fingerprint": "0123456789abcdef",
        "name": "security key",
        "rp_id": "zoeymcp.tailnet.example",
        "alg": "EdDSA",
        "synced": False,
        "transports": ["usb"],
        "via": "portal",
        "origin": "https://zoeymcp.tailnet.example",
        "created": 1_759_000_000,
        "last_used": None,
    },
]
LISTED_LINES = [
    "3f9a1c0e52d4b7a8  laptop",
    "  ES256, synced, for localhost; enrolled 2025-10-09T08:54:03Z via setup_code on "
    "http://localhost:8081; last used 2025-10-10",
    "0123456789abcdef  security key",
    "  EdDSA, device-bound, for zoeymcp.tailnet.example; enrolled 2025-09-27T19:06:40Z via "
    "portal on https://zoeymcp.tailnet.example; never used",
]


def test_passkeys_are_listed(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/passkeys")] = (200, {"passkeys": LISTED})
    text = "".join(f"{line}\n" for line in LISTED_LINES)
    assert cli(["passkeys", "--socket", "x"]) == (EXIT_OK, text, "")
    admin.answers[("GET", "/passkeys")] = (200, {"passkeys": []})
    assert cli(["passkeys", "--socket", "x"]) == (EXIT_OK, "no passkeys\n", "")
    unavailable = {"error": "the passkey file can't be verified", "reason": "unavailable"}
    admin.answers[("GET", "/passkeys")] = (503, unavailable)
    assert cli(["passkeys", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp passkeys: the passkey file can't be verified\n",
    )


def test_a_passkey_is_removed(admin: FakeAdmin) -> None:
    path = "/passkeys/3f9a1c0e52d4b7a8"
    removed = {"removed": LISTED[0], "sessions_ended": 2, "remaining": 1}
    admin.answers[("DELETE", path)] = (200, removed)
    assert cli(["passkeys", "--remove", "3f9a1c0e52d4b7a8", "--socket", "x"]) == (
        EXIT_OK,
        f"removed {LISTED_LINES[0]}\n{LISTED_LINES[1]}\n2 session(s) ended; 1 passkey(s) left\n",
        "",
    )
    admin.answers[("DELETE", path)] = (200, {**removed, "remaining": 0})
    code, out, err = cli(["passkeys", "--remove", "3f9a1c0e52d4b7a8", "--socket", "x"])
    assert (code, out.splitlines()[-1]) == (EXIT_OK, "2 session(s) ended; 0 passkey(s) left")
    assert err == "No passkey is left: the portal waits for a setup code (zoeymcp setup-code).\n"
    admin.answers[("DELETE", "/passkeys/0000000000000000")] = (
        404,
        {"error": "no passkey has that fingerprint", "reason": "not_found"},
    )
    assert cli(["passkeys", "--remove", "0000000000000000", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp passkeys: no passkey has that fingerprint\n",
    )
    admin.answers[("DELETE", "/passkeys/a%2Fb")] = (400, {"error": "bad", "reason": "x"})
    assert cli(["passkeys", "--remove", "a/b", "--socket", "x"])[0] == EXIT_FINDINGS


def test_sessions_are_listed_and_ended(admin: FakeAdmin) -> None:
    admin.answers[("GET", "/sessions")] = (200, {"sessions": []})
    assert cli(["sessions", "--socket", "x"]) == (EXIT_OK, "no portal sessions\n", "")
    session = {"session": "ab12", "scope": "full"}
    admin.answers[("GET", "/sessions")] = (200, {"sessions": [session]})
    assert cli(["sessions", "--socket", "x"]) == (
        EXIT_OK,
        '{"scope": "full", "session": "ab12"}\n',
        "",
    )
    admin.answers[("DELETE", "/sessions")] = (200, {"ended": 3})
    assert cli(["sessions", "--end-all", "--socket", "x"]) == (
        EXIT_OK,
        "ended 3 portal session(s)\n",
        "",
    )
    admin.answers[("DELETE", "/sessions")] = (503, {"error": "stopping"})
    assert cli(["sessions", "--end-all", "--socket", "x"]) == (
        EXIT_FINDINGS,
        "",
        "zoeymcp sessions: stopping\n",
    )


# --- login --mcp: onboarding by URL (M7 design D.10-D.12, M.7; step 8b) ---------------------------

URL = "https://mcp.notes.example/mcp"
HOSTILE_URL = "https://mcp.notes.example/a;id"
ISSUER = "https://auth.notes.example"
HARDENED = "docker compose -f deploy/compose.hardened.yaml"
FRAGMENT = (
    "# zoeymcp: onboarding notes (1 of 2). Merge into your policy; nothing here replaces a key "
    'you have.\ncredentials:\n  "notes":\n    kind: "oauth2"\n'
)
PLAN_ROWS = [
    ["Server", URL],
    ["Resource name", "Notes\u202e\x1b[2J"],
    ["Issuer", f"{ISSUER} (the only one the server names)"],
    ["Client", "zc_given (given)"],
]


def discovered(**changes: Any) -> dict[str, Any]:
    """A discover answer for a given public client (M.1)."""
    plan = {"server_url": URL, "issuer": ISSUER, "client_id": "zc_given"}
    answer = {
        "onboarding": "ob-0001",
        "stage": "discovered",
        "expires": 1_800_000_000,
        "names": {"credential": "notes", "route": "notes", "server": "notes", "source": "given"},
        "plan": plan,
        "rows": PLAN_ROWS,
        "allowance": [],
        "draft_check": [{"level": "warning", "path": "routes", "message": "a warning"}],
        "next": [{"do": "make_fragment", "label": "Make the YAML"}],
    }
    return {**answer, **changes}


def registered_next(server_url: str = HOSTILE_URL) -> list[dict[str, Any]]:
    """The vault's own next list after fragment 1, for an inline policy (onboarding.next_for)."""
    record = replace(onboarding_staged("registered"), server_url=server_url)
    return [step.answer() for step in next_for(record, INLINE_SOURCE)]


def made(**changes: Any) -> dict[str, Any]:
    """A fragment answer (M.1's register answer)."""
    answer = {
        "onboarding": "ob-0001",
        "stage": "registered",
        "credential": "notes",
        "client_auth": "none",
        "secret_stored": False,
        "secret_name": None,
        "client_secret_expires_at": None,
        "diff": {"yaml": FRAGMENT, "check": []},
        "next": registered_next(),
    }
    return {**answer, **changes}


@pytest.fixture
def onboard_admin(admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch) -> FakeAdmin:
    """The admin socket answering one public client's onboarding, with no compose variables."""
    for name in (onboard_cli.COMPOSE_CMD_ENV, onboard_cli.EXEC_SERVICE_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv(onboard_cli.REVIEW_SERVICE_ENV, raising=False)
    admin.answers[("POST", "/onboard/discover")] = (200, discovered())
    admin.answers[("POST", "/onboard/ob-0001/fragment")] = (200, made())
    admin.answers[("DELETE", "/onboard/ob-0001")] = (204, {})
    return admin


PUBLIC_ARGV = ["login", "--mcp", URL, "--name", "notes", "--client-id", "zc_given", "--socket", "x"]


def test_login_mcp_writes_fragment_1_to_stdout_and_the_rest_to_stderr(
    onboard_admin: FakeAdmin,
) -> None:
    """J1 for a given public client: the plan, fragment 1 and the next commands, each as typed on
    the host: shell-quoted by the vault (a URL with ;id), prefixed here (M.7, TI-14)."""
    code, out, err = cli([*PUBLIC_ARGV, "--yes"])
    assert (code, out) == (EXIT_OK, FRAGMENT)
    assert onboard_admin.requests == [
        (
            "POST",
            "/onboard/discover",
            {"url": URL, "name": "notes", "client_id": "zc_given"},
        ),
        ("POST", "/onboard/ob-0001/fragment", {"indent": 0}),
    ]
    # Discovery waits for its fetches and lookups (the vault's 30 s and 3 x 5 s).
    assert onboard_admin.timeouts == [60.0, 60.0]
    assert admin_client.ONBOARD_TIMEOUT == fetch.DISCOVERY_DEADLINE + 3 * RESOLVE_TIMEOUT + 15
    assert err == (
        f"Discovering {URL}\n"
        f"  Server                  {URL}\n"
        "  Resource name           Notes[U+202E][U+001B][2J\n"
        f"  Issuer                  {ISSUER} (the only one the server names)\n"
        "  Client                  zc_given (given)\n"
        "check, with this server merged:\n"
        "  warning routes: a warning\n"
        "Wrote fragment 1 of 2 to stdout.\n"
        "Next:\n"
        "  Check fragment 1 with the running policy:\n"
        f'    {HARDENED} run --rm --no-deps -v "$PWD:/w:ro" vault check --with '
        "/w/onboard-notes-1.yaml\n"
        "  Merge it into the policy under ZOEYMCP_CONFIG in the compose form (--for compose), or "
        "print the whole merged block with --print-merged --for compose and replace it\n"
        "  Then check the edited policy:\n"
        f"    {HARDENED} run --rm --no-deps vault check\n"
        "  Commit, then recreate the vault:\n"
        f"    {HARDENED} up -d vault\n"
        "  Then sign in and review:\n"
        f"    {HARDENED} exec vault zoeymcp login --mcp 'https://mcp.notes.example/a;id' "
        "--name notes\n"
    )


def test_the_prefix_comes_from_the_compose_variables(
    onboard_admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OPS-17: an operator with override files sets ZOEYMCP_COMPOSE_CMD; the compose files set
    the services."""
    monkeypatch.setenv(onboard_cli.COMPOSE_CMD_ENV, "docker compose -f deploy/compose.yaml -p mine")
    monkeypatch.setenv(onboard_cli.EXEC_SERVICE_ENV, "zoeymcp")
    code, _, err = cli([*PUBLIC_ARGV, "--yes"])
    assert code == EXIT_OK
    assert "    docker compose -f deploy/compose.yaml -p mine up -d zoeymcp\n" in err
    assert "docker compose -f deploy/compose.yaml -p mine exec zoeymcp zoeymcp login" in err


def test_each_way_a_command_runs() -> None:
    prefix = onboard_cli.Prefix("dc", "my vault", "gw")
    assert prefix.line("zoeymcp x", "exec") == "dc exec 'my vault' zoeymcp x"
    assert prefix.line("zoeymcp x", "exec", piped=True) == "dc exec -T 'my vault' zoeymcp x"
    assert prefix.line("zoeymcp review s", "exec_gateway") == "dc exec gw zoeymcp review s"
    assert prefix.line("check", "run") == "dc run --rm --no-deps 'my vault' check"
    assert prefix.line("check", "run_mount") == (
        "dc run --rm --no-deps -v \"$PWD:/w:ro\" 'my vault' check"
    )
    assert prefix.line("", "up") == "dc up -d 'my vault'"
    assert prefix.line("zoeymcp check --config p.yaml", None) == "zoeymcp check --config p.yaml"
    assert onboard_cli.Prefix.from_environ({}) == onboard_cli.Prefix(
        "docker compose -f deploy/compose.hardened.yaml", "vault", "gateway"
    )


def test_login_mcp_as_json(onboard_admin: FakeAdmin) -> None:
    """D-171: --format json; stdout holds one ASCII JSON document of the vault's answers."""
    code, out, err = cli([*PUBLIC_ARGV, "--yes", "--format", "json"])
    assert code == EXIT_OK
    assert out.isascii()
    assert json.loads(out) == {"discover": discovered(), "fragment": made()}
    assert "Wrote fragment 1 of 2 to stdout." in err


@pytest.mark.parametrize(("answer", "goes_on"), [("y\n", True), ("YES\n", True), ("n\n", False)])
def test_the_operator_confirms_the_client(
    onboard_admin: FakeAdmin, answer: str, goes_on: bool
) -> None:
    code, out, err = cli(PUBLIC_ARGV, io.StringIO(answer))
    assert "\nUse client zc_given at auth.notes.example? [y/N] " in err
    if goes_on:
        assert (code, out) == (EXIT_OK, FRAGMENT)
        return
    assert (code, out) == (EXIT_FINDINGS, "")
    assert err.endswith("zoeymcp login: nothing was registered or stored\n")
    assert onboard_admin.requests[-1] == ("DELETE", "/onboard/ob-0001", None)


def test_a_registration_is_asked_for_by_its_host(onboard_admin: FakeAdmin) -> None:
    plan = discovered(plan={"server_url": URL, "issuer": ISSUER, "client_id": None})
    onboard_admin.answers[("POST", "/onboard/discover")] = (200, plan)
    _, _, err = cli(["login", "--mcp", URL, "--socket", "x"])
    assert "Register a client at auth.notes.example? [y/N] " in err


SECRET_ARGV = [
    "login",
    "--mcp",
    URL,
    "--name",
    "notes",
    "--issuer",
    ISSUER,
    "--client-id",
    "zc_given",
    "--client-secret",
    "--socket",
    "x",
]


def test_a_piped_client_secret_needs_yes(onboard_admin: FakeAdmin) -> None:
    """OPS-4: the confirmation can't come from the stdin the secret does; the refusal names the
    piped exec -T form, and nothing is asked of the vault."""
    code, out, err = cli(SECRET_ARGV, io.StringIO("onboard-cli-secret-0001\n"))
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err == (
        "zoeymcp login: a client secret read from a pipe needs --yes, since the confirmation "
        "can't come from the same stdin: printf '%s' \"$CLIENT_SECRET\" | "
        f"{HARDENED} exec -T vault zoeymcp login --mcp {URL} --name notes --issuer {ISSUER} "
        "--client-id zc_given --client-secret --socket x --yes\n"
    )
    assert onboard_admin.requests == []


def test_a_piped_client_secret_with_yes_goes_only_to_register(onboard_admin: FakeAdmin) -> None:
    secret = "onboard-cli-secret-0001"
    plan = discovered(next=[{"do": "register", "label": "Store the secret and make the YAML"}])
    onboard_admin.answers[("POST", "/onboard/discover")] = (200, plan)
    stored = made(client_auth="basic", secret_stored=True, secret_name="notes-client-secret")
    onboard_admin.answers[("POST", "/onboard/ob-0001/register")] = (200, stored)
    composed = made(diff={"yaml": " " * 8 + FRAGMENT, "check": []})
    onboard_admin.answers[("POST", "/onboard/ob-0001/fragment")] = (200, composed)
    code, out, err = cli([*SECRET_ARGV, "--yes", "--for", "compose"], io.StringIO(secret + "\n"))
    assert (code, out) == (EXIT_OK, " " * 8 + FRAGMENT)
    assert onboard_admin.requests == [
        (
            "POST",
            "/onboard/discover",
            {
                "url": URL,
                "name": "notes",
                "issuer": ISSUER,
                "client_id": "zc_given",
                "secret_given": True,
            },
        ),
        ("POST", "/onboard/ob-0001/register", {"client_secret": secret}),
        ("POST", "/onboard/ob-0001/fragment", {"indent": "compose"}),
    ]
    assert "Stored the client secret as notes-client-secret, bound to the token endpoint" in err
    assert secret not in out + err


def test_a_terminal_reads_the_secret_hidden(
    onboard_admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    prompts: list[str] = []

    def hidden(prompt: str) -> str:
        prompts.append(prompt)
        return "onboard-cli-secret-0002"

    monkeypatch.setattr(getpass, "getpass", hidden)
    stored = made(secret_stored=True, secret_name="notes-client-secret")
    onboard_admin.answers[("POST", "/onboard/ob-0001/register")] = (200, stored)
    code, _, _ = cli([*SECRET_ARGV, "--yes"], TTY())
    assert code == EXIT_OK
    assert prompts == ["Secret value (input hidden): "]
    assert onboard_admin.requests[-1] == (
        "POST",
        "/onboard/ob-0001/register",
        {"client_secret": "onboard-cli-secret-0002"},
    )


@pytest.mark.parametrize(
    "written",
    [
        ["--client-secret", "s3cret-in-argv"],
        ["--client-secret=s3cret-in-argv"],
        ["--client-sec=s3cret-in-argv"],
        ["--client-secret="],
    ],
)
def test_a_client_secret_is_never_an_argument(admin: FakeAdmin, written: list[str]) -> None:
    """--client-secret takes no value, however it is written, and the refusal doesn't echo it
    (D.10, OPS-4)."""
    argv = ["login", "--mcp", URL, "--client-id", "c", "--issuer", ISSUER, *written, "--yes"]
    code, out, err = cli([*argv, "--socket", "x"])
    assert (code, out) == (EXIT_UNREADABLE, "")
    assert err == (
        "zoeymcp login: a client secret is never an argument: give --client-secret alone, and "
        "pipe the secret in with --yes or type it at the hidden prompt\n"
    )
    assert admin.requests == []


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["--mcp", URL, "--start"], "--start and --flow go with a credential, not --mcp"),
        (
            ["--mcp", URL, "--client-secret", "--issuer", ISSUER, "--yes"],
            "--client-secret goes with --client-id",
        ),
        (
            ["--mcp", URL, "--client-id", "c", "--client-secret", "--yes"],
            "--client-secret needs --issuer, the authorization server that issued the client: a "
            "discovered one that differs is refused",
        ),
        (
            ["--mcp", URL, "--client-id", "c", "--client-auth", "post"],
            "--client-auth goes with --client-secret",
        ),
        (
            ["--mcp", URL, "--reregister", "--no-connect"],
            "--no-connect goes with the run after the commit, not with --reregister",
        ),
        (["--mcp", URL, "--indent", "17"], "--indent is 0 to 16"),
        (
            ["--mcp", URL, "--squid-src", "gateway=acl"],
            "--squid-src gateway=acl: write vault=ACL, ACL 1 to 64 letters, digits or underscores",
        ),
        (
            ["--mcp", URL, "--squid-src", "vault=bad-acl"],
            "--squid-src vault=bad-acl: write vault=ACL, ACL 1 to 64 letters, digits or "
            "underscores",
        ),
        (["music", "--plan-only"], "--plan-only goes with --mcp"),
        (["music", "--name", "n", "--yes"], "--name, --yes go with --mcp"),
    ],
)
def test_login_mcp_usage_errors(admin: FakeAdmin, argv: list[str], message: str) -> None:
    code, out, err = cli(["login", *argv, "--socket", "x"])
    assert (code, out, err) == (EXIT_UNREADABLE, "", f"zoeymcp login: {message}\n")
    assert admin.requests == []


@pytest.mark.parametrize("argv", [["music", "--mcp", URL], []])
def test_a_credential_and_mcp_exclude_each_other(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as info, contextlib.redirect_stderr(io.StringIO()):
        main(["login", *argv], out=io.StringIO(), err=io.StringIO())
    assert info.value.code == 2


def test_a_draft_check_error_stops_before_anything_is_asked(onboard_admin: FakeAdmin) -> None:
    error = {"level": "error", "path": "routes[3].prefix", "message": "/notes is taken\x07"}
    fix = {
        "do": "fix_policy",
        "label": "Fix the policy first: check finds 1 error(s) with this server merged",
    }
    plan = discovered(draft_check=[error], next=[fix])
    onboard_admin.answers[("POST", "/onboard/discover")] = (200, plan)
    code, out, err = cli([*PUBLIC_ARGV, "--yes"])
    assert (code, out) == (EXIT_FINDINGS, "")
    assert "  error   routes[3].prefix: /notes is taken[U+0007]\n" in err
    assert err.endswith(f"Next:\n  {fix['label']}\n")
    assert [request[1] for request in onboard_admin.requests] == ["/onboard/discover"]


def test_plan_only_stops_after_the_plan(onboard_admin: FakeAdmin) -> None:
    code, out, err = cli([*PUBLIC_ARGV, "--plan-only"])
    assert (code, out) == (EXIT_OK, "")
    assert err.endswith(
        "Plan only: nothing was registered or stored. The same command without --plan-only "
        "carries on from this plan within 30 minutes.\n"
    )
    assert [request[1] for request in onboard_admin.requests] == ["/onboard/discover"]


def proxy_refusal() -> dict[str, Any]:
    """D.11's answer, as the vault words it (onboarding.allow_hosts)."""
    hosts = allow_hosts([("auth.notes.example", 443), ("mcp.notes.example", 443)], {})
    return {
        "reason": "proxy_refused",
        "error": "Your egress proxy refused the vault's connection to auth.notes.example. Allow "
        "the hosts listed here in it for the vault, then run the same command again.",
        "host": "auth.notes.example",
        "port": 443,
        "status": 403,
        "next": [hosts.answer()],
    }


def test_a_proxy_refusal_names_the_hosts_and_the_command_again(onboard_admin: FakeAdmin) -> None:
    """D.11: the hosts, their Squid lines with the vault's source ACL from --squid-src (OPS-7),
    and this run's argv again, every argument shell-quoted, with -T for a piped stdin and the
    fragment's redirect for a redirected stdout."""
    onboard_admin.answers[("POST", "/onboard/discover")] = (502, proxy_refusal())
    argv = ["login", "--mcp", HOSTILE_URL, "--name", "notes", "--client-id", "zc_given"]
    argv += ["--squid-src", "vault=stack_vault_net", "--socket", "x"]
    code, out, err = cli(argv)
    assert (code, out) == (EXIT_FINDINGS, "")
    assert err == (
        "zoeymcp login: Your egress proxy refused the vault's connection to auth.notes.example. "
        "Allow the hosts listed here in it for the vault, then run the same command again.\n"
        "Next:\n"
        "  Allow these hosts in your proxy for the vault\n"
        "    auth.notes.example:443\n"
        "    mcp.notes.example:443\n"
        "    acl zoeymcp_port_443 port 443\n"
        "    acl zoeymcp_onboard_1 dstdomain -n auth.notes.example\n"
        "    http_access allow stack_vault_net CONNECT zoeymcp_onboard_1 zoeymcp_port_443 "
        "!zoeymcp_private_dst\n"
        "    acl zoeymcp_onboard_2 dstdomain -n mcp.notes.example\n"
        "    http_access allow stack_vault_net CONNECT zoeymcp_onboard_2 zoeymcp_port_443 "
        "!zoeymcp_private_dst\n"
        "  Then run the same command again:\n"
        f"    {HARDENED} exec -T vault zoeymcp login --mcp 'https://mcp.notes.example/a;id' "
        "--name notes --client-id zc_given --squid-src vault=stack_vault_net --socket x "
        "> onboard-notes-1.yaml\n"
    )


def test_the_retry_on_a_terminal_has_no_redirect(
    onboard_admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    onboard_admin.answers[("POST", "/onboard/discover")] = (502, proxy_refusal())
    out, err = TTY(), io.StringIO()
    code = main(["login", "--mcp", URL, "--socket", "x"], stdin=TTY(), out=out, err=err)
    assert code == EXIT_FINDINGS
    assert err.getvalue().endswith(
        f"  Then run the same command again:\n    {HARDENED} exec vault zoeymcp login --mcp {URL} "
        "--socket x\n"
    )


@pytest.mark.parametrize(
    ("answer", "lines"),
    [
        (
            {
                "reason": "as_choice_needed",
                "error": "The server names several authorization servers.",
                "issuers": ["https://a.example", "https://b.example"],
            },
            ["  issuers: https://a.example, https://b.example", "  name one with --issuer"],
        ),
        (
            {"reason": "prm_not_found", "error": "No metadata.", "tried": [f"{URL}/x"]},
            [f"  tried: {URL}/x"],
        ),
        (
            {"reason": "bad_body", "error": "The request didn't fit.", "detail": "scope is bad"},
            ["  scope is bad"],
        ),
        (
            {
                "reason": "diff_invalid",
                "error": "Fails check.",
                "check": [{"level": "error", "path": "routes", "message": "taken"}],
                "secret_deleted": True,
            },
            ["  error   routes: taken", "  The client secret this run stored was deleted again."],
        ),
        (
            {"reason": "not_written", "error": "Not written.", "secret_restored": True},
            ["  The client secret it replaced was put back; the policy still uses it."],
        ),
        (
            {
                "reason": "onboarding_mismatch",
                "error": "Differs.",
                "fields": ["credentials.notes.token_url"],
                "next": [onboard_again(URL).answer()],
            },
            [
                "  differs: credentials.notes.token_url",
                "Next:",
                "  Register a new client:",
                f"    {HARDENED} exec vault zoeymcp login --mcp {URL} --reregister",
            ],
        ),
    ],
)
def test_what_a_refusal_carries_is_shown(
    onboard_admin: FakeAdmin, answer: dict[str, Any], lines: list[str]
) -> None:
    onboard_admin.answers[("POST", "/onboard/discover")] = (409, answer)
    code, _, err = cli([*PUBLIC_ARGV, "--yes"])
    assert code == EXIT_FINDINGS
    assert err.splitlines() == [f"zoeymcp login: {answer['error']}", *lines]


def test_a_refusal_as_json(onboard_admin: FakeAdmin) -> None:
    onboard_admin.answers[("POST", "/onboard/discover")] = (502, proxy_refusal())
    code, out, _ = cli([*PUBLIC_ARGV, "--format", "json"])
    assert code == EXIT_FINDINGS
    refused = json.loads(out)["refused"]
    assert refused["reason"] == "proxy_refused"
    assert [step["do"] for step in refused["next"]] == ["allow_hosts", "retry"]


def test_a_cancelled_onboarding_answers_nothing(onboard_admin: FakeAdmin) -> None:
    assert admin_client.onboard_cancel("x", "ob-0001") == {}


def test_a_registration_from_the_cli(onboard_admin: FakeAdmin) -> None:
    """D.4, D.10: no --client-id, so register (with no secret) makes the client and fragment 1,
    at a portal origin's callback with --callback-origin; the client, its stored secret and the
    secret's expiry are said on stderr, and a fragment at another indent is asked for again."""
    plan = {
        "server_url": URL,
        "issuer": ISSUER,
        "client_id": None,
        "registration": "dcr",
        "registration_endpoint": f"{ISSUER}/register",
    }
    onboard_admin.answers[("POST", "/onboard/discover")] = (200, discovered(plan=plan))
    registered = made(
        client_id="zc_issued",
        client_auth="basic",
        secret_stored=True,
        secret_name="notes-client-secret",
        client_secret_expires_at=1_900_000_000,
        notes=["grant_types_absent"],
    )
    onboard_admin.answers[("POST", "/onboard/ob-0001/register")] = (200, registered)
    origin = "https://zoeymcp.tailnet.example"
    argv = ["login", "--mcp", URL, "--name", "notes", "--callback-origin", origin, "--socket", "x"]
    code, out, err = cli([*argv, "--yes", "--indent", "4"])
    assert (code, out) == (EXIT_OK, FRAGMENT)
    assert onboard_admin.requests == [
        ("POST", "/onboard/discover", {"url": URL, "name": "notes", "callback_origin": origin}),
        ("POST", "/onboard/ob-0001/register", {}),
        ("POST", "/onboard/ob-0001/fragment", {"indent": 4}),
    ]
    assert (
        "Registered client zc_issued at auth.notes.example.\n"
        f"  {NOTES['grant_types_absent']}\n"
        "Stored the client secret as notes-client-secret, bound to the token endpoint and the "
        "server's origin fragment 1 names.\n"
        "The provider expires that secret at 2030-03-17 17:46 UTC; zoeymcp health warns 14 days "
        "before.\n"
        "Wrote fragment 1 of 2 to stdout.\n"
    ) in err
    # Without --yes, the question names the authorization server.
    code, _, err = cli(argv, stdin=io.StringIO("n\n"))
    assert code == EXIT_FINDINGS
    assert "Register a client at auth.notes.example? [y/N] " in err
    # An onboarding's flag, which a login of a named credential doesn't take.
    code, _, err = cli(["login", "music", "--callback-origin", origin, "--socket", "x"])
    assert (code, err) == (
        onboard_cli.EXIT_USAGE,
        "zoeymcp login: --callback-origin goes with --mcp\n",
    )


def test_an_expiry_past_what_a_date_holds(onboard_admin: FakeAdmin) -> None:
    """X7 takes any non-negative integer as the secret's expiry; one past year 9999 is said as
    its epoch second, and the run still finishes, as JSON too."""
    plan = {
        "server_url": URL,
        "issuer": ISSUER,
        "client_id": None,
        "registration": "dcr",
        "registration_endpoint": f"{ISSUER}/register",
    }
    registered = made(
        client_id="zc_issued",
        client_auth="basic",
        secret_stored=True,
        secret_name="notes-client-secret",
        client_secret_expires_at=2**40,
        notes=[],
    )
    argv = ["login", "--mcp", URL, "--name", "notes", "--socket", "x", "--yes"]
    for extra in ([], ["--format", "json"]):
        onboard_admin.answers[("POST", "/onboard/discover")] = (200, discovered(plan=plan))
        onboard_admin.answers[("POST", "/onboard/ob-0001/register")] = (200, registered)
        code, out, err = cli([*argv, *extra])
        assert code == EXIT_OK
        if extra:
            assert json.loads(out)["fragment"]["client_secret_expires_at"] == 2**40
        else:
            assert out == FRAGMENT
            assert (
                f"The provider expires that secret at epoch second {2**40}; zoeymcp health warns "
                "14 days before.\n"
                "Wrote fragment 1 of 2 to stdout.\n"
            ) in err


# --- the second run, through the real admin app (D.12, J1, J3) -----------------------------------


def notes_tools() -> list[Tool]:
    """What the notes server lists in these tests: one tool it marks read-only, one it marks
    destructive, one it doesn't annotate, and one whose description fails the text rules."""

    def tool(name: str, description: str = "Does a thing.", **annotations: bool) -> Tool:
        wire: dict[str, Any] = {
            "name": name,
            "description": description,
            "inputSchema": {"type": "object"},
        }
        if annotations:
            wire["annotations"] = annotations
        return Tool.model_validate(wire)

    return [
        tool("list_notes", readOnlyHint=True),
        tool("delete_note", destructiveHint=True),
        tool("export_all"),
        tool("bad_tool", "Clears \x1b[2J the screen."),
    ]


def notes_report(served: ViewRemoteServer, limits: GatewayLimits) -> dict[str, Any]:
    """The gateway's review of :func:`notes_tools` under ``served``, fitted and through JSON, as
    the review poller posts it."""
    tools = notes_tools()
    evaluation = gateway_pins.evaluate(tools, served, frozenset(), limits)
    answer = gateway_review.report(
        "notes",
        served,
        tools,
        evaluation,
        marks=frozenset(),
        defs=lambda pin: None,
        limits=limits,
        era="modern",
        protocol_version="2026-07-28",
        server_info=None,
        instructions=None,
    )
    fitted: dict[str, Any] = json.loads(json.dumps(fit(answer, limits)))
    return fitted


class Reviews:
    """The vault's review jobs as the admin socket reaches them, on a real job table, with the
    gateway's side done at once: a job queued is claimed at the policy's view and answered with
    the gateway's review of :func:`notes_tools`, read as the vault reads a report, or with
    ``error``, the gateway's error. ``queued`` lists each server a new job was queued for."""

    def __init__(self, policy: Callable[[], Policy]) -> None:
        self.policy = policy
        self.jobs = JobTable(time.monotonic)
        self.jobs.poll_began()
        self.jobs.poll_ended()
        self.queued: list[str] = []
        self.error: dict[str, Any] | None = None

    async def queue_review(self, server: str, owner: Owner, *, fresh: bool = False) -> Job:
        view = build_view(self.policy())
        servers: dict[str, ServerKind] = {
            name: entry.kind
            for name, entry in view.gateway.servers.items()
            if isinstance(entry, ViewRemoteServer | ViewToolkitServer)
        }
        job = self.jobs.queue(server, owner, view.digest, servers, fresh=fresh)
        assert isinstance(job, Job)
        if job.state == "queued":
            self.queued.append(server)
            [claimed] = self.jobs.claim(view.digest)
            body: dict[str, Any] = {"v": 1, "job": claimed.id}
            if self.error is not None:
                body["error"] = self.error
            else:
                served = view.gateway.servers[server]
                assert isinstance(served, ViewRemoteServer)
                body |= {"server": server, "report": notes_report(served, view.gateway.limits)}
            self.jobs.post(read_result(body, view.gateway.limits))
        return job

    async def review_job(self, job_id: str, owner: Owner, *, wait: float = 0) -> Job:
        return self.jobs.get(job_id, owner)


class Vault(httpx.BaseTransport):
    """The vault's admin app, reached as the CLI reaches its socket: the onboarding service on
    onboard_model's in-process server and its authorization server's metadata, a token manager
    and login whose token endpoint is the fake authorization server, and review jobs a gateway
    answers at once (:class:`Reviews`), all on the portal's one event loop."""

    def __init__(self, tmp_path: Path, portal: BlockingPortal) -> None:
        self.portal = portal
        self.policy = parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")
        self.store = SecretStore(tmp_path, KEYS)
        self.store.load()
        self.auth = FakeAuthServer(
            client_id=onboard_model.CLIENT_ID,
            auth="none",
            issuer=onboard_model.ISSUER,
            scopes=("notes.read", "offline_access"),
            registration="none",
            prefix="fake-notes",
        )
        self.auth_app = self.auth.app()
        self.token_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.auth_app))
        self.tokens = TokenManager(self.store, self.token_client)
        self.tokens.configure(self.policy, {})
        onboard = onboard_model.onboard_service(self.store, self.tokens, lambda: self.policy)
        self.setup = SetupCodes(tmp_path, KEYS.portal_key)
        self.reviews = Reviews(lambda: self.policy)
        self.admin = AdminApp(
            self.store,
            KEYS,
            lambda: self.policy,
            self.setup,
            self.tokens,
            onboard=onboard,
            reviews=self.reviews,
        )

    def set_policy(self, policy: Policy) -> None:
        """As a reload does: the admin and the token manager see the same policy."""
        self.policy = policy
        self.tokens.configure(policy, {})

    def registering(self) -> None:
        """The server's metadata names a registration endpoint, which the fake authorization
        server answers (M7 D.4): the vault registers a client when none is given."""
        self.auth.registration = "open"
        onboard = onboard_model.onboard_service(
            self.store, self.tokens, lambda: self.policy, register=self.register
        )
        self.admin = AdminApp(
            self.store,
            KEYS,
            lambda: self.policy,
            self.setup,
            self.tokens,
            onboard=onboard,
            reviews=self.reviews,
        )

    async def register(self, request: httpx.Request) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.auth_app)
        async with httpx.AsyncClient(transport=transport) as client:
            answer = await client.post(
                str(request.url),
                content=request.content,
                headers={"content-type": "application/json"},
            )
        headers = {"content-type": answer.headers["content-type"]}
        return httpx.Response(
            answer.status_code, headers=headers, stream=onboard_model.Body(answer.content)
        )

    def commit(self, fragment: str) -> None:
        """Fragment 1 merged as ``check --with`` merges it, committed and reloaded."""
        base = self.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
        merged = merge(base, load_mapping(fragment), replace=replace_paths(fragment))
        assert isinstance(merged, Merged)
        self.set_policy(Policy.model_validate(merged.data))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        content = request.read()
        path = request.url.raw_path.decode()

        async def call() -> tuple[int, bytes]:
            transport = httpx.ASGITransport(app=self.admin.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://vault-admin") as c:
                answer = await c.request(
                    request.method,
                    path,
                    content=content,
                    headers={"content-type": "application/json"} if content else {},
                )
            return answer.status_code, answer.content

        status, body = self.portal.call(call)
        return httpx.Response(status, content=body)

    def browse(self, url: str) -> str:
        """The operator's browser at the authorization URL: where it is sent back to."""

        async def go() -> str:
            transport = httpx.ASGITransport(app=self.auth_app)
            async with httpx.AsyncClient(transport=transport) as client:
                answer = await client.get(url)
            assert answer.status_code == 302, answer.text
            return answer.headers["location"]

        return self.portal.call(go)


class Browser(io.StringIO):
    """The paste: reading it opens the authorization URL the CLI printed, in the fake's
    browser, and answers the address the browser was sent to."""

    def __init__(self, vault: Vault, shown: io.StringIO, text: str = "") -> None:
        super().__init__(text)
        self.vault = vault
        self.shown = shown
        self.visits = 0

    def readline(self, size: int = -1, /) -> str:  # type: ignore[override]  # as typeshed
        found = re.findall(
            r"^  (https://auth\.notes\.example/authorize\?\S+)$", self.shown.getvalue(), re.M
        )
        if not found:
            return super().readline()
        self.visits += 1
        return self.vault.browse(found[-1]) + "\n"


@pytest.fixture
def vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Vault]:
    for name in (
        onboard_cli.COMPOSE_CMD_ENV,
        onboard_cli.EXEC_SERVICE_ENV,
        onboard_cli.REVIEW_SERVICE_ENV,
    ):
        monkeypatch.delenv(name, raising=False)
    with start_blocking_portal() as portal:
        rig = Vault(tmp_path, portal)
        monkeypatch.setattr(httpx, "HTTPTransport", lambda **_: rig)
        try:
            yield rig
        finally:
            portal.call(rig.token_client.aclose)


def onboarded(vault: Vault, argv: list[str], text: str = "") -> tuple[int, str, str, Browser]:
    out, err = io.StringIO(), io.StringIO()
    stdin = Browser(vault, out, text)
    code = main(argv, stdin=stdin, out=out, err=err)
    return code, out.getvalue(), err.getvalue(), stdin


J1 = ["login", "--mcp", onboard_model.SERVER_URL, "--name", "notes", "--socket", "x"]
# The second run's last step (J1): fragment 2 from the edited choices file.
SECOND_CHOICES = (
    f"{HARDENED} exec -T vault zoeymcp review notes --via vault --choices - < notes.choices > "
    "onboard-notes-2.yaml"
)


def test_j1_through_the_cli_up_to_a_completed_login(vault: Vault) -> None:
    """J1 for a given public client against the fakes: fragment 1, the commit, and the second
    run, which compares, signs in with login's paste flow and names the review next (D.12)."""
    code, fragment, err, _ = onboarded(
        vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"]
    )
    assert code == EXIT_OK, err
    assert fragment.startswith("# zoeymcp: onboarding notes (1 of 2).")
    assert vault.store.names() == []
    vault.commit(fragment)
    code, out, err, browser = onboarded(vault, J1)
    assert code == EXIT_OK, err
    assert browser.visits == 1
    assert "Stored the refresh token for notes as notes-refresh.\n" in out
    assert err.startswith(
        "notes is in the policy and matches what the server publishes "
        f"({onboard_model.SERVER_URL}).\nConnecting:\n"
    )
    assert err.endswith(
        "Reviewing through the gateway: 4 tools (1 the server marks read-only, 1 it marks "
        "otherwise, 2 not annotated, 1 with an error finding).\n"
        f"Next:\n  Choose its tools:\n    {HARDENED} exec vault zoeymcp review notes --via vault "
        "--choose --suggest > notes.choices\n"
        "  Edit notes.choices (skip, allow, approve or decline on each line; decline the tools "
        "you leave out), then make fragment 2:\n"
        f"    {SECOND_CHOICES}\n"
    )
    assert vault.store.names() == ["notes-refresh"]
    assert vault.reviews.queued == ["notes"]
    # Signed in, the run again compares and doesn't sign in over the token it holds (OPS-13).
    code, out, err, browser = onboarded(vault, J1)
    assert (code, out, browser.visits) == (EXIT_OK, "", 0)
    assert "notes already holds a refresh token (stored), so this run doesn't sign in again" in err


def test_j3_through_the_cli_up_to_a_completed_login(vault: Vault) -> None:
    """J3: a given confidential client, its secret piped with --yes and stored under the
    predicted binding, then the second run signs in with it."""
    vault.auth.client_secret = onboard_model.GIVEN_SECRET
    vault.auth.auth = "basic"
    argv = [*J1, "--issuer", onboard_model.ISSUER, "--client-id", onboard_model.CLIENT_ID]
    argv += ["--client-secret", "--yes"]
    code, fragment, err, _ = onboarded(vault, argv, onboard_model.GIVEN_SECRET + "\n")
    assert code == EXIT_OK, err
    assert 'client_secret: "store:notes-client-secret"' in fragment
    assert vault.store.names() == ["notes-client-secret"]
    vault.commit(fragment)
    code, out, err, browser = onboarded(vault, J1)
    assert (code, browser.visits) == (EXIT_OK, 1), err
    assert "(confidential client, PKCE S256" in out
    assert "Stored the refresh token for notes as notes-refresh.\n" in out
    assert onboard_model.GIVEN_SECRET not in out + err + fragment


def test_j1_with_a_registered_client_up_to_a_completed_login(vault: Vault) -> None:
    """J1 (DCR) against the fakes: no client ID, so the vault registers a public client at the
    server's registration endpoint, keeps its ID for a restart, and fragment 1 holds it with the
    credential's own redirect address; the second run signs in with it and deletes the kept ID
    (D.4, D.8, OPS-2)."""
    vault.registering()
    code, fragment, err, _ = onboarded(vault, [*J1, "--yes"])
    assert code == EXIT_OK, err
    [client_id] = vault.auth.registered
    assert f"Registered client {client_id} at auth.notes.example.\n" in err
    credential = load_mapping(fragment)["credentials"]["notes"]
    assert (credential["client_id"], credential["redirect_uri"]) == (
        client_id,
        "http://127.0.0.1/callback/notes",
    )
    assert vault.store.names() == ["notes-client-id"]
    vault.commit(fragment)
    code, out, err, browser = onboarded(vault, J1)
    assert (code, browser.visits) == (EXIT_OK, 1), err
    assert "Stored the refresh token for notes as notes-refresh.\n" in out
    assert vault.store.names() == ["notes-refresh"]


def test_a_refused_registration_shows_the_providers_words(vault: Vault) -> None:
    """D.4: the code and the cleaned description, on stderr only; nothing stored."""
    vault.registering()
    vault.auth.switches = {AuthSwitch.DCR_ERROR_INJECTED}
    code, out, err, _ = onboarded(vault, [*J1, "--yes"])
    assert (code, out) == (EXIT_FINDINGS, "")
    lines = err.splitlines()
    assert (
        "zoeymcp login: The authorization server refused the registration "
        "(invalid_client_metadata), so no client was registered."
    ) in lines
    [said] = [line for line in lines if line.startswith("  the provider says: ")]
    assert "[U+000D]" in said
    assert vault.store.names() == []


def test_a_reregistration_signs_in_over_a_moved_token_endpoint(
    vault: Vault, monkeypatch: pytest.MonkeyPatch
) -> None:
    """OPS-3, D-10: the old client's grant is bound to the old token endpoint's origin, so the
    re-registration's sign-in command passes --rebind, and completes once the endpoint moved."""
    code, fragment, _, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    vault.commit(fragment)
    code, _, err, _ = onboarded(vault, J1)
    assert code == EXIT_OK, err
    held = vault.store.entry("notes-refresh")
    moved = {
        **onboard_model.metadata(),
        "token_endpoint": "https://tokens.notes.example/token",
        "revocation_endpoint": "https://tokens.notes.example/revoke",
    }
    monkeypatch.setattr(onboard_model, "metadata", lambda: moved)
    argv = [*J1, "--client-id", onboard_model.CLIENT_ID, "--reregister", "--yes"]
    code, fragment, err, _ = onboarded(vault, argv)
    assert code == EXIT_OK, err
    assert "# changed: notes (token_url)" in fragment.splitlines()
    assert err.endswith(
        f"  Then sign in with the new client:\n    {HARDENED} exec vault zoeymcp login notes "
        "--rebind\n"
    )
    vault.commit(fragment)
    # Without it, login refuses the old grant's binding.
    code, _, err, _ = onboarded(vault, ["login", "notes", "--socket", "x"])
    assert code != EXIT_OK
    assert "pass --rebind to accept" in err
    code, out, err, browser = onboarded(vault, ["login", "notes", "--rebind", "--socket", "x"])
    assert (code, browser.visits) == (EXIT_OK, 1), err
    assert "Stored the refresh token for notes as notes-refresh.\n" in out
    entry = vault.store.entry("notes-refresh")
    assert held is not None
    assert entry is not None
    assert entry.binding != held.binding


def test_the_second_run_names_each_field_that_differs(vault: Vault) -> None:
    code, fragment, _, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    vault.commit(fragment)
    raw = vault.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    raw["credentials"]["notes"]["token_url"] = f"{onboard_model.ISSUER}/edited"
    vault.set_policy(Policy.model_validate(raw))
    code, out, err, browser = onboarded(vault, J1)
    assert (code, out, browser.visits) == (EXIT_FINDINGS, "", 0)
    assert err.splitlines() == [
        "zoeymcp login: The committed policy differs from what the server publishes now, at "
        "credentials.notes.token_url. Revert the edit, or register a new client with zoeymcp "
        "login --mcp URL --reregister.",
        "  differs: credentials.notes.token_url",
        "Next:",
        "  Register a new client:",
        f"    {HARDENED} exec vault zoeymcp login --mcp {onboard_model.SERVER_URL} --reregister",
    ]


def test_the_shipped_static_key_notes_is_already_configured(vault: Vault) -> None:
    """OPS-14: J1 walked verbatim against the shipped compose file's policy."""
    vault.set_policy(inline_policy(compose("compose.hardened.yaml"), "compose.hardened.yaml"))
    code, out, err, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    assert (code, out) == (EXIT_FINDINGS, "")
    assert err.splitlines() == [
        "zoeymcp login: The server notes already reaches this URL, with a credential of kind "
        "header, not oauth2. Remove it, its route and that credential from the policy and reload "
        "first.",
        "Next:",
        "  Remove gateway.servers.notes, routes notes-mcp and credentials.notes-key from the "
        "policy, reload, then run this command again",
    ]


def test_adopting_a_grant_with_no_connect(vault: Vault) -> None:
    """OPS-13 (D.10): fragment 1 for the other tool's client, committed; --no-connect before the
    seed signs in nothing and says how; the refresh token seeded with secret set; the second run
    then compares and leaves it alone."""
    code, fragment, _, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    vault.commit(fragment)
    code, out, err, browser = onboarded(vault, [*J1, "--no-connect"])
    assert (code, out, browser.visits) == (EXIT_OK, "", 0)
    assert "Not signing in (--no-connect).\nNext:\n  Sign in:\n" in err
    assert f"    {HARDENED} exec vault zoeymcp login notes\n" in err
    seeded = cli(["secret", "set", "notes-refresh", "--socket", "x"], io.StringIO("rt-adopted-1"))
    assert seeded[0] == EXIT_OK, seeded
    code, out, err, browser = onboarded(vault, [*J1, "--no-connect"])
    assert (code, out, browser.visits) == (EXIT_OK, "", 0)
    assert "notes already holds a refresh token (stored)" in err
    assert vault.auth.seen == []


# --- the second run's review, and review --via vault (D.12 step 4, F.5; step 12b2) ---------------


def test_login_then_two_reviews_read_one_report(vault: Vault) -> None:
    """OPS-11: the second run queues the review and prints its counts; review --via vault then
    reads that same report, twice, as --choose and --choices will, until --fresh asks again."""
    code, fragment, _, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    vault.commit(fragment)
    code, _, err, _ = onboarded(vault, J1)
    assert code == EXIT_OK, err
    assert "Reviewing through the gateway: 4 tools (" in err
    assert vault.reviews.queued == ["notes"]
    shown = []
    for _ in range(2):
        code, out, err = cli(["review", "notes", "--via", "vault", "--socket", "x"])
        # Nothing is included yet, so the server lists tools nobody reviewed (M6 design J.5).
        assert (code, err) == (review_view.EXIT_NEEDS_OPERATOR, "")
        shown.append(out)
    assert shown[0] == shown[1]
    assert vault.reviews.queued == ["notes"]
    lines = shown[0].splitlines()
    assert lines[0].startswith("server notes  (remote, vault path ")
    assert any(
        line.startswith("  bad_tool: error /description: control character") for line in lines
    )
    # bad_tool has an error finding, so it can't be pinned: the attention decision leaves it out.
    assert "3 listed that nobody reviewed: delete_note, export_all, list_notes" in lines
    assert "# YAML to commit (declarative mode). Review the changes above first." in lines
    code, _, _ = cli(["review", "notes", "--via", "vault", "--fresh", "--socket", "x"])
    assert code == review_view.EXIT_NEEDS_OPERATOR
    assert vault.reviews.queued == ["notes", "notes"]


def test_j1_choose_then_choices_makes_a_fragment_check_with_accepts(
    vault: Vault, tmp_path: Path
) -> None:
    """J1's choices-file commands (F.5): after the second run, --choose --suggest writes the file
    from the report it queued, the operator edits it, and --choices - reads it back into
    fragment 2, which check --with merges into the committed policy with no error."""
    code, fragment, _, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    vault.commit(fragment)
    assert onboarded(vault, J1)[0] == EXIT_OK
    review = ["review", "notes", "--via", "vault", "--socket", "x"]
    code, written, err = cli([*review, "--choose", "--suggest"])
    assert (code, err) == (review_view.EXIT_NEEDS_OPERATOR, "")  # fragment 2 isn't committed yet
    rows = {line.split()[1]: line.split()[0] for line in written.splitlines() if line[0] != "#"}
    # Only the tool the server marks read-only is allowed; the error finding has no line.
    assert rows == {"delete_note": "skip", "export_all": "skip", "list_notes": "allow"}
    assert "# bad_tool can't be included: error finding (" in written
    choices = written.replace("skip     export_all", "approve  export_all")
    code, fragment_2, err = cli([*review, "--choices", "-"], io.StringIO(choices))
    assert code == review_view.EXIT_NEEDS_OPERATOR, err
    assert vault.reviews.queued == ["notes"]  # one report for the second run and both
    assert err == (
        "zoeymcp review: the file includes 2 tools (1 allow, 1 approve). Prove it with check "
        "--with, commit it and reload, then assign the server to its clients.\n"
    )
    assert fragment_2.startswith(
        "# zoeymcp: review of notes (2 of 2). Replace the tools: and review: blocks of "
        "gateway.servers.notes, then assign notes to its clients.\n"
        "# zoeymcp replace: gateway.servers.notes.tools gateway.servers.notes.review\n"
    )
    entry = load_mapping(fragment_2)["gateway"]["servers"]["notes"]
    assert entry["tools"] == {
        "include": ["export_all", "list_notes"],
        "allow": ["list_notes"],
        "approve": ["export_all"],
    }
    policy_file, fragment_file = tmp_path / "policy.yaml", tmp_path / "onboard-notes-2.yaml"
    base = vault.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    policy_file.write_bytes(policy_emit.document(base).encode())
    fragment_file.write_bytes(fragment_2.encode())
    code, out, err = cli(["check", "--config", str(policy_file), "--with", str(fragment_file)])
    assert code == EXIT_OK, out + err
    assert "with onboard-notes-2.yaml merged: 0 errors, " in out + err
    assert "and replaces gateway.servers.notes.tools and gateway.servers.notes.review" in out + err
    # A file whose pin no longer matches is refused before anything is printed.
    stale = choices.replace(entry["review"]["list_notes"], "sha256:" + "0" * 64)
    code, out, err = cli([*review, "--choices", "-"], io.StringIO(stale))
    assert (code, out) == (2, "")
    assert err.startswith("zoeymcp review: choices_invalid: line ")


def test_j1_a_choices_file_that_declines_the_rest(vault: Vault, tmp_path: Path) -> None:
    """J2's CLI half on J1's commands (M6 design J.3, J.5): a choices file that writes decline
    on the tools the operator leaves out gives fragment 2 a declined block, replaced whole, and
    check --with merges it with no error."""
    code, fragment, _, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    vault.commit(fragment)
    assert onboarded(vault, J1)[0] == EXIT_OK
    review = ["review", "notes", "--via", "vault", "--socket", "x"]
    _, written, _ = cli([*review, "--choose", "--suggest"])
    choices = written.replace("skip     export_all", "approve  export_all")
    choices = choices.replace("skip     delete_note", "decline  delete_note")
    code, fragment_2, err = cli([*review, "--choices", "-"], io.StringIO(choices))
    assert code == review_view.EXIT_NEEDS_OPERATOR, err  # nothing is committed yet
    assert err == (
        "zoeymcp review: the file includes 2 tools (1 allow, 1 approve), and leaves 1 declined. "
        "Prove it with check --with, commit it and reload, then assign the server to its "
        "clients.\n"
    )
    assert fragment_2.startswith(
        "# zoeymcp: review of notes (2 of 2). Replace the tools:, review: and declined: blocks "
        "of gateway.servers.notes, then assign notes to its clients.\n"
        "# zoeymcp replace: gateway.servers.notes.tools gateway.servers.notes.review "
        "gateway.servers.notes.declined\n"
    )
    entry = load_mapping(fragment_2)["gateway"]["servers"]["notes"]
    [pin] = [line.split()[2] for line in choices.splitlines() if "delete_note" in line[:20]]
    assert entry["declined"] == {"delete_note": pin}
    assert "# declined: delete_note (" + pin + ")" in fragment_2
    policy_file, fragment_file = tmp_path / "policy.yaml", tmp_path / "onboard-notes-2.yaml"
    base = vault.policy.model_dump(mode="json", by_alias=True, exclude_defaults=True)
    policy_file.write_bytes(policy_emit.document(base).encode())
    fragment_file.write_bytes(fragment_2.encode())
    code, out, err = cli(["check", "--config", str(policy_file), "--with", str(fragment_file)])
    assert code == EXIT_OK, out + err
    assert "with onboard-notes-2.yaml merged: 0 errors, " in out + err
    assert "gateway.servers.notes.declined" in out + err


def test_the_second_run_as_json_carries_the_counts(vault: Vault) -> None:
    """Run again once signed in, the second run hands back the review the first one queued."""
    code, fragment, _, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    vault.commit(fragment)
    assert onboarded(vault, J1)[0] == EXIT_OK
    code, out, err, _ = onboarded(vault, [*J1, "--format", "json"])
    assert code == EXIT_OK, err
    review = json.loads(out)["review"]
    assert (review["state"], review["reused"]) == ("done", True)
    assert vault.reviews.queued == ["notes"]
    assert review["counts"] == {
        "tools": 4,
        "read_only": 1,
        "marked_otherwise": 1,
        "not_annotated": 2,
        "errors": 1,
    }


def test_a_review_that_fails_says_so_after_the_sign_in(vault: Vault) -> None:
    """The gateway's error ends the job failed: the run signed in, says the review didn't run,
    still prints what is next, and exits 1. The gateway's message stays in its own log."""
    vault.reviews.error = {"status": 502, "code": "upstream", "message": "the listing failed"}
    code, fragment, _, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    vault.commit(fragment)
    code, out, err, browser = onboarded(vault, J1)
    assert (code, browser.visits) == (EXIT_FINDINGS, 1), err
    assert "Stored the refresh token for notes as notes-refresh.\n" in out
    assert "The review didn't run: The gateway couldn't review the server (upstream)." in err
    assert err.endswith(f"    {SECOND_CHOICES}\n")
    assert "the listing failed" not in err


def test_no_connect_before_a_token_queues_no_review(vault: Vault) -> None:
    """Nothing could be reviewed without a token: the run names the sign-in and the review."""
    code, fragment, _, _ = onboarded(vault, [*J1, "--client-id", onboard_model.CLIENT_ID, "--yes"])
    vault.commit(fragment)
    code, _, err, _ = onboarded(vault, [*J1, "--no-connect"])
    assert code == EXIT_OK, err
    assert vault.reviews.queued == []
    assert "Reviewing" not in err
    assert err.endswith(f"    {SECOND_CHOICES}\n")


def job_answer(state: str, **more: Any) -> dict[str, Any]:
    return {"job": "job-0001", "server": "notes", "state": state, **more}


def vault_report() -> dict[str, Any]:
    """A report as the socket answers it, for a server that includes nothing yet."""
    return notes_report(review_server([], {}), GatewayLimits())


def test_review_via_vault_queues_then_reads_the_job(admin: FakeAdmin) -> None:
    report = vault_report()
    admin.answers[("POST", "/review/notes")] = (200, job_answer("queued", reused=False))
    admin.answers[("GET", "/review/jobs/job-0001?wait=30")] = (
        200,
        job_answer("done", report=report),
    )
    code, out, err = cli(["review", "notes", "--via", "vault", "--socket", "x"])
    assert (code, err) == (review_view.EXIT_NEEDS_OPERATOR, "")  # it includes nothing yet
    assert admin.requests == [
        ("POST", "/review/notes", {"fresh": False}),
        ("GET", "/review/jobs/job-0001?wait=30", None),
    ]
    # Queueing may wait out the vault's start grace; a read waits up to 30 s.
    assert admin.timeouts == [60.0, 40.0]
    assert out == "".join(
        f"{review_view.untrusted(line, 1_000_000)}\n"
        for line in review_view.render(report, review_view.Choices())
    )
    cli(["review", "notes", "--via", "vault", "--fresh", "--socket", "x"])
    assert admin.requests[-2] == ("POST", "/review/notes", {"fresh": True})
    code, out, _ = cli(["review", "notes", "--via", "vault", "--format", "json", "--socket", "x"])
    assert json.loads(out)["tools"] == report["tools"]


def test_a_reused_review_is_read_from_the_queue_answer(admin: FakeAdmin) -> None:
    admin.answers[("POST", "/review/notes")] = (
        200,
        job_answer("done", reused=True, report=vault_report()),
    )
    code, _, err = cli(["review", "notes", "--via", "vault", "--socket", "x"])
    assert (code, err) == (review_view.EXIT_NEEDS_OPERATOR, "")
    assert [path for _, path, _ in admin.requests] == ["/review/notes"]


def test_a_failed_review_job_couldnt_run(admin: FakeAdmin) -> None:
    admin.answers[("POST", "/review/notes")] = (200, job_answer("queued", reused=False))
    refused = job_answer(
        "failed",
        error="The gateway couldn't review the server (upstream\x1b[2J).",
        reason="review_failed",
    )
    admin.answers[("GET", "/review/jobs/job-0001?wait=30")] = (502, refused)
    code, out, err = cli(["review", "notes", "--via", "vault", "--socket", "x"])
    assert (code, out) == (2, "")
    assert err == "zoeymcp review: The gateway couldn't review the server (upstream[U+001B][2J).\n"


def test_a_review_job_still_running_when_the_wait_ends(
    admin: FakeAdmin, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(review_view, "JOB_WAIT_MAX", 0)
    admin.answers[("POST", "/review/notes")] = (200, job_answer("queued", reused=False))
    code, out, err = cli(["review", "notes", "--via", "vault", "--socket", "x"])
    assert (code, out) == (2, "")
    assert "the review is still running in the gateway" in err


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["review", "--via", "vault"], "through the vault, name the server to review"),
        (["review", "notes", "--via", "vault", "--clear"], "--clear runs in the gateway's"),
        (["review", "notes", "--via", "gateway", "--fresh"], "--fresh goes with --via vault"),
        (["review", "notes", "--fresh"], "--fresh goes with --via vault"),  # auto, on the gateway's
    ],
)
def test_review_via_usage_errors(admin: FakeAdmin, argv: list[str], message: str) -> None:
    code, out, err = cli([*argv, "--socket", "x"])
    assert (code, out) == (2, "")
    assert message in err
    assert admin.requests == []


def test_auto_takes_the_gateways_socket_when_the_container_has_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(admin_client.GATEWAY_SOCKET_ENV, raising=False)
    monkeypatch.delenv(SOCKET_ENV, raising=False)
    gateway, vault = admin_client.GATEWAY_SOCKET, admin_client.socket_path(None)
    for present, socket, picked in (
        ({gateway, vault}, None, "gateway"),  # the standard tier's one container
        ({gateway}, None, "gateway"),
        ({vault}, None, "vault"),
        (set(), None, "gateway"),  # whose missing socket the error then names
        ({vault}, "/run/elsewhere.sock", "gateway"),  # a --socket is the gateway's
    ):
        assert review_view.pick_via("auto", socket, present.__contains__) == picked
    assert review_view.pick_via("vault", None, lambda path: False) == "vault"
    assert review_view.pick_via("gateway", None, lambda path: True) == "gateway"


def test_the_counts_line() -> None:
    counts = {"tools": 96, "read_only": 64, "marked_otherwise": 0, "not_annotated": 32}
    assert review_view.counts_line({**counts, "errors": 1}) == (
        "96 tools (64 the server marks read-only, 32 not annotated, 1 with an error finding)"
    )
    one = {"tools": 1, "read_only": 0, "marked_otherwise": 1, "not_annotated": 0, "errors": 0}
    assert review_view.counts_line(one) == (
        "1 tool (0 the server marks read-only, 1 it marks otherwise, 0 not annotated)"
    )
    missing: dict[str, Any] = {"name": "x", "state": "missing", "definition": None, "findings": []}
    assert review_view.report_counts({"tools": [missing]})["tools"] == 0


# --- zoeymcp bridge's command line (M7 design C.8, C.10) ----------------------------------------

# What the standard launcher puts first (C.10), before the operator's arguments.
LAUNCHED = [
    "bridge",
    "--control-fd",
    "5",
    "--listen",
    "unix:/run/zoeymcp-bridge-fetch/mcp.sock",
    "--peer-uid",
    "10001",
    "--work-dir",
    "/run/zoeymcp-bridge-fetch/work",
]


def bridge_parse_error(words: list[str]) -> str:
    """The parser's refusal of ``words`` (exit 2), as it prints it."""
    with pytest.raises(SystemExit) as info, contextlib.redirect_stderr(io.StringIO()) as printed:
        main_module._build_parser().parse_args(words)
    assert info.value.code == 2
    return printed.getvalue()


@pytest.mark.parametrize("abbreviated", [["--liste", "127.0.0.1:9"], ["--peer=10002"]])
def test_the_bridge_parser_takes_no_abbreviation(abbreviated: list[str]) -> None:
    words = ["bridge", *abbreviated, "--era", "legacy", "--", "server"]
    assert "unrecognized arguments" in bridge_parse_error(words)


@pytest.mark.parametrize("option", ["--listen", "--peer-uid", "--work-dir", "--control-fd"])
@pytest.mark.parametrize("spelling", ["alone", "joined"])
def test_the_launchers_options_are_refused_a_second_time(option: str, spelling: str) -> None:
    value = {"--listen": "127.0.0.1:9", "--work-dir": "/run/elsewhere"}.get(option, "7")
    again = [option, value] if spelling == "alone" else [f"{option}={value}"]
    words = [*LAUNCHED, "--era", "legacy", *again, "--", "server"]
    assert f"{option} is given once" in bridge_parse_error(words)


def test_the_bridge_parser_leaves_the_commands_words_alone() -> None:
    args = main_module._build_parser().parse_args(
        [*LAUNCHED, "--era", "legacy", "--", "server", "--listen=x", "--work-dir", "y"]
    )
    assert args.listen == "unix:/run/zoeymcp-bridge-fetch/mcp.sock"
    assert (args.peer_uid, args.control_fd) == (10001, 5)
    assert args.work_dir == "/run/zoeymcp-bridge-fetch/work"
    assert args.program == ["server", "--listen=x", "--work-dir", "y"]
    assert (args.max_procs, args.keepalive, args.stderr) == (64, 15.0, "counts")


def test_the_bridge_needs_its_listen_and_era() -> None:
    code, _, err = cli(["bridge", "--", "server"])
    assert code == EXIT_UNREADABLE
    assert err == "zoeymcp bridge: --listen and --era are required\n"


@pytest.mark.skipif(sys.platform == "win32", reason="--work-dir is a POSIX path")
def test_ready_check_tests_the_ready_file(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    words = ["bridge", "--ready-check", "--work-dir", work.as_posix()]
    assert cli(words)[0] == EXIT_FINDINGS
    (work / "ready").write_bytes(b"")
    assert cli(words)[0] == EXIT_OK
    assert cli(["bridge", "--ready-check", "--work-dir", "relative"])[0] == EXIT_FINDINGS


# --- secret set --generate (M7 design C.2, GR-27) ------------------------------------------------

BRIDGE_UPSTREAM = "unix:/run/zoeymcp-bridge-fetch/mcp.sock"


def test_generate_prints_only_the_hash(admin: FakeAdmin) -> None:
    digest = "sha256:" + "ab" * 32
    binding = {"origins": [BRIDGE_UPSTREAM]}
    answer = {"name": "fetch-token", "binding": binding, "sha256": digest}
    admin.answers[("PUT", "/secrets/fetch-token")] = (200, answer)
    code, out, err = cli(["secret", "set", "fetch-token", "--generate", "--socket", "x"])
    assert code == EXIT_OK
    assert out == f"{digest}\n"
    assert admin.requests == [("PUT", "/secrets/fetch-token", {"generate": True})]
    assert err == (
        f"Stored a new token as fetch-token, bound to origins {BRIDGE_UPSTREAM}. Set the line "
        "above as the bridge's ZOEYMCP_BRIDGE_TOKEN_SHA256.\n"
    )


def generating(rig: AdminRig) -> str:
    """The rig's admin with fixed random bytes; the token it then generates."""
    rig.admin = AdminApp(
        rig.store, ADMIN_KEYS, lambda: rig.policy, rig.setup, rig.tokens, random=bytes
    )
    return "A" * 43  # base64url of 32 zero bytes, unpadded


@pytest.mark.anyio
async def test_generate_binds_a_unix_routes_token_to_its_socket(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    policy = bridges_policy({"fetch": BRIDGE_UPSTREAM})
    rig.set_policy(policy)
    token = generating(rig)
    answer = await rig.call("PUT", "/secrets/fetch-token", {"generate": True})
    await rig.token_client.aclose()
    binding = {"origins": [BRIDGE_UPSTREAM]}
    assert derive_binding(policy, "fetch-token") == binding
    expected = {"name": "fetch-token", "binding": binding, "sha256": hash_token(token)}
    assert (answer.status_code, answer.json()) == (200, expected)
    assert token not in answer.text
    assert rig.store.get_for_binding("fetch-token", binding).reveal() == token


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("name", "body", "status", "error"),
    [
        ("broker-refresh", {"generate": True}, 409, admin_module.GENERATE_REFUSED.message),
        ("broker-client-id", {"generate": True}, 409, admin_module.GENERATE_REFUSED.message),
        ("mail-pass", {"generate": True}, 409, admin_module.GENERATE_REFUSED.message),
        # Origins would bind a connector's secret elsewhere; it is still refused.
        (
            "mail-pass",
            {"generate": True, "origins": ["https://x.example"]},
            409,
            admin_module.GENERATE_REFUSED.message,
        ),
        ("music-stats", {"generate": False}, 400, "expected {generate: true, origins?}"),
        (
            "music-stats",
            {"generate": True, "value": "x"},
            400,
            "expected {generate: true, origins?}",
        ),
        (
            "oauth.broker-mcp.live",
            {"generate": True},
            409,
            "managed by the vault; use zoeymcp login",
        ),
    ],
)
async def test_generate_is_refused_for_an_oauth_or_connector_secret(
    tmp_path: Path, name: str, body: dict[str, Any], status: int, error: str
) -> None:
    rig = AdminRig(tmp_path)
    generating(rig)
    answer = await rig.call("PUT", f"/secrets/{name}", body)
    await rig.token_client.aclose()
    assert (answer.status_code, answer.json()) == (status, {"error": error})
    assert rig.store.metadata() == []


@pytest.mark.anyio
async def test_generate_for_a_header_secret_of_the_example(tmp_path: Path) -> None:
    rig = AdminRig(tmp_path)
    token = generating(rig)
    answer = await rig.call("PUT", "/secrets/music-stats", {"generate": True})
    await rig.token_client.aclose()
    assert answer.json()["sha256"] == hash_token(token)
    assert set(answer.json()) == {"name", "binding", "sha256"}
