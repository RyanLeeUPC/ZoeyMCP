"""The one parse-and-check gate (M6 design C, O.3; Y2): each refusal reason and its text, the
first five errors named and every one counted, the environment reaching ``check``, and an
admitted policy carrying its warnings."""

from __future__ import annotations

import pytest

from zoeymcp.common.policy import Finding, PolicyError, check_policy, gate, parse_policy
from zoeymcp.common.policy.gate import SHOWN, Admitted, GateRefused, admit, admit_text

BASE = "version: 1\nmode: declarative\n"
SOURCE = "policy.yaml"


def env_credentials(count: int) -> str:
    """A policy with ``count`` header credentials, each read from ``env:K<n>``."""
    lines = [
        f'  k{n}: {{kind: header, header: X-Key, format: "{{secret}}", secret: "env:K{n}"}}\n'
        for n in range(1, count + 1)
    ]
    return BASE + "credentials:\n" + "".join(lines)


def env_for(count: int) -> dict[str, str]:
    return {f"K{n}": "value" for n in range(1, count + 1)}


def refused_text(text: str, environ: dict[str, str] | None = None) -> GateRefused:
    with pytest.raises(GateRefused) as refused:
        admit_text(text, SOURCE, environ=environ or {})
    return refused.value


def parse_findings(text: str) -> list[Finding]:
    """What ``parse_policy`` reports for ``text``, which the gate's first two steps must keep."""
    with pytest.raises(PolicyError) as refused:
        parse_policy(text, SOURCE)
    return refused.value.findings


def test_shown_is_five() -> None:
    assert SHOWN == 5


def test_the_example_is_admitted_with_its_warning(example_text: str) -> None:
    admitted = admit_text(example_text, SOURCE, environ={})
    assert admitted.policy == parse_policy(example_text, SOURCE)
    assert admitted.findings == tuple(check_policy(admitted.policy, environ={}))
    assert len(admitted.findings) == 1
    assert admitted.findings[0].level == "warning"


def test_a_policy_with_no_finding_is_admitted_with_none() -> None:
    assert admit_text(BASE, SOURCE, environ={}) == Admitted(parse_policy(BASE, SOURCE), ())


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (BASE + "x: !!str y\n", "tags are not allowed (line 3)"),
        ("- a\n", "the top level must be a mapping"),
    ],
)
def test_a_document_the_loader_refuses_is_unreadable(text: str, message: str) -> None:
    refused = refused_text(text)
    assert refused.reason == "unreadable"
    assert refused.source == SOURCE
    assert refused.findings == (Finding("(document)", "error", message),)
    assert list(refused.findings) == parse_findings(text)
    assert refused.count == 1
    assert str(refused) == f"policy {SOURCE} refused: (document): {message}"


def test_a_document_the_schema_refuses_is_invalid() -> None:
    refused = refused_text("version: 2\nmode: declarative\n")
    assert refused.reason == "invalid"
    assert refused.findings == (Finding("version", "error", "Input should be 1"),)
    assert refused.count == 1
    assert str(refused) == f"policy {SOURCE} refused: version: Input should be 1"


def test_an_invalid_refusal_names_the_first_five_of_its_errors() -> None:
    text = BASE + "".join(f"a{n}: 1\n" for n in range(1, 7))
    refused = refused_text(text)
    assert refused.reason == "invalid"
    assert refused.findings == tuple(parse_findings(text)[:5])
    assert refused.count == 6
    extra = "Extra inputs are not permitted"
    assert str(refused) == f"policy {SOURCE} refused: " + "; ".join(
        f"a{n}: {extra}" for n in range(1, 6)
    )


def test_a_check_error_fails_check_and_counts_every_error() -> None:
    refused = refused_text(env_credentials(6))
    assert refused.reason == "fails_check"
    assert refused.source == SOURCE
    # Errors only: each credential's warnings sort among them, and none is named.
    assert refused.findings == tuple(
        Finding(f"credentials.k{n}.secret", "error", f"env var K{n} is not set")
        for n in range(1, 6)
    )
    assert refused.count == 6
    assert str(refused) == f"policy {SOURCE} fails check (6 error(s)): " + "; ".join(
        f"credentials.k{n}.secret: env var K{n} is not set" for n in range(1, 6)
    )


def test_five_errors_are_all_named() -> None:
    refused = refused_text(env_credentials(5))
    assert refused.count == 5
    assert len(refused.findings) == 5
    assert str(refused).startswith(f"policy {SOURCE} fails check (5 error(s)): credentials.k1")
    assert str(refused).endswith("credentials.k5.secret: env var K5 is not set")


def test_check_runs_with_the_environment() -> None:
    text = env_credentials(2)
    refused = refused_text(text, env_for(1))
    assert refused.findings == (Finding("credentials.k2.secret", "error", "env var K2 is not set"),)
    admitted = admit_text(text, SOURCE, environ=env_for(2))
    assert admitted.findings
    assert all(finding.level == "warning" for finding in admitted.findings)
    assert admitted.findings == tuple(check_policy(admitted.policy, environ=env_for(2)))


def test_admit_checks_a_policy_built_in_memory() -> None:
    policy = parse_policy(env_credentials(1), SOURCE)
    with pytest.raises(GateRefused) as refused:
        admit(policy, "revision 3", environ={})
    assert refused.value.reason == "fails_check"
    assert refused.value.source == "revision 3"
    assert str(refused.value) == (
        "policy revision 3 fails check (1 error(s)): credentials.k1.secret: env var K1 is not set"
    )
    admitted = admit(policy, "revision 3", environ=env_for(1))
    assert admitted.policy is policy
    assert admitted.findings == tuple(check_policy(policy, environ=env_for(1)))


def test_a_source_the_caller_couldnt_read_has_the_same_text() -> None:
    """``load_policy``'s text for a source it couldn't read, which is no refusal of the gate's."""
    found = [Finding("(document)", "error", "can't read: gone")]
    text = "policy missing.yaml refused: (document): can't read: gone"
    assert gate.refused_text("missing.yaml", found) == text
    assert str(GateRefused("unreadable", "missing.yaml", found)) == text
    assert str(GateRefused("invalid", "missing.yaml", found)) == text


def test_the_text_names_the_first_errors_only() -> None:
    found = [Finding(f"routes[{n}]", "error", "bad") for n in range(SHOWN + 1)]
    details = "; ".join(f"routes[{n}]: bad" for n in range(SHOWN))
    assert gate.refused_text("p.yaml", found) == f"policy p.yaml refused: {details}"
