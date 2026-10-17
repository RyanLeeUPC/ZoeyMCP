from __future__ import annotations

import asyncio
import io
from pathlib import Path

import pytest
import yaml

from zoeymcp.cli.main import EXIT_FINDINGS, EXIT_OK, main
from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.selftest.cases import CaseFile, parse_cases
from zoeymcp.selftest.runner import Rig, generate_mutants, mutate

from .conftest import EXAMPLE_POLICY

EXAMPLE_CASES = EXAMPLE_POLICY.parent / "selftest-cases.yaml"


def example_policy() -> Policy:
    return parse_policy(EXAMPLE_POLICY.read_text(encoding="utf-8"), "example")


def example_cases() -> CaseFile:
    return parse_cases(EXAMPLE_CASES.read_text(encoding="utf-8"))


def without(cases: CaseFile, name: str) -> CaseFile:
    kept = [c for c in cases.cases if c.name != name]
    assert len(kept) == len(cases.cases) - 1
    return CaseFile(cases=kept)


def test_example_cases_pass(tmp_path: Path) -> None:
    policy = example_policy()
    results = asyncio.run(Rig(policy, tmp_path).run(policy, example_cases()))
    assert [(r.name, r.problems) for r in results if not r.ok] == []


def test_example_cases_kill_every_mutant(tmp_path: Path) -> None:
    policy = example_policy()
    report = asyncio.run(mutate(policy, example_cases(), Rig(policy, tmp_path)))
    assert report.survived == []
    assert len(report.killed) == len(generate_mutants(policy)) >= 10


def test_a_missing_refusal_case_lets_a_mutant_survive(tmp_path: Path) -> None:
    policy = example_policy()
    weaker = without(example_cases(), "stats refuses writes")
    report = asyncio.run(mutate(policy, weaker, Rig(policy, tmp_path)))
    assert report.survived == ["routes[0] (stats).rules[0]: allow every method"]


def test_a_missing_upstream_check_lets_force_go_unnoticed(tmp_path: Path) -> None:
    policy = example_policy()
    cases = example_cases()
    first = cases.cases[0]
    relaxed = first.model_copy(
        update={"expect": first.expect.model_copy(update={"upstream": None})}
    )
    weaker = CaseFile(cases=[relaxed, *cases.cases[1:]])
    report = asyncio.run(mutate(policy, weaker, Rig(policy, tmp_path)))
    assert "routes[0] (stats).query.force.user: no longer forced" in report.survived


def test_equivalent_mutants_are_not_generated() -> None:
    descriptions = [m.description for m in generate_mutants(example_policy())]
    # api_key is the credential's own parameter: the vault always removes it.
    assert not any("api_key no longer stripped" in d for d in descriptions)


def test_failures_are_reported(tmp_path: Path) -> None:
    policy = example_policy()
    text = EXAMPLE_CASES.read_text(encoding="utf-8").replace("user: alice", "user: bob")
    results = asyncio.run(Rig(policy, tmp_path).run(policy, parse_cases(text)))
    [failed] = [r for r in results if not r.ok]
    assert failed.problems == ["query 'user' is 'alice', expected 'bob'"]


def test_credential_false_catches_a_leak(tmp_path: Path) -> None:
    policy = example_policy()
    cases = parse_cases(
        yaml.safe_dump(
            {
                "cases": [
                    {
                        "name": "claims no credential",
                        "request": {
                            "method": "GET",
                            "path": "/stats/2.0/",
                            "caller": {"placeholder": "ph-agent1-stats-4c1f9b27"},
                        },
                        "expect": {"status": 200, "upstream": {"credential": False}},
                    }
                ]
            }
        )
    )
    [result] = asyncio.run(Rig(policy, tmp_path).run(policy, cases))
    assert result.problems == ["a secret reached the upstream"]


def test_case_file_validation() -> None:
    with pytest.raises(ValueError, match="forwarded request"):
        parse_cases(
            "cases:\n  - name: x\n    request: {method: GET, path: /a}\n"
            "    expect: {status: 403, upstream: {path: /a}}\n"
        )


def run_cli(argv: list[str]) -> tuple[int, str]:
    out = io.StringIO()
    return main(argv, out=out, err=io.StringIO()), out.getvalue()


def test_cli_selftest_with_mutation() -> None:
    code, out = run_cli(
        ["selftest", "--config", str(EXAMPLE_POLICY), "--cases", str(EXAMPLE_CASES), "--mutate"]
    )
    assert code == EXIT_OK, out
    assert "16/16 cases passed" in out
    assert "SURVIVED" not in out


def test_cli_selftest_reports_survivors(tmp_path: Path) -> None:
    weaker = without(example_cases(), "stats refuses other API versions")
    cases_file = tmp_path / "weaker.yaml"
    cases_file.write_text(
        yaml.safe_dump({"cases": [c.model_dump() for c in weaker.cases]}), encoding="utf-8"
    )
    code, out = run_cli(
        ["selftest", "--config", str(EXAMPLE_POLICY), "--cases", str(cases_file), "--mutate"]
    )
    assert code == EXIT_FINDINGS
    assert "SURVIVED  routes[0] (stats).rules[0].paths[0]: /2.0/** widened to /**" in out
