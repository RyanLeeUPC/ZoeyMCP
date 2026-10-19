"""The shipped toolkit profiles: each passes ``check`` (with the connector profile it needs), and
its pins are the ones the gateway computes from the example toolkits' code."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
from mcp.types import Tool

from zoeymcp.cli.main import main
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.gateway import pins
from zoeymcp.toolkit import Toolkit

PROFILES = Path(__file__).resolve().parents[2] / "profiles"
BASE: dict[str, Any] = {
    "version": 1,
    "mode": "declarative",
    "admin": {"listen": "0.0.0.0:8081", "hosts": ["localhost"]},
}


def merged(*names: str) -> dict[str, Any]:
    """The profiles' fragments merged into one policy, as an operator would paste them."""
    document: dict[str, Any] = dict(BASE)
    for name in names:
        document = _merge(document, load_mapping((PROFILES / name).read_text(encoding="utf-8")))
    return document


def _merge(into: dict[str, Any], fragment: dict[str, Any]) -> dict[str, Any]:
    """Mappings merge key by key, at any depth; lists are joined; anything else is replaced."""
    merged_: dict[str, Any] = dict(into)
    for key, value in fragment.items():
        if isinstance(value, dict) and isinstance(merged_.get(key), dict):
            merged_[key] = _merge(merged_[key], value)
        elif isinstance(value, list) and isinstance(merged_.get(key), list):
            merged_[key] = [*merged_[key], *value]
        else:
            merged_[key] = value
    return merged_


@pytest.mark.parametrize(
    "names",
    [
        ("toolkit-records.yaml",),
        ("smtp-implicit-tls.yaml", "toolkit-mail.yaml"),
        ("smtp-starttls.yaml", "toolkit-mail.yaml"),
    ],
)
def test_the_toolkit_profiles_pass_check(names: tuple[str, ...]) -> None:
    out = io.StringIO()
    document = io.StringIO(json.dumps(merged(*names)))
    assert main(["check", "--config", "-"], stdin=document, out=out) == 0
    assert out.getvalue() == "<stdin>: ok (0 error(s), 0 warning(s))\n"


def generated(toolkit: Toolkit) -> dict[str, str]:
    return {
        name: pins.project_and_pin(Tool.model_validate(spec.definition())).pin
        for name, spec in sorted(toolkit.tools.items())
    }


def test_the_profiles_pin_what_the_code_generates() -> None:
    from example_toolkits import mail, records

    servers = {
        **merged("toolkit-mail.yaml")["gateway"]["servers"],
        **merged("toolkit-records.yaml")["gateway"]["servers"],
    }
    assert servers["mail"]["review"] == generated(mail.toolkit)
    assert servers["records"]["review"] == generated(records.toolkit)
