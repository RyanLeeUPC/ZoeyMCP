from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from zoeymcp.common.yamlload import load_mapping

EXAMPLE_POLICY = Path(__file__).resolve().parents[2] / "examples" / "policy.yaml"


@pytest.fixture
def example_text() -> str:
    return EXAMPLE_POLICY.read_text(encoding="utf-8")


@pytest.fixture
def example_raw(example_text: str) -> dict[str, Any]:
    """The example policy as a plain mapping, for tests that mutate one field at a time."""
    return load_mapping(example_text)
