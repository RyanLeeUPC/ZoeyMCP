"""The Policy page, over the real API (M5 design L, D-09, P9).

``GET /api/policy`` shows the running policy, read-only, built from an allowlist of its fields
(``portal/policyview.py``, whose own tests hold completeness and redaction): here, that the
portal serves it to a full session only, says where the policy came from, hides what L hides,
and shows a reload at once. No route writes it.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.authenticator import SoftAuthenticator
from zoeymcp.portal.routes import ROUTES

from .flows import issue, redeem, set_up, status_reason
from .rig import PortalRig, rig_policy, running

PLACEHOLDER = "ph-agent1-stats-0001"
STATS: dict[str, Any] = {
    "credentials": {
        "music-stats": {"kind": "query", "param": "api_key", "secret": "store:music-stats"}
    },
    "routes": [
        {
            "name": "stats",
            "prefix": "/stats",
            "upstream": "https://api.stats.example",
            "credential": "music-stats",
            "callers": [{"placeholder": PLACEHOLDER}],
            "rules": [{"methods": ["GET"], "paths": ["/**"]}],
        }
    ],
}


@pytest.fixture
def rig(tmp_path: Path) -> Iterator[PortalRig]:
    with running(tmp_path, policy=STATS) as portal:
        yield portal


def test_the_running_policy_read_only(rig: PortalRig) -> None:
    page = rig.browser().page(rig.origin)
    set_up(rig, page, SoftAuthenticator())
    answer = page.fetch("GET", "/api/policy")
    assert answer.status_code == 200, answer.text
    view = answer.json()
    assert (view["mode"], view["source"]) == ("declarative", "file")  # the rig's --config
    assert view["source_shown"] == "the file given with --config"
    policy = view["policy"]
    assert policy["admin"] == {"listen": f"127.0.0.1:{rig.portal_port}", "origins": [rig.origin]}
    assert policy["credentials"]["music-stats"]["secret"] == "store:music-stats"
    assert policy["routes"][0]["callers"][0]["placeholder"] == "(set)"
    assert view["hidden"] == ["routes[0].callers[0].placeholder"]
    assert PLACEHOLDER not in json.dumps(view)
    # A reload shows at once: the view is of the running policy.
    rig.reload(rig_policy(rig.portal_port))
    reloaded = page.fetch("GET", "/api/policy").json()
    assert (reloaded["policy"]["routes"], reloaded["hidden"]) == ([], [])


def test_only_a_full_session_reads_it(rig: PortalRig) -> None:
    anonymous = rig.browser().page(rig.origin)
    assert status_reason(anonymous.fetch("GET", "/api/policy")) == (401, "no_session")
    setup = rig.browser().page(rig.origin)
    assert redeem(setup, issue(rig)).status_code == 200
    assert status_reason(setup.fetch("GET", "/api/policy")) == (403, "scope")


def test_no_route_writes_the_policy() -> None:
    """P9: the policy has one route, a GET."""
    assert [(r.method, r.path) for r in ROUTES if "polic" in r.path] == [("GET", "/api/policy")]
