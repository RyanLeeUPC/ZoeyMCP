"""check and the view for toolkit servers (M4 design A.2 step 12 rows, A.3)."""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest
import yaml

from zoeymcp.common.policy import Policy, parse_policy
from zoeymcp.common.policy.view import ViewToolkitServer, build_view

from .test_policy import errors, run, warnings

Raw = dict[str, Any]
PIN = "sha256:" + "0" * 64


def mail(raw: Raw) -> Raw:
    found: Raw = raw["gateway"]["servers"]["mail"]
    return found


def http_route(raw: Raw, **changes: Any) -> Raw:
    """Add an HTTP route a records toolkit could use, and a toolkit server on it."""
    route = {
        "name": "records",
        "prefix": "/records",
        "upstream": "https://api.records.example",
        "credential": "music-stats",
        "callers": ["gateway"],
        "rules": [
            {
                "methods": ["GET"],
                "paths": ["/v1/records/{id}"],
                "params": {"id": {"regex": "r[0-9]{1,8}"}},
            },
            {"methods": ["POST"], "paths": ["/v1/records/batch", "/v1/notes"]},
        ],
        **changes,
    }
    raw["routes"].append(route)
    raw["gateway"]["servers"]["records"] = {
        "kind": "toolkit",
        "module": "example_toolkits.records",
        "tools": {"include": ["get_records"], "allow": ["get_records"]},
        "review": {"get_records": PIN},
        "slots": {
            "db": {
                "route": "records",
                "rules": [
                    {"methods": ["GET"], "paths": ["/v1/records/{id}"]},
                    {"methods": ["POST"], "paths": ["/v1/records/batch"], "approved": True},
                ],
            }
        },
    }
    raw["gateway"]["clients"]["agent1"]["servers"].append("records")
    return raw


def test_the_example_is_clean(example_raw: Raw) -> None:
    assert errors(run(example_raw)) == []
    assert [w for w in warnings(run(example_raw)) if "mail" in w] == []


def test_an_http_slot_is_clean(example_raw: Raw) -> None:
    findings = run(http_route(copy.deepcopy(example_raw)))
    assert errors(findings) == []
    assert [w for w in warnings(findings) if "records" in w] == []


# --- pins ---------------------------------------------------------------------------------------


def test_pins_are_required_by_default(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    mail(raw)["review"] = {}
    assert errors(run(raw)) == [
        "gateway.servers.mail.review: 'send_note' is included but has no review pin"
    ]


def test_pinning_off(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    mail(raw)["pinning"] = "off"
    findings = run(raw)
    assert errors(findings) == ["gateway.servers.mail.review: pins are given but pinning is off"]
    assert (
        "gateway.servers.mail.pinning: definitions follow the image; a rebuild can change a tool "
        "without review"
    ) in warnings(findings)
    mail(raw)["review"] = {}
    assert errors(run(raw)) == []


# --- slots --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda r: mail(r)["slots"]["mail"].update(route="nowhere"),
            "gateway.servers.mail.slots.mail.route: unknown route 'nowhere'",
        ),
        (
            lambda r: mail(r)["slots"]["mail"].update(route="broker-mcp"),
            "gateway.servers.mail.slots.mail.route: a toolkit must not speak raw MCP to a "
            "reviewed server",
        ),
        (
            lambda r: mail(r)["slots"]["mail"].update(route="stats"),
            "gateway.servers.mail.slots.mail.route: a route a toolkit uses must accept only the "
            "gateway",
        ),
        (
            lambda r: mail(r)["slots"]["mail"]["rules"][1].update(paths=["/sends"]),
            "gateway.servers.mail.slots.mail.rules[1]: POST /sends: the vault has no rule for this",
        ),
        (
            lambda r: mail(r)["slots"]["mail"]["rules"][0].update(methods=["GET", "PUT"]),
            "gateway.servers.mail.slots.mail.rules[0]: PUT /config: the vault has no rule for this",
        ),
        (
            lambda r: mail(r)["slots"]["mail"]["rules"][1].update(approved=False),
            "gateway.servers.mail.slots.mail.rules[1].approved: POST /send through a connector "
            "needs approved: true",
        ),
        (
            lambda r: mail(r)["slots"]["mail"]["rules"][0].update(paths=["config"]),
            "gateway.servers.mail.slots.mail.rules[0].paths[0]: 'config': must start with '/'",
        ),
    ],
)
def test_slot_errors(example_raw: Raw, mutate: Callable[[Raw], object], expected: str) -> None:
    raw = copy.deepcopy(example_raw)
    mutate(raw)
    assert expected in errors(run(raw))


def test_a_slot_rule_must_equal_a_route_rule_textually(example_raw: Raw) -> None:
    raw = http_route(copy.deepcopy(example_raw))
    slot = raw["gateway"]["servers"]["records"]["slots"]["db"]
    slot["rules"][0]["paths"] = ["/v1/records/{rid}"]  # same shape, another capture name
    assert errors(run(raw)) == [
        "gateway.servers.records.slots.db.rules[0]: GET /v1/records/{rid}: the vault has no rule "
        "for this"
    ]
    slot["rules"][0]["paths"] = ["/v1/records/*"]  # contained, but not the same text
    assert len(errors(run(raw))) == 1


def test_http_write_warnings(example_raw: Raw) -> None:
    raw = http_route(copy.deepcopy(example_raw))
    slot = raw["gateway"]["servers"]["records"]["slots"]["db"]
    slot["rules"].append({"methods": ["POST"], "paths": ["/v1/notes"]})
    slot["rules"][0]["approved"] = True
    found = warnings(run(raw))
    assert (
        "gateway.servers.records.slots.db.rules[2]: every tool of this toolkit can make this "
        "write without a prompt"
    ) in found
    assert "gateway.servers.records.slots.db.rules[0].approved: has no effect on a GET" in found


def test_a_connector_no_slot_uses(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    del raw["gateway"]["servers"]["mail"]
    raw["gateway"]["clients"]["agent1"]["servers"].remove("mail")
    assert "connectors.mail-out: no toolkit slot maps a route to it" in warnings(run(raw))


def test_the_stop_window_covers_toolkits(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    mail(raw)["call_timeout"] = 900
    assert any(
        w.startswith("gateway.servers.mail.call_timeout: an approved call may run 900 s")
        for w in warnings(run(raw))
    )


# --- the prompt size estimate -------------------------------------------------------------------


def size_warnings(raw: Raw) -> list[str]:
    return [w for w in warnings(run(raw)) if "can't be approved" in w]


def test_the_defaults_fit_the_default_budget(example_raw: Raw) -> None:
    assert size_warnings(example_raw) == []


def test_a_longer_body_warns(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["connectors"]["mail-out"]["max_body_chars"] = 2700
    [found] = size_warnings(raw)
    assert found.startswith("connectors.mail-out: a message near these limits can't be approved")
    assert "lower max_body_chars" in found


def test_a_client_budget_and_a_confirmation_code_count(example_raw: Raw) -> None:
    raw = copy.deepcopy(example_raw)
    raw["gateway"]["clients"]["agent1"]["approvals"]["budget_chars"] = 2900
    assert size_warnings(raw) == []
    raw["gateway"]["clients"]["agent1"]["approvals"]["confirm_code"] = True
    assert len(size_warnings(raw)) == 1
    raw["gateway"]["clients"]["agent1"]["approvals"] = None
    assert size_warnings(raw) == []  # never asked, so never too long


# --- the view -----------------------------------------------------------------------------------


def test_the_view_holds_slots_by_prefix_and_connector_kind(example_raw: Raw) -> None:
    raw = http_route(copy.deepcopy(example_raw))
    policy: Policy = parse_policy(yaml.safe_dump(raw, sort_keys=False), "test")
    view = build_view(policy)
    server = view.gateway.servers["mail"]
    assert isinstance(server, ViewToolkitServer)
    assert server.module == "example_toolkits.mail"
    assert server.model_dump()["slots"] == {
        "mail": {
            "prefix": "/mail",
            "connector": "smtp",
            "rules": [
                {"methods": ["GET"], "paths": ["/mail/config"], "approved": False},
                {"methods": ["POST"], "paths": ["/mail/send"], "approved": True},
            ],
        }
    }
    records = view.gateway.servers["records"]
    assert isinstance(records, ViewToolkitServer)
    assert records.slots["db"].connector is None
    assert records.slots["db"].rules[0].paths == ["/records/v1/records/{id}"]
    assert "mail-out" not in view.model_dump_json()  # the connector's name stays vault-side


def test_the_example_pin_is_the_generated_one(example_raw: Raw) -> None:
    """examples/policy.yaml pins send_note as the gateway would compute it from the code."""
    from example_toolkits.mail import toolkit
    from mcp.types import Tool

    from zoeymcp.gateway import pins

    definition = toolkit.tools["send_note"].definition()
    pin = pins.project_and_pin(Tool.model_validate(definition)).pin
    assert mail(example_raw)["review"] == {"send_note": pin}
