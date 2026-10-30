"""The gateway's status report to the vault (M6 design K.1; D-29, D-72's rule, FM-19, FM-20).

- ``_StatusOnly``: the status client reaches the status path and nothing else;
- the report (:func:`statuspush.content`): the attention decision's lists from the status, names
  that aren't tool names counted, not named (T-7), every list capped;
- the pusher against a scripted vault: the first report at once, a change after the debounce,
  the same report again only after a minute, a 429 waiting the debounce, and a failure backing
  off, logged at most once a minute;
- against the real vault app over both links (TCP with the gateway key, and the link socket,
  which is Linux only): a pushed report is kept and read back; one sooner than 5 s after it is
  429, one over 256 KiB is 413, one with a witness above ``REVISION_MAX`` is refused whole, each
  refusal logged at most once a minute (FM-19); a query, another content type and a body that
  isn't a report are refused before anything is kept;
- the whole gateway: it pushes after its first view, the vault's health reads it, and a new
  gateway process pushes again within the minute (FM-20);
- the report's leak sweep (O.6, Y13): on a policy holding the secret-heavy policy's values, the
  report, what the vault keeps of it and the gateway's ``GET /status`` hold none of them, no
  token or its hash, no client name and no definition; health holds none the policy view hides;
- prompts and resources (D-216): a server enabling them has ``kinds`` in the gateway's status,
  each kind's attention decision over its connections' listings, and in the report, each list
  capped; a tools-only server's entry and every toolkit's are as before, with no ``kinds``;
  ``kinds`` carries names alone, no pin and no definition; and long URIs never take the report
  over its size, the kinds' lists cut in their order.
"""

from __future__ import annotations

import copy
import io
import json
import os
import shutil
import sys
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import anyio
import httpx
import httpx2
import pytest
from mcp.types import Prompt, Resource, ResourceTemplate

from tests.fakes.harness import serve
from tests.fakes.mcp_server import (
    ASSISTANT_PROMPT,
    FIXED,
    HIDDEN_PROMPT,
    TEMPLATE,
    McpFake,
    base_prompts,
    base_resources,
    base_templates,
    base_tools,
)
from tests.gateway.rig import (
    CLIENTS,
    KEYS,
    RELOAD_PATH,
    SERVER,
    agent,
    deployment,
    gateway,
    pin_of_fake,
    raw_policy,
    token_for,
    until,
)
from tests.gateway.test_upstream_kinds import FIXED_PIN, PROMPT_PIN, TEMPLATE_PIN, with_kinds
from tests.unit.test_leak_sweep import (
    LITERAL_TOKEN,
    POLICY_VIEW_HIDES,
    VAULT_SIDE,
    secret_heavy_policy,
)
from tests.unit.test_peer import my_uid, serve_link
from zoeymcp.common import logs
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.attention import Attention
from zoeymcp.common.policy.schema import GatewayLimits, hash_token
from zoeymcp.common.policy.view import (
    GatewayView,
    ViewRemoteServer,
    build_view,
    dump_view,
    view_digest,
)
from zoeymcp.gateway import pins, statuspush, witness
from zoeymcp.gateway.server import pushed_status, status
from zoeymcp.gateway.statuspush import DEBOUNCE, EVERY, StatusPusher, content
from zoeymcp.gateway.vaultlink import (
    STATUS_MAX_ANSWER_BYTES,
    STATUS_PATH,
    KeySource,
    Link,
    ResponseTooLarge,
    UpstreamBlocked,
    UpstreamRedirect,
    parse_link,
    status_client,
)
from zoeymcp.vault import internal
from zoeymcp.vault.app import VaultApp
from zoeymcp.vault.server import ListenerTag
from zoeymcp.vault.store import SecretStore

pytestmark = pytest.mark.anyio
LINKS = ["tcp", pytest.param("unix", marks=pytest.mark.skipif(
    sys.platform != "linux", reason="the link socket's peer check is Linux only"
))]  # fmt: skip
LINK = "unix:/run/zoeymcp-link/vault.sock"
VIEW = "sha256:" + "ab" * 32
PIN = "sha256:" + "c" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        yield stream
    finally:
        logs.set_stream(None)


def events(stream: io.StringIO, kind: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in stream.getvalue().splitlines() if line]
    return [line for line in lines if line["event"] == kind]


def remote(**fields: Any) -> dict[str, Any]:
    """A remote server's entry in the gateway's status (``server.status``)."""
    entry: dict[str, Any] = {
        "kind": "remote",
        "state": ["ready"],
        "era": "modern",
        "connections": 1,
        "included": 2,
        "exposed": 2,
        "marked": [],
        "reports": {},
        "attention": Attention().as_dict(),
        "blocked": False,
        "unreviewed_pins": {},
        "offered": None,
        "listed_s_ago": 1.0,
    }
    return {**entry, **fields}


def status_of(**servers: dict[str, Any]) -> dict[str, Any]:
    return {"version": "1", "view": VIEW, "fresh": True, "servers": servers}


# --- _StatusOnly --------------------------------------------------------------------------------


def test_the_path_and_timings_are_the_vaults() -> None:
    """The gateway can't import the vault: its copies are kept equal here."""
    assert internal.STATUS.path.text == STATUS_PATH
    assert statuspush.MAX_BYTES == internal.STATUS_MAX_BYTES
    assert statuspush.DEBOUNCE == internal.STATUS_MIN_INTERVAL
    assert (statuspush.EVERY, statuspush.LOG_EVERY) == (60.0, 60.0)


REFUSED = [
    ("GET", STATUS_PATH),
    ("PUT", STATUS_PATH),
    ("DELETE", STATUS_PATH),
    ("POST", STATUS_PATH + "?x=1"),
    ("POST", STATUS_PATH + "/"),
    ("POST", "/_zoeymcp/gateway/v1/report/review"),
    ("POST", "/_zoeymcp/gateway/v1/report/ledger"),
    ("GET", "/_zoeymcp/gateway/v1/view"),
    ("POST", "/_zoeymcp/gateway/v1/report/%73tatus"),
    ("POST", "/notes/mcp"),
    ("POST", "http://elsewhere.invalid" + STATUS_PATH),
    ("POST", "http://vault.invalid:8080" + STATUS_PATH),
    ("POST", "https://vault.invalid" + STATUS_PATH),
]


@pytest.mark.parametrize("spec", [LINK, "http://vault:8080"])
async def test_the_status_client_reaches_the_status_path_only(spec: str) -> None:
    seen: list[str] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        seen.append(request.url.raw_path.decode())
        return httpx2.Response(200, json={"v": 1})

    link = parse_link(spec)
    async with status_client(link, None, inner=httpx2.MockTransport(vault)) as http:
        assert (await http.post(STATUS_PATH, content=b"{}")).status_code == 200
        for method, url in REFUSED:
            if spec != LINK and url.startswith("http://vault.invalid"):
                url = url.replace("vault.invalid:8080", "vault:9999")
            with pytest.raises(UpstreamBlocked):
                await http.request(method, url, content=b"{}" if method != "GET" else None)
    assert seen == [STATUS_PATH]


async def test_the_status_client_follows_no_redirect_and_caps_answers() -> None:
    answers = [
        httpx2.Response(307, headers={"location": STATUS_PATH}),
        httpx2.Response(200, content=b" " * (STATUS_MAX_ANSWER_BYTES + 1)),
        httpx2.Response(429, content=b" " * STATUS_MAX_ANSWER_BYTES),
    ]

    def vault(request: httpx2.Request) -> httpx2.Response:
        return answers.pop(0)

    async with status_client(parse_link(LINK), None, inner=httpx2.MockTransport(vault)) as http:
        with pytest.raises(UpstreamRedirect):
            await http.post(STATUS_PATH, content=b"{}")
        with pytest.raises(ResponseTooLarge):
            await http.post(STATUS_PATH, content=b"{}")
        assert len((await http.post(STATUS_PATH, content=b"{}")).content) == 4096


async def test_the_gateway_key_goes_with_every_status_on_tcp() -> None:
    headers: list[str | None] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        headers.append(request.headers.get("x-zoeymcp-gateway"))
        return httpx2.Response(200, json={"v": 1})

    keys = KeySource(KEYS.gateway_key(1))
    async with status_client(
        parse_link("http://vault:8080"), keys, inner=httpx2.MockTransport(vault)
    ) as http:
        await http.post(STATUS_PATH, content=b"{}")
    async with status_client(parse_link(LINK), None, inner=httpx2.MockTransport(vault)) as http:
        await http.post(STATUS_PATH, content=b"{}")
    assert headers == [KEYS.gateway_key(1), None]


# --- the report ---------------------------------------------------------------------------------


def test_no_report_before_a_view() -> None:
    assert content({"view": None, "servers": {}}, started=1, max_tools=10) is None


def test_the_report_is_the_attention_decision_and_counts() -> None:
    decided = Attention(
        drifted=("d",), marked=("m",), new=("n",), changed_declined=("c",), missing=("x",)
    )
    status = status_of(
        notes=remote(
            attention=decided.as_dict(),
            unreviewed_pins={"n": PIN, "c": PIN},
            reports={"invalid": ["bad.one", "a b", "é"], "duplicate": ["dup", "x y"]},
            offered={"prompts": True, "resources": False, "completions": False, "logging": True},
            marked=["m", "old"],  # every mark the gateway holds; the decision's is "m"
            blocked=True,
        ),
        kit={"kind": "toolkit", "state": "unavailable", "reason": "not_loaded"},
    )
    assert content(status, started=7, max_tools=10) == {
        "v": 1,
        "view": VIEW,
        "started": 7,
        "servers": {
            "kit": {
                "kind": "toolkit",
                "state": ["unavailable"],
                "era": None,
                "blocked": False,
                "included": 0,
                "exposed": 0,
                "marked": [],
                "unreviewed": [],
                "declined_changed": [],
                "drift": [],
                "missing": [],
                "invalid": [],
                "invalid_unnamed": 0,
                "duplicate_unnamed": 0,
                "offered": None,
            },
            "notes": {
                "kind": "remote",
                "state": ["ready"],
                "era": "modern",
                "blocked": True,
                "included": 2,
                "exposed": 2,
                "marked": ["m"],
                "unreviewed": [["c", PIN], ["n", PIN]],
                "declined_changed": ["c"],
                "drift": ["d"],
                "missing": ["x"],
                "invalid": ["bad.one", "dup"],
                "invalid_unnamed": 2,
                "duplicate_unnamed": 1,
                "offered": {
                    "prompts": True,
                    "resources": False,
                    "completions": False,
                    "logging": True,
                },
            },
        },
        "witness": {},
        "deployments_seen": 0,
        "policy_mode": "unknown",
    }


def test_every_list_is_capped() -> None:
    names = [f"t{n}" for n in range(5)]
    decided = Attention(drifted=tuple(names), new=tuple(names))
    status = status_of(
        notes=remote(
            attention=decided.as_dict(),
            unreviewed_pins=dict.fromkeys(names, PIN),
            reports={"invalid": [*names, "a b", "c d", "e f"]},
        )
    )
    document = content(status, started=1, max_tools=3)
    assert document is not None
    entry = document["servers"]["notes"]
    assert entry["drift"] == ["t0", "t1", "t2"]
    assert entry["unreviewed"] == [["t0", PIN], ["t1", PIN], ["t2", PIN]]
    assert entry["invalid"] == ["t0", "t1", "t2"]
    assert entry["invalid_unnamed"] == 3
    capped = content(status, started=1, max_tools=2)
    assert capped is not None
    assert capped["servers"]["notes"]["invalid_unnamed"] == 2


def test_the_tool_counts_are_capped_at_the_schemas_ceiling() -> None:
    """The include list isn't held to the running limit, so its count goes as it is, up to
    max_tools_per_server's own ceiling, which the vault takes."""
    status = status_of(notes=remote(included=12, exposed=10_001))
    document = content(status, started=1, max_tools=3)
    assert document is not None
    assert (document["servers"]["notes"]["included"], document["servers"]["notes"]["exposed"]) == (
        12,
        10_000,
    )


def test_a_server_never_listed_reports_nothing_to_attend_to() -> None:
    document = content(status_of(notes=remote(attention=None)), started=1, max_tools=10)
    assert document is not None
    entry = document["servers"]["notes"]
    assert [entry[key] for key in ("marked", "unreviewed", "drift", "missing")] == [[]] * 4


def test_the_report_carries_the_witness_first_seen_first() -> None:
    """K.3: the restore witness's record, in the order the gateway first saw each deployment
    (the vault reads that order), and how many it has recorded; none before a managed view."""
    held = {"b" * 32: 4, "a" * 32: 31}
    document = content(
        {**status_of(), "witness": held, "deployments_seen": 3}, started=1, max_tools=10
    )
    assert document is not None
    assert (document["witness"], document["deployments_seen"]) == (held, 3)
    assert list(document["witness"]) == ["b" * 32, "a" * 32]
    assert (
        '"witness":{"' + "b" * 32 + '":4,"' + "a" * 32 + '":31}'
        in statuspush.encoded(document).decode()
    )
    bare = content(status_of(), started=1, max_tools=10)
    assert bare is not None
    assert (bare["witness"], bare["deployments_seen"]) == ({}, 0)


def test_the_report_names_the_mode_the_gateway_last_saw() -> None:
    """``policy_mode`` is the status's, the mode the vault last stated beside the view (M6 design
    K.3); a status naming none reports ``unknown``."""
    for mode in ("managed", "declarative", "unknown"):
        document = content({**status_of(), "policy_mode": mode}, started=1, max_tools=10)
        assert document is not None
        assert document["policy_mode"] == mode
    document = content(status_of(), started=1, max_tools=10)
    assert document is not None
    assert document["policy_mode"] == "unknown"


# --- prompts and resources (D-216) -------------------------------------------------------------

WRONG = "sha256:" + "0" * 64
KIND_ORDER = ["prompt", "resource_template", "resource"]


def test_a_server_enabling_kinds_sends_each_kinds_lists_capped() -> None:
    """Each kind's five lists go as the gateway decided them, each sorted and capped at
    max_tools_per_server, beside the tools' own; nothing else of the kind goes."""
    many = [f"p{n}" for n in range(5)]
    kinds = {
        "prompt": Attention(new=tuple(reversed(many)), drifted=("summarize",)).as_dict(),
        "resource_template": Attention(marked=(TEMPLATE,)).as_dict(),
        "resource": Attention(
            missing=(FIXED,), changed_declined=("notes://b", "notes://a")
        ).as_dict(),
    }
    tools = Attention(drifted=("echo",)).as_dict()
    document = content(
        status_of(notes=remote(kinds=kinds, attention=tools)), started=1, max_tools=3
    )
    assert document is not None
    entry = document["servers"]["notes"]
    assert entry["kinds"] == {
        "prompt": {
            "drifted": ["summarize"],
            "marked": [],
            "new": ["p0", "p1", "p2"],
            "changed_declined": [],
            "missing": [],
        },
        "resource_template": {
            "drifted": [],
            "marked": [TEMPLATE],
            "new": [],
            "changed_declined": [],
            "missing": [],
        },
        "resource": {
            "drifted": [],
            "marked": [],
            "new": [],
            "changed_declined": ["notes://a", "notes://b"],
            "missing": [FIXED],
        },
    }
    assert entry["drift"] == ["echo"]
    plain = content(status_of(notes=remote()), started=1, max_tools=3)
    assert plain is not None
    assert list(entry) == [*plain["servers"]["notes"], "kinds"]


def test_a_tools_only_entry_is_todays() -> None:
    """A server that enables nothing beyond tools sends no ``kinds`` (an empty one is none), so
    its entry, and the report's version, are as before."""
    plain = content(status_of(notes=remote()), started=1, max_tools=3)
    empty = content(status_of(notes=remote(kinds={})), started=1, max_tools=3)
    assert plain is not None
    assert plain == empty
    assert "kinds" not in plain["servers"]["notes"]
    assert plain["v"] == 1


def long_uri(n: int) -> str:
    """A fixed resource's URI near the policy's 2,048 characters."""
    return f"notes://notes/{n:04d}/" + "x" * 2020


def test_long_uris_never_take_the_report_over_its_size() -> None:
    """A server listing max_tools_per_server fixed resources of near 2,048 characters, none
    reviewed, would be about 1 MB of ``new``: its ``kinds`` are cut until the report fits, the
    names nobody reviewed going first, so the other servers' entries, its tools and its
    included names are as they were."""
    uris = [long_uri(n) for n in range(512)]
    kinds = {
        "resource": Attention(new=tuple(uris), marked=(uris[0],), missing=(FIXED,)).as_dict(),
        "prompt": Attention(new=("p",)).as_dict(),
    }
    other = {"prompt": Attention(drifted=("summarize",), new=("q",)).as_dict()}
    tools = Attention(drifted=("echo",)).as_dict()
    found = status_of(
        big=remote(kinds=kinds, attention=tools), notes=remote(kinds=other, attention=tools)
    )
    document = content(found, started=1, max_tools=512)
    assert document is not None
    assert len(statuspush.encoded(document)) <= statuspush.MAX_BYTES
    alone = content(status_of(notes=remote(kinds=other, attention=tools)), started=1, max_tools=512)
    assert alone is not None
    assert document["servers"]["notes"] == alone["servers"]["notes"]
    big = document["servers"]["big"]
    assert big["drift"] == ["echo"]
    assert (big["kinds"]["resource"]["marked"], big["kinds"]["resource"]["missing"]) == (
        [uris[0]],
        [FIXED],
    )
    assert big["kinds"]["prompt"]["new"] == ["p"]
    kept = big["kinds"]["resource"]["new"]
    assert 0 < len(kept) < 512
    assert kept == uris[: len(kept)]  # the last cut first


def cut_status() -> dict[str, Any]:
    """Two servers' kinds: ``a``'s resources with four new, two declined at another pin and two
    marked; ``b``'s prompts with five new."""
    resources = Attention(
        new=("n1", "n2", "n3", "n4"), changed_declined=("c1", "c2"), marked=("m1", "m2")
    )
    prompts = Attention(new=("q1", "q2", "q3", "q4", "q5"))
    return status_of(
        a=remote(kinds={"resource": resources.as_dict()}),
        b=remote(kinds={"prompt": prompts.as_dict()}),
    )


def kinds_cut(document: dict[str, Any] | None) -> dict[str, dict[str, list[str]]]:
    assert document is not None
    return {
        name: {member: names for member, names in entry["kinds"].popitem()[1].items() if names}
        for name, entry in document["servers"].items()
    }


def test_the_kinds_are_cut_in_their_order(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exactly what the size needs, from the end: the longest ``new`` first, each list kept to
    one name, then ``changed_declined``, and only then any list emptied; the tools are never
    cut."""
    full = content(cut_status(), started=1, max_tools=10)
    assert full is not None
    size = len(statuspush.encoded(full))
    monkeypatch.setattr(statuspush, "MAX_BYTES", size)
    assert content(cut_status(), started=1, max_tools=10) == full
    monkeypatch.setattr(statuspush, "MAX_BYTES", size - 1)
    assert kinds_cut(content(cut_status(), started=1, max_tools=10)) == {
        "a": {
            "new": ["n1", "n2", "n3", "n4"],
            "changed_declined": ["c1", "c2"],
            "marked": ["m1", "m2"],
        },
        "b": {"new": ["q1", "q2", "q3", "q4"]},
    }
    one_new = copy.deepcopy(full)
    for entry in one_new["servers"].values():
        for decided in entry["kinds"].values():
            del decided["new"][1:]
    monkeypatch.setattr(statuspush, "MAX_BYTES", len(statuspush.encoded(one_new)))
    assert content(cut_status(), started=1, max_tools=10) == one_new
    monkeypatch.setattr(statuspush, "MAX_BYTES", len(statuspush.encoded(one_new)) - 1)
    assert kinds_cut(content(cut_status(), started=1, max_tools=10)) == {
        "a": {"new": ["n1"], "changed_declined": ["c1"], "marked": ["m1", "m2"]},
        "b": {"new": ["q1"]},
    }
    one_each = copy.deepcopy(one_new)
    for entry in one_each["servers"].values():
        for decided in entry["kinds"].values():
            for names in decided.values():
                del names[1:]
    monkeypatch.setattr(statuspush, "MAX_BYTES", len(statuspush.encoded(one_each)) - 1)
    assert kinds_cut(content(cut_status(), started=1, max_tools=10)) == {
        "a": {"changed_declined": ["c1"], "marked": ["m1"]},
        "b": {"new": ["q1"]},
    }
    monkeypatch.setattr(statuspush, "MAX_BYTES", 0)
    emptied = content(cut_status(), started=1, max_tools=10)
    assert kinds_cut(emptied) == {"a": {}, "b": {}}
    assert emptied is not None
    assert {name: entry["drift"] for name, entry in emptied["servers"].items()} == {
        "a": [],
        "b": [],
    }


def kinds_app(server: ViewRemoteServer, *evaluations: pins.Evaluation | None) -> Any:
    """A gateway app holding ``server`` (as ``notes``) and the tools-only ``plain``, with one
    connection of ``notes`` per evaluation (None: not listed yet), and the fixed resource's
    mark."""
    policy = Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}))
    view = build_view(policy)
    assert view.gateway is not None
    plain = view.gateway.servers[SERVER].model_copy()
    gateway = view.gateway.model_copy(update={"servers": {SERVER: server, "plain": plain}})
    held = {"resource": frozenset({(FIXED, FIXED_PIN)})}

    def connection(found: pins.Evaluation | None) -> SimpleNamespace:
        state = SimpleNamespace(
            phase=SimpleNamespace(value="ready"), verified_at=None, evaluation=found
        )
        return SimpleNamespace(server=SERVER, state=state, client=None)

    def for_server(name: str, kind: str = "tool") -> frozenset[tuple[str, str]]:
        return held.get(kind, frozenset())

    built = GatewayView(v=view.v, digest=view_digest(gateway), gateway=gateway)
    snapshot = SimpleNamespace(view=built)
    connections = [connection(found) for found in evaluations]
    return SimpleNamespace(
        policy=SimpleNamespace(
            snapshot=snapshot, fresh=lambda: snapshot, mode="declarative", witness=None
        ),
        pool=SimpleNamespace(
            connections=lambda: connections,
            marks=SimpleNamespace(for_server=for_server),
            eras={},
        ),
        clock=lambda: 10.0,
    )


def listed_kinds(server: ViewRemoteServer, prompts: int = 2) -> pins.Evaluation:
    """One listing of the fake's prompts (the first ``prompts`` of them), template and fixed
    resource, evaluated with the fixed resource's mark."""
    listings: dict[pins.DefinitionKind, pins.KindListing] = {
        "prompt": pins.KindListing([Prompt.model_validate(p) for p in base_prompts()[:prompts]]),
        "resource_template": pins.KindListing(
            [ResourceTemplate.model_validate(t) for t in base_templates()]
        ),
        "resource": pins.KindListing([Resource.model_validate(r) for r in base_resources()]),
    }
    marks: dict[pins.DefinitionKind, frozenset[pins.Mark]] = {
        "resource": frozenset({(FIXED, FIXED_PIN)})
    }
    return pins.evaluate_server([], listings, server, marks, GatewayLimits())


def kinds_server() -> ViewRemoteServer:
    """``notes`` enabling prompts and resources: the first prompt at its pin, the template at
    a pin it isn't listed at (drifted), the fixed resource at its pin (marked by the app)."""
    policy = Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}))
    view = build_view(policy)
    assert view.gateway is not None
    server = view.gateway.servers[SERVER]
    assert isinstance(server, ViewRemoteServer)
    return with_kinds(
        server,
        prompts={"include": [ASSISTANT_PROMPT], "review": {ASSISTANT_PROMPT: PROMPT_PIN}},
        templates={"include": [TEMPLATE], "review": {TEMPLATE: WRONG}},
        fixed={"include": [FIXED], "review": {FIXED: FIXED_PIN}},
    )


def test_the_gateways_status_has_each_kinds_decision() -> None:
    """``status``'s ``kinds``: per enabled kind, the one attention decision over that kind's
    listings, its block and its marks, combined across connections as the tools' is (Y29); a
    connection not listed yet adds nothing; the tools-only server has none."""
    server = kinds_server()
    found = status(kinds_app(server, listed_kinds(server), None, listed_kinds(server, prompts=1)))
    notes = found["servers"][SERVER]
    assert notes["kinds"] == {
        "prompt": Attention(new=(HIDDEN_PROMPT,)).as_dict(),
        "resource_template": Attention(drifted=(TEMPLATE,)).as_dict(),
        "resource": Attention(marked=(FIXED,)).as_dict(),
    }
    assert list(notes["kinds"]) == KIND_ORDER
    assert notes["attention"] == Attention().as_dict()  # the tools' decision is its own
    assert "kinds" not in found["servers"]["plain"]
    # Only what the server enables: prompts alone.
    prompts = with_kinds(
        server,
        enable=["prompts"],
        prompts={"include": [ASSISTANT_PROMPT], "review": {ASSISTANT_PROMPT: PROMPT_PIN}},
    )
    alone = status(kinds_app(prompts, listed_kinds(prompts)))
    assert alone["servers"][SERVER]["kinds"] == {
        "prompt": Attention(new=(HIDDEN_PROMPT,)).as_dict()
    }


def test_before_any_listing_each_kind_is_quiet() -> None:
    server = kinds_server()
    quiet = Attention().as_dict()
    for app in (kinds_app(server, None), kinds_app(server)):
        assert status(app)["servers"][SERVER]["kinds"] == dict.fromkeys(KIND_ORDER, quiet)


def test_the_kinds_carry_names_alone() -> None:
    """The leak sweep over ``kinds`` (O.6, Y13): the report a server enabling every kind pushes
    names its prompts, templates and resources, and holds none of their pins, the policy's or
    the listed ones, nor any member of a definition but its name."""
    server = kinds_server()
    pushed = content(
        pushed_status(kinds_app(server, listed_kinds(server))), started=1, max_tools=10
    )
    assert pushed is not None
    kinds = statuspush.encoded(pushed["servers"][SERVER]["kinds"]).decode()
    for name in (HIDDEN_PROMPT, TEMPLATE, FIXED):
        assert name in kinds
    whole = statuspush.encoded(pushed).decode()
    assert "sha256:" not in kinds
    for pin in (PROMPT_PIN, TEMPLATE_PIN, FIXED_PIN, WRONG):
        assert pin not in whole
    for wire in [*base_prompts(), *base_templates(), *base_resources()]:
        for member, value in wire.items():
            if member not in ("name", "uri", "uriTemplate") and isinstance(value, str):
                assert value not in whole, member


# --- the pusher against a scripted vault --------------------------------------------------------


class Moment:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class Scripted:
    pusher: StatusPusher
    clock: Moment
    posted: list[dict[str, Any]]
    answers: list[httpx2.Response | Exception]
    status: dict[str, Any]


@contextmanager
def scripted() -> Iterator[Scripted]:
    clock = Moment()
    posted: list[dict[str, Any]] = []
    answers: list[httpx2.Response | Exception] = []

    def vault(request: httpx2.Request) -> httpx2.Response:
        posted.append(json.loads(request.content))
        answer = answers.pop(0) if answers else httpx2.Response(200, json={"v": 1})
        if isinstance(answer, Exception):
            raise answer
        return answer

    policy = Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}))
    app = SimpleNamespace(policy=SimpleNamespace(snapshot=SimpleNamespace(view=build_view(policy))))
    status = status_of(notes=remote())
    http = httpx2.AsyncClient(transport=httpx2.MockTransport(vault), base_url="http://vault")
    pusher = StatusPusher(
        app, http, lambda _: status, clock=clock, wall=lambda: 1234.9, jitter=lambda: 0.5
    )
    yield Scripted(pusher, clock, posted, answers, status)


async def push_if_due(world: Scripted) -> bool:
    document = world.pusher.document()
    assert document is not None
    if not world.pusher.due(document, world.clock()):
        return False
    return await world.pusher.push_once(document)


async def test_the_first_report_at_once_then_on_change_or_each_minute() -> None:
    with scripted() as world:
        assert await push_if_due(world)
        assert world.posted[0]["started"] == 1234
        assert world.posted[0]["servers"]["notes"]["state"] == ["ready"]
        world.clock.now += EVERY - 0.1
        assert not await push_if_due(world)  # nothing changed
        world.clock.now += 0.1
        assert await push_if_due(world)  # a minute on: the same again
        world.status["servers"]["notes"]["exposed"] = 1
        world.clock.now += DEBOUNCE - 0.1
        assert not await push_if_due(world)  # changed, but within the debounce
        world.clock.now += 0.1
        assert await push_if_due(world)
        assert [post["servers"]["notes"]["exposed"] for post in world.posted] == [2, 2, 1]
        assert world.pusher.sent == world.posted[-1]


async def test_a_429_waits_the_debounce(log: io.StringIO) -> None:
    with scripted() as world:
        world.answers.append(httpx2.Response(429, json={"code": "too_soon"}))
        assert not await push_if_due(world)
        world.clock.now += DEBOUNCE - 0.1
        assert not await push_if_due(world)
        world.clock.now += 0.1
        assert await push_if_due(world)
        assert len(world.posted) == 2
    assert events(log, "status_push_failed") == []


async def test_a_failure_backs_off_and_is_logged_once_a_minute(log: io.StringIO) -> None:
    with scripted() as world:
        world.answers += [
            httpx2.ConnectError("down"),
            httpx2.Response(503, json={"code": "unavailable"}),
            httpx2.Response(400, json={"code": "invalid"}),
        ]
        # Backing off 1, 2, then 4 s (the jitter here is 1).
        for wait in (1.0, 2.0, 4.0):
            assert not await push_if_due(world)
            world.clock.now += wait - 0.1
            assert not await push_if_due(world)
            world.clock.now += 0.1
        assert await push_if_due(world)
        assert len(world.posted) == 4
    [failed] = events(log, "status_push_failed")
    assert (failed["reason"], failed["level"]) == ("ConnectError", "warning")


async def test_a_report_over_the_cap_isnt_sent(log: io.StringIO) -> None:
    with scripted() as world:
        assert not await world.pusher.push_once({"v": 1, "pad": "x" * statuspush.MAX_BYTES})
        assert world.posted == []
    [failed] = events(log, "status_push_failed")
    assert failed["reason"] == "too_large"


async def test_the_loop_pushes_after_each_step() -> None:
    steps: list[float] = []
    with scripted() as world:

        async def sleep(seconds: float) -> None:
            steps.append(seconds)
            if len(steps) == 3:
                raise anyio.get_cancelled_exc_class()
            world.clock.now += seconds

        world.pusher._sleep = sleep
        with pytest.raises(anyio.get_cancelled_exc_class()):
            await world.pusher.run()
        assert steps == [statuspush.STEP] * 3
        assert len(world.posted) == 1


async def test_a_status_that_cant_be_read_ends_only_its_round(log: io.StringIO) -> None:
    """Nothing the gateway serves waits for the pusher: a status that raises is a failed round,
    logged, and the loop pushes once its backoff ends."""
    steps: list[float] = []
    with scripted() as world:
        good = world.pusher._status
        calls = 0

        def status(app: Any) -> Any:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise KeyError("servers")
            return good(app)

        async def sleep(seconds: float) -> None:
            steps.append(seconds)
            if len(steps) == 3:
                raise anyio.get_cancelled_exc_class()
            world.clock.now += seconds

        world.pusher._status = status
        world.pusher._sleep = sleep
        with pytest.raises(anyio.get_cancelled_exc_class()):
            await world.pusher.run()
        assert steps == [statuspush.STEP] * 3
        assert len(world.posted) == 1  # the backoff (1 s here) passed by the third round
    [failed] = events(log, "status_push_failed")
    assert failed["reason"] == "KeyError"


# --- against the real vault, over both links ----------------------------------------------------


@dataclass
class Real:
    app: VaultApp
    link: Link
    keys: KeySource | None


@contextmanager
def real_vault(tmp_path: Path, link: str) -> Iterator[Real]:
    policy = Policy.model_validate(raw_policy("http://127.0.0.1:9", include=[], review={}))
    store = SecretStore(tmp_path / "vault", KEYS)
    store.load()
    app = VaultApp(
        policy, store, KEYS, client=httpx.AsyncClient(), environ={}, gateway_link=link == "unix"
    )
    if link == "tcp":
        with serve(app) as url:
            yield Real(app, parse_link(url), KeySource(KEYS.gateway_key(1)))
        return
    # A short path: AF_UNIX paths are limited to about 100 bytes.
    directory = Path(tempfile.mkdtemp(prefix="zm-", dir="/tmp"))
    os.chmod(directory, 0o700)
    try:
        socket = str(directory / "vault.sock")
        with serve_link(ListenerTag(app, "gateway"), socket, my_uid()):
            yield Real(app, parse_link(f"unix:{socket}"), None)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


@pytest.mark.parametrize("link", LINKS)
async def test_a_report_is_kept_and_floods_are_refused_over_either_link(
    tmp_path: Path, link: str, log: io.StringIO
) -> None:
    """FM-19: the vault keeps the report and its attention decision; a second one at once is
    429, one over 256 KiB is 413 before its body is read, a witness of 10^10 refuses its report
    whole; status_refused is logged once in the minute."""
    decided = Attention(drifted=("list_notes",), new=("purge",))
    status = status_of(notes=remote(attention=decided.as_dict(), unreviewed_pins={"purge": PIN}))
    with real_vault(tmp_path, link) as vault:
        app = SimpleNamespace(
            policy=SimpleNamespace(snapshot=SimpleNamespace(view=build_view(vault.app.policy)))
        )
        async with status_client(vault.link, vault.keys) as http:
            pusher = StatusPusher(app, http, lambda _: status)
            with anyio.fail_after(10):
                document = pusher.document()
                assert document is not None
                assert vault.app.gateway_status().report is None
                assert await pusher.push_once(document)
                held = vault.app.gateway_status()
                assert held.report is not None
                assert held.report.view == VIEW
                assert held.report.servers["notes"].attention() == decided
                assert held.age < 5
                assert not await pusher.push_once(document)  # sooner than 5 s: 429
                big = await http.post(
                    STATUS_PATH,
                    content=b" " * (internal.STATUS_MAX_BYTES + 1),
                    headers={"content-type": "application/json"},
                )
                assert (big.status_code, big.json()["code"]) == (413, "too_large")
                vault.app._status_gate.accepted_at = None  # as if 5 s had passed
                claimed = {**document, "witness": {"0" * 32: 10**10}}
                answer = await http.post(
                    STATUS_PATH,
                    content=statuspush.encoded(claimed),
                    headers={"content-type": "application/json"},
                )
                assert (answer.status_code, answer.json()["code"]) == (400, "witness_range")
                assert vault.app.gateway_status().report is held.report
    [refused] = events(log, "status_refused")
    assert (refused["reason"], refused["level"]) == ("too_soon", "warning")
    [received] = events(log, "status_received")
    assert received["servers"] == 1
    assert received["bytes"] == len(statuspush.encoded(document))


# --- the whole gateway --------------------------------------------------------------------------


def health(deployed: Any) -> dict[str, Any]:
    answer = httpx.get(deployed.vault_admin_url + "/health", timeout=10)
    assert answer.status_code == 200, answer.text
    report: dict[str, Any] = answer.json()
    return report


async def test_restart(tmp_path: Path) -> None:
    """FM-20: the gateway pushes once it holds a view, and the vault's health reads it; a new
    gateway process pushes again within the minute (at most one debounce after the last). The
    restore witness (K.3): the head the vault states is in the report, kept in
    ``policy-seen.json``, and read again by the new process, which keeps the higher revision
    when the vault now states a lower one."""
    fake = McpFake()
    tools = [tool["name"] for tool in base_tools()]
    include = tools[:2]
    with deployment(
        tmp_path,
        fake,
        include=include,
        review={name: pin_of_fake(fake, name) for name in include},
    ) as deployed:
        vault = deployed.vault
        assert vault is not None
        stated = "ab" * 16
        vault.state_head(stated, 7)
        with gateway(deployed, status_push=True):
            await until(lambda: vault.gateway_status().report is not None, timeout=20)
        first = vault.gateway_status().report
        assert first is not None
        assert "notes" in first.servers
        assert (dict(first.witness), first.deployments_seen) == ({stated: 7}, 1)
        assert witness.loads((deployed.state / witness.FILE).read_bytes()).report() == {stated: 7}
        vault.state_head(stated, 5)
        section = health(deployed)["gateway"]
        assert [row["name"] for row in section["servers"]] == ["notes"]
        started = time.monotonic()
        with gateway(deployed, status_push=True):
            await until(lambda: vault.gateway_status().report is not first, timeout=20)
        assert time.monotonic() - started < EVERY
        again = vault.gateway_status().report
        assert again is not None
        assert (dict(again.witness), again.deployments_seen) == ({stated: 7}, 1)


async def test_the_status_path_checks_before_it_reads(tmp_path: Path, log: io.StringIO) -> None:
    """No query (400), one JSON content type (415), strict JSON in the frame (400 ``invalid``):
    each refused before the report is kept, and none of them starts the 5 s interval."""
    with real_vault(tmp_path, "tcp") as vault:
        assert vault.keys is not None
        key = vault.keys.current()
        assert key is not None
        headers = {"x-zoeymcp-gateway": key.reveal(), "content-type": "application/json"}
        base = vault.link.base_url
        async with httpx.AsyncClient(base_url=base, headers=headers, timeout=10) as http:
            with anyio.fail_after(10):
                query = await http.post(STATUS_PATH + "?x=1", content=b"{}")
                assert query.status_code == 400
                typed = await http.post(
                    STATUS_PATH, content=b"{}", headers={"content-type": "text/plain"}
                )
                assert typed.status_code == 415
                for body in (b"{", b'{"v": 1}', b"[]", b'{"v": 1, "v": 1}'):
                    answer = await http.post(STATUS_PATH, content=body)
                    assert (answer.status_code, answer.json()["code"]) == (400, "invalid")
                assert vault.app.gateway_status().report is None
                assert vault.app._status_gate.accepted_at is None
                anonymous = await http.post(
                    STATUS_PATH, content=b"{}", headers={"x-zoeymcp-gateway": ""}
                )
                assert anonymous.status_code == 403
    [refused] = events(log, "status_refused")
    assert refused["reason"] == "invalid"


# --- the report's leak sweep (M6 design O.6, Y13; D-117's M6 obligation, step 22) ---------------

# The secret-heavy policy's values the merged policy below leaves out: its local routes, and so
# their programs and upstreams, as the vault's other sweeps leave them out.
LOCAL_ONLY = ("program egress", "program private egress", "local upstream", "unix upstream")


def secret_heavy_beside(raw: dict[str, Any]) -> dict[str, Any]:
    """The rig's policy, ``raw``, with the leak sweep's secret-heavy policy beside it: its egress
    proxy, admin block, credentials, connector and routes, and its two clients (the literal
    token's among them) on the rig's server."""
    heavy = secret_heavy_policy().model_dump(mode="json", by_alias=True, exclude_defaults=True)
    local = ("leak-route-bridge", "leak-route-socket")
    routes = [route for route in heavy["routes"] if route["name"] not in local]
    clients = {
        name: {**client, "servers": [SERVER]}
        for name, client in heavy["gateway"]["clients"].items()
    }
    return {
        **raw,
        "egress_proxy": heavy["egress_proxy"],
        "admin": heavy["admin"],
        "credentials": {**raw["credentials"], **heavy["credentials"]},
        "connectors": heavy["connectors"],
        "routes": [*raw["routes"], *routes],
        "gateway": {**raw["gateway"], "clients": {**raw["gateway"]["clients"], **clients}},
    }


async def test_the_status_report_shows_no_policy_value(tmp_path: Path) -> None:
    """O.6 for the status kind (Y13): a gateway on a policy holding the secret-heavy policy's
    values and its literal client token, with a drifted tool and tools nobody reviewed. The
    report it would push (:func:`content` of :func:`pushed_status`), the report the vault keeps
    and the gateway's ``GET /status`` hold no vault-side value, no client token or its hash, no
    client name and no tool's definition, only names, pins and counts; and the vault's health
    after it holds no value the policy view hides, nor a token's hash or a definition."""
    fake = McpFake()
    tools = [tool["name"] for tool in base_tools()]
    include = tools[:2]  # echo, which drifts, and add; the rest nobody reviewed
    review = {name: pin_of_fake(fake, name) for name in include}
    with deployment(tmp_path, fake, include=include, review=review) as deployed:
        vault = deployed.vault
        assert vault is not None
        merged = secret_heavy_beside(raw_policy(deployed.fake_url, include=include, review=review))
        text = json.dumps(merged, separators=(",", ":"))
        kept = {where: value for where, value in VAULT_SIDE.items() if where not in LOCAL_ONLY}
        for where, value in kept.items():
            assert value in text, where  # every sentinel is really in the policy
        answer = httpx.post(deployed.vault_url + RELOAD_PATH, json=merged, timeout=10)
        assert answer.status_code == 204, answer.text
        policy = Policy.model_validate(merged)
        view = build_view(policy)
        assert view.gateway is not None
        assert hash_token(LITERAL_TOKEN) in dump_view(view).decode()  # the gateway holds it
        fake.change_tool("description")
        with gateway(deployed, status_push=True) as running:

            def attended() -> bool:
                report = vault.gateway_status().report
                if report is None:
                    return False
                server = report.servers.get(SERVER)
                return server is not None and bool(server.drift) and bool(server.unreviewed)

            async with agent(running) as connected:  # the server's connection opens
                listed = sorted(tool.name for tool in (await connected.list_tools()).tools)
            assert listed == ["add"]
            await until(attended, timeout=20)
            pushed = content(
                pushed_status(running.app),
                started=1,
                max_tools=view.gateway.limits.max_tools_per_server,
            )
            assert pushed is not None
            served = httpx.get(running.admin_url + "/status", timeout=10)
            assert served.status_code == 200, served.text
            report = vault.gateway_status().report
        checked = health(deployed)
    assert pushed["servers"][SERVER]["drift"] == ["echo"]
    unreviewed = pushed["servers"][SERVER]["unreviewed"]
    assert unreviewed
    assert all(name in tools and pin.startswith("sha256:") for name, pin in unreviewed)
    shown = {
        "pushed": statuspush.encoded(pushed).decode(),
        "kept": repr(report),
        "status": served.text,
    }
    clients = [*CLIENTS, *secret_heavy_policy().model_dump()["gateway"]["clients"]]
    hashes = {
        "the literal token's hash": hash_token(LITERAL_TOKEN),
        "the other token's hash": "3" * 64,
        **{f"{name}'s hash": hash_token(token_for(name)) for name in CLIENTS},
        **{f"{wire['name']}'s description": wire["description"] for wire in base_tools()},
    }
    hidden = {**kept, **hashes, **{f"client {name}": f'"{name}"' for name in clients}}
    for where, text in shown.items():
        for what, value in hidden.items():
            assert value not in text, f"{what} in {where}"
    # Health is the vault's own answer to its host, which names credentials, routes and clients
    # (M.5): it holds nothing the policy view hides, as the vault's sweeps check.
    answered = json.dumps(checked)
    assert '"name": "notes"' in answered
    for what, value in {
        **{where: VAULT_SIDE[where] for where in POLICY_VIEW_HIDES},
        **hashes,
    }.items():
        assert value not in answered, f"{what} in health"
