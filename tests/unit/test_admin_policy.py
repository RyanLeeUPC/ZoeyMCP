"""The admin socket's policy routes (M6 design H, N.1; FM-15, FM-16, FM-22, FM-32; Y2, Y13, Y17),
in process: the head, history, a diff and the export (R61's fourth scoped exception) read the
managed store; an import (an edited export, the vault's own configured policy, or that policy
recorded as the seed's baseline) and a rollback are planned with ``plan=1``, then committed with
``If-Match`` and the plan's digest, through the one write path (``vault/managed.py``).

Each test starts a managed vault on a fresh volume as ``tests/unit/test_managed.py`` does and
serves the socket's app over ASGI. :class:`SocketTransport` serves the same app to the CLI's
synchronous client, on one event loop in a thread, for ``tests/unit/test_cli_policy.py``.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import anyio.from_thread
import httpx
import pytest
from starlette.types import ASGIApp

from zoeymcp.common.policy import gate
from zoeymcp.common.policy.plan import normalized_digest
from zoeymcp.common.policy.restart import Effect
from zoeymcp.common.policy.schema import Policy, hash_token
from zoeymcp.portal.passkeys import Passkeys
from zoeymcp.vault import logs
from zoeymcp.vault.admin import AdminApp, SetupCodes
from zoeymcp.vault.managed import Lockout, WriteRefused, Written, lockout_rows
from zoeymcp.vault.onboarding import NextStep, saved_next
from zoeymcp.vault.policyseal import REVISION_MAX
from zoeymcp.vault.policystart import Ok
from zoeymcp.vault.policystore import PolicyStore
from zoeymcp.vault.statusreport import Report

from .test_managed import Rig, edited, import_, managed_text, start

pytestmark = pytest.mark.anyio

REPORTS_TOKEN = "admin-policy-reports-token-0001"
YAML = {"content-type": "application/yaml"}


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def log_buffer() -> Iterator[io.StringIO]:
    buffer = io.StringIO()
    logs.set_stream(buffer)
    try:
        yield buffer
    finally:
        logs.set_stream(None)


def events(buffer: io.StringIO, name: str) -> list[dict[str, Any]]:
    lines = [json.loads(line) for line in buffer.getvalue().splitlines()]
    return [
        {k: v for k, v in line.items() if k not in ("ts", "role")}
        for line in lines
        if line["event"] == name
    ]


class Holder:
    """A passkey file's holder as the socket reads it for the lockout rows (I.1): the RP ID of
    each passkey, or a file that can't be verified."""

    def __init__(self, rp_ids: Sequence[str], *, unavailable: bool = False) -> None:
        self.unavailable = unavailable
        self.document = SimpleNamespace(credentials=[SimpleNamespace(rp_id=r) for r in rp_ids])


class PolicyRig:
    """A managed vault's admin app: its store, the managed holder, the passkeys ``holder`` and
    the configured policy ``source`` (``ZOEYMCP_CONFIG``'s text) for ``from_env``; the vault's
    token manager and revoker unless ``tokens`` and ``revoker`` stand in for them."""

    def __init__(
        self,
        tmp_path: Path,
        text: str | None = None,
        *,
        holder: Holder | None = None,
        tokens: Any = None,
        revoker: Any = None,
        **environ: str,
    ) -> None:
        self.vault: Rig = start(tmp_path, text, **environ)
        self.configured = text or managed_text()
        self.admin = AdminApp(
            self.vault.runtime.store,
            self.vault.runtime.keys,
            lambda: self.vault.app.policy,
            SetupCodes(self.vault.state, self.vault.runtime.keys.portal_key),
            tokens or self.vault.app.tokens,
            passkeys=cast(Passkeys, holder),
            revoker=revoker or self.vault.app.revoker,
            managed=self.vault.managed,
            source=lambda: (self.configured, "$ZOEYMCP_CONFIG"),
        )

    async def call(
        self,
        method: str,
        path: str,
        *,
        content: bytes | None = None,
        headers: Mapping[str, str] | None = None,
        params: Sequence[tuple[str, str]] = (),
    ) -> httpx.Response:
        transport = httpx.ASGITransport(app=self.admin.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://admin") as client:
            return await client.request(
                method, path, content=content, headers=headers, params=list(params)
            )

    async def first_line(self) -> str:
        """The export header of the head, as an edited export keeps it (H.6)."""
        answer = await self.call("GET", "/policy/export")
        assert answer.status_code == 200, answer.text
        line: str = answer.json()["export"].splitlines()[0]
        return line

    def document(self) -> dict[str, Any]:
        found: dict[str, Any] = self.vault.managed.policy.model_dump(
            mode="json", by_alias=True, exclude_defaults=True
        )
        return found

    async def write(
        self,
        path: str,
        *,
        body: bytes = b"",
        base: int | None = None,
        query: Sequence[tuple[str, str]] = (),
    ) -> tuple[httpx.Response, httpx.Response | None]:
        """A write as the CLI makes it: the plan, then (if the plan was answered) the commit
        naming ``base`` (the plan's when None) and the plan's digest."""
        headers = dict(YAML) if body else {}
        if base is not None:
            headers["if-match"] = f'"{base}"'
        planned = await self.call(
            "POST", path, content=body, headers=headers, params=[("plan", "1"), *query]
        )
        if planned.status_code != 200:
            return planned, None
        headers["if-match"] = f'"{planned.json()["base"]}"'
        headers["x-zoeymcp-plan"] = planned.json()["digest"]
        committed = await self.call("POST", path, content=body, headers=headers, params=query)
        return planned, committed

    async def aclose(self) -> None:
        await self.vault.app.aclose()


def body(first_line: str, data: Mapping[str, Any]) -> bytes:
    """An edited export: its header line, then the document (JSON is YAML)."""
    return (first_line + "\n" + json.dumps(data) + "\n").encode()


def with_reports(data: dict[str, Any]) -> dict[str, Any]:
    """A new client, a widening (G.7 row 2)."""
    data["gateway"]["clients"]["reports"] = {"token_sha256": hash_token(REPORTS_TOKEN)}
    return data


def without_stats(data: dict[str, Any]) -> dict[str, Any]:
    """The stats route and its credential removed: the store entry it used is left unused."""
    data["routes"] = [route for route in data["routes"] if route["name"] != "stats"]
    del data["credentials"]["music-stats"]
    return data


# --- reading (H.1, H.2, H.6) -------------------------------------------------------------------


async def test_the_head_and_the_declarative_answers(tmp_path: Path) -> None:
    """N.1: GET /policy names the mode and the head, never a hidden field; without a managed
    holder the mode is declarative and every other policy route answers policy_not_managed."""
    rig = PolicyRig(tmp_path)
    head = (await rig.call("GET", "/policy")).json()
    store = rig.vault.store
    assert store.head is not None
    assert head == {
        "mode": "managed",
        "revision": 1,
        "digest8": store.head.digest.removeprefix("sha256:")[:8],
        "deployment8": store.head.deployment[:8],
        "created": head["created"],
        "origin": "seed",
        "kind": "policy.seed",
        "author": {"by": "seed"},
        "witness": None,
        "gateway": {"state": "unknown", "revision": None},
        "not_running": None,
    }
    declarative = AdminApp(
        rig.vault.runtime.store,
        rig.vault.runtime.keys,
        lambda: Policy.model_validate({"version": 1, "mode": "declarative"}),
        SetupCodes(rig.vault.state, rig.vault.runtime.keys.portal_key),
    )
    rig.admin = declarative
    assert (await rig.call("GET", "/policy")).json() == {"mode": "declarative", "revision": None}
    for method, path in (
        ("GET", "/policy/revisions"),
        ("GET", "/policy/revisions/1"),
        ("GET", "/policy/revisions/1/diff"),
        ("GET", "/policy/export"),
        ("POST", "/policy/import"),
        ("POST", "/policy/rollback/1"),
    ):
        answer = await rig.call(method, path)
        assert (answer.status_code, answer.json()["reason"]) == (409, "policy_not_managed"), path
    await rig.aclose()


async def test_history_a_diff_and_one_revision(tmp_path: Path) -> None:
    """H.1, H.2, Y13: history pages newest first, a revision's header has no digest, and a
    diff renders through the policy view: a new client's token hash shows only as set."""
    rig = PolicyRig(tmp_path)
    first = await rig.first_line()
    accept = [("accept_widening", "1")]
    _, done = await rig.write(
        "/policy/import", body=body(first, with_reports(rig.document())), base=1, query=accept
    )
    assert done is not None
    assert done.status_code == 200, done.text
    raised = {**rig.document(), "egress_key_generation": 2}
    _, done = await rig.write("/policy/import", body=body(await rig.first_line(), raised))
    assert done is not None
    assert done.status_code == 200, done.text
    page = (await rig.call("GET", "/policy/revisions", params=[("limit", "2")])).json()
    assert [entry["revision"] for entry in page["revisions"]] == [3, 2]
    assert page["next"] == 2
    older = (await rig.call("GET", "/policy/revisions", params=[("before", "2")])).json()
    assert [entry["revision"] for entry in older["revisions"]] == [1]
    assert older["next"] is None
    one = (await rig.call("GET", "/policy/revisions/2")).json()
    assert set(one) == {
        "revision",
        "created",
        "origin",
        "kind",
        "author",
        "base",
        "target",
        "jumped_from",
        "reason",
    }
    assert (one["kind"], one["author"], one["base"]) == (
        "policy.import",
        {"by": "host", "via": "socket"},
        1,
    )
    diff = (await rig.call("GET", "/policy/revisions/2/diff")).json()
    assert diff["against"] == 1
    [row] = diff["rows"]
    assert (row["path_shown"], row["op"], row["direction"]) == (
        ["gateway", "clients", "reports"],
        "added",
        "wider",
    )
    assert hash_token(REPORTS_TOKEN) not in json.dumps(diff)
    seed = (await rig.call("GET", "/policy/revisions/1/diff")).json()
    assert seed["against"] is None
    assert seed["rows"]
    against = (await rig.call("GET", "/policy/revisions/3/diff", params=[("against", "1")])).json()
    assert {tuple(row["path_shown"]) for row in against["rows"]} == {
        ("egress_key_generation",),
        ("gateway", "clients", "reports"),
    }
    for path, reason in (
        ("/policy/revisions/9", "revision_unknown"),
        ("/policy/revisions/9/diff", "revision_unknown"),
    ):
        answer = await rig.call("GET", path)
        assert (answer.status_code, answer.json()["reason"]) == (409, reason)
    assert (await rig.call("GET", "/policy/revisions/x")).json()["reason"] == "bad_query"
    await rig.aclose()


async def test_the_export_is_the_fourth_exception(tmp_path: Path, log_buffer: io.StringIO) -> None:
    """H.6, DD-4: the export holds the client token hashes, is never cached and is logged;
    a kept revision, declarative and the compose form are asked by query."""
    rig = PolicyRig(tmp_path)
    answer = await rig.call("GET", "/policy/export")
    assert answer.headers["cache-control"] == "no-store"
    found = answer.json()
    assert found["revision"] == 1
    assert found["export"].startswith(
        f"# zoeymcp policy export: revision 1 of deployment {found['deployment']}, "
    )
    assert found["notes"][0].startswith(f"Exported revision 1 of deployment {found['deployment']}")
    params = [("mode", "declarative"), ("for", "compose"), ("revision", "1")]
    compose = (await rig.call("GET", "/policy/export", params=params)).json()
    assert '        mode: "declarative"' in compose["export"]
    assert compose["notes"][1].startswith("gateway_key_generation is now a literal 1")
    assert events(log_buffer, "policy_exported") == [
        {"event": "policy_exported", "revision": 1, "via": "socket"},
        {"event": "policy_exported", "revision": 1, "via": "socket"},
    ]
    for params in ([("mode", "other")], [("for", "x")], [("revision", "-1")], [("x", "1")]):
        refused = await rig.call("GET", "/policy/export", params=params)
        assert (refused.status_code, refused.json()["reason"]) == (400, "bad_query")
    gone = await rig.call("GET", "/policy/export", params=[("revision", "5")])
    assert gone.json()["reason"] == "revision_unknown"
    await rig.aclose()


# --- an import (H.5) ---------------------------------------------------------------------------


async def test_an_import_planned_then_committed(tmp_path: Path, log_buffer: io.StringIO) -> None:
    """H.5, J7: the plan names the widening first and its digest; the commit needs If-Match
    (428 base_required), the plan's digest (plan_changed) and, for a widening,
    accept_widening (import_widens); then the revision is written, logged, and its answer
    names the gateway's state and the way on (M.7)."""
    rig = PolicyRig(tmp_path)
    first = await rig.first_line()
    document = body(first, with_reports(rig.document()))
    plan = await rig.call(
        "POST", "/policy/import", content=document, headers=YAML, params=[("plan", "1")]
    )
    assert plan.status_code == 200, plan.text
    planned = plan.json()
    assert (planned["kind"], planned["base"], planned["revision"]) == ("policy.import", 1, 2)
    assert planned["rows"][0] == ["Revision", "2, from 1"]
    assert planned["rows"][1] == ["gateway.clients.reports", "added (wider)"]
    assert (planned["widens"], planned["widenings"], planned["lockout"]) == (
        True,
        ["gateway.clients.reports"],
        [],
    )
    commit = {**YAML, "x-zoeymcp-plan": planned["digest"]}
    refused = await rig.call("POST", "/policy/import", content=document, headers=commit)
    assert (refused.status_code, refused.json()["reason"]) == (428, "base_required")
    commit["if-match"] = '"1"'
    wider = await rig.call("POST", "/policy/import", content=document, headers=commit)
    assert (wider.status_code, wider.json()["reason"]) == (400, "import_widens")
    assert "gateway.clients.reports" in wider.json()["error"]
    other = {**commit, "x-zoeymcp-plan": "sha256:" + "0" * 64}
    accept = [("accept_widening", "1")]
    changed = await rig.call(
        "POST", "/policy/import", content=document, headers=other, params=accept
    )
    assert (changed.status_code, changed.json()["reason"]) == (409, "plan_changed")
    assert rig.vault.managed.revision == 1
    done = await rig.call(
        "POST",
        "/policy/import",
        content=document,
        headers=commit,
        params=[*accept, ("reason", "a reports client")],
    )
    assert done.status_code == 200, done.text
    answer = done.json()
    assert (answer["revision"], answer["already_saved"], answer["gateway"]) == (2, False, "pending")
    assert answer["next"] == [
        {"do": "wait_gateway", "label": "The gateway takes the new view within seconds"}
    ]
    [line] = events(log_buffer, "policy_imported")
    assert (line["revision"], line["author"], line["from_env"], line["baseline_only"]) == (
        2,
        "host",
        False,
        False,
    )
    entry = (await rig.call("GET", "/policy/revisions/2")).json()
    assert entry["reason"] == "a reports client"
    await rig.aclose()


async def test_a_retry_is_already_saved_and_a_moved_head_is_412(tmp_path: Path) -> None:
    """FM-16, N.1: the same commit again after its answer was lost is already_saved, with the
    same revision; one planned on revision 1 after another write is 412 policy_moved."""
    rig = PolicyRig(tmp_path)
    first = await rig.first_line()
    document = body(first, with_reports(rig.document()))
    accept = [("accept_widening", "1")]
    plan, done = await rig.write("/policy/import", body=document, base=1, query=accept)
    assert done is not None
    assert done.status_code == 200, done.text
    headers = {**YAML, "if-match": '"1"', "x-zoeymcp-plan": plan.json()["digest"]}
    again = await rig.call(
        "POST", "/policy/import", content=document, headers=headers, params=accept
    )
    assert again.status_code == 200, again.text
    assert (again.json()["revision"], again.json()["already_saved"]) == (2, True)
    # The CLI plans before it commits: its rerun meets the retry at the plan.
    replan = await rig.call(
        "POST",
        "/policy/import",
        content=document,
        headers={**YAML, "if-match": '"1"'},
        params=[("plan", "1")],
    )
    assert replan.status_code == 200, replan.text
    assert (replan.json()["revision"], replan.json()["already_saved"]) == (2, True)
    assert rig.vault.managed.revision == 2
    other = rig.document()
    other["egress_key_generation"] = 2
    stale = await rig.call(
        "POST", "/policy/import", content=body(first, other), headers=headers, params=accept
    )
    assert (stale.status_code, stale.json()["reason"], stale.json()["revision"]) == (
        412,
        "policy_moved",
        2,
    )
    moved_plan = await rig.call(
        "POST",
        "/policy/import",
        content=body(first, other),
        headers={**YAML, "if-match": '"1"'},
        params=[("plan", "1")],
    )
    assert (moved_plan.status_code, moved_plan.json()["reason"]) == (412, "policy_moved")
    await rig.aclose()


async def test_import_races_a_save(tmp_path: Path) -> None:
    """FM-15: a socket import planned on revision 1 meets a write that committed revision 2 in
    the meantime (the portal's, through the same section): the import's commit is 412
    policy_moved, and only the other write is in the store."""
    rig = PolicyRig(tmp_path)
    first = await rig.first_line()
    document = body(first, with_reports(rig.document()))
    plan = await rig.call(
        "POST", "/policy/import", content=document, headers=YAML, params=[("plan", "1")]
    )
    saved = import_(rig.vault, edited(lambda data: data.update(egress_key_generation=2)))
    assert isinstance(saved, Written)
    headers = {**YAML, "if-match": '"1"', "x-zoeymcp-plan": plan.json()["digest"]}
    late = await rig.call(
        "POST",
        "/policy/import",
        content=document,
        headers=headers,
        params=[("accept_widening", "1")],
    )
    assert (late.status_code, late.json()["reason"]) == (412, "policy_moved")
    assert rig.vault.managed.revision == 2
    assert rig.vault.managed.policy.gateway is not None
    assert "reports" not in rig.vault.managed.policy.gateway.clients
    await rig.aclose()


HOSTILE = [
    ("version: 1\nmode: !!python/object:os.system managed\n", "tags are not allowed"),
    ("version: 1\nmode: managed\u0085x: 1\n", "U+0085"),
    ("version: 1\nmode: managed\nx: " + "[" * 5000 + "]" * 5000 + "\n", "nested deeper than 64"),
]


@pytest.mark.parametrize(("text", "said"), HOSTILE, ids=["tag", "nel", "brackets"])
async def test_hostile_yaml(tmp_path: Path, text: str, said: str) -> None:
    """FM-22, B: an import whose YAML has a tag, a NEL or 5,000 brackets is import_refused
    with the loader's reason, before any plan; nothing is written."""
    rig = PolicyRig(tmp_path)
    refused = await rig.call(
        "POST", "/policy/import", content=text.encode(), headers=YAML, params=[("plan", "1")]
    )
    assert (refused.status_code, refused.json()["reason"]) == (400, "import_refused")
    assert said in refused.json()["error"]
    assert rig.vault.managed.revision == 1
    await rig.aclose()


async def test_what_the_gate_and_the_socket_refuse(tmp_path: Path) -> None:
    """Y2, H.5 steps 1-2, N.1: an import that fails check here (an env: name unset in the vault's
    environment) or isn't managed is refused; so is a body that isn't YAML, too large, or a
    query the route doesn't take."""
    rig = PolicyRig(tmp_path)
    first = await rig.first_line()
    data = rig.document()
    data["credentials"]["music-stats"]["secret"] = "env:UNSET_IN_THE_VAULT"
    refused = await rig.call(
        "POST", "/policy/import", content=body(first, data), headers=YAML, params=[("plan", "1")]
    )
    assert (refused.status_code, refused.json()["reason"]) == (400, "import_refused")
    assert "UNSET_IN_THE_VAULT" in refused.json()["error"]
    declarative = {**rig.document(), "mode": "declarative"}
    answer = await rig.call(
        "POST",
        "/policy/import",
        content=body(first, declarative),
        headers=YAML,
        params=[("plan", "1")],
    )
    assert (answer.status_code, answer.json()["reason"]) == (400, "import_declarative")
    plain = await rig.call(
        "POST",
        "/policy/import",
        content=body(first, rig.document()),
        headers={"content-type": "application/json"},
        params=[("plan", "1")],
    )
    assert (plain.status_code, plain.json()["reason"]) == (415, "content_type")
    big = await rig.call(
        "POST",
        "/policy/import",
        content=b"#" * (1_048_576 + 1),
        headers=YAML,
        params=[("plan", "1")],
    )
    assert (big.status_code, big.json()["reason"]) == (413, "too_large")
    for params in (
        [("plan", "2")],
        [("plan", "1"), ("plan", "1")],
        [("nope", "1")],
        [("reason", "a\tb")],
        [("baseline_only", "1")],
    ):
        bad = await rig.call(
            "POST",
            "/policy/import",
            content=body(first, rig.document()),
            headers=YAML,
            params=params,
        )
        assert (bad.status_code, bad.json()["reason"]) == (400, "bad_query"), params
    nothing = await rig.call(
        "POST",
        "/policy/import",
        content=body(first, rig.document()),
        headers=YAML,
        params=[("plan", "1")],
    )
    assert (nothing.status_code, nothing.json()["reason"]) == (400, "no_change")
    await rig.aclose()


async def test_from_env_and_the_baseline(tmp_path: Path, log_buffer: io.StringIO) -> None:
    """G-14, F.5, OPS-7: baseline_only records a changed configured policy's digest as the
    seed's and applies nothing (policy.acknowledge), so policy_seed_ignored ends; one that
    already matches has nothing_to_acknowledge; from_env plans the configured policy as an
    import and records its digest the same way."""
    rig = PolicyRig(tmp_path)
    baseline = [("from_env", "1"), ("baseline_only", "1")]
    nothing = await rig.call("POST", "/policy/import", params=[("plan", "1"), *baseline])
    assert (nothing.status_code, nothing.json()["reason"]) == (409, "nothing_to_acknowledge")
    rig.configured = rig.configured.replace(
        "gateway_key_generation: 1", "egress_key_generation: 2", 1
    )
    plan, done = await rig.write("/policy/import", query=baseline)
    assert plan.json()["kind"] == "policy.acknowledge"
    assert done is not None
    assert done.status_code == 200, done.text
    assert rig.vault.managed.policy.egress_key_generation == 1
    header = rig.vault.store.header
    assert header is not None
    assert (header["kind"], header["origin"]) == ("policy.acknowledge", "acknowledge")
    assert rig.vault.store.seed_digest == configured_digest(rig)
    [line] = events(log_buffer, "policy_acknowledged")
    assert (line["from_env"], line["baseline_only"]) == (True, True)
    assert (await retried(rig, plan, baseline)).json()["already_saved"] is True
    again = await rig.call("POST", "/policy/import", params=[("plan", "1"), *baseline])
    assert again.json()["reason"] == "nothing_to_acknowledge"
    rig.configured = rig.configured.replace("egress_key_generation: 2", "egress_key_generation: 3")
    plan, done = await rig.write("/policy/import", query=[("from_env", "1")])
    assert plan.json()["kind"] == "policy.import"
    assert done is not None
    assert done.status_code == 200, done.text
    assert rig.vault.managed.policy.egress_key_generation == 3
    assert rig.vault.store.seed_digest == configured_digest(rig)
    # Its retry after a lost answer is shaped on revision 2, as it was: already_saved; run
    # again on the head, the configured policy is the head's and its seed's.
    again = await retried(rig, plan, [("from_env", "1")])
    assert (again.json()["revision"], again.json()["already_saved"]) == (3, True)
    same = await rig.call("POST", "/policy/import", params=[("plan", "1"), ("from_env", "1")])
    assert (same.status_code, same.json()["reason"]) == (409, "nothing_to_acknowledge")
    assert rig.vault.managed.revision == 3
    without = await rig.call("POST", "/policy/import", content=b"x", params=[("from_env", "1")])
    assert (without.status_code, without.json()["reason"]) == (400, "bad_body")
    await rig.aclose()


async def retried(
    rig: PolicyRig, plan: httpx.Response, query: Sequence[tuple[str, str]]
) -> httpx.Response:
    """A from_env commit sent again as it was, its first answer lost (MISS-9, FM-16)."""
    headers = {"if-match": f'"{plan.json()["base"]}"', "x-zoeymcp-plan": plan.json()["digest"]}
    answer = await rig.call("POST", "/policy/import", headers=headers, params=query)
    assert answer.status_code == 200, answer.text
    return answer


def configured_digest(rig: PolicyRig) -> str:
    """The normalized digest of the configured policy, as the vault records it (F.5)."""
    admitted = gate.admit_text(rig.configured, "$ZOEYMCP_CONFIG", environ=rig.vault.environ)
    return normalized_digest(admitted.policy)


async def test_revoke_removed_after_refused_commit_keeps_slots(tmp_path: Path) -> None:
    """FM-32, G.8, CR-5: an import that removes a credential, with revoke_removed, whose commit
    is refused, leaves its store entry in place; committed, the entry is deleted (and its grant
    revoked, where it has one) after the commit, and the answer names it. Without the flag the
    plan names the entry left unused."""
    rig = PolicyRig(tmp_path)
    store = rig.vault.runtime.store
    store.put("music-stats", "v", {"origins": ["https://api.stats.example:443"]})
    first = await rig.first_line()
    document = body(first, without_stats(rig.document()))
    query = [("revoke_removed", "1")]
    plan = await rig.call(
        "POST", "/policy/import", content=document, headers=YAML, params=[("plan", "1"), *query]
    )
    assert plan.json()["unused"] == ["music-stats"]
    assert ["Left unused", "music-stats"] in plan.json()["rows"]
    wrong = {**YAML, "if-match": '"1"', "x-zoeymcp-plan": "sha256:" + "1" * 64}
    refused = await rig.call(
        "POST", "/policy/import", content=document, headers=wrong, params=query
    )
    assert refused.json()["reason"] == "plan_changed"
    moved = {**wrong, "if-match": '"7"'}
    refused = await rig.call(
        "POST", "/policy/import", content=document, headers=moved, params=query
    )
    assert refused.json()["reason"] == "policy_moved"
    assert [entry.name for entry in store.metadata()] == ["music-stats"]
    _, done = await rig.write("/policy/import", body=document, base=1, query=query)
    assert done is not None
    assert done.status_code == 200, done.text
    # A query credential's entry has nothing to revoke: deleted, and said so.
    assert done.json()["removed"] == [{"name": "music-stats", "revoked": False}]
    assert [entry.name for entry in store.metadata()] == []
    await rig.aclose()


class Tokens:
    """A token manager as a host write's removal reads it (G.8, CR-5): the material it has for
    each slot, and for each read the head's revision and whether the policy the vault runs
    then still names the credential; each wait for a refresh in flight."""

    def __init__(self, material: Mapping[str, Any]) -> None:
        self.material = material
        self.rig: PolicyRig | None = None
        self.read: list[tuple[str, int, bool]] = []
        self.waited: list[str] = []

    def revocation(self, name: str) -> Any:
        assert self.rig is not None
        running = self.rig.vault.app.policy
        self.read.append((name, self.rig.vault.managed.revision, name in running.credentials))
        return self.material.get(name)

    async def settled(self, name: str) -> None:
        self.waited.append(name)


class Revoker:
    """The revoker: each material asked for, with the head's revision then and whether the
    store still held the entry."""

    def __init__(self) -> None:
        self.rig: PolicyRig | None = None
        self.requested: list[tuple[Any, int, bool]] = []

    def request(self, material: Any) -> None:
        assert self.rig is not None
        held = self.rig.vault.runtime.store.entry("music-stats") is not None
        self.requested.append((material, self.rig.vault.managed.revision, held))


async def test_revoke_removed_takes_the_material_before_and_revokes_after(
    tmp_path: Path,
) -> None:
    """G.8, CR-5, FM-32: with revoke_removed, the removed credential's revocation material is
    taken inside the commit section from the policy still running (revision 1's, which names
    it), and its provider is asked only after the commit, the wait for a refresh in flight and
    the delete; a refused commit takes and asks nothing. The answer says it was revoked."""
    material = SimpleNamespace(credential="music-stats")
    tokens, revoker = Tokens({"music-stats": material}), Revoker()
    rig = PolicyRig(tmp_path, tokens=tokens, revoker=revoker)
    tokens.rig = revoker.rig = rig
    store = rig.vault.runtime.store
    store.put("music-stats", "v", {"origins": ["https://api.stats.example:443"]})
    document = body(await rig.first_line(), without_stats(rig.document()))
    query = [("revoke_removed", "1")]
    wrong = {**YAML, "if-match": '"1"', "x-zoeymcp-plan": "sha256:" + "1" * 64}
    refused = await rig.call(
        "POST", "/policy/import", content=document, headers=wrong, params=query
    )
    assert refused.json()["reason"] == "plan_changed"
    assert (tokens.read, tokens.waited, revoker.requested) == ([], [], [])
    assert store.entry("music-stats") is not None
    _, done = await rig.write("/policy/import", body=document, base=1, query=query)
    assert done is not None
    assert done.status_code == 200, done.text
    assert done.json()["removed"] == [{"name": "music-stats", "revoked": True}]
    assert tokens.read == [("music-stats", 1, True)]
    assert tokens.waited == ["music-stats"]
    assert revoker.requested == [(material, 2, False)]
    await rig.aclose()


# --- a rollback (H.3, H.4) ---------------------------------------------------------------------


async def test_a_rollback_and_what_it_brings_back(tmp_path: Path, log_buffer: io.StringIO) -> None:
    """H.3, H.4, E3, J6's socket half: revision 2 removes agent1; a rollback to 1 brings back
    its token, refused revives_client naming the revision that removed it and the grant;
    granted, revision 3 has 1's content, its target logged; a revision no longer kept is
    revision_unknown."""
    rig = PolicyRig(tmp_path)
    first = await rig.first_line()
    data = rig.document()
    del data["gateway"]["clients"]["agent1"]
    _, done = await rig.write("/policy/import", body=body(first, data), base=1)
    assert done is not None
    assert done.status_code == 200, done.text
    refused = await rig.call("POST", "/policy/rollback/1", params=[("plan", "1")])
    assert refused.status_code == 409
    assert refused.json()["reason"] == "revives_client"
    assert refused.json()["subjects"] == ["client:agent1"]
    assert "client agent1, removed in revision 2" in refused.json()["error"]
    grant = [("allow_revive", "client:agent1"), ("accept_widening", "1")]
    plan, done = await rig.write("/policy/rollback/1", query=grant)
    assert plan.json()["rows"][0] == ["Revision", "3, from 2: the content of revision 1"]
    assert ["Granted by the host", "revives_client: client:agent1"] in plan.json()["rows"]
    assert done is not None
    assert done.status_code == 200, done.text
    assert rig.vault.managed.policy.gateway is not None
    assert "agent1" in rig.vault.managed.policy.gateway.clients
    [line] = events(log_buffer, "policy_rolled_back")
    assert (line["revision"], line["base"], line["target"]) == (3, 2, 1)
    gone = await rig.call("POST", "/policy/rollback/40", params=[("plan", "1")])
    assert (gone.status_code, gone.json()["reason"]) == (409, "revision_unknown")
    assert gone.json()["error"] == "Revision 40 is no longer kept, or never was."
    await rig.aclose()


async def test_a_new_env_name_needs_allow_env(tmp_path: Path) -> None:
    """D-194, I.3 (E5, E6), Y14: an import that adds an env: name the seed didn't use is refused
    env_name_new, naming the grant; with allow_env it is written, and the name's reach is then
    the ratchet's, so sending it to another origin is env_reach_grows until granted again."""
    rig = PolicyRig(tmp_path, LEAK_LIKE="v")
    first = await rig.first_line()
    data = rig.document()
    data["credentials"]["music-stats"]["secret"] = "env:LEAK_LIKE"
    document = body(first, data)
    refused = await rig.call(
        "POST", "/policy/import", content=document, headers=YAML, params=[("plan", "1")]
    )
    assert (refused.status_code, refused.json()["reason"]) == (403, "env_name_new")
    assert refused.json()["subjects"] == ["LEAK_LIKE"]
    grant = [("allow_env", "LEAK_LIKE"), ("accept_widening", "1")]
    plan, done = await rig.write("/policy/import", body=document, base=1, query=grant)
    assert ["Granted by the host", "env_name_new: LEAK_LIKE"] in plan.json()["rows"]
    assert done is not None
    assert done.status_code == 200, done.text
    moved = rig.document()
    moved["routes"][0]["upstream"] = "https://api.other-stats.example"
    again = await rig.call(
        "POST",
        "/policy/import",
        content=body(await rig.first_line(), moved),
        headers=YAML,
        params=[("plan", "1")],
    )
    assert (again.status_code, again.json()["reason"]) == (403, "env_reach_grows")
    await rig.aclose()


async def test_lockout_rows_need_lockout_ok(tmp_path: Path) -> None:
    """I.1, G-17, Y17: an import that drops the origin a passkey was enrolled through, and
    moves admin.listen, plans two lockout rows; its commit is lockout_unconfirmed without
    lockout_ok, and written with it, admin as the import gives it."""
    rig = PolicyRig(tmp_path, holder=Holder(["localhost"]))
    first = await rig.first_line()
    data = rig.document()
    data["admin"] = {"listen": "127.0.0.1:9091", "origins": ["https://zoeymcp.tailnet.example"]}
    document = body(first, data)
    plan = await rig.call(
        "POST", "/policy/import", content=document, headers=YAML, params=[("plan", "1")]
    )
    assert plan.json()["lockout"] == [
        {
            "text": "removes http://localhost:8081, where 1 passkey was enrolled: it stops working",
            "confirm": "http://localhost:8081",
        },
        {
            "text": "moves the portal from 127.0.0.1:8081 to 127.0.0.1:9091: after the vault's "
            "restart it listens there",
            "confirm": "127.0.0.1:9091",
        },
    ]
    headers = {**YAML, "if-match": '"1"', "x-zoeymcp-plan": plan.json()["digest"]}
    accept = [("accept_widening", "1")]
    refused = await rig.call(
        "POST", "/policy/import", content=document, headers=headers, params=accept
    )
    assert (refused.status_code, refused.json()["reason"]) == (400, "lockout_unconfirmed")
    done = await rig.call(
        "POST",
        "/policy/import",
        content=document,
        headers=headers,
        params=[*accept, ("lockout_ok", "1")],
    )
    assert done.status_code == 200, done.text
    assert [step["do"] for step in done.json()["next"]] == ["restart", "wait_gateway"]
    assert rig.vault.managed.policy.admin is not None
    assert rig.vault.managed.policy.admin.listen == "127.0.0.1:9091"
    await rig.aclose()


# --- the pure parts the routes use -------------------------------------------------------------


def policy_with(origins: list[str], listen: str = "127.0.0.1:8081") -> Policy:
    return Policy.model_validate(
        {"version": 1, "mode": "managed", "admin": {"listen": listen, "origins": origins}}
    )


def test_lockout_rows() -> None:
    """I.1: a removed origin is a row when a passkey's RP ID is its host and no origin kept has
    that host; a passkey file that can't be read makes every such origin a row; a changed
    listen is a row; nothing else is."""
    both = policy_with(["http://localhost:8081", "https://a.example"])
    assert lockout_rows(both, both, ["localhost"]) == ()
    gone = policy_with(["https://a.example"])
    assert lockout_rows(both, gone, ["a.example"]) == ()
    assert lockout_rows(both, gone, ["LOCALHOST", "localhost"]) == (
        Lockout(
            "removes http://localhost:8081, where 2 passkeys were enrolled: they stop working",
            "http://localhost:8081",
        ),
    )
    moved_port = policy_with(["http://localhost:9091", "https://a.example"])
    assert lockout_rows(both, moved_port, ["localhost"]) == ()
    assert lockout_rows(both, gone, None) == (
        Lockout(
            "removes http://localhost:8081: the passkey file can't be read, so passkeys enrolled "
            "through it may stop working",
            "http://localhost:8081",
        ),
    )
    listen = policy_with(["http://localhost:8081", "https://a.example"], "0.0.0.0:8081")
    assert lockout_rows(both, listen, []) == (
        Lockout(
            "moves the portal from 127.0.0.1:8081 to 0.0.0.0:8081: after the vault's restart "
            "it listens there",
            "0.0.0.0:8081",
        ),
    )
    bare = Policy.model_validate({"version": 1, "mode": "managed"})
    assert lockout_rows(bare, both, ["localhost"]) == ()


def effect(kind: str, text: str = "said") -> Effect:
    return Effect(kind, "path", text)  # type: ignore[arg-type]


def test_saved_next() -> None:
    """M.7, I.2: the vault's restart first and once; a key to give in the vault's container; the
    gateway's or a bridge's restart and the proxy's allowlist in their own words; nothing for a
    live change; and the gateway's view until it is applied."""
    wait = NextStep("wait_gateway", "The gateway takes the new view within seconds")
    assert saved_next(()) == (wait,)
    assert saved_next((), applied=True) == ()
    assert saved_next([effect("live")], applied=True) == ()
    restart = NextStep("restart", "Restart the vault: the change waits for it", via="restart")
    found = saved_next(
        [
            effect("redeliver_gateway_key"),
            effect("vault_restart"),
            effect("gateway_restart", "restart the gateway"),
            effect("vault_restart"),
            effect("reemit_proxy_allowlist", "your proxy's allowlist is out of date"),
            effect("start_bridge", "the launcher didn't start bridge b"),
            effect("redeliver_egress_key"),
        ],
        applied=True,
    )
    assert found == (
        restart,
        NextStep(
            "deliver_key",
            "Give the gateway its new key within 5 minutes",
            ("zoeymcp", "gateway-key"),
            "exec",
        ),
        NextStep("restart", "restart the gateway"),
        NextStep("update_proxy_allowlist", "your proxy's allowlist is out of date"),
        NextStep("restart", "the launcher didn't start bridge b"),
        NextStep(
            "deliver_key",
            "Write the egress role's new key, then restart the role",
            ("zoeymcp", "egress-key"),
            "exec",
        ),
    )
    assert restart.answer() == {
        "do": "restart",
        "label": "Restart the vault: the change waits for it",
        "via": "restart",
    }


def test_a_refused_write_keeps_its_fields() -> None:
    """N.2: a write's refusal is the catalogue's sentence with the fields it names."""
    from zoeymcp.vault.managed import refused_answer, refused_body

    detail = "the policy moved to revision 4 since you started"
    moved = WriteRefused("policy_moved", detail, revision=4)
    assert refused_answer(moved).error == (
        "Nothing was written: the policy moved to revision 4 since you started. For an import, "
        "export again and redo your edit; for a rollback, run it again."
    )
    status, answer = refused_body(moved)
    assert (status, answer["reason"], answer["revision"], answer["subjects"]) == (
        412,
        "policy_moved",
        4,
        [],
    )
    full = refused_answer(WriteRefused("ratchet_full", "ignored"))
    assert full.error.startswith("The ratchet holds 10,000 retired entries")
    status, _ = refused_body(WriteRefused("import_refused", "bad"))
    assert status == 400


# --- the CLI's socket, in process (tests/unit/test_cli_policy.py) -----------------------------


class SocketTransport(httpx.BaseTransport):
    """An ASGI app served to a synchronous ``httpx.Client``, as the admin socket serves the CLI:
    every request on one event loop, in the portal's thread."""

    def __init__(self, app: ASGIApp, portal: anyio.from_thread.BlockingPortal) -> None:
        self._app = app
        self._portal = portal

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        content = request.read()

        async def call() -> tuple[int, list[tuple[str, str]], bytes]:
            transport = httpx.ASGITransport(app=self._app)
            async with httpx.AsyncClient(transport=transport, base_url="http://vault-admin") as c:
                answer = await c.request(
                    request.method, request.url, headers=request.headers, content=content
                )
                return answer.status_code, answer.headers.multi_items(), answer.content

        status, headers, body = self._portal.call(call)
        return httpx.Response(status, headers=headers, content=body)


def serve(
    monkeypatch: pytest.MonkeyPatch,
    app: Callable[[], ASGIApp],
    portal: anyio.from_thread.BlockingPortal,
) -> None:
    """The CLI's admin client reaches ``app()`` (read at each request) instead of a socket."""
    from zoeymcp.cli import admin_client

    class Late(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return SocketTransport(app(), portal).handle_request(request)

    monkeypatch.setattr(admin_client, "become_socket_owner", lambda socket: None)
    monkeypatch.setattr(httpx, "HTTPTransport", lambda uds: Late())


async def test_a_revision_that_no_longer_verifies_is_a_gap(tmp_path: Path) -> None:
    """H.1, H.3, D.6 row 14: a kept revision whose file no longer verifies shows in history as
    a gap, and can't be diffed, exported or rolled back to (revision_unreadable)."""
    rig = PolicyRig(tmp_path)
    for value in (2, 3):
        written = import_(rig.vault, generation_of(value))
        assert isinstance(written, Written)
    (rig.vault.state / "policy" / "revisions" / "0000000002.json").write_bytes(b"{}")
    page = (await rig.call("GET", "/policy/revisions")).json()
    assert page["revisions"][1] == {"revision": 2, "gap": True}
    assert [entry["revision"] for entry in page["revisions"]] == [3, 2, 1]
    for method, path, params in (
        ("GET", "/policy/revisions/2", []),
        ("GET", "/policy/revisions/3/diff", []),
        ("GET", "/policy/export", [("revision", "2")]),
        ("POST", "/policy/rollback/2", [("plan", "1")]),
    ):
        answer = await rig.call(method, path, params=params)
        assert (answer.status_code, answer.json()["reason"]) == (409, "revision_unreadable"), path
        assert answer.json()["error"] == (
            "Revision 2 is in quarantine: it can't be read, so it can't be used."
        )
    await rig.aclose()


def generation_of(value: int) -> Callable[[Policy], Policy]:
    """A candidate builder: the egress key generation raised to ``value``."""
    return edited(lambda data: data.update(egress_key_generation=value))


# --- acknowledging a restore (K.3, J11, T-4) ------------------------------------------------------

OTHER_DEPLOYMENT = "fedcba9876543210" * 2


def witness_of(rig: PolicyRig, witness: dict[str, int]) -> None:
    """The gateway's status report as the vault keeps it, its witness ``witness``."""
    rig.vault.app.keep_status(
        Report(view="sha256:" + "0" * 64, started=1, servers={}, witness=witness)
    )


def deployment_of(rig: PolicyRig) -> str:
    head = rig.vault.store.head
    assert head is not None
    return head.deployment


async def test_the_head_names_the_witness(tmp_path: Path) -> None:
    """N.1: ``GET /policy``'s ``witness`` is null before any status report, then what the
    gateway has seen of this deployment, whether the head is behind it, another deployment's
    claim, and the acknowledgment's number."""
    rig = PolicyRig(tmp_path)
    assert (await rig.call("GET", "/policy")).json()["witness"] is None
    witness_of(rig, {OTHER_DEPLOYMENT: 31, deployment_of(rig): 4})
    assert (await rig.call("GET", "/policy")).json()["witness"] == {
        "revision": 4,
        "behind": True,
        "other": {"deployment8": OTHER_DEPLOYMENT[:8], "revision": 31},
        "target": 32,
    }
    await rig.aclose()


async def test_an_acknowledgment_planned_then_committed(
    tmp_path: Path, log_buffer: io.StringIO
) -> None:
    """K.3: the plan names the revision one above the gateway's claim and the claim; the commit
    takes the number the host typed (``to``), the base and the plan's digest, and writes the
    head's content there, ``jumped_from`` the head; then there is nothing to acknowledge."""
    rig = PolicyRig(tmp_path)
    nothing = await rig.call("POST", "/policy/acknowledge-restore", params=[("plan", "1")])
    assert (nothing.status_code, nothing.json()["reason"]) == (409, "nothing_to_acknowledge")
    assert nothing.json()["error"] == (
        "There is nothing to record: the gateway reports no revision of this deployment above "
        "the head, and no other deployment it hasn't passed."
    )
    witness_of(rig, {deployment_of(rig): 1})
    still = await rig.call("POST", "/policy/acknowledge-restore", params=[("plan", "1")])
    assert still.json()["reason"] == "nothing_to_acknowledge"
    witness_of(rig, {deployment_of(rig): 31})
    planned = await rig.call("POST", "/policy/acknowledge-restore", params=[("plan", "1")])
    assert planned.status_code == 200, planned.text
    plan = planned.json()
    assert (plan["kind"], plan["base"], plan["revision"]) == ("policy.acknowledge", 1, 32)
    assert plan["rows"][0] == ["Revision", "32, from 1, past 2-31, which are never written"]
    assert plan["witness"] == {"revision": 31, "behind": True, "other": None, "target": 32}
    assert (plan["widens"], plan["lockout"]) == (False, [])
    headers = {"if-match": '"1"', "x-zoeymcp-plan": plan["digest"]}
    untyped = await rig.call("POST", "/policy/acknowledge-restore", headers=headers)
    assert (untyped.status_code, untyped.json()["reason"]) == (400, "bad_query")
    other = await rig.call(
        "POST", "/policy/acknowledge-restore", headers=headers, params=[("to", "40")]
    )
    assert (other.status_code, other.json()["reason"]) == (409, "plan_changed")
    unbased = await rig.call(
        "POST",
        "/policy/acknowledge-restore",
        headers={"x-zoeymcp-plan": plan["digest"]},
        params=[("to", "32")],
    )
    assert (unbased.status_code, unbased.json()["reason"]) == (428, "base_required")
    done = await rig.call(
        "POST", "/policy/acknowledge-restore", headers=headers, params=[("to", "32")]
    )
    assert done.status_code == 200, done.text
    assert (done.json()["revision"], done.json()["already_saved"]) == (32, False)
    store = rig.vault.store
    assert store.header is not None
    assert (store.header["origin"], store.header["jumped_from"]) == ("acknowledge", 1)
    head = (await rig.call("GET", "/policy")).json()
    assert (head["revision"], head["kind"]) == (32, "policy.acknowledge")
    assert head["witness"] == {"revision": 31, "behind": False, "other": None, "target": None}
    history = (await rig.call("GET", "/policy/revisions")).json()["revisions"]
    assert [entry["revision"] for entry in history] == [32, 1]
    gone = await rig.call("GET", "/policy/revisions/5")
    assert (gone.status_code, gone.json()["reason"]) == (409, "revision_unknown")
    [line] = events(log_buffer, "policy_acknowledged")
    assert (line["revision"], line["base"], line["jumped_from"], line["author"]) == (
        32,
        1,
        1,
        "host",
    )
    again = await rig.call("POST", "/policy/acknowledge-restore", params=[("plan", "1")])
    assert again.json()["reason"] == "nothing_to_acknowledge"
    await rig.aclose()


async def test_a_claim_at_the_maximum_is_out_of_range(tmp_path: Path) -> None:
    """T-4: the claim the status reader admits goes up to 9,999,999,999; its acknowledgment
    would be one above, which no revision can be, and no claim makes the next start fail."""
    rig = PolicyRig(tmp_path)
    witness_of(rig, {deployment_of(rig): REVISION_MAX})
    refused = await rig.call("POST", "/policy/acknowledge-restore", params=[("plan", "1")])
    assert (refused.status_code, refused.json()["reason"]) == (400, "revision_out_of_range")
    witness_of(rig, {deployment_of(rig): REVISION_MAX - 1})
    planned, done = await rig.write("/policy/acknowledge-restore", base=1)
    assert planned.status_code == 200, planned.text
    assert done is not None
    assert (done.status_code, done.json()["reason"]) == (400, "bad_query")  # no to=N
    headers = {"if-match": '"1"', "x-zoeymcp-plan": planned.json()["digest"]}
    done = await rig.call(
        "POST", "/policy/acknowledge-restore", headers=headers, params=[("to", str(REVISION_MAX))]
    )
    assert done.status_code == 200, done.text
    keys = rig.vault.runtime.keys
    reopened = PolicyStore.open(rig.vault.state, keys, None)
    assert isinstance(reopened.verdict, Ok)
    assert reopened.verdict.revision == REVISION_MAX
    await rig.aclose()


@pytest.mark.parametrize(
    "query",
    [
        [("to", "x")],
        [("to", "0")],
        [("to", "1"), ("to", "2")],
        [("from_env", "1")],
        [("allow_revive", "client:a")],
    ],
    ids=["not-a-number", "zero", "twice", "from-env", "a-grant"],
)
async def test_what_an_acknowledgment_query_refuses(
    tmp_path: Path, query: list[tuple[str, str]]
) -> None:
    rig = PolicyRig(tmp_path)
    witness_of(rig, {deployment_of(rig): 5})
    answer = await rig.call("POST", "/policy/acknowledge-restore", params=[("plan", "1"), *query])
    assert (answer.status_code, answer.json()["reason"]) == (400, "bad_query")
    body = await rig.call(
        "POST", "/policy/acknowledge-restore", content=b"x", params=[("plan", "1")]
    )
    assert (body.status_code, body.json()["reason"]) == (400, "bad_body")
    await rig.aclose()


async def test_a_declarative_vault_has_nothing_to_acknowledge(tmp_path: Path) -> None:
    rig = PolicyRig(tmp_path)
    rig.admin = AdminApp(
        rig.vault.runtime.store,
        rig.vault.runtime.keys,
        lambda: Policy.model_validate({"version": 1, "mode": "declarative"}),
        SetupCodes(rig.vault.state, rig.vault.runtime.keys.portal_key),
    )
    answer = await rig.call("POST", "/policy/acknowledge-restore", params=[("plan", "1")])
    assert (answer.status_code, answer.json()["reason"]) == (409, "policy_not_managed")
    await rig.aclose()
