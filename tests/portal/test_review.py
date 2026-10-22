"""The review screen's routes over the real API (M7 design K.1 item 4, K.2, F.2, F.6; J4).

The vault's review jobs are the real ones; the gateway is played on the vault's loop, as its poll
would: a poll waiting, then the jobs at the vault's view claimed and each answered with a report
straight from the gateway's review code, the ``large`` fake's 96 tools (K.1's sizing case). The
page's polls read the rows once (F.6); "Select suggested" includes the 64 tools the server marks
read-only; and fragment 2 comes back from the choices, nothing saved. Every refusal is the
catalogue's: a stale report after a reload (GR-11), an unknown tool, a job not done yet, a job
of the CLI's, a failed job.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from tests.fakes.authenticator import SoftAuthenticator
from tests.fakes.browser import Page
from tests.unit.test_portal_static import reads
from tests.unit.test_review_choices import large
from tests.unit.test_reviewview import held
from zoeymcp.common import pinhash
from zoeymcp.common.policy.findings import Finding
from zoeymcp.common.policy.schema import GatewayLimits
from zoeymcp.common.yamlload import load_mapping
from zoeymcp.portal import reviewview
from zoeymcp.portal.reviewview import rows
from zoeymcp.vault.onboarding import reviewed_next
from zoeymcp.vault.reviewjobs import read_result

from .flows import set_up, status_reason
from .rig import PortalRig, rig_policy, running

SERVER_URL = "https://mcp.notes.example/mcp"
ISSUER = "https://auth.notes.example"
RLO = "\u202e"


def notes_entries(**server: Any) -> dict[str, Any]:
    """A committed onboarding of notes (E.2): its credential, its route for the gateway alone,
    and its server, including nothing yet unless ``server`` says so."""
    return {
        "credentials": {
            "notes": {
                "kind": "oauth2",
                "token_url": f"{ISSUER}/token",
                "authorize_url": f"{ISSUER}/authorize",
                "client_id": "notes-client",
                "client_auth": "none",
                "rotates": True,
                "refresh_token": "store:notes-refresh",
                "scope": "notes.read",
                "extra_params": {"resource": SERVER_URL},
                "authorize_params": {"resource": SERVER_URL},
            }
        },
        "routes": [
            {
                "name": "notes",
                "prefix": "/notes",
                "upstream": "https://mcp.notes.example",
                "credential": "notes",
                "callers": ["gateway"],
                "stream": True,
                "rules": [{"methods": ["POST", "GET", "DELETE"], "paths": ["/mcp"]}],
            }
        ],
        "gateway": {
            "servers": {"notes": {"kind": "remote", "route": "notes", "path": "/mcp", **server}}
        },
    }


def poller(rig: PortalRig) -> None:
    """A gateway's poll waiting on the vault, so a review can be queued now (F.2)."""
    rig.call(lambda: rig.vault.app._reviews.poll_began())


def gateway_answers(rig: PortalRig, report: dict[str, Any] | None = None, **error: Any) -> None:
    """The gateway's side, on the vault's loop: every job queued at the vault's view claimed,
    and each answered with ``report`` (``large()`` by default), or with the gateway's
    ``error``."""
    answer = large() if report is None else report

    def run() -> None:
        app = rig.vault.app
        table = app._reviews
        for job in table.claim(app.view_digest):
            body: dict[str, Any] = {"v": 1, "job": job.id}
            if error:
                body["error"] = error
            else:
                body |= {"server": job.server, "report": json.loads(json.dumps(answer))}
            table.post(read_result(body, GatewayLimits()))
        app._wake_reviews()

    rig.call(run)


def store_names(rig: PortalRig) -> list[str]:
    secrets = rig.app.secrets
    assert secrets is not None
    return secrets.store.names()


@dataclass
class World:
    rig: PortalRig
    page: Page


@pytest.fixture
def world(tmp_path: Path) -> Iterator[World]:
    with running(tmp_path, policy=notes_entries()) as rig:
        page = rig.browser().page(rig.origin)
        set_up(rig, page, SoftAuthenticator())
        poller(rig)
        yield World(rig, page)


def queued(world: World) -> str:
    answer = world.page.fetch("POST", "/api/review/notes", json={})
    assert answer.status_code == 200, answer.text
    job: str = answer.json()["job"]
    return job


def done(world: World, report: dict[str, Any] | None = None) -> tuple[str, dict[str, Any]]:
    job = queued(world)
    gateway_answers(world.rig, report)
    answer = world.page.fetch("GET", f"/api/review/jobs/{job}")
    assert answer.status_code == 200, answer.text
    read: dict[str, Any] = answer.json()
    assert read["state"] == "done"
    return job, read


def diffed(world: World, job: str, body: dict[str, Any]) -> dict[str, Any]:
    answer = world.page.fetch("POST", f"/api/review/jobs/{job}/diff", json=body)
    assert answer.status_code == 200, answer.text
    made: dict[str, Any] = answer.json()
    return made


def test_a_hundred_tools_from_queue_to_fragment_2(world: World) -> None:
    """J4: the job queued, polled until done, its rows read once, the suggested tools selected,
    and fragment 2 made; the policy and the store are as they were."""
    rig, page = world.rig, world.page
    job = queued(world)
    waiting = page.fetch("GET", f"/api/review/jobs/{job}")
    assert waiting.json() == {"job": job, "server_shown": "notes", "state": "queued"}
    gateway_answers(rig)
    read = page.fetch("GET", f"/api/review/jobs/{job}").json()
    assert read == {"job": job, **rows(held(large()))}
    assert (read["counts"]["tools"], read["counts"]["read_only"]) == (96, 64)
    # Asked again at the same view, the portal's finished review is handed back (OPS-11).
    again = page.fetch("POST", "/api/review/notes", json={}).json()
    assert (again["job"], again["state"], again["reused"]) == (job, "done", True)
    suggested = [t["name"] for t in read["tools"] if t["pinnable"] and t["suggested"] == "allow"]
    assert len(suggested) == 64
    before = (rig.policy_file.read_bytes(), sorted(store_names(rig)))
    made = diffed(
        world, job, {"include": [*suggested, "add"], "allow": suggested, "approve": ["add"]}
    )
    entry = load_mapping(made["diff"]["yaml"])["gateway"]["servers"]["notes"]
    assert entry["tools"] == {
        "include": [*suggested, "add"],
        "allow": suggested,
        "approve": ["add"],
    }
    assert set(entry["review"]) == {*suggested, "add"}
    assert all(set(f) == {"level", "path", "message_shown"} for f in made["diff"]["check"])
    assert not [f for f in made["diff"]["check"] if f["level"] == "error"]
    source = str(rig.policy_file)
    assert made["next"] == [step.answer() for step in reviewed_next("notes", source)]
    compose = diffed(world, job, {"include": [], "allow": [], "approve": [], "indent": "compose"})
    assert compose["diff"]["yaml"].startswith("        # zoeymcp: review of notes (2 of 2)")
    assert (rig.policy_file.read_bytes(), sorted(store_names(rig))) == (before)


def test_server_text_is_shown_never_raw(world: World) -> None:
    """K.5: a description holding a bidi override reaches the page revealed in its text and as
    an escape in its definition, never as the character."""
    report = large()
    [add] = [entry for entry in report["tools"] if entry["name"] == "add"]
    add["definition"]["description"] = f"Adds{RLO} numbers."
    add["pin"] = pinhash.pin_of(add["definition"])
    job = queued(world)
    gateway_answers(world.rig, copy.deepcopy(report))
    answer = world.page.fetch("GET", f"/api/review/jobs/{job}")
    assert RLO not in answer.text
    [row] = [t for t in answer.json()["tools"] if t["name"] == "add"]
    assert row["description_shown"] == "Adds[U+202E] numbers."
    assert any("\\u202e" in chunk for line in row["definition_lines"] for chunk in line)


def test_what_a_diff_refuses(world: World) -> None:
    rig, page = world.rig, world.page
    job = queued(world)
    path = f"/api/review/jobs/{job}/diff"
    body = {"include": ["echo"], "allow": ["echo"], "approve": []}
    waiting = page.fetch("POST", path, json=body)
    assert status_reason(waiting) == (400, "bad_body")
    assert waiting.json()["detail"] == "the review isn't done yet"
    gateway_answers(rig)
    unknown = page.fetch("POST", path, json={**body, "include": ["nope"], "allow": ["nope"]})
    assert status_reason(unknown) == (422, "diff_invalid")
    assert "the server lists no tool nope" in unknown.json()["error"]
    shape = page.fetch("POST", path, json={**body, "indent": 17})
    assert status_reason(shape) == (400, "bad_body")
    extra = page.fetch("POST", path, json={**body, "fresh": True})
    assert status_reason(extra) == (400, "bad_body")
    # GR-11: a reload that changes the server's entry since the review.
    rig.reload(rig_policy(rig.portal_port, **notes_entries(on_drift="fail")))
    stale = page.fetch("POST", path, json=body)
    assert status_reason(stale) == (409, "review_stale")


def test_a_merged_policy_that_fails_check_answers_its_findings_shown(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    """K.5: a ``diff_invalid`` carries ``check``'s findings, each message shown as a success's
    are (review.js renders them alike), never the raw message."""
    found = [Finding("gateway.clients", "error", f"unknown server 'gh{RLO}ost'")]
    monkeypatch.setattr(reviewview, "validate", lambda policy, change: found)
    job, _ = done(world)
    body = {"include": ["echo"], "allow": ["echo"], "approve": []}
    refused = world.page.fetch("POST", f"/api/review/jobs/{job}/diff", json=body)
    assert status_reason(refused) == (422, "diff_invalid")
    assert refused.json()["check"] == [
        {
            "level": "error",
            "path": "gateway.clients",
            "message_shown": "unknown server 'gh[U+202E]ost'",
        }
    ]
    assert reads("renderChecks", "finding") == set(refused.json()["check"][0])


def test_a_job_of_another_surface_or_none(world: World) -> None:
    """The CLI's job answers as an unknown one (F.2's surfaces), as does no job; a server the
    running view lacks is review_unknown_server."""
    rig, page = world.rig, world.page

    def cli_job() -> str:
        app = rig.vault.app
        made = app._reviews.queue("notes", "cli", app.view_digest, {"notes": "remote"})
        return str(made.id)  # type: ignore[union-attr]

    theirs = rig.call(cli_job)
    for path in (f"/api/review/jobs/{theirs}", "/api/review/jobs/nope"):
        assert status_reason(page.fetch("GET", path)) == (409, "job_unknown")
    body: dict[str, list[str]] = {"include": [], "allow": [], "approve": []}
    assert status_reason(page.fetch("POST", f"/api/review/jobs/{theirs}/diff", json=body)) == (
        409,
        "job_unknown",
    )
    other = page.fetch("POST", "/api/review/other", json={})
    assert status_reason(other) == (404, "review_unknown_server")
    busy = page.fetch("POST", "/api/review/notes", json={})
    assert status_reason(busy) == (409, "review_busy")


def test_a_failed_job_reads_as_its_refusal(world: World) -> None:
    job = queued(world)
    gateway_answers(world.rig, status=502, code="upstream_down", message="no answer")
    read = world.page.fetch("GET", f"/api/review/jobs/{job}")
    assert status_reason(read) == (502, "review_failed")
    assert (read.json()["job"], read.json()["state"]) == (job, "failed")
    assert "(upstream_down)" in read.json()["error"]
    body: dict[str, list[str]] = {"include": [], "allow": [], "approve": []}
    diff = world.page.fetch("POST", f"/api/review/jobs/{job}/diff", json=body)
    assert status_reason(diff) == (502, "review_failed")


def test_the_log_names_a_job_by_hash8(world: World) -> None:
    job, _ = done(world)
    [line] = world.rig.lines("review_requested")
    assert (line["server"], line["owner"], line["reused"]) == ("notes", "portal", False)
    assert job not in world.rig.log.getvalue()
