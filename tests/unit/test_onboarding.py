"""Onboardings in progress (M7 design D.8, D.11, D.12, I.3, M.7; O.2 ``test_onboarding.py``).

The table's owners, TTL (on the injected monotonic clock, FM-28) and caps; resuming, and
``onboarding_options_changed`` when the options differ (OPS-8); two owners under the same names
(FM-10); the stages, with ``registered`` holding fragment 1's change (OPS-2); allowances (I.3);
the name defaults (OPS-15); the second run's comparison by field name (D.12, GR-26); and the
``next`` lists with every command shell-quoted (M.7, TI-14).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from zoeymcp.common.egresslist import Allowance
from zoeymcp.common.policy import Policy
from zoeymcp.common.policy.change import apply
from zoeymcp.common.policy.findings import Finding
from zoeymcp.common.policy.schema import HeaderCredential
from zoeymcp.vault import onboarding
from zoeymcp.vault.oauth.discovery import AsMetadata, Plan, Prm, build_plan
from zoeymcp.vault.onboarding import (
    ADDRESS_NAME,
    GENERIC_LABELS,
    ID_BYTES,
    INLINE_SOURCE,
    NAME_SOURCES,
    ONBOARDING_TTL,
    ONBOARDINGS_MAX,
    STDIN_SOURCE,
    Committed,
    Ended,
    Names,
    NextStep,
    OnboardingRecord,
    OnboardingRefused,
    OnboardingTable,
    Options,
    allow_hosts,
    choose_names,
    committed_for,
    default_name,
    fragment_file,
    in_use,
    mismatches,
    name_taken,
    next_for,
    onboard_again,
    secret_names,
    server_host_port,
    server_path,
)

from .test_policy_change import NOTES_CREDENTIAL, example, notes_change

SERVER = "https://mcp.notes.example/mcp"
ISSUER = "https://auth.notes.example"
SESSION = "session:0a1b"
OTHER_SESSION = "session:ff"
NOTES = Names("notes", "notes", "notes")
NO_OPTIONS = Options()
META = AsMetadata(
    issuer=ISSUER,
    authorization_endpoint=NOTES_CREDENTIAL["authorize_url"],
    token_endpoint=NOTES_CREDENTIAL["token_url"],
    registration_endpoint="https://auth.notes.example/oauth/register",
    revocation_endpoint=NOTES_CREDENTIAL["revocation_url"],
    require_iss=True,
    scopes_supported=None,
    token_auth_methods=("none", "client_secret_basic"),
    revocation_auth_methods=None,
    notes=(),
)
PRM = Prm(
    resource=SERVER,
    authorization_servers=(ISSUER,),
    scopes_supported=("notes.read",),
    resource_name=None,
    source="path",
)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Tokens:
    def __init__(self) -> None:
        self.count = 0
        self.sizes: list[int] = []

    def __call__(self, size: int) -> str:
        self.count += 1
        self.sizes.append(size)
        return f"o{size:02d}x{self.count:040d}"


def table() -> tuple[OnboardingTable, Clock, Tokens]:
    clock, tokens = Clock(), Tokens()
    return OnboardingTable(clock, token=tokens), clock, tokens


def plan(**changes: object) -> Plan:
    made = build_plan(
        SERVER,
        challenge=None,
        prm=PRM,
        resource_metadata="https://mcp.notes.example/.well-known/oauth-protected-resource/mcp",
        issuer_source="only",
        metadata_url=f"{ISSUER}/.well-known/oauth-authorization-server",
        metadata=replace(META, **changes),  # type: ignore[arg-type]
    )
    assert isinstance(made, Plan)
    return made


def committed() -> Policy:
    """The example policy with fragment 1 for notes committed (E.2)."""
    return apply(example(), notes_change(private=False))


def refused(caught: pytest.ExceptionInfo[OnboardingRefused], reason: str) -> OnboardingRefused:
    assert caught.value.reason == reason
    return caught.value


# --- the table ---------------------------------------------------------------------------------


def test_the_limits_are_pinned() -> None:
    assert ONBOARDING_TTL == 1800.0
    assert ONBOARDINGS_MAX == 4
    assert ID_BYTES == 32
    assert frozenset({"mcp", "api", "www", "app", "server"}) == GENERIC_LABELS
    assert ADDRESS_NAME == "server"


def test_an_onboarding() -> None:
    onboardings, _, tokens = table()
    started = onboardings.start("cli", SERVER, NOTES, Options())
    record = started.record
    assert started.resumed is False
    assert tokens.sizes == [ID_BYTES]
    assert record.id == "o32x" + "0" * 39 + "1"
    assert record.owner == "cli"
    assert record.server_url == SERVER
    assert record.names == NOTES
    assert record.options == Options()
    assert record.stage == "discovering"
    assert record.expires_at == 1000.0 + ONBOARDING_TTL
    assert record.allowance == frozenset({("mcp.notes.example", 443)})
    assert record.blocked_on is None
    assert record.needed_hosts == ()
    assert record.plan is None
    assert record.draft_check == ()
    assert record.change is None
    assert len(onboardings) == 1
    assert onboardings.get(record.id, "cli") is record


def test_a_record_never_shows_its_id() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    assert repr(record) == "OnboardingRecord(server='notes', stage='discovering')"
    assert str(record) == repr(record)
    assert record.id not in repr(record)


def test_records_are_frozen() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    with pytest.raises(FrozenInstanceError):
        record.stage = "registered"  # type: ignore[misc]


@pytest.mark.parametrize("owner", ["cli", SESSION, "session:0"])
def test_owners(owner: str) -> None:
    onboardings, _, _ = table()
    assert onboardings.start(owner, SERVER, NOTES, Options()).record.owner == owner


@pytest.mark.parametrize("owner", ["", "CLI", "session:", "session:0A", "session:xyz", "portal"])
def test_other_owners_are_refused(owner: str) -> None:
    onboardings, _, _ = table()
    with pytest.raises(ValueError, match=r"^an onboarding's owner is cli or session:<hex id>$"):
        onboardings.start(owner, SERVER, NOTES, Options())


def test_another_owners_onboarding_is_unknown() -> None:
    onboardings, _, _ = table()
    record = onboardings.start(SESSION, SERVER, NOTES, Options()).record
    for owner in ("cli", OTHER_SESSION):
        with pytest.raises(
            OnboardingRefused, match=r"^no such onboarding is in progress$"
        ) as caught:
            onboardings.get(record.id, owner)
        refused(caught, "onboarding_unknown")
        assert onboardings.cancel(record.id, owner) is None
    assert onboardings.get(record.id, SESSION) is record


@pytest.mark.parametrize("onboarding", ["", "unknown", "o32x" + "0" * 39 + "2", "\udc80", "\u00e9"])
def test_an_unknown_id_is_unknown(onboarding: str) -> None:
    onboardings, _, _ = table()
    onboardings.start("cli", SERVER, NOTES, Options())
    with pytest.raises(OnboardingRefused) as caught:
        onboardings.get(onboarding, "cli")
    refused(caught, "onboarding_unknown")


def test_onboardings_expire_exactly_at_the_ttl() -> None:
    onboardings, clock, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    clock.now = record.expires_at - 0.001
    assert onboardings.get(record.id, "cli") is record
    assert len(onboardings) == 1
    clock.now = record.expires_at
    with pytest.raises(OnboardingRefused) as caught:
        onboardings.get(record.id, "cli")
    refused(caught, "onboarding_unknown")
    assert onboardings.sweep() == (Ended(record, "expired"),)
    assert onboardings.sweep() == ()
    assert len(onboardings) == 0


def test_an_expiry_counted_by_len_is_still_reported() -> None:
    onboardings, clock, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    clock.now = record.expires_at
    assert len(onboardings) == 0
    assert onboardings.sweep() == (Ended(record, "expired"),)


def test_one_onboarding_per_owner() -> None:
    onboardings, _, _ = table()
    first = onboardings.start("cli", SERVER, NOTES, Options()).record
    other = onboardings.start(
        SESSION, "https://mcp.music.example/", Names("music", "music", "music"), Options()
    ).record
    second = onboardings.start(
        "cli", "https://mcp.calendar.example/mcp", Names("cal", "cal", "cal"), Options()
    ).record
    assert len(onboardings) == 2
    assert second.id != first.id
    with pytest.raises(OnboardingRefused):
        onboardings.get(first.id, "cli")
    assert onboardings.get(other.id, SESSION) is other
    assert onboardings.sweep() == (Ended(first, "cancelled"),)


def test_the_total_limit() -> None:
    onboardings, clock, _ = table()
    owners = ["cli", "session:1", "session:2", "session:3"]
    started = [
        onboardings.start(owner, SERVER, Names(f"n{i}", f"n{i}", f"n{i}"), Options()).record
        for i, owner in enumerate(owners)
    ]
    assert len(onboardings) == ONBOARDINGS_MAX
    with pytest.raises(
        OnboardingRefused, match=f"^at most {ONBOARDINGS_MAX} onboardings can be in progress$"
    ) as caught:
        onboardings.start("session:4", SERVER, Names("n4", "n4", "n4"), Options())
    refused(caught, "onboarding_busy")
    # Replacing an owner's own is fine at the limit.
    onboardings.start("cli", SERVER, Names("n9", "n9", "n9"), Options())
    assert len(onboardings) == ONBOARDINGS_MAX
    # An expired one makes room.
    clock.now = started[1].expires_at
    onboardings.start("session:4", SERVER, Names("n4", "n4", "n4"), Options())
    assert len(onboardings) == 1


def test_a_refused_start_keeps_the_owners_own() -> None:
    """A refused start changes nothing: the owner's own onboarding stays."""
    onboardings, _, _ = table()
    mine = onboardings.start("cli", SERVER, NOTES, Options()).record
    onboardings.start(SESSION, SERVER, Names("other", "other", "other"), Options())
    with pytest.raises(OnboardingRefused):
        onboardings.start("cli", SERVER, Names("other", "x", "y"), Options())
    assert onboardings.get(mine.id, "cli") is mine


def test_cancel() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    assert onboardings.cancel(record.id, "cli") == Ended(record, "cancelled")
    assert onboardings.cancel(record.id, "cli") is None
    assert onboardings.cancel("unknown", "cli") is None
    assert len(onboardings) == 0
    # A cancel is the caller's to report; the sweep doesn't repeat it.
    assert onboardings.sweep() == ()


def test_an_expired_onboarding_is_reported_expired_not_cancelled() -> None:
    onboardings, clock, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    mine = onboardings.start(SESSION, SERVER, Names("cal", "cal", "cal"), Options()).record
    clock.now = record.expires_at
    assert onboardings.cancel(record.id, "cli") is None
    assert onboardings.cancel_owner(SESSION) == ()
    assert onboardings.sweep() == (Ended(record, "expired"), Ended(mine, "expired"))


def test_a_sessions_end_cancels_its_onboarding() -> None:
    onboardings, _, _ = table()
    mine = onboardings.start(SESSION, SERVER, NOTES, Options()).record
    other = onboardings.start("cli", SERVER, Names("cal", "cal", "cal"), Options()).record
    assert onboardings.cancel_owner(SESSION) == (Ended(mine, "owner_gone"),)
    assert onboardings.cancel_owner(SESSION) == ()
    assert onboardings.get(other.id, "cli") is other
    assert len(onboardings) == 1


# --- resuming (D.11, OPS-8) --------------------------------------------------------------------


def blocked_record(onboardings: OnboardingTable, options: Options = NO_OPTIONS) -> OnboardingRecord:
    record = onboardings.start("cli", SERVER, NOTES, options).record
    return onboardings.block(record.id, "cli", ("auth.notes.example", 443), example())


def test_a_blocked_onboarding_resumes_where_it_stopped() -> None:
    onboardings, clock, tokens = table()
    options = Options(client_id="zc_1", issuer=ISSUER)
    blocked = blocked_record(onboardings, options)
    clock.now += 600
    started = onboardings.start("cli", SERVER, NOTES, options)
    assert started.resumed is True
    record = started.record
    assert record.id == blocked.id
    assert record.stage == "discovering"
    assert record.blocked_on is None
    assert record.needed_hosts == ()
    # Everything it fetched stays, and a resume doesn't extend it.
    assert record.allowance == blocked.allowance
    assert record.expires_at == blocked.expires_at
    assert tokens.count == 1
    assert onboardings.get(record.id, "cli") is record


@pytest.mark.parametrize(
    "changed",
    [
        {"client_id": "zc_2"},
        {"secret_given": True},
        {"secret_given": True, "client_auth": "post"},
        {"client_auth": "none"},
        {"redirect_uri": "http://127.0.0.1:8765/callback"},
        {"issuer": "https://auth2.notes.example"},
        {"scope": "notes.read"},
        {"client_name": "Notes"},
        {"allow_private": True},
    ],
)
def test_a_resume_with_other_options_is_refused(changed: dict[str, object]) -> None:
    onboardings, _, _ = table()
    options = Options(client_id="zc_1", issuer=ISSUER)
    blocked = blocked_record(onboardings, options)
    other = replace(options, **changed)  # type: ignore[arg-type]
    with pytest.raises(
        OnboardingRefused,
        match=r"^the onboarding in progress for this URL was started with other options$",
    ) as caught:
        onboardings.start("cli", SERVER, NOTES, other)
    refused(caught, "onboarding_options_changed")
    assert onboardings.get(blocked.id, "cli") is blocked


def test_a_discovered_or_registered_onboarding_resumes_as_it_is() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    found = onboardings.discovered(record.id, "cli", plan(), ())
    again = onboardings.start("cli", SERVER, NOTES, Options())
    assert again == onboarding.Started(found, resumed=True)
    registered = onboardings.registered(record.id, "cli", notes_change())
    assert onboardings.start("cli", SERVER, NOTES, Options()).record is registered


@pytest.mark.parametrize("stage", ["discovered", "registered"])
def test_a_discovered_or_registered_onboarding_with_other_options_is_replaced(stage: str) -> None:
    """Only a blocked onboarding refuses other options (D.11); any other is replaced (D.8)."""
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options(client_id="zc_1")).record
    found = onboardings.discovered(record.id, "cli", plan(), ())
    if stage == "registered":
        found = onboardings.registered(record.id, "cli", notes_change())
    other = Options(client_id="zc_1", secret_given=True)
    started = onboardings.start("cli", SERVER, NOTES, other)
    assert started.resumed is False
    assert started.record.id != record.id
    assert started.record.stage == "discovering"
    assert started.record.options == other
    assert onboardings.sweep() == (Ended(found, "cancelled"),)


@pytest.mark.parametrize(
    ("url", "names"),
    [
        ("https://mcp.notes.example/other", NOTES),
        (SERVER, Names("notes", "notes", "notes-2")),
        (SERVER, Names("notes", "notes-2", "notes")),
        (SERVER, Names("notes-2", "notes", "notes")),
    ],
)
def test_another_url_or_names_replaces_it(url: str, names: Names) -> None:
    onboardings, _, _ = table()
    blocked = blocked_record(onboardings)
    started = onboardings.start("cli", url, names, Options(client_id="other"))
    assert started.resumed is False
    assert started.record.id != blocked.id
    assert onboardings.sweep() == (Ended(blocked, "cancelled"),)


def test_where_the_names_came_from_doesnt_stop_a_resume() -> None:
    onboardings, _, _ = table()
    blocked = blocked_record(onboardings)
    assert onboardings.start("cli", SERVER, replace(NOTES, source="label"), Options()).resumed
    assert onboardings.get(blocked.id, "cli").stage == "discovering"


def test_one_still_discovering_is_replaced() -> None:
    onboardings, _, _ = table()
    first = onboardings.start("cli", SERVER, NOTES, Options()).record
    second = onboardings.start("cli", SERVER, NOTES, Options())
    assert second.resumed is False
    assert second.record.id != first.id


def test_another_owner_never_resumes_it() -> None:
    onboardings, _, _ = table()
    blocked_record(onboardings)
    with pytest.raises(OnboardingRefused) as caught:
        onboardings.start(SESSION, SERVER, NOTES, Options())
    refused(caught, "name_taken")


# --- two owners under the same names (FM-10) ---------------------------------------------------


@pytest.mark.parametrize(
    ("names", "taken"),
    [
        (NOTES, "notes"),
        (Names("notes", "a", "b"), "notes"),
        (Names("a", "notes", "b"), "notes"),
        (Names("a", "b", "notes"), "notes"),
    ],
)
def test_a_second_owner_under_the_same_names_gets_name_taken(names: Names, taken: str) -> None:
    onboardings, _, _ = table()
    onboardings.start("cli", SERVER, NOTES, Options())
    with pytest.raises(
        OnboardingRefused, match=f"^{taken} is taken by another onboarding, started from the cli$"
    ) as caught:
        onboardings.start(SESSION, "https://mcp.other.example/mcp", names, Options())
    assert refused(caught, "name_taken").values == (taken, "cli")
    assert len(onboardings) == 1


def test_the_refusal_names_where_the_other_was_started() -> None:
    onboardings, _, _ = table()
    onboardings.start(SESSION, SERVER, NOTES, Options())
    with pytest.raises(OnboardingRefused) as caught:
        onboardings.start("cli", SERVER, NOTES, Options())
    assert refused(caught, "name_taken").values == ("notes", "portal")


def test_names_of_another_kind_dont_collide() -> None:
    onboardings, _, _ = table()
    onboardings.start("cli", SERVER, Names("a", "b", "c"), Options())
    started = onboardings.start(SESSION, SERVER, Names("b", "c", "a"), Options())
    assert started.resumed is False
    assert len(onboardings) == 2


def test_an_expired_onboardings_names_are_free() -> None:
    onboardings, clock, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    clock.now = record.expires_at
    assert onboardings.start(SESSION, SERVER, NOTES, Options()).record.owner == SESSION


def test_names_in_use() -> None:
    onboardings, clock, _ = table()
    record = onboardings.start("cli", SERVER, Names("a", "b", "c"), Options()).record
    onboardings.start(SESSION, SERVER, Names("d", "d", "d"), Options())
    assert onboardings.names_in_use(SESSION) == frozenset({"a", "b", "c"})
    assert onboardings.names_in_use("cli") == frozenset({"d"})
    assert onboardings.names_in_use(OTHER_SESSION) == frozenset({"a", "b", "c", "d"})
    clock.now = record.expires_at
    assert onboardings.names_in_use(OTHER_SESSION) == frozenset()


# --- stages ------------------------------------------------------------------------------------


def test_widening_the_allowance() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    wider = onboardings.widen(record.id, "cli", [("AUTH.notes.example", 443), ("x.example", 8443)])
    assert wider.allowance == frozenset(
        {("mcp.notes.example", 443), ("auth.notes.example", 443), ("x.example", 8443)}
    )
    assert onboardings.get(record.id, "cli") is wider
    found = onboardings.discovered(record.id, "cli", plan(), ())
    assert onboardings.widen(record.id, "cli", [("reg.example", 443)]).allowance == (
        found.allowance | {("reg.example", 443)}
    )


def test_a_proxy_refusal_blocks_with_the_hosts_still_needed() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    # The example policy already allows mcp.broker.example:443 (a route).
    onboardings.widen(record.id, "cli", [("mcp.broker.example", 443)])
    blocked = onboardings.block(record.id, "cli", ("Auth.Notes.example", 443), example())
    assert blocked.stage == "blocked"
    assert blocked.blocked_on == ("auth.notes.example", 443)
    assert blocked.needed_hosts == (("auth.notes.example", 443), ("mcp.notes.example", 443))
    assert ("auth.notes.example", 443) in blocked.allowance
    assert onboardings.get(record.id, "cli") is blocked


def test_a_refused_target_the_policy_names_is_still_needed() -> None:
    """The proxy refused it, so its list is behind the policy: the target stays needed."""
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    blocked = onboardings.block(record.id, "cli", ("mcp.broker.example", 443), example())
    assert blocked.needed_hosts == (("mcp.broker.example", 443), ("mcp.notes.example", 443))
    (step,) = next_for(blocked, INLINE_SOURCE)
    assert step.hosts == ("mcp.broker.example:443", "mcp.notes.example:443")
    assert "acl zoeymcp_onboard_1 dstdomain -n mcp.broker.example" in step.squid


def test_discovered_holds_the_plan_and_the_draft_check() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    finding = Finding("routes[3].prefix", "error", "duplicate prefix")
    found = onboardings.discovered(record.id, "cli", plan(), [finding])
    assert found.stage == "discovered"
    assert found.plan == plan()
    assert found.draft_check == (finding,)


def test_registered_holds_fragment_1_and_contacts_nothing_more() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    onboardings.discovered(record.id, "cli", plan(), ())
    change = notes_change()
    registered = onboardings.registered(record.id, "cli", change)
    assert registered.stage == "registered"
    assert registered.change is change
    assert registered.plan == plan()
    assert registered.allowance == frozenset()
    with pytest.raises(ValueError, match=r"^a registered onboarding contacts nothing more$"):
        onboardings.widen(record.id, "cli", [("x.example", 443)])


def test_each_step_needs_its_stage() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    with pytest.raises(ValueError, match=r"^the onboarding is discovering, not discovered$"):
        onboardings.registered(record.id, "cli", notes_change())
    onboardings.block(record.id, "cli", ("auth.notes.example", 443), example())
    with pytest.raises(ValueError, match=r"^the onboarding is blocked, not discovering$"):
        onboardings.discovered(record.id, "cli", plan(), ())
    with pytest.raises(ValueError, match=r"^the onboarding is blocked, not discovering$"):
        onboardings.block(record.id, "cli", ("auth.notes.example", 443), example())


def test_a_step_on_another_owners_onboarding_is_unknown() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    with pytest.raises(OnboardingRefused):
        onboardings.widen(record.id, SESSION, [("x.example", 443)])
    with pytest.raises(OnboardingRefused):
        onboardings.discovered(record.id, SESSION, plan(), ())
    assert onboardings.get(record.id, "cli") is record


def test_a_committed_credential_ends_its_registered_onboarding() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    onboardings.discovered(record.id, "cli", plan(), ())
    registered = onboardings.registered(record.id, "cli", notes_change())
    waiting = onboardings.start(SESSION, SERVER, Names("cal", "cal", "cal"), Options()).record
    assert onboardings.sweep(["other"]) == ()
    assert onboardings.sweep(["notes", "cal"]) == (Ended(registered, "registered"),)
    # Only a registered onboarding ends so: one still discovering stays.
    assert onboardings.get(waiting.id, SESSION) is waiting


# --- allowances (I.3) --------------------------------------------------------------------------


def test_allowances_are_the_live_onboardings_until_they_register() -> None:
    onboardings, clock, _ = table()
    first = onboardings.start("cli", SERVER, NOTES, Options()).record
    onboardings.widen(first.id, "cli", [("auth.notes.example", 443)])
    second = onboardings.start(
        SESSION, "https://mcp.cal.example:8443/", Names("cal", "cal", "cal"), Options()
    ).record
    assert set(onboardings.allowances()) == {
        Allowance(frozenset({("mcp.notes.example", 443), ("auth.notes.example", 443)})),
        Allowance(frozenset({("mcp.cal.example", 8443)})),
    }
    onboardings.discovered(second.id, SESSION, plan(), ())
    onboardings.registered(second.id, SESSION, notes_change())
    assert len(onboardings.allowances()) == 1
    clock.now = first.expires_at
    assert onboardings.allowances() == ()


def test_the_private_target_is_the_typed_servers_alone() -> None:
    onboardings, _, _ = table()
    plain = onboardings.start("cli", SERVER, NOTES, Options()).record
    assert plain.private_target is None
    private = onboardings.start(
        SESSION, "https://NAS.lan:8443/mcp", Names("nas", "nas", "nas"), Options(allow_private=True)
    ).record
    assert private.private_target == "nas.lan:8443"
    literal = replace(private, server_url="https://[fd00::1]/mcp")
    assert literal.private_target == "[fd00::1]:443"


def test_the_servers_host_port_and_path() -> None:
    assert server_host_port("https://MCP.example:8443/x") == ("mcp.example", 8443)
    assert server_host_port("https://mcp.example") == ("mcp.example", 443)
    assert server_path("https://mcp.example") == "/"
    assert server_path("https://mcp.example/") == "/"
    assert server_path("https://mcp.example/a/mcp") == "/a/mcp"


# --- names (OPS-15) ----------------------------------------------------------------------------


def free(name: str) -> bool:
    return False


@pytest.mark.parametrize(
    ("url", "name", "source"),
    [
        ("https://mcp.notes.example/mcp", "notes", "label"),
        ("https://notes.example/mcp", "notes", "label"),
        ("https://api.github.example", "github", "label"),
        ("https://www.app.server.notes.example/", "notes", "label"),
        ("https://mcp.api.example/mcp", "api", "second_label"),
        ("https://mcp.example", "mcp", "second_label"),
        ("https://xn--bcher-kva.example", "xn--bcher-kva", "label"),
        ("https://notes", "notes", "label"),
        ("https://mcp", "mcp", "label"),
        ("https://10.0.0.5:8443/mcp", ADDRESS_NAME, "address"),
        ("https://[fd00::1]/mcp", ADDRESS_NAME, "address"),
        ("https://_x.-y/mcp", ADDRESS_NAME, "address"),
    ],
)
def test_the_default_name(url: str, name: str, source: str) -> None:
    assert default_name(url, free) == (name, source)


def test_a_taken_default_gets_a_number() -> None:
    taken = {"notes", "notes-2"}
    assert default_name(SERVER, taken.__contains__) == ("notes-3", "label")
    assert default_name(SERVER, {"notes"}.__contains__) == ("notes-2", "label")


def test_a_numbered_default_still_fits() -> None:
    label = "n" * 63
    url = f"https://{label}.example/mcp"
    assert default_name(url, free) == (label, "label")
    name, _ = default_name(url, {label}.__contains__)
    assert name == "n" * 61 + "-2"
    taken = {label, *(f"{'n' * 61}-{n}" for n in range(2, 10))}
    name, _ = default_name(url, taken.__contains__)
    assert name == "n" * 60 + "-10"
    assert Names(name, name, name).credential == name


def test_every_name_source_is_worded() -> None:
    assert set(NAME_SOURCES) == {"given", "label", "second_label", "address"}


@pytest.mark.parametrize("value", ["", "Notes", "-notes", "no tes", "n" * 64, "notes.x"])
def test_names_must_be_policy_names(value: str) -> None:
    with pytest.raises(ValueError, match=r"isn't a policy name$"):
        Names(value, "notes", "notes")
    with pytest.raises(ValueError, match=r"isn't a policy name$"):
        Names("notes", value, "notes")
    with pytest.raises(ValueError, match=r"isn't a policy name$"):
        Names("notes", "notes", value)


def test_choosing_names() -> None:
    assert choose_names(SERVER, free) == Names("notes", "notes", "notes", "label")
    assert choose_names(SERVER, free, name="mine") == Names("mine", "mine", "mine", "given")
    assert choose_names(SERVER, free, name="mine", route="r") == Names("mine", "r", "mine")
    assert choose_names(SERVER, free, server="s") == Names("notes", "notes", "s", "label")

    def never(name: str) -> bool:
        raise AssertionError("no default is needed")

    assert choose_names(SERVER, never, credential="c", route="r", server="s") == Names(
        "c", "r", "s", "given"
    )


def test_what_a_default_may_not_take() -> None:
    policy = example()
    taken = in_use(policy, {"kept-client-id"}, {"pending"})
    # The example's credentials, routes, a route prefix and servers.
    for name in (
        "music-stats",
        "broker-mcp",
        "stats",
        "mail-send",
        "broker",
        "mail",
        "broker-read",
    ):
        assert taken(name), name
    assert taken("pending")
    assert taken("kept")  # an onboarding of "kept" would write kept-client-id
    assert not taken("notes")
    assert not taken("client")


def test_secret_names() -> None:
    assert secret_names("notes") == ("notes-client-secret", "notes-client-id", "notes-refresh")


@pytest.mark.parametrize(
    ("names", "store", "taken"),
    [
        (NOTES, set(), None),
        (Names("music-stats", "a", "b"), set(), "music-stats"),
        (Names("a", "stats", "b"), set(), "stats"),
        (Names("a", "broker", "b"), set(), "broker"),
        (Names("a", "b", "broker-read"), set(), "broker-read"),
        (NOTES, {"notes-client-secret"}, "notes"),
        (NOTES, {"notes-client-id"}, "notes"),
        (NOTES, {"notes-refresh"}, "notes"),
        (NOTES, {"notes", "other-refresh"}, None),
        (Names("stats", "a", "b"), set(), None),
    ],
)
def test_name_taken(names: Names, store: set[str], taken: str | None) -> None:
    assert name_taken(names, example(), store) == taken


def test_a_policy_without_a_gateway_has_no_servers() -> None:
    policy = Policy.model_validate({"version": 1, "mode": "declarative"})
    assert name_taken(NOTES, policy, set()) is None
    assert not in_use(policy, set())("notes")
    assert committed_for(policy, SERVER) is None


# --- the second run's comparison (D.12, GR-26) -------------------------------------------------


def test_a_route_with_another_kind_of_credential_isnt_committed() -> None:
    """A static key on the route to the URL (J1's notes) is D.12's ``already_configured``, never
    a committed oauth2 server."""
    policy = committed()
    key = HeaderCredential.model_validate({"kind": "header", "secret": "store:notes-key"})
    policy = policy.model_copy(update={"credentials": {**policy.credentials, "notes": key}})
    assert committed_for(policy, SERVER) is None


def test_the_first_matching_server_by_name_is_committed() -> None:
    policy = committed()
    assert policy.gateway is not None
    servers = dict(policy.gateway.servers)
    servers["a-notes"] = servers["notes"]
    gateway = policy.gateway.model_copy(update={"servers": servers})
    policy = policy.model_copy(update={"gateway": gateway})
    assert list(servers)[-1] == "a-notes"
    assert committed_for(policy, SERVER) == Committed("notes", "notes", "a-notes")


def test_the_committed_server_is_found_by_its_resource() -> None:
    assert committed_for(committed(), SERVER) == Committed("notes", "notes", "notes")
    assert committed_for(committed(), "https://mcp.notes.example/other") is None
    assert committed_for(example(), SERVER) is None


def test_a_credential_without_a_resource_is_found_by_its_route() -> None:
    policy = committed()
    cred = policy.credentials["notes"]
    bare = cred.model_copy(update={"extra_params": {}, "authorize_params": {}})
    policy = policy.model_copy(update={"credentials": {**policy.credentials, "notes": bare}})
    assert committed_for(policy, SERVER) == Committed("notes", "notes", "notes")
    assert committed_for(policy, "https://mcp.notes.example/mcp2") is None
    assert committed_for(policy, "https://mcp2.notes.example/mcp") is None


def test_a_hand_written_credential_is_found_by_its_route() -> None:
    """The example's broker credential (oauth2, no resource) serves two servers on one route:
    the first by name is the one compared."""
    found = committed_for(example(), "https://mcp.broker.example/mcp")
    assert found == Committed("broker-mcp", "broker-mcp", "broker-read")


def test_nothing_differs_from_the_discovery_it_was_made_from() -> None:
    assert mismatches(committed(), plan()) == []


@pytest.mark.parametrize(
    ("changes", "fields"),
    [
        ({"token_endpoint": "https://auth.notes.example/oauth/token"}, ["token_url"]),
        (
            {"authorization_endpoint": "https://auth.notes.example/oauth/authorize?x=1"},
            ["authorize_url"],
        ),
        ({"issuer": "https://auth.notes.example/"}, ["issuer"]),
        ({"revocation_endpoint": None}, ["revocation_url"]),
        ({"token_auth_methods": ("client_secret_basic",)}, ["client_auth"]),
        ({"require_iss": False}, []),
    ],
)
def test_each_differing_field_is_named(changes: dict[str, object], fields: list[str]) -> None:
    assert mismatches(committed(), plan(**changes)) == [f"credentials.notes.{f}" for f in fields]


def test_a_looser_require_iss_is_named_and_a_stricter_one_isnt() -> None:
    policy = committed()
    loose = policy.credentials["notes"].model_copy(update={"require_iss": False})
    policy = policy.model_copy(update={"credentials": {**policy.credentials, "notes": loose}})
    assert mismatches(policy, plan()) == ["credentials.notes.require_iss"]
    assert mismatches(policy, plan(require_iss=False)) == []


def test_the_resources_route_and_path_are_compared() -> None:
    policy = committed()
    cred = policy.credentials["notes"].model_copy(
        update={"authorize_params": {"resource": "https://mcp.notes.example/"}}
    )
    route = policy.routes[-1].model_copy(update={"upstream": "https://mcp.notes.example:443"})
    policy = policy.model_copy(
        update={
            "credentials": {**policy.credentials, "notes": cred},
            "routes": [*policy.routes[:-1], route],
        }
    )
    assert mismatches(policy, plan()) == [
        "credentials.notes.authorize_params.resource",
        "routes.notes.upstream",
    ]
    other = replace(plan(), resource="https://mcp.notes.example/")
    assert mismatches(policy, other) == [
        "credentials.notes.extra_params.resource",
        "routes.notes.upstream",
    ]


def test_a_changed_server_path() -> None:
    policy = committed()
    assert policy.gateway is not None
    servers = dict(policy.gateway.servers)
    servers["notes"] = servers["notes"].model_copy(update={"path": "/mcp/"})
    gateway = policy.gateway.model_copy(update={"servers": servers})
    policy = policy.model_copy(update={"gateway": gateway})
    # Found by its resource, the path still differs.
    assert mismatches(policy, plan()) == ["gateway.servers.notes.path"]


@pytest.mark.parametrize(
    ("auth", "secret", "methods", "same"),
    [
        ("none", None, ("none",), True),
        (None, None, ("none",), True),
        (None, "store:notes-client-secret", ("client_secret_basic",), True),
        ("basic", "store:notes-client-secret", ("client_secret_basic",), True),
        ("post", "store:notes-client-secret", ("client_secret_post",), True),
        ("post", "store:notes-client-secret", ("client_secret_basic", "none"), False),
        ("basic", "store:notes-client-secret", ("client_secret_post", "none"), False),
        ("none", None, ("client_secret_basic",), False),
    ],
)
def test_client_authentication_against_the_servers_methods(
    auth: str | None, secret: str | None, methods: tuple[str, ...], same: bool
) -> None:
    policy = committed()
    cred = policy.credentials["notes"].model_copy(
        update={"client_auth": auth, "client_secret": secret}
    )
    policy = policy.model_copy(update={"credentials": {**policy.credentials, "notes": cred}})
    found = mismatches(policy, plan(token_auth_methods=methods))
    assert found == ([] if same else ["credentials.notes.client_auth"])


def test_mismatches_name_fields_never_values() -> None:
    other = plan(token_endpoint="https://evil.example/token", issuer="https://evil.example")
    found = mismatches(committed(), other)
    assert found == ["credentials.notes.token_url", "credentials.notes.issuer"]
    assert not any("evil" in field for field in found)


def test_mismatches_need_a_committed_server() -> None:
    with pytest.raises(ValueError, match=r"^no running credential names this URL$"):
        mismatches(example(), plan())


# --- next (M.7) --------------------------------------------------------------------------------


def staged(stage: str, options: Options = NO_OPTIONS, names: Names = NOTES) -> OnboardingRecord:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, names, options).record
    if stage == "blocked":
        return onboardings.block(record.id, "cli", ("auth.notes.example", 443), example())
    if stage == "discovering":
        return record
    found = onboardings.discovered(record.id, "cli", plan(), ())
    if stage == "discovered":
        return found
    return onboardings.registered(record.id, "cli", notes_change())


def test_nothing_is_next_while_discovering() -> None:
    assert next_for(staged("discovering"), INLINE_SOURCE) == ()


def test_a_blocked_onboarding_names_the_hosts_and_squid_lines() -> None:
    (step,) = next_for(staged("blocked"), INLINE_SOURCE, acl_names={"vault": "stack_vault_net"})
    assert step.answer() == {
        "do": "allow_hosts",
        "label": "Allow these hosts in your proxy for the vault",
        "hosts": ["auth.notes.example:443", "mcp.notes.example:443"],
        "squid": [
            "acl zoeymcp_onboard_1 dstdomain -n auth.notes.example",
            "http_access allow stack_vault_net CONNECT zoeymcp_onboard_1 zoeymcp_port_443 "
            "!zoeymcp_private_dst",
            "acl zoeymcp_onboard_2 dstdomain -n mcp.notes.example",
            "http_access allow stack_vault_net CONNECT zoeymcp_onboard_2 zoeymcp_port_443 "
            "!zoeymcp_private_dst",
        ],
    }


def test_allow_hosts_defaults_the_source_acl_and_writes_literals_as_dst() -> None:
    step = allow_hosts([("10.0.0.5", 8443), ("10.0.0.5", 8443), ("fd00::1", 443)], {})
    assert step.hosts == ("10.0.0.5:8443", "[fd00::1]:443")
    assert step.squid == (
        "acl zoeymcp_onboard_1 dst -n 10.0.0.5",
        "http_access allow zoeymcp_src_vault CONNECT zoeymcp_onboard_1 zoeymcp_port_8443 "
        "!zoeymcp_private_dst",
        "acl zoeymcp_onboard_2 dst -n fd00::1",
        "http_access allow zoeymcp_src_vault CONNECT zoeymcp_onboard_2 zoeymcp_port_443 "
        "!zoeymcp_private_dst",
    )


def test_allow_hosts_writes_hosts_in_lower_case() -> None:
    step = allow_hosts([("Auth.Notes.EXAMPLE", 443), ("auth.notes.example", 443)], {})
    assert step.hosts == ("auth.notes.example:443",)
    assert step.squid[0] == "acl zoeymcp_onboard_1 dstdomain -n auth.notes.example"
    assert len(step.squid) == 2


def test_a_given_secret_defaults_to_basic() -> None:
    """D.10: ``--client-auth`` defaults to basic with a secret, so a resume that adds or drops
    the secret has other options (OPS-8)."""
    given = Options(client_id="c", secret_given=True)
    assert given.client_auth == "basic"
    assert given == Options(client_id="c", secret_given=True, client_auth="basic")
    assert given != Options(client_id="c")
    assert Options(client_id="c", secret_given=True, client_auth="post").client_auth == "post"
    assert Options(client_id="c").client_auth is None


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"secret_given": True}, r"^a client secret needs its client ID$"),
        (
            {"client_id": "c", "secret_given": True, "client_auth": "none"},
            r"^a client with a secret authenticates with basic or post$",
        ),
        ({"client_id": "c", "client_auth": "basic"}, r"^client authentication basic needs a "),
        ({"client_id": "c", "client_auth": "post"}, r"^client authentication post needs a "),
    ],
)
def test_options_that_dont_fit_together(changes: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        Options(**changes)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("options", "do", "label"),
    [
        (Options(), "register", "Register and make the YAML"),
        (
            Options(client_id="c", secret_given=True),
            "register",
            "Store the secret and make the YAML",
        ),
        (
            Options(client_id="c", secret_given=True, client_auth="post"),
            "register",
            "Store the secret and make the YAML",
        ),
        (Options(client_id="c"), "make_fragment", "Make the YAML"),
        (Options(client_id="c", client_auth="none"), "make_fragment", "Make the YAML"),
    ],
)
def test_a_discovered_onboardings_one_action(options: Options, do: str, label: str) -> None:
    assert next_for(staged("discovered", options), INLINE_SOURCE) == (NextStep(do, label),)  # type: ignore[arg-type]


def test_a_draft_check_error_comes_first() -> None:
    onboardings, _, _ = table()
    record = onboardings.start("cli", SERVER, NOTES, Options()).record
    warning = Finding("routes", "warning", "a warning")
    error = Finding("routes[3].prefix", "error", "duplicate prefix")
    found = onboardings.discovered(record.id, "cli", plan(), [warning])
    assert next_for(found, INLINE_SOURCE)[0].do == "register"
    found = replace(found, draft_check=(warning, error, error))
    assert next_for(found, INLINE_SOURCE) == (
        NextStep(
            "fix_policy", "Fix the policy first: check finds 2 error(s) with this server merged"
        ),
    )


def test_the_steps_after_fragment_1_for_an_inline_policy() -> None:
    steps = next_for(staged("registered"), INLINE_SOURCE)
    assert [step.answer() for step in steps] == [
        {
            "do": "check_fragment",
            "label": "Check fragment 1 with the running policy",
            "command": "check --with /w/onboard-notes-1.yaml",
            "via": "run_mount",
        },
        {
            "do": "commit_fragment",
            "label": "Merge it into the policy under ZOEYMCP_CONFIG in the compose form (--for "
            "compose), or print the whole merged block with --print-merged --for compose and "
            "replace it",
        },
        {
            "do": "check_policy",
            "label": "Then check the edited policy",
            "command": "check",
            "via": "run",
        },
        {"do": "reload", "label": "Commit, then recreate the vault", "via": "up"},
        {
            "do": "connect",
            "label": "Then sign in and review",
            "command": "zoeymcp login --mcp https://mcp.notes.example/mcp --name notes",
            "via": "exec",
        },
    ]


def test_the_steps_after_fragment_1_for_a_policy_file() -> None:
    steps = next_for(staged("registered"), "/config/my policy.yaml")
    assert [(step.do, step.shell(), step.via) for step in steps] == [
        (
            "check_fragment",
            "zoeymcp check --config '/config/my policy.yaml' --with onboard-notes-1.yaml",
            None,
        ),
        ("commit_fragment", "", None),
        ("check_policy", "zoeymcp check --config '/config/my policy.yaml'", None),
        ("reload", "", None),
        ("connect", "zoeymcp login --mcp https://mcp.notes.example/mcp --name notes", "exec"),
    ]
    assert steps[1].label == (
        "Merge it into the policy, or print the whole merged policy with --print-merged and "
        "replace it"
    )
    assert steps[3].label == "Commit, then send the vault SIGHUP (docker kill -s HUP)"


def test_the_steps_after_fragment_1_for_a_policy_on_stdin() -> None:
    steps = next_for(staged("registered"), STDIN_SOURCE)
    assert steps[0].command == (
        "zoeymcp",
        "check",
        "--config",
        "-",
        "--with",
        "onboard-notes-1.yaml",
    )
    assert steps[2].command == ("zoeymcp", "check", "--config", "-")
    assert steps[3].label == "Commit, then restart the vault with the new policy"


def test_an_operators_own_proxy_adds_the_allowlist_update() -> None:
    steps = next_for(staged("registered"), INLINE_SOURCE, own_proxy=True)
    assert [step.do for step in steps] == [
        "check_fragment",
        "commit_fragment",
        "check_policy",
        "reload",
        "update_proxy_allowlist",
        "connect",
    ]
    assert steps[4] == NextStep(
        "update_proxy_allowlist",
        "Update your proxy's allowlist from the committed policy, reload your proxy, then remove "
        "the onboarding lines",
        ("check", "--emit-egress-allowlist", "--allowlist-format", "squid"),
        "run",
    )
    on_file = next_for(staged("registered"), "policy.yaml", own_proxy=True)[4]
    assert on_file.shell() == (
        "zoeymcp check --config policy.yaml --emit-egress-allowlist --allowlist-format squid"
    )


def test_the_second_run_carries_the_names_and_discovery_options() -> None:
    names = Names("c", "r", "s")
    options = Options(issuer=ISSUER, allow_private=True, client_id="ignored")
    connect = next_for(staged("registered", options, names), INLINE_SOURCE)[-1]
    assert connect.command == (
        "zoeymcp",
        "login",
        "--mcp",
        SERVER,
        "--credential",
        "c",
        "--route",
        "r",
        "--server",
        "s",
        "--issuer",
        ISSUER,
        "--allow-private",
    )
    # The fragment is named for the server.
    assert next_for(staged("registered", options, names), INLINE_SOURCE)[0].command[-1] == (
        "/w/onboard-s-1.yaml"
    )


def test_every_argument_is_shell_quoted() -> None:
    """TI-14: an operator-typed URL may hold ;, |, &, a backquote or $(."""
    hostile = "https://mcp.notes.example/a;id|x&y`z`$(w)"
    step = onboard_again(hostile)
    assert step.shell() == (
        "zoeymcp login --mcp 'https://mcp.notes.example/a;id|x&y`z`$(w)' --reregister"
    )
    record = replace(staged("registered"), server_url="https://mcp.notes.example/;id")
    assert next_for(record, INLINE_SOURCE)[-1].shell() == (
        "zoeymcp login --mcp 'https://mcp.notes.example/;id' --name notes"
    )


def test_onboard_again() -> None:
    assert onboard_again(SERVER).answer() == {
        "do": "onboard_again",
        "label": "Register a new client",
        "command": "zoeymcp login --mcp https://mcp.notes.example/mcp --reregister",
        "via": "exec",
    }


def test_a_step_without_a_command() -> None:
    step = NextStep("register", "Register and make the YAML")
    assert step.shell() == ""
    assert step.answer() == {"do": "register", "label": "Register and make the YAML"}


def test_fragment_files() -> None:
    assert fragment_file("notes", 1) == "onboard-notes-1.yaml"
    assert fragment_file("notes", 2) == "onboard-notes-2.yaml"
