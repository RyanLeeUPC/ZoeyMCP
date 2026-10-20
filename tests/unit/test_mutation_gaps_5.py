"""Killing tests for mutants that survived the M5 modules' mutation run on 5a1db99 (step 19b).

Each test names what it pins. The mutants left alive on purpose are in :data:`EQUIVALENT`, each
with why no test can tell it from the original; :func:`test_each_equivalent_names_a_function`
keeps the list honest when a function is renamed or removed. mutmut still counts them as
survivors, so they stay in each module's score.
"""

from __future__ import annotations

import importlib
import os
import time
from collections.abc import Iterator
from types import MappingProxyType
from typing import Final

import pytest

from tests.fakes.authenticator import SoftAuthenticator, Switch
from tests.unit.test_health import (
    API,
    LIVE,
    SEEDED,
    SPOTIFY_ENTRIES,
    TOKEN_URL,
    entry,
    journal,
    make_policy,
    oauth_findings,
    one,
    report,
    sending,
    spotify,
)
from tests.unit.test_health import T0 as SEND_T0
from tests.unit.test_listen import nothing, portal
from tests.unit.test_sessions import ORIGIN, mint, scripted
from tests.unit.test_sessions import T0 as SESSION_T0
from tests.unit.test_webauthn import attest, enrol, register, with_body
from zoeymcp.portal import policyview, routes
from zoeymcp.portal.limits import ADMIN_CONNECTIONS, Connections, Opened
from zoeymcp.portal.listen import conflict
from zoeymcp.portal.sessions import MAX_LOGIN_CEREMONIES_PER_PEER, Ceremonies, Sessions
from zoeymcp.portal.webauthn import b64url, b64url_decode
from zoeymcp.vault.bindings import oauth_binding
from zoeymcp.vault.health import sends
from zoeymcp.vault.ledgerview import page, when
from zoeymcp.vault.reports import Held

_BIG: Final = 'int.from_bytes(..., "big") without the byteorder: it defaults to "big" since 3.11'
_CASE: Final = "a codec name in another case: Python's codec lookup ignores case"

EQUIVALENT: Final[dict[str, str]] = {
    # --- portal.admission
    "zoeymcp.portal.admission.x_callback_query__mutmut_9": _CASE,
    "zoeymcp.portal.admission.x_values__mutmut_3": _CASE,
    "zoeymcp.portal.admission.x_origin_entry__mutmut_5": (
        '`parts.hostname or "XXXX"`: only an origin without a host reaches the fallback, and '
        "origin_entry is given only the policy's origins, which the schema has checked to have one"
    ),
    # --- portal.refusals
    "zoeymcp.portal.refusals.x_login__mutmut_19": (
        '`- {"XXcodeXX"}` for `- {"code"}`: `offered` has no "code" key, so whether "code" is in '
        "`wanted` never changes which fields are kept"
    ),
    "zoeymcp.portal.refusals.x_login__mutmut_20": '`- {"CODE"}`: as mutant 19',
    # --- portal.policyview
    "zoeymcp.portal.policyview.x_view__mutmut_11": (
        '`_model(policy, None, ...)` for "": `_model` only asks `if path`, and both are false'
    ),
    # --- portal.sessions
    "zoeymcp.portal.sessions.x_new_token__mutmut_6": (
        '`rstrip(b"XX=XX")` also strips trailing "X": 32 bytes encode to 43 characters whose last '
        "holds 4 bits and two zero bits, so it is A, E, I, M, Q, U, Y, c, g, k, o, s, w, 0, 4 or "
        "8, never X"
    ),
    "zoeymcp.portal.sessions.xǁSessionTokenǁsha256__mutmut_4": _CASE,
    # --- portal.setupcode
    "zoeymcp.portal.setupcode.x_decide__mutmut_10": (
        '`"XXXX"` for "" as the candidate of a code that doesn\'t parse: a record\'s sha256 is '
        "64 hex digits (checked when it is read), so neither compares equal and both are wrong"
    ),
    "zoeymcp.portal.setupcode.x_digest__mutmut_4": _CASE,
    "zoeymcp.portal.setupcode.x_new_code__mutmut_7": _CASE,
    # --- portal.webauthn
    "zoeymcp.portal.webauthn.x__public_key__mutmut_5": _BIG,
    "zoeymcp.portal.webauthn.x__read_key__mutmut_29": _BIG,
    "zoeymcp.portal.webauthn.x_verify_assertion__mutmut_132": _BIG,
    "zoeymcp.portal.webauthn.x_verify_registration__mutmut_80": _BIG,
    "zoeymcp.portal.webauthn.x_verify_registration__mutmut_162": _BIG,
    "zoeymcp.portal.webauthn.x_b64url__mutmut_7": _CASE,
    # --- vault.health
    "zoeymcp.vault.health.x__connector__mutmut_7": (
        "a connector reference's `needs` None for frozenset(): judge reads `needs` only for an "
        "origin or OAuth binding, and a name a connector uses derives an smtp binding or a conflict"
    ),
    "zoeymcp.vault.health.x__credential__mutmut_36": (
        "`break` for `continue` after a seeded refresh token: secret_references lists a "
        "credential's refresh_token last, so no reference is left to skip"
    ),
    "zoeymcp.vault.health.x__renew__mutmut_34": (
        '`refresh_token or "XXXX"`: reached only by a refresh_token grant with neither an '
        "authorize_url nor a refresh_token, which check refuses, so the vault never starts with one"
    ),
    "zoeymcp.vault.health.x__seeded__mutmut_4": (
        '`refresh_token or "XXXX"`: "XXXX" doesn\'t start with "env:" any more than "" does'
    ),
    "zoeymcp.vault.health.x_assess__mutmut_32": (
        "`refs.get(..., None)` for a credential: every credential of a policy the vault loads has "
        "a reference (a static secret is one; check requires a refresh token or a client secret "
        "for each grant), so the default is never used"
    ),
    "zoeymcp.vault.health.x_assess__mutmut_34": "`refs.get(...)` with no default: as mutant 32",
    "zoeymcp.vault.health.x_assess__mutmut_47": (
        "`refs.get(..., None)` for a connector: the schema requires its password reference, so "
        "the default is never used"
    ),
    "zoeymcp.vault.health.x_assess__mutmut_49": "`refs.get(...)` with no default: as mutant 47",
    # --- vault.ledgerview
    "zoeymcp.vault.ledgerview.x_state__mutmut_20": (
        "`max(1, ago) // 1000` for `max(0, ago) // 1000`: both are 0 for any ago below 1000"
    ),
    "zoeymcp.vault.ledgerview.x_when__mutmut_6": (
        "`ts / 1000` for `ts // 1000`: the format has whole seconds, and a millisecond fraction "
        "rounds to microseconds without carrying into the next second"
    ),
    # --- vault.reports
    "zoeymcp.vault.reports.x__lines__mutmut_42": _CASE,
    # --- vault.secretplan
    "zoeymcp.vault.secretplan.x_plan_put__mutmut_45": (
        "`allow_tabs=None` for False: with single_line=True, find_violations refuses a tab "
        "whatever allow_tabs says"
    ),
    "zoeymcp.vault.secretplan.x_plan_put__mutmut_49": "no allow_tabs: as mutant 45",
    "zoeymcp.vault.secretplan.x_plan_put__mutmut_51": "`allow_tabs=True`: as mutant 45",
    # --- gateway.reporting
    "zoeymcp.gateway.reporting.x_backoff__mutmut_20": (
        "the exponent capped at 17 for 16: FIRST_BACKOFF * 2**16 is already far above "
        "MAX_BACKOFF, so the min() gives MAX_BACKOFF either way"
    ),
    "zoeymcp.gateway.reporting.x_parse_head__mutmut_34": (
        "`cast(None, state)`: typing.cast does nothing at run time"
    ),
    "zoeymcp.gateway.reporting.x_parse_head__mutmut_59": "`cast(None, state)`: as mutant 34",
}


def _function(key: str) -> tuple[str, str, str | None]:
    """A mutant key's module, function and class (None for a module-level function)."""
    path, _, _ = key.partition("__mutmut_")
    if "xǁ" in path:
        module, _, rest = path.partition(".xǁ")
        cls, _, name = rest.partition("ǁ")
        return module, name, cls
    module, _, name = path.rpartition(".x_")
    return module, name, None


@pytest.mark.parametrize("key", sorted(EQUIVALENT))
def test_each_equivalent_names_a_function(key: str) -> None:
    module_name, name, cls = _function(key)
    owner: object = importlib.import_module(module_name)
    if cls is not None:
        owner = getattr(owner, cls)
    assert callable(getattr(owner, name)), key


# --- portal.policyview ---------------------------------------------------------------------------
# FIELDS is built at import, where mutmut can't switch a mutant in, so `_fields` is called here.


def test_a_field_table_shows_the_named_fields_and_treats_the_rest_as_given() -> None:
    table = policyview._fields("kind", "secret", username="hidden", force="names")
    assert isinstance(table, MappingProxyType)
    assert dict(table) == {
        "kind": "shown",
        "secret": "shown",
        "username": "hidden",
        "force": "names",
    }
    assert dict(policyview._fields()) == {}


# --- portal.routes -------------------------------------------------------------------------------


def test_params_never_pairs_a_template_with_a_path_of_another_length() -> None:
    # match() compares the lengths first; _params refuses rather than read a prefix.
    assert routes._params(["api", "{credential}"], ["api", "notes"]) == {"credential": "notes"}
    with pytest.raises(ValueError, match="shorter"):
        routes._params(["api", "{credential}"], ["api"])


# --- portal.limits -------------------------------------------------------------------------------


def test_connections_idle_since_the_same_instant_are_evicted_oldest_first() -> None:
    # Only the idle time orders them: a tie never compares the connections themselves.
    table: Connections[object] = Connections()
    held = [object() for _ in range(ADMIN_CONNECTIONS)]
    for conn in held:
        assert table.open(conn, 5.0) == Opened(accepted=True)
    assert table.open(object(), 6.0) == Opened(accepted=True, evict=held[0])
    assert table.open(object(), 7.0) == Opened(accepted=True, evict=held[1])


# --- portal.listen -------------------------------------------------------------------------------


def test_a_clash_after_a_listen_on_another_port_is_found() -> None:
    admin = "127.0.0.1:8081"
    found = conflict(portal(admin), ["127.0.0.1:9000", admin], nothing)
    assert found == f"admin.listen {admin} is --listen {admin}'s address"


# --- portal.sessions -----------------------------------------------------------------------------


def test_a_peer_over_its_quota_loses_its_own_oldest_not_an_older_peers() -> None:
    table = Ceremonies()
    table.begin_login(origin=ORIGIN, peer="b", now=SESSION_T0)
    for _ in range(MAX_LOGIN_CEREMONIES_PER_PEER + 1):
        table.begin_login(origin=ORIGIN, peer="a", now=SESSION_T0)
    assert (table.logins("a"), table.logins("b")) == (MAX_LOGIN_CEREMONIES_PER_PEER, 1)


def test_a_header_half_another_session_shares_doesnt_end_the_search() -> None:
    header = b"\x07" * 32
    table = Sessions(
        scripted(b"\x01" * 32, header, b"\xaa" * 16, b"\x02" * 32, header, b"\xbb" * 16)
    )
    first = mint(table)
    second = mint(table, SESSION_T0 + 1)
    assert first.header.reveal() == second.header.reveal()
    now = SESSION_T0 + 2
    assert table.lookup([second.cookie], second.header, origin=ORIGIN, now=now) is second.session
    assert table.lookup([first.cookie], first.header, origin=ORIGIN, now=now) is first.session


# --- portal.webauthn -----------------------------------------------------------------------------


def test_a_registration_counter_keeps_its_high_byte() -> None:
    good = attest()
    auth = bytearray(good.authenticator_data)
    auth[33:37] = (0x01020304).to_bytes(4, "big")
    new = register(with_body(good, authenticator_data=b64url(bytes(auth))))
    assert new.sign_count == 0x01020304


def test_an_assertion_counter_is_its_four_bytes() -> None:
    enrolled = enrol()
    assertion = enrolled.get()
    auth = assertion.authenticator_data
    counted = enrolled.resigned(assertion, auth_data=auth[:33] + (0x01000002).to_bytes(4, "big"))
    asserted = enrolled.verify(counted)
    assert (asserted.sign_count, asserted.regressed) == (0x01000002, False)
    # Extensions follow the counter when ED is set; none of their bytes is counted.
    counting = enrol(authenticator=SoftAuthenticator(counts=True))
    with_extensions = counting.verify(counting.get(Switch.EXTENSIONS))
    assert (with_extensions.sign_count, with_extensions.regressed) == (1, False)


def test_a_non_canonical_text_is_refused_as_such() -> None:
    assert b64url_decode("AA") == b"\x00"
    with pytest.raises(ValueError, match=r"^not canonical base64url$"):
        b64url_decode("AA==")


# --- vault.health --------------------------------------------------------------------------------


def test_a_seeded_refresh_token_keeps_the_findings_before_it() -> None:
    policy = make_policy({"music": spotify(**SEEDED)})
    found = one(report(policy, SPOTIFY_ENTRIES[:1], env=["MUSIC_SEED"]))
    assert [f["code"] for f in found["findings"]] == ["missing"]
    assert "store:music-secret" in found["findings"][0]["text"]


def test_a_live_slot_the_policy_cant_bind_is_fixed_in_the_policy() -> None:
    policy = make_policy({"music": spotify(**SEEDED)}, {"music": ()})
    entries = [*SPOTIFY_ENTRIES[:2], entry(LIVE, oauth_binding(TOKEN_URL, [API]))]
    found = one(report(policy, entries))
    live = found["refs"][-1]
    assert (live["ref"], live["present"], live["binding"]) == (f"store:{LIVE}", True, "no_route")
    assert found["findings"][-1]["code"] == "no_route"
    assert found["findings"][-1]["action"] == {"kind": "fix_policy", "credential": "music"}


def test_missing_scopes_are_listed_with_spaces() -> None:
    [missing] = oauth_findings({"scopes": {"missing": ["read", "write"]}})
    assert missing["text"] == "expected scopes not granted: read write"


def test_a_send_that_succeeded_is_not_unknown() -> None:
    sent = journal(
        sending("a" * 16, SEND_T0 - 2000),
        {
            "kind": "sent",
            "key": "a" * 16,
            "ts": SEND_T0 - 1000,
            "message_id": "<m@x>",
            "smtp_code": 250,
        },
    )
    assert (sends(sent, SEND_T0).sent_24h, sends(sent, SEND_T0).unknown_24h) == (1, 0)


# --- vault.ledgerview ----------------------------------------------------------------------------


def test_a_page_shows_where_the_copy_breaks() -> None:
    found = page([], held=Held(), journals={}, now=SEND_T0, broken_at=7)
    assert found["state"]["broken_at"] == 7
    assert page([], held=Held(), journals={}, now=SEND_T0)["state"]["broken_at"] is None


@pytest.fixture
def east_of_utc() -> Iterator[None]:
    """The process's local time zone set 5:30 east of UTC (POSIX only: time.tzset)."""
    tzset = getattr(time, "tzset", None)
    if tzset is None:
        pytest.skip("time.tzset is POSIX only")
    old = os.environ.get("TZ")
    os.environ["TZ"] = "XST-5:30"
    tzset()
    try:
        yield
    finally:
        if old is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = old
        tzset()


@pytest.mark.usefixtures("east_of_utc")
def test_when_is_utc_whatever_the_local_time_zone() -> None:
    assert time.localtime(0).tm_hour == 5  # the zone took effect
    assert when(0) == "1970-01-01T00:00:00Z"
    assert when(1_790_000_000_999) == "2026-09-21T14:13:20Z"
