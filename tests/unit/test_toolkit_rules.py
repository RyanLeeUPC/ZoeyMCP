"""What the gateway lets a toolkit do (M4 design G.3, H.2, H.4): send-once accounting, every cell
of H.4's table, paths that would leave a slot, and the loader's decisions."""

from __future__ import annotations

import stat

import pytest
from hypothesis import given
from hypothesis import strategies as st

from zoeymcp.common.approvaltext import Plan, Write
from zoeymcp.toolkit.plan import SendLedger
from zoeymcp.toolkit.rules import (
    Entry,
    Slot,
    SlotRule,
    check_call,
    classification_hidden,
    entry_module,
    module_refused,
    outside_roots,
    slot_mismatch,
    writable_problems,
)

GET = frozenset({"GET"})
POST = frozenset({"POST"})

MAIL = Slot(
    "/mail",
    "smtp",
    (SlotRule(GET, ("/mail/config",)), SlotRule(POST, ("/mail/send",), approved=True)),
)
DB = Slot(
    "/db",
    None,
    (
        SlotRule(GET, ("/db/v1/records/{id}",)),
        SlotRule(POST, ("/db/v1/records/batch",), approved=True),
        SlotRule(POST, ("/db/v1/notes",)),
        SlotRule(GET, ("/db/v1/approved",), approved=True),
    ),
)


# --- send-once accounting -----------------------------------------------------------------------


def writes(n: int) -> list[Write]:
    return [Write.post("/send", {"n": i}) for i in range(n)]


def test_each_write_once_in_any_order() -> None:
    planned = writes(3)
    ledger = SendLedger(Plan("Send", planned))
    assert ledger.claim(planned[2]) == "ok"
    assert ledger.claim(planned[0]) == "ok"
    assert ledger.claim(planned[2]) == "already_sent"
    assert ledger.unsent == (planned[1],)
    assert ledger.claim(planned[1]) == "ok"
    assert not ledger.unsent


def test_only_the_plans_own_writes() -> None:
    planned = writes(1)
    ledger = SendLedger(Plan("Send", planned))
    assert ledger.claim(Write.post("/send", {"n": 0})) == "not_in_plan"  # equal, not the same
    assert ledger.claim(planned[0]) == "ok"
    assert SendLedger(None).claim(planned[0]) == "not_in_plan"
    assert SendLedger(None).unsent == ()


def test_a_write_with_another_digest_is_refused() -> None:
    planned = writes(1)
    ledger = SendLedger(Plan("Send", planned))
    forged = Write.post("/send", {"n": 9})
    object.__setattr__(forged, "digest", "sha256:" + "0" * 64)
    assert ledger.claim(forged) == "not_in_plan"
    object.__setattr__(planned[0], "digest", "sha256:" + "1" * 64)
    assert ledger.claim(planned[0]) == "ok"  # the same object: its digest is its own


@given(st.lists(st.integers(min_value=0, max_value=4), max_size=20))
def test_no_order_sends_a_write_twice(order: list[int]) -> None:
    planned = writes(5)
    ledger = SendLedger(Plan("Send", planned))
    sent = [i for i in order if ledger.claim(planned[i]) == "ok"]
    assert sorted(sent) == sorted(set(order))


# --- H.4's table --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("phase", "method", "path", "claim", "expected"),
    [
        # prepare: only an smtp connector's config
        ("prepare", "GET", "/config", None, None),
        ("prepare", "GET", "/send", None, "prepare_upstream_read"),
        ("prepare", "POST", "/send", None, "write_in_prepare"),
        ("prepare", "POST", "/send", "ok", "write_in_prepare"),
        # an allow call's body
        ("allow", "GET", "/config", None, None),
        ("allow", "POST", "/send", None, "needs_approval"),
        ("allow", "POST", "/send", "ok", "needs_approval"),
        # an approve call's body, after the accept
        ("approve", "GET", "/config", None, None),
        ("approve", "POST", "/send", "ok", None),
        ("approve", "POST", "/send", "already_sent", "already_sent"),
        ("approve", "POST", "/send", "not_in_plan", "not_in_plan"),
        ("approve", "POST", "/send", None, "not_in_plan"),
        # after the call returned
        ("closed", "GET", "/config", None, "closed"),
        ("closed", "POST", "/send", "ok", "closed"),
        # no rule
        ("approve", "GET", "/other", None, "no_rule"),
        ("approve", "PUT", "/send", None, "no_rule"),
        ("approve", "HEAD", "/config", None, "no_rule"),
    ],
)
def test_the_smtp_slot(
    phase: str, method: str, path: str, claim: str | None, expected: str | None
) -> None:
    assert check_call(MAIL, phase, method, path, plan_write=claim) == expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("phase", "method", "path", "claim", "expected"),
    [
        ("prepare", "GET", "/v1/records/r1", None, "prepare_upstream_read"),
        ("prepare", "GET", "/config", None, "prepare_upstream_read"),
        ("prepare", "POST", "/v1/notes", None, "write_in_prepare"),
        ("allow", "GET", "/v1/records/r1", None, None),
        ("allow", "POST", "/v1/notes", None, None),
        ("allow", "POST", "/v1/records/batch", None, "needs_approval"),
        ("allow", "GET", "/v1/approved", None, None),  # approved has no effect on a GET
        ("approve", "GET", "/v1/records/r1", None, None),
        ("approve", "POST", "/v1/notes", None, None),
        ("approve", "POST", "/v1/notes", "ok", "not_approved_rule"),
        ("approve", "POST", "/v1/records/batch", "ok", None),
        ("approve", "POST", "/v1/records/batch", None, "not_in_plan"),
        ("approve", "DELETE", "/v1/records/r1", None, "no_rule"),
        ("approve", "GET", "/v1/records/r1/x", None, "no_rule"),
        ("closed", "GET", "/v1/records/r1", None, "closed"),
    ],
)
def test_the_http_slot(
    phase: str, method: str, path: str, claim: str | None, expected: str | None
) -> None:
    assert check_call(DB, phase, method, path, plan_write=claim) == expected  # type: ignore[arg-type]


def test_an_approved_rule_wins_over_a_plain_one() -> None:
    both = Slot("/db", None, (SlotRule(POST, ("/db/v1/**",)), SlotRule(POST, ("/db/v1/x",), True)))
    assert check_call(both, "allow", "POST", "/v1/y") is None
    assert check_call(both, "allow", "POST", "/v1/x") == "needs_approval"


@pytest.mark.parametrize(
    "path",
    [
        "/../broker/mcp",
        "/v1/records/..",
        "/v1/records/.",
        "/v1/records/a%2Fb",
        "/v1/records/a%5Cb",
        "/v1/records/%2e%2e",
        "/v1/records/a%25b",
        "/v1/records/a%zz",
        "/v1//records",
        "/v1/records/a b",
        "/v1/records/é",
        "/v1/records/a\nb",
        "v1/records/r1",
        "",
    ],
)
def test_a_path_that_would_leave_its_slot_is_refused_first(path: str) -> None:
    for phase in ("prepare", "allow", "approve"):
        assert check_call(DB, phase, "GET", path) == "bad_path"
    assert check_call(DB, "closed", "GET", path) == "closed"


def test_an_encoded_character_that_is_allowed() -> None:
    assert check_call(DB, "allow", "GET", "/v1/records/r%31") is None  # r1, decoded once


# --- loading ------------------------------------------------------------------------------------


def test_module_names() -> None:
    assert module_refused("zoeymcp")
    assert module_refused("zoeymcp.gateway.app")
    assert not module_refused("zoeymcpx")
    assert not module_refused("example_toolkits.mail")
    assert entry_module("example_toolkits.mail:toolkit") == "example_toolkits.mail"
    assert entry_module(" pkg.mod : attr") == "pkg.mod"
    assert entry_module("pkg.mod") == "pkg.mod"


def test_slot_matching() -> None:
    assert slot_mismatch({"mail": "smtp"}, {"mail": "smtp"}) is None
    assert slot_mismatch({"db": "http"}, {"db": None}) is None
    assert slot_mismatch({}, {}) is None
    assert slot_mismatch({"mail": "smtp"}, {"mail": None}) == "mail"
    assert slot_mismatch({"db": "http"}, {"db": "smtp"}) == "db"
    assert slot_mismatch({"mail": "smtp"}, {}) == "mail"
    assert slot_mismatch({}, {"extra": None}) == "extra"
    assert slot_mismatch({"a": "http", "b": "smtp"}, {"a": None, "b": None}) == "b"


def test_the_classification_floor() -> None:
    assert classification_hidden(True, "allow")
    assert not classification_hidden(True, "approve")
    assert not classification_hidden(False, "allow")
    assert not classification_hidden(False, "approve")  # the policy may be stricter


def entry(mode: int, uid: int = 0, gid: int = 0, path: str = "/p") -> Entry:
    return Entry(path, mode, uid, gid)


@pytest.mark.parametrize(
    ("found", "writable"),
    [
        (entry(0o644, uid=0), False),
        (entry(0o755 | stat.S_IFDIR, uid=0), False),
        (entry(0o644, uid=1000), True),  # the gateway owns it
        (entry(0o444, uid=1000), False),  # owned but read-only
        (entry(0o664, gid=1000), True),  # one of its groups may write
        (entry(0o664, gid=50), False),
        (entry(0o646), True),  # anyone may write
        (entry(0o1777 | stat.S_IFDIR), True),
    ],
)
def test_writable_paths(found: Entry, writable: bool) -> None:
    assert writable_problems([found], uid=1000, gids=frozenset({1000})) == (
        [found.path] if writable else []
    )


def test_root_may_write_anything() -> None:
    assert writable_problems([entry(0o444)], uid=0, gids=frozenset()) == ["/p"]


def test_files_outside_the_environment() -> None:
    roots = ["/opt/gateway/lib/python3.12/site-packages"]
    files = [
        "/opt/gateway/lib/python3.12/site-packages/example_toolkits/mail.py",
        "/opt/gateway/lib/python3.12/site-packages-evil/x.py",
        "/srv/elsewhere/x.py",
    ]
    assert outside_roots(files, roots) == files[1:]
