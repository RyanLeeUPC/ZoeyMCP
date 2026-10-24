"""The words each mode shows (M6 design Y25, M.1, M.7; CR-15, OPS-18; step 15a).

In managed mode nothing the operator is shown says to commit, reload, generate or make a
fragment: every ``next`` list a managed answer carries, the refusal text of every reason a
managed save meets, and ``index.html``'s static text outside its ``data-mode="declarative"``
blocks; in declarative mode nothing says to save. ``index.html``'s six mode-bound texts and
Generate are pairs of blocks, one per mode, which ``drift.js`` shows from the session's mode
(BP-7). The repository's own files are read, so mutmut skips this file
(``pytest_add_cli_args``).
"""

from __future__ import annotations

import re
import typing
from html.parser import HTMLParser
from pathlib import Path

from tests.unit.test_portal_static import code_of
from tests.unit.test_portal_static import read as static
from zoeymcp.common.policy import plan, restart
from zoeymcp.portal import app as portal_app
from zoeymcp.portal.refusals import CATALOGUE, SAVE_MOVED, refusal
from zoeymcp.vault import managed, onboarding
from zoeymcp.vault.onboarding import NextStep, job_next, managed_next, saved_next

INDEX = Path(__file__).resolve().parents[2] / "src" / "zoeymcp" / "portal" / "static" / "index.html"
MANAGED_WORDS = re.compile(r"commit|fragment|reload|generate", re.IGNORECASE)
DECLARATIVE_WORDS = re.compile(r"\bsav(e|ed|es|ing)\b", re.IGNORECASE)
# The reasons a managed save can meet in the portal (N.2): the planner's, the write's, the
# store's, a draft's, and the review's own refusals of the choices, in managed mode's words.
MANAGED_REASONS = (
    *typing.get_args(plan.Reason),
    *typing.get_args(managed.Reason),
    "policy_write_failed",
    "revision_out_of_range",
    "draft_unknown",
    "save_invalid",
    "review_stale",
    "bad_body",
    "changed",
    "action_unknown",
    "step_up_refused",
)


class _Texts(HTMLParser):
    """Each text node of a page, with the mode of the nearest block that names one."""

    def __init__(self) -> None:
        super().__init__()
        self.modes: list[str | None] = []
        self.found: list[tuple[str | None, str]] = []
        self.blocks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mode = dict(attrs).get("data-mode")
        if mode is not None:
            self.blocks.append(mode)
        inherited = self.modes[-1] if self.modes else None
        if tag not in ("input", "meta", "link", "br"):
            self.modes.append(mode or inherited)

    def handle_endtag(self, tag: str) -> None:
        if tag not in ("input", "meta", "link", "br") and self.modes:
            self.modes.pop()

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.found.append((self.modes[-1] if self.modes else None, " ".join(data.split())))


def texts() -> _Texts:
    parser = _Texts()
    parser.feed(INDEX.read_bytes().decode("utf-8"))
    return parser


def steps_words(steps: typing.Iterable[NextStep]) -> list[str]:
    return [f"{step.label} {step.shell()}" for step in steps]


def test_index_html_says_each_modes_words() -> None:
    """CR-15: the four "declarative" sentences and the two that say to commit are each a pair,
    and so is Generate, Save its managed half; in managed mode nothing shown says to commit,
    reload, generate or make a fragment, and in declarative mode nothing says save."""
    found = texts()
    assert found.blocks.count("managed") == found.blocks.count("declarative") == 7
    managed_shown = [text for mode, text in found.found if mode != "declarative"]
    declarative_shown = [text for mode, text in found.found if mode != "managed"]
    assert [t for t in managed_shown if MANAGED_WORDS.search(t)] == []
    assert [t for t in declarative_shown if DECLARATIVE_WORDS.search(t)] == []
    assert ("managed", "Save") in found.found
    assert ("declarative", "Generate") in found.found


def test_drift_js_shows_the_sessions_mode() -> None:
    """BP-7: drift.js reads the session's mode and shows each block in its own mode only;
    every managed block starts hidden, so a page that can't ask shows the declarative words."""
    code = code_of(static("drift.js"))
    assert 'mode = (await api("GET", "/api/session")).mode;' in code
    assert "block.hidden = block.dataset.mode !== mode;" in code
    page = INDEX.read_bytes().decode("utf-8")
    assert page.count('data-mode="managed" hidden') == page.count('data-mode="managed"')


def test_drift_js_says_each_modes_words() -> None:
    """Y25: every text drift.js can show in managed mode says no commit, fragment, reload or
    generate. The two that do are declarative's alone: a proposed tool's sentence, whose
    managed half says the save's plan lists the kept allow (Q8, Q27), and the move Allow without
    asking makes on the review screen, which in managed mode opens a dialog instead (J.4)."""
    code = code_of(static("drift.js"))
    declarative_only = {"PROPOSED", "MOVED"}
    constant = re.compile(r'const ([A-Z_]+) = ((?:"[^"]*"\s*\+?\s*)+);')
    found = dict(constant.findall(code))
    assert declarative_only <= set(found)
    for name in declarative_only:
        assert MANAGED_WORDS.search(found[name]), name
    assert 'make("p", mode === "managed" ? PROPOSED_SAVED : PROPOSED)' in code
    start = code.index("function then(asked, held) {")
    then = code[start : code.index("\n  }\n", start)]
    assert then.index("return allowReviewed(asked);") < then.index("move(")
    assert len(re.findall(r"(?<![A-Z_])MOVED\b", code)) == 2  # its line, and move()'s
    shown = constant.sub(
        lambda match: "" if match.group(1) in declarative_only else match.group(0), code
    )
    literals = re.findall(r'"((?:[^"\\]|\\.)*)"', shown)
    assert "Choose allow above to keep it: the save's plan lists it as its own row." in "".join(
        literals
    )
    assert [text for text in literals if MANAGED_WORDS.search(text)] == []


def test_managed_next_lists_say_save() -> None:
    """M.7, Y25: a managed done review's way on, and a save's for every effect, name no commit,
    fragment, reload or generate."""
    # Every effect kind, with each of I.2's fixed texts, a restart's step reads.
    words_of = [v for k, v in vars(restart).items() if k.endswith("_TEXT") and isinstance(v, str)]
    assert words_of
    effects = [
        restart.Effect(kind, "p", text)
        for kind in typing.get_args(restart.EffectKind)
        for text in words_of
    ]
    lists = [
        managed_next(),
        managed_next(None),
        job_next("notes", clear=False, managed=True),
        job_next("notes", clear=True, managed=True),
        saved_next(effects),
        saved_next(effects, applied=True),
    ]
    words = [word for steps in lists for word in steps_words(steps)]
    assert words
    assert [w for w in words if MANAGED_WORDS.search(w)] == []
    # J15's line: the vault's restart names its command's way (via restart).
    assert onboarding.RESTART_VAULT.answer()["via"] == "restart"
    # Declarative ways on say no save.
    declarative = steps_words(job_next("notes", clear=False))
    assert [w for w in declarative if DECLARATIVE_WORDS.search(w)] == []


def test_a_managed_saves_refusals_say_save() -> None:
    """Y25, OPS-18: every reason a managed save meets in the portal is catalogued and says no
    commit, fragment, reload or generate; ``policy_moved`` is worded for a save; and the
    review's ``diff_invalid`` is ``save_invalid`` in managed mode."""
    for reason in MANAGED_REASONS:
        assert reason in CATALOGUE, reason
        assert not MANAGED_WORDS.search(CATALOGUE[reason].text), reason
    assert not MANAGED_WORDS.search(SAVE_MOVED)
    made = portal_app._saving(refusal("diff_invalid", detail="list is unknown"))
    assert (made.reason, made.error) == (
        "save_invalid",
        "The running policy with this change fails check (list is unknown), so it can't be saved.",
    )
    assert portal_app._saving(refusal("review_stale")).reason == "review_stale"
    # The declarative refusal a managed kind meets there says no save.
    assert not DECLARATIVE_WORDS.search(CATALOGUE["policy_not_managed"].text)
