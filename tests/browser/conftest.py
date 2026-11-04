"""The browser harness's fixtures (M8 design step 27a; D-222).

The directory is skipped unless Playwright is installed (the ``browser`` dependency group, which
only the browser jobs and the lint job sync) and ``ZOEYMCP_BROWSER`` names the browser to drive
(``engines.py``): the ordinary test jobs, mutation and a development host's plain ``pytest`` never
run it. A development host runs one test at a time against its installed Chrome
(``ZOEYMCP_BROWSER=chrome``); CI is the judge.

One browser per session; each test gets a fresh context (a fresh profile: no cookies, no
storage) at 1280x800, scale 1, ``en-US``, UTC (rows show times) and reduced motion, never with
``bypass_csp``, its every page watched (``watch.py``) and its trace recorded. Page time is
Playwright's fake clock, installed and paused when the context opens: the page's polls (every 2,
5 and 10 s) fire only when a test moves it (``page.clock.run_for``), never on the wall clock;
server time is the rig's ``Clock``. When the test fails the trace and a screenshot of each open
page are kept under ``test-results/`` (CI uploads them; they hold only a throwaway vault's codes
and sessions, never a real secret), and the watch isn't asserted on top of the failure; when it
passes the watch must be clean, and an unclean watch keeps them too. A second browser
(``other_context``) keeps its own, beside the first's.
"""

from __future__ import annotations

import importlib.util
import os
import re
import time
from collections.abc import Generator, Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from . import engines

if TYPE_CHECKING:
    from playwright.sync_api import Browser, BrowserContext, Page, Playwright

    from .watch import Watch

ENGINE = os.environ.get("ZOEYMCP_BROWSER", "")
collect_ignore_glob = (
    ["test_*.py"] if importlib.util.find_spec("playwright") is None or not ENGINE else []
)
FAILED = pytest.StashKey[bool]()


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    if report.failed:
        item.stash[FAILED] = True
    return report


@pytest.fixture(scope="session")
def playwright() -> Iterator[Playwright]:
    from playwright.sync_api import expect, sync_playwright

    expect.set_options(timeout=engines.TIMEOUT)
    with sync_playwright() as driver:
        yield driver


@pytest.fixture(scope="session")
def browser(playwright: Playwright) -> Iterator[Browser]:
    try:
        options = engines.launch_options(ENGINE)
    except ValueError as error:
        raise pytest.UsageError(str(error)) from None
    launched = playwright.chromium.launch(**options)
    yield launched
    launched.close()


@pytest.fixture
def watch() -> Watch:
    from .watch import Watch

    return Watch()


def profile(browser: Browser, watch: Watch) -> BrowserContext:
    """A fresh browser profile with the fixed settings, every page of it watched and on a
    paused clock, its trace recording."""
    made = browser.new_context(
        viewport={"width": 1280, "height": 800},
        device_scale_factor=1,
        locale="en-US",
        timezone_id="UTC",
        reduced_motion="reduce",
    )
    made.set_default_timeout(engines.TIMEOUT * 2)
    watch.attach(made)
    # Installed before any page opens, so every page starts on it, at the time the context
    # opened, paused there.
    opened = time.time()
    made.clock.install(time=opened)
    made.clock.pause_at(opened)
    made.tracing.start(screenshots=True, snapshots=True)
    return made


def close(made: BrowserContext, request: pytest.FixtureRequest, watch: Watch, label: str) -> bool:
    """Closes ``made``, first keeping its trace and a screenshot of each open page if the test
    failed or the watch is unclean (``trace.zip`` and ``page-N.png``, or with ``label`` in each
    name for a second browser). Returns whether the watch is unclean on a test that passed."""
    failed = request.node.stash.get(FAILED, False)
    unclean = not failed and watch.problems() != {}
    if failed or unclean:
        kept = results(request)
        named = f"-{label}" if label else ""
        for number, page in enumerate(made.pages):
            page.screenshot(path=kept / f"page{named}-{number}.png")
        made.tracing.stop(path=kept / f"trace{named}.zip")
    else:
        made.tracing.stop()
    made.close()
    return unclean


@pytest.fixture
def context(
    browser: Browser, watch: Watch, request: pytest.FixtureRequest
) -> Iterator[BrowserContext]:
    made = profile(browser, watch)
    try:
        yield made
    finally:
        unclean = close(made, request, watch, "")
    if unclean:
        watch.assert_clean()


@pytest.fixture
def other_context(
    context: BrowserContext, browser: Browser, watch: Watch, request: pytest.FixtureRequest
) -> Iterator[BrowserContext]:
    """A second browser (a restarted one, or another operator's), watched with the first and
    closed before it; the first's teardown asserts the watch."""
    made = profile(browser, watch)
    try:
        yield made
    finally:
        close(made, request, watch, "other")


@pytest.fixture
def page(context: BrowserContext) -> Page:
    return context.new_page()


def results(request: pytest.FixtureRequest) -> Path:
    """``test-results/<the test's name>/``, for what a failed test keeps."""
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", request.node.nodeid).strip("-")
    kept = request.config.rootpath / "test-results" / name
    kept.mkdir(mode=0o700, parents=True, exist_ok=True)
    return kept
