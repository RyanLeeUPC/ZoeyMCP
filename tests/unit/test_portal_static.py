"""The portal's static files, checked as text (M5 design K.2, K.4, C.4, D-123).

The page holds no decision, so it is tested by what it may contain and by drift checks against
the server: every API path the script names is a route, and every route is named; every refusal
reason it handles is catalogued; every WebAuthn field the verifier requires is posted. Nothing
here runs the script: what it sends is pinned by ``test_portal_wire.py`` and the portal tests,
and what only a browser shows is on the manual checklist (``docs/manual-checks.md``).

Each checker is first shown to catch what it is for, on hostile text built from escapes, so a
check that silently matched nothing would fail here.
"""

from __future__ import annotations

import re
import typing
from html.parser import HTMLParser
from pathlib import Path

import pytest

from tests.unit.test_approvalsview import closed as closed_hold
from tests.unit.test_approvalsview import hold as held_hold
from tests.unit.test_review_choices import large
from tests.unit.test_reviewview import held
from zoeymcp import __version__
from zoeymcp.common.policy.attention import approvals_item
from zoeymcp.common.policy.change import CONNECTOR_LIMITS
from zoeymcp.common.policy.diff import Change
from zoeymcp.common.policy.emit import INDENT_MAX
from zoeymcp.common.policy.plan import WriteKind
from zoeymcp.common.policy.schema import Policy
from zoeymcp.portal import app as portal_app
from zoeymcp.portal import approvalsview, policydiffview, reviewview
from zoeymcp.portal.refusals import CATALOGUE, WEBAUTHN, reasons
from zoeymcp.portal.routes import CSS, JAVASCRIPT, REVIEW_DIFF, ROUTES, STATIC, WOFF2
from zoeymcp.portal.webauthn import ASSERTION_FIELDS, REGISTRATION_FIELDS
from zoeymcp.vault import onboarding
from zoeymcp.vault.oauth import dcr

STATIC_DIR = Path(__file__).resolve().parents[2] / "src" / "zoeymcp" / "portal" / "static"
DOCS_DIR = Path(__file__).resolve().parents[2] / "docs"
# Every script the map serves (M7 K.4), so a new one can't escape a check below.
SCRIPTS = tuple(file.name for file in STATIC.values() if file.content_type == JAVASCRIPT)
# And every stylesheet: the Zoey design system's tokens and components, then the portal's own.
STYLESHEETS = tuple(file.name for file in STATIC.values() if file.content_type == CSS)
# A stylesheet's url(): a quoted path the static map serves, nothing else (the UX pass, owner).
CSS_URL = re.compile(r"url\(([^)]*)\)")
# The static total's cap (M5 M.4). M8 (Q19 (a), owner): 160 KiB once a step measures the total
# over 124 KiB. M6 left it at 123.9 KiB (126,862 bytes with 21a's per-kind rows and M8's one health
# label); M8 step 15's Approvals queue (approvals.js, its section and two rules) takes it to 133.4
# KiB (136,607 bytes), so the cap is 160 KiB from that step. The UX pass (owner, 2026-11-05):
# the Zoey design system's stylesheets, its self-hosted fonts (54,432 bytes) and the app icon;
# the owner raised the cap for them (and for the help's short explanations in the page), to 288
# KiB: 239,055 bytes with the assets, 260,579 with index.html's help.
MAX_ASSETS = 288 * 1024
# Line caps, per file (M7 K.4); a script with no cap fails. K.2 set 1,000 lines for app.js and
# webauthn.js together. Step 15's Ledger and Policy pages took them past it (998 before, 1,041
# after) although every line they show is made by the server and the existing pages were folded
# onto one helper, so the cap moved by 50 lines rather than squeeze the script further. M7 keeps
# it, and gives review.js, the MCP servers section, its own. M6 (M.4, Q14): the owner raised
# app.js and webauthn.js to 1,060 for the few lines Home and health need (1,048 before step 7,
# 1,051 after), and drift.js, Home's attention list and the drift review, has its own 450;
# policy.js, the Policy page's managed half (step 15b), its own 500. M8 (H.1, Q19 (a)):
# approvals.js, the Approvals queue, the badge and Home's approvals item, its own 400, so app.js
# gains the nav entry and one call (1,053 lines with webauthn.js, BP-12). The UX pass (owner,
# 2026-11-05, raising the caps for the design system's classes in the rows the scripts draw):
# app.js and webauthn.js 1,150 (1,105 with its row, tag and finding builders and help links).
LINE_CAPS = {
    ("app.js", "webauthn.js"): 1150,
    ("review.js",): 700,
    ("drift.js",): 450,
    ("policy.js",): 500,
    ("approvals.js",): 400,
}

LT, GT, QUOTE = chr(0x3C), chr(0x3E), chr(0x22)
# An SMTP connector, for the Policy page's connector row (M6 G.3, step 15c).
MAIL = {
    "kind": "smtp",
    "host": "smtp.mail.example",
    "port": 465,
    "username": "user",
    "password": "store:mail-pass",
    "from": "zoeymcp@mail.example",
    "to": ["ops@mail.example"],
}
FORBIDDEN_TAGS = frozenset({"style", "form", "iframe", "base", "object", "embed", "frame"})
# K.2's sinks and the rest the page must never use.
SINKS = (
    r"\binnerHTML\b",
    r"\bouterHTML\b",
    r"\binsertAdjacentHTML\b",
    r"\bdocument\.write",
    r"\beval\s*\(",
    r"\bFunction\s*\(",
    r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]",
    r"\bsrcdoc\b",
    r"javascript:",
    r"\bdata:(?!\s)",  # a data: URL, not the "data: value" key of an action's body
    r"\blocalStorage\b",
    r"\bdocument\.cookie\b",
    r"\.style\b",
    r"\bsetAttribute\s*\(",
    r"\bon[a-z]+\s*=",
    r"\bimportScripts\b",
    r"\bwindow\.open\b",
)
# A scheme's "://", or a protocol-relative "//host" (not a regular expression's escaped slash).
ABSOLUTE_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://|(?<![:/A-Za-z0-9\\])//[A-Za-z0-9]")
# A path is a literal, or a route's template with its parameters filled in by fill().
API_CALL = re.compile(r"api\(\s*\"(GET|POST|DELETE)\",\s*(?:fill\()?\"(/api/[^\"]*)\"")
API_PATH = re.compile(r"\"(/api/[^\"]*)\"")
HANDLED = re.compile(r"error\.reason\s*===\s*\"([a-z_]+)\"")
STORAGE = re.compile(r"sessionStorage\.(\w+)\(([^)]*)\)")


def read(name: str) -> str:
    data = (STATIC_DIR / name).read_bytes()
    return data.decode("utf-8")


def code_of(script: str) -> str:
    """The script without its comments, so a sentence in a comment can't hide or fake a match.
    The page's scripts put no // or /* inside a string."""
    without_blocks = re.sub(r"/\*.*?\*/", "", script, flags=re.DOTALL)
    return re.sub(r"(?m)^\s*//.*$|\s//\s.*$", "", without_blocks)


def keys(constant: str) -> set[str]:
    """The keys of review.js's object ``constant``, one per line."""
    code = code_of(read("review.js"))
    block = code[code.index(f"const {constant} = {{") :]
    return set(re.findall(r"^\s+([a-z_]+):", block[: block.index("};")], flags=re.M))


def reads(function: str, name: str) -> set[str]:
    """The fields review.js's ``function`` reads of ``name`` (``name.field``): the drift checks
    against what the vault sends, here and in tests/portal (M7 K.4)."""
    code = code_of(read("review.js"))
    start = code.index(f"function {function}(")
    found = set(re.findall(rf"\b{name}\.([a-z_]+)", code[start : code.index("\n  }\n", start)]))
    assert found, (function, name)
    return found


# --- index.html ---------------------------------------------------------------------------------


class Page(HTMLParser):
    """What K.4 checks of an HTML file: its tags, their attributes and any inline script."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.problems: list[str] = []
        self.assets: list[str] = []
        self.ids: set[str] = set()
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in FORBIDDEN_TAGS:
            self.problems.append(f"<{tag}>")
        if tag == "meta" and any(name == "http-equiv" for name, _ in attrs):
            self.problems.append("<meta http-equiv>")  # the CSP is a header, never a <meta>
        for name, value in attrs:
            if name.startswith("on") or name in ("style", "srcdoc", "formaction"):
                self.problems.append(f"{tag}[{name}]")
            if name == "id" and value:
                self.ids.add(value)
            if name in ("href", "src", "action", "poster", "data") and value is not None:
                if ABSOLUTE_URL.search(value) or ":" in value:
                    self.problems.append(f"absolute URL {value}")
                self.assets.append(value)
        if tag == "script":
            if not dict(attrs).get("src"):
                self.problems.append("a <script> without src")
            self._in_script = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if self._in_script and data.strip():
            self.problems.append("an inline <script> body")


def parsed(html: str) -> Page:
    page = Page()
    page.feed(html)
    page.close()
    return page


def test_the_html_checker_catches_what_it_is_for() -> None:
    hostile = [
        f"{LT}script{GT}alert(1){LT}/script{GT}",
        f"{LT}p onclick={QUOTE}x(){QUOTE}{GT}",
        f"{LT}p style={QUOTE}color:red{QUOTE}{GT}",
        f"{LT}style{GT}p{{}}{LT}/style{GT}",
        f"{LT}form{GT}",
        f"{LT}iframe srcdoc={QUOTE}x{QUOTE}{GT}",
        f"{LT}base href={QUOTE}/{QUOTE}{GT}",
        f"{LT}object data={QUOTE}x{QUOTE}{GT}",
        f"{LT}a href={QUOTE}https://evil.example/{QUOTE}{GT}",
        f"{LT}a href={QUOTE}//evil.example/{QUOTE}{GT}",
        f"{LT}a href={QUOTE}javascript:x(){QUOTE}{GT}",
        f"{LT}img src={QUOTE}data:image/png,x{QUOTE}{GT}",
        f"{LT}meta http-equiv={QUOTE}Content-Security-Policy{QUOTE}{GT}",
    ]
    for html in hostile:
        assert parsed(html).problems, html


def test_index_html() -> None:
    page = parsed(read("index.html"))
    assert page.problems == []
    # Every asset it loads is in the static map, and it loads every script, the stylesheets and
    # the icon.
    assert sorted(page.assets) == [
        "/app.css",
        "/app.js",
        "/approvals.js",
        "/drift.js",
        "/policy.js",
        "/review.js",
        "/tokens.css",
        "/webauthn.js",
        "/zoey-icon.svg",
        "/zoey-icon.svg",
        "/zoey-icon.svg",
        "/zoey.css",
    ]
    assert set(page.assets) <= set(STATIC)
    sheets = re.findall(r'<link rel="stylesheet" href="([^"]+)">', read("index.html"))
    assert sheets == ["/tokens.css", "/zoey.css", "/app.css"]  # tokens, components, the portal's


@pytest.mark.parametrize("name", ["callback-received.html", "callback-refused.html"])
def test_the_callback_pages_run_no_script(name: str) -> None:
    """C.7, K.4: where the callback sends the tab, and the page a refusal answers in place.
    Fixed bytes with no script at all and no text from the query, the flow or the provider, so
    P14 holds without escaping; they load only the stylesheets and the icon."""
    html = read(name)
    page = parsed(html)
    assert page.problems == []
    assert page.assets == [
        "/zoey-icon.svg",
        "/tokens.css",
        "/zoey.css",
        "/app.css",
        "/zoey-icon.svg",
    ]
    assert "<script" not in html.lower()
    path = "/callback/" + name.removeprefix("callback-").removesuffix(".html")
    assert STATIC[path].name == name


def test_the_refused_page_says_what_the_catalogue_says() -> None:
    """One page for every refusal of the callback, never naming the cause (M.2): its sentence
    is the catalogue's, so operations.md's table and the page agree."""
    text = CATALOGUE["callback_not_taken"].text
    assert {CATALOGUE[r].text for r in ("not_navigation", "bad_query")} == {text}
    assert f"<p>{text}</p>" in read("callback-refused.html")
    assert text not in read("callback-received.html")


@pytest.mark.parametrize("name", ["app.js", "review.js", "drift.js", "policy.js", "approvals.js"])
def test_every_element_the_script_names_exists(name: str) -> None:
    ids = parsed(read("index.html")).ids
    script = read(name)
    named = set(re.findall(r"\$\(\"([a-z-]+)\"\)", script))
    named |= set(re.findall(r"renderSummary\(\"([a-z-]+)\"", script))
    named |= set(re.findall(r"on\(\"([a-z-]+)\"", script))
    for listed in re.findall(r"PAGES = \[([^\]]*)\]|SETUP_STEPS = \[([^\]]*)\]", script):
        named |= set(re.findall(r"\"([a-z-]+)\"", "".join(listed)))
    assert named
    assert named <= ids, sorted(named - ids)


# --- the scripts and the stylesheet (K.2, C.4) --------------------------------------------------


def sinks_in(text: str) -> list[str]:
    return [pattern for pattern in SINKS if re.search(pattern, text)]


def test_the_sink_checker_catches_what_it_is_for() -> None:
    hostile = [
        "el.innerHTML = x",
        "el.outerHTML = x",
        "el.insertAdjacentHTML('beforeend', x)",
        "document.write(x)",
        "eval(x)",
        "new Function(x)",
        'setTimeout("x()", 1)',
        "frame.srcdoc = x",
        "a.href = 'javascript:x'",
        "img.src = 'data:x'",
        "localStorage.setItem('k', v)",
        "document.cookie = x",
        "el.style.color = 'red'",
        "el.setAttribute('onclick', x)",
        "el.onclick = f",
        "window.open(u)",
    ]
    for line in hostile:
        assert sinks_in(line), line
    assert sinks_in("{ kind: kind, data: data }") == []
    assert ABSOLUTE_URL.search("fetch('https://evil.example/x')")
    assert ABSOLUTE_URL.search("fetch('//evil.example/x')")
    assert not ABSOLUTE_URL.search('fetch("/api/session")')


def css_urls_outside_the_map(css: str) -> list[str]:
    """Each url() in the stylesheet that isn't a quoted path the static map serves."""
    found = []
    for inner in CSS_URL.findall(css):
        path = inner.strip()
        if not (len(path) > 2 and path[0] == path[-1] == QUOTE and path[1:-1] in STATIC):
            found.append(inner)
    return found


def test_the_css_url_checker_catches_what_it_is_for() -> None:
    hostile = [
        "src: url(https://fonts.example/x.woff2)",
        "src: url(//fonts.example/x.woff2)",
        f"src: url({QUOTE}/x.woff2{QUOTE})",
        "src: url(/Manrope-Variable.woff2)",  # unquoted
        f"src: url( {QUOTE}data:font/woff2,x{QUOTE} )",
    ]
    for css in hostile:
        assert css_urls_outside_the_map(css), css
    assert css_urls_outside_the_map(f"src: url({QUOTE}/Manrope-Variable.woff2{QUOTE})") == []


def test_the_fonts_are_the_packages_own() -> None:
    """The fonts are self-hosted (owner): tokens.css names each font file the map serves, and no
    stylesheet loads anything but a font file."""
    fonts = {path for path, file in STATIC.items() if file.content_type == WOFF2}
    assert len(fonts) == 3
    urls = {name: CSS_URL.findall(read(name)) for name in STYLESHEETS}
    assert {inner.strip(QUOTE) for inner in urls["tokens.css"]} == fonts
    assert all(urls[name] == [] for name in STYLESHEETS if name != "tokens.css")
    licenses = STATIC_DIR.parent / "licenses"
    assert sorted(path.name for path in licenses.iterdir()) == [
        "OFL-IBM-Plex-Mono.txt",
        "OFL-Manrope.txt",
    ]
    for path in licenses.iterdir():
        assert "SIL Open Font License, Version 1.1" in path.read_text(encoding="utf-8")


def docs_ref() -> str:
    """The ref the help's links read the docs at: the release's tag, or dev's branch while the
    version is a development one (UX pass, owner: GitHub's docs at the release tag)."""
    return "dev" if ".dev" in __version__ else f"v{__version__}"


def github_anchor(heading: str) -> str:
    """GitHub's anchor for a Markdown heading: lower case, punctuation but hyphens dropped,
    spaces as hyphens."""
    text = heading.lstrip("#").strip().lower()
    return re.sub(r"[^\w\- ]", "", text).replace(" ", "-")


@pytest.mark.parametrize("name", [*SCRIPTS, *STYLESHEETS])
def test_no_sink_and_no_absolute_url(name: str) -> None:
    text = read(name)
    code = code_of(text) if name.endswith(".js") else text
    assert sinks_in(code) == []
    # The https check of the authorization link (C.4) compares the protocol only, so the page
    # holds no absolute URL but the help's: app.js's DOCS, the docs at this release (UX pass).
    if name == "app.js":
        docs = f'  const DOCS = "https://github.com/RyanLeeUPC/ZoeyMCP/blob/{docs_ref()}/docs/";\n'
        assert code.count(docs) == 1
        code = code.replace(docs, "")
    assert ABSOLUTE_URL.findall(code) == []
    if name.endswith(".css"):
        assert "@import" not in text
        assert css_urls_outside_the_map(text) == []


def test_the_scripts_are_small_strict_and_hand_written() -> None:
    capped = [name for group in LINE_CAPS for name in group]
    assert sorted(capped) == sorted(SCRIPTS)  # every script has one cap, and only scripts do
    for group, cap in LINE_CAPS.items():
        lines = sum(len(read(name).splitlines()) for name in group)
        assert lines < cap, group
    total = sum((STATIC_DIR / file.name).stat().st_size for file in STATIC.values())
    assert total <= MAX_ASSETS
    for name in SCRIPTS:
        assert '"use strict";' in read(name)
        assert "import " not in code_of(read(name))  # no module, no dependency


def test_the_scripts_are_derived_from_the_static_map() -> None:
    """M7 K.4: SCRIPTS is every text/javascript file the map serves, and index.html loads each
    of them, review.js, drift.js and policy.js (M6 M.4) and approvals.js (M8 H.1) after the
    app.js whose helpers they use."""
    assert SCRIPTS == (
        "app.js",
        "webauthn.js",
        "review.js",
        "drift.js",
        "policy.js",
        "approvals.js",
    )
    order = re.findall(r'<script src="/([a-z]+\.js)" defer></script>', read("index.html"))
    assert order == ["webauthn.js", "app.js", "review.js", "drift.js", "policy.js", "approvals.js"]


def test_every_button_runs_its_handler_once_at_a_time() -> None:
    """A double click sent two logouts in one manual check: every click handler goes through
    guard(), which ignores a click while the last one's handler is pending and disables the
    button meanwhile, re-enabling it in a finally."""
    code = code_of(read("app.js"))
    # The one click binding is guard()'s; on() and button() both use guard().
    assert code.count('addEventListener("click"') == 1
    start = code.index("function guard(element, handler) {")
    end = code.index("\n  }\n", start)
    body = code[start:end]
    assert body.index('addEventListener("click"') < body.index("if (busy) {")
    for step in (
        "if (busy) {\n        return;\n      }",
        "busy = true;",
        "element.disabled = true;",
        "await handler(event);",
        "} finally {",
        "busy = false;\n        element.disabled = false;",
    ):
        assert step in body, step
    assert body.index("element.disabled = true;") < body.index("await handler(event);")
    assert body.index("await handler(event);") < body.index("} finally {")
    assert re.search(r"function on\(id, handler\) \{\s*guard\(\$\(id\), handler\);\s*\}", code)
    assert re.search(
        r"function button\(label, handler, kind\) \{[^}]*guard\(element, handler\);", code
    )
    # The others are the dialogs' Escape, which no click can repeat, and the connect dialog's
    # poll when the tab is shown again (C.4), which sends nothing while one is in flight.
    assert re.findall(r"addEventListener\(\"(\w+)\"", code) == [
        "click",
        "cancel",
        "visibilitychange",
    ]


class Anchors(HTMLParser):
    """Every <a>'s attributes, by its id (or its place, for one without)."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: dict[str, dict[str, str | None]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        found = dict(attrs)
        if tag == "a":
            self.anchors[str(found.get("id") or f"anchor {len(self.anchors)}")] = found


def test_the_authorization_link_opens_alone() -> None:
    """C.4, O.6 item 9: the provider's sign-in page opens from a link to a new tab with no
    opener and no referrer; the page sets its address by property, and only to an https URL
    the vault sent, never through a redirect or window.open."""
    parser = Anchors()
    parser.feed(read("index.html"))
    assert parser.anchors.pop("connect-link") == {
        "id": "connect-link",
        "class": "z-link z-link--external",
        "target": "_blank",
        "rel": "noopener noreferrer",
    }
    code = code_of(read("app.js"))
    check = code.index('const https = new URL(started.authorize_url).protocol === "https:";')
    assigned = code.index('$("connect-link").href = https ? started.authorize_url : "";')
    assert check < assigned
    # The rest are the help's Learn more links: a new tab with no opener and no referrer, and an
    # address app.js makes from DOCS and the section the link names, which docs/ has.
    assert len(parser.anchors) > 5
    for anchor in parser.anchors.values():
        assert (anchor["target"], anchor["rel"]) == ("_blank", "noopener noreferrer"), anchor
        assert "href" not in anchor
        doc, section = str(anchor["data-doc"]).split("#")
        headings = (DOCS_DIR / doc).read_text(encoding="utf-8").splitlines()
        assert section in {github_anchor(h) for h in headings if h.startswith("#")}, section
    assert code.count(".href =") == 2
    assert "link.href = DOCS + link.dataset.doc;" in code


class Inputs(HTMLParser):
    """Every <input>'s and <textarea>'s attributes, by its id, with the tag as "tag"."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.inputs: dict[str, dict[str, str | None]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        found = dict(attrs)
        if tag in ("input", "textarea") and found.get("id"):
            self.inputs[str(found["id"])] = {**found, "tag": tag}


def test_a_secret_value_is_write_only_in_the_page() -> None:
    """G, P1: the value field is a text area, masked by the stylesheet where the browser can,
    because Chrome offered to save a password field's value despite autocomplete="off" (manual
    check 15) and password managers don't save or fill a text area. It is read once, into the
    prepare's body, and emptied as soon as that request is made; the page never writes anything
    else into it, and leaving the Secrets page empties it too."""
    parser = Inputs()
    parser.feed(read("index.html"))
    value = parser.inputs["secret-value"]
    assert (value["tag"], value["autocomplete"]) == ("textarea", "off")
    assert "type" not in value
    assert "name" not in value  # nothing a form or a password manager keys on
    for attribute, wanted in (
        ("spellcheck", "false"),
        ("autocapitalize", "off"),
        ("autocorrect", "off"),
    ):
        assert value[attribute] == wanted, attribute
    for hint in ("data-1p-ignore", "data-lpignore", "data-bwignore"):
        assert hint in value, hint  # 1Password, LastPass and Bitwarden leave it alone
    assert "masked" in str(value["class"]).split()
    css = read("app.css")
    masked = css[css.index("textarea.masked {") : css.index("}", css.index("textarea.masked {"))]
    assert "-webkit-text-security: disc;" in masked
    for field in ("secret-name", "secret-origins"):
        assert parser.inputs[field]["type"] == "text", field
    code = code_of(read("app.js"))
    field = '$("secret-value").value'
    assert code.count(field) == 4
    assert re.findall(re.escape(field) + r" = (.*);", code) == ['""', '""', '""']
    start = code.index("async function prepareSecret() {")
    body = code[start : code.index("\n  }\n", start)]
    sent = body.index('prepare(\n      "secret.put",')
    assert sent < body.index(f"value: {field}") < body.index(f'{field} = "";')
    assert body.index(f'{field} = "";') < body.index("await sent;")
    assert re.search(r'if \(page !== "secrets"\) \{\s*\$\("secret-value"\)\.value = "";', code)
    # Nothing the vault answers is put back into a field: the list shows names and metadata.
    assert "secret.value" not in code


def test_session_storage_holds_one_key() -> None:
    """The header half under one key; no other storage, no cookie access from script (K.2)."""
    uses = STORAGE.findall(code_of(read("app.js")))
    assert uses
    for method, argument in uses:
        assert method in ("getItem", "setItem", "removeItem", "clear"), method
        if method != "clear":
            assert argument.split(",")[0].strip() == "TOKEN"
    assert 'const TOKEN = "session";' in read("app.js")
    for name in SCRIPTS:
        assert name == "app.js" or "sessionStorage" not in read(name), name


def test_every_fetch_is_same_origin_with_no_redirect_and_no_cache() -> None:
    """C.4: one fetch() in the page, with these options, and the session's header half; the
    other scripts call the API through it (review.js through window.zoeyPortal, M7 K.4)."""
    code = code_of(read("app.js"))
    assert code.count("fetch(") == 1
    for option in ('credentials: "same-origin"', 'redirect: "error"', 'cache: "no-store"'):
        assert option in code
    assert 'const HEADER = "X-ZoeyMCP-Session";' in code
    assert "headers[HEADER] = saved" in code
    for name in SCRIPTS:
        assert name == "app.js" or "fetch(" not in code_of(read(name)), name


def test_the_prompts_and_the_load_checks() -> None:
    """K.2: create() and get() only in webauthn.js; at load, the four checks in order."""
    app = code_of(read("app.js"))
    webauthn = code_of(read("webauthn.js"))
    assert "navigator.credentials" not in app
    assert "navigator.credentials" not in code_of(read("review.js"))
    assert webauthn.count("navigator.credentials.create(") == 1
    assert webauthn.count("navigator.credentials.get(") == 1
    order = [
        app.index("ip_literal"),
        app.index("isSecureContext"),
        webauthn.index("window.PublicKeyCredential"),
        webauthn.index('"getPublicKey" in AuthenticatorAttestationResponse.prototype'),
    ]
    assert order[0] < order[1]
    assert order[2] < order[3]
    assert app.index("blocked()") < app.index('on("login-passkey"')


# --- drift against the server (K.4) -------------------------------------------------------------


def test_every_api_path_the_script_names_is_a_route_and_every_route_is_named() -> None:
    """Across the scripts, M7 K.2's routes included (review.js names them)."""
    named: set[tuple[str, str]] = set()
    for name in SCRIPTS:
        code = code_of(read(name))
        named |= set(API_CALL.findall(code))
        # Every /api/ string is in a call this pattern sees, so none hides from the check.
        assert len(API_PATH.findall(code)) == len(API_CALL.findall(code)), name
    assert named == {(route.method, route.path) for route in ROUTES}


def test_every_reason_the_script_handles_is_catalogued() -> None:
    handled = {reason for name in SCRIPTS for reason in HANDLED.findall(code_of(read(name)))}
    assert handled
    assert handled <= reasons()
    for entry in CATALOGUE.values():
        assert entry.text.strip()
    assert all(text.strip() for text in WEBAUTHN.values())


def test_every_webauthn_field_the_server_requires_is_posted() -> None:
    code = code_of(read("webauthn.js"))
    keys = set(re.findall(r"^\s*([a-z_]+):", code, flags=re.MULTILINE))
    assert keys >= REGISTRATION_FIELDS
    assert keys >= ASSERTION_FIELDS
    # The option fields the vault sends in base64url, each turned into an ArrayBuffer.
    for field in ("options.challenge", "options.user.id", "descriptor.id"):
        assert f"fromBase64url({field})" in code


def test_the_browsers_own_refusals_are_worded_in_the_page() -> None:
    """M.2: an IP literal, not a secure context, no WebAuthn, and the four prompt errors."""
    app = read("app.js")
    for name in (
        "ip_literal",
        "insecure",
        "no_webauthn",
        "no_get_public_key",
        "NotAllowedError",
        "InvalidStateError",
        "SecurityError",
        "NotSupportedError",
    ):
        assert re.search(rf"^\s*{name}:", app, flags=re.MULTILINE), name
    assert {"no_webauthn", "no_get_public_key"} <= set(
        re.findall(r"\"(no_[a-z_]+)\"", read("webauthn.js"))
    )


# --- the MCP servers section (M7 K.1, K.4, K.5, M.7) ---------------------------------------------


def test_review_js_clicks_go_through_app_js_guard() -> None:
    """Every click in review.js goes through app.js's guard(): its buttons are button() and on(),
    shared through window.zoeyPortal, and its own listeners are for changes and typing only."""
    code = code_of(read("review.js"))
    assert 'addEventListener("click"' not in code
    assert set(re.findall(r"addEventListener\(\"(\w+)\"", code)) == {"change", "input"}
    assert "function button(" not in code
    assert "function guard(" not in code
    app = code_of(read("app.js"))
    shared = re.search(r"window\.zoeyPortal = Object\.freeze\(\{([^}]*)\}\);", app)
    assert shared
    exported = {word.strip() for word in shared.group(1).split(",")}
    taken = re.search(r"const \{([^}]*)\} = window\.zoeyPortal;", code)
    assert taken
    assert {word.strip() for word in taken.group(1).split(",")} == exported
    for helper in exported:
        assert re.search(rf"function {helper}\(|const {helper} = \(", app), helper
    # The one call app.js makes into review.js: a server row's Connect, once it completes.
    assert re.findall(r"window\.zoeyReview\.(\w+)\(", app) == ["connected"]
    assert (
        "window.zoeyReview = Object.freeze({ connected: connected, stepText: stepText });" in code
    )
    # drift.js words a managed save's next steps as review.js words every one (M.7, J15).
    drift = code_of(read("drift.js"))
    assert re.findall(r"window\.zoeyReview\.(\w+)\(", drift) == ["stepText"]
    # And into drift.js (M6 M.4, Q14): Home's hook in enter(), after the checklist, and a gateway
    # finding's Review.
    assert re.findall(r"window\.zoeyDrift\.(\w+)\(", app) == ["home", "review"]
    assert "if (window.zoeyDrift) await window.zoeyDrift.home();" in app
    enter = app[app.index("async function enter() {") :]
    enter = enter[: enter.index("\n  }\n")]
    assert enter.index('renderFindings($("checklist")') < enter.index("zoeyDrift.home()")
    assert enter.index("zoeyDrift.home()") < enter.index('show("home");')
    # review.js's hooks into drift.js (M6 J.2, M.4): the servers rows, what a registration's
    # confirm does next (managed mode's save, step 15c), the review's footer, a tool's row, and
    # the lists Generate sends; each read when called, since drift.js loads after.
    assert re.findall(r"window\.zoeyDrift\.(\w+)\(", code) == [
        "saveOnboarding",
        "servers",
        "registered",
        "footer",
        "row",
        "lists",
    ]
    # A managed onboarding's save is its first step's button on the row and on the plan alike
    # (step 15c): a given public client's plan has no other.
    assert (
        "save: context.boarding && (() => window.zoeyDrift.saveOnboarding(context.boarding)),"
        in code
    )


def test_a_client_secret_is_write_only_in_the_page() -> None:
    """K.1, G: the client secret of Add by URL is the Secrets page's kind of field, a masked text
    area no password manager keys on. It is read once, into onboard.register's prepare, and
    emptied as soon as that request is made; leaving the section empties it too."""
    parser = Inputs()
    parser.feed(read("index.html"))
    secret = parser.inputs["add-client-secret"]
    assert (secret["tag"], secret["autocomplete"]) == ("textarea", "off")
    assert "type" not in secret
    assert "name" not in secret
    for hint in ("data-1p-ignore", "data-lpignore", "data-bwignore"):
        assert hint in secret, hint
    assert "masked" in str(secret["class"]).split()
    field = '$("add-client-secret").value'
    code = code_of(read("review.js"))
    assert code.count(field) == 2
    start = code.index("async function prepareRegister(boarding) {")
    body = code[start : code.index("\n  }\n", start)]
    sent = body.index('prepare(\n      "onboard.register",')
    assert sent < body.index(f"client_secret: {field}") < body.index(f'{field} = "";')
    assert body.index(f'{field} = "";') < body.index("await sent;")
    app = code_of(read("app.js"))
    assert re.search(r'if \(page !== "servers"\) \{\s*\$\("add-client-secret"\)\.value = "";', app)
    assert app.count(field) == 1


def test_copy_puts_on_the_clipboard_the_text_shown() -> None:
    """K.4, 14b's acceptance: a fragment's shown text and the copied string are one value, the
    vault's YAML as it came, so a 2,048-character URL shows and copies the same."""
    code = code_of(read("review.js"))
    assert code.count("fragment = { yaml: answer.diff.yaml, again: again };") == 1
    assert re.findall(r'\$\("fragment-text"\)\.textContent = (.*);', code) == ["fragment.yaml"]
    assert re.findall(r"navigator\.clipboard\.writeText\((.*)\)", code) == ["fragment.yaml"]
    assert "yaml =" not in code


def test_the_page_words_every_row_state_and_where_every_command_runs() -> None:
    """K.1's row states are the vault's (vault/onboarding.py's and the portal's own onboarding
    rows'); M.7's next steps show every via, and the piped and redirect keys of J1's commands."""
    code = code_of(read("review.js"))
    # A server's states, and an onboarding's: each stage as the portal's row names it, in each
    # mode (managed mode's needs_save, M6 G.9).
    stages = typing.get_args(onboarding.Stage)
    states = {
        by_stage.get(stage, stage)
        for by_stage in portal_app.ROW_STATES.values()
        for stage in stages
    }
    assert {"needs_commit", "needs_save"} <= states
    assert keys("STATES") == set(typing.get_args(onboarding.RowState)) | states
    assert keys("VIA") == set(typing.get_args(onboarding.Via))
    assert "step.piped" in code
    assert '(step.redirect || "")' in code
    # The steps the page has a button for: M.7's, and the portal's own show_fragment.
    taken = keys("runs")
    assert taken <= set(typing.get_args(onboarding.Do)) | {portal_app.SHOW_FRAGMENT["do"]}
    assert portal_app.SHOW_FRAGMENT["do"] in taken
    assert {"register", "make_fragment", "connect", "review", "allow_hosts"} <= taken


def test_the_chips_read_the_vaults_flags() -> None:
    """K.1's chips keep the tools the counts count (D-188): the page reads each row's
    ``read_only_hint`` and ``annotated`` flags, never the suggestion or its reason, so a
    toolkit's unannotated consequential tool is a not-annotated one too."""
    code = code_of(read("review.js"))
    assert "UNANNOTATED" not in code
    assert "suggested_why ===" not in code
    assert '[$("review-chip-read-only").checked, (tool) => tool.read_only_hint],' in code
    assert '[$("review-chip-unannotated").checked, (tool) => !tool.annotated],' in code


def test_select_suggested_makes_no_move() -> None:
    """M6 J.3, Q27 (D-180): the three places review.js sets a tool's choice (a row drawn, a box
    ticked, Select suggested) each set it from the vault's ``tool.prefill``, and no code line
    sets a choice to a literal, so Select suggested, after Clear or not, never moves a tool from
    approve to allow (tests/portal's browser runs no script, so the page is pinned here)."""
    code = code_of(read("review.js"))
    assigned = re.findall(r"\bchoice\.value = (.*);", code)
    assert assigned == ["tool.prefill", "entry.tool.prefill", "entry.tool.prefill"]
    for function in ("toolEntry", "changed", "selectSuggested"):
        start = code.index(f"function {function}(")
        body = code[start : code.index("\n  }\n", start)]
        assert re.search(r"\bchoice\.value = (?:entry\.)?tool\.prefill;", body), function
    assert not re.search(r"\bchoice\.value = [\"'`]", code)
    drift = code_of(read("drift.js"))
    # drift.js sets a choice in two places only: accepting a proposed tool's new definition
    # chooses approve (Q8), and unticking it puts the vault's prefill back; and Allow without
    # asking moves the one tool whose button was pressed (J3, declarative), in move(), called for
    # that tool alone once the review of the job it queued draws: no bulk control moves a tool. In
    # managed mode it moves none on the screen: it opens that one tool's tool.allow dialog (J.4).
    assert re.findall(r"\bchoice\.value = (.*);", drift) == [
        "entry.repin.checked ? APPROVE : tool.prefill",
        "ALLOW",
    ]
    assert 'const APPROVE = "approve";' in drift
    assert 'const ALLOW = "allow";' in drift
    start = drift.index("function move(entry) {")
    assert "entry.choice.value = ALLOW;" in drift[start : drift.index("\n  }\n", start)]
    assert re.findall(r"\bmove\((.*)\);", drift) == [
        "held.entries.find((entry) => entry.tool.name === asked.named.name)",
    ]
    # The pending move is that job's alone: allow() drops any earlier one and keeps none when the
    # vault refused the review (queueReview answers its job, or nothing), and footer() moves only
    # on that job's review, so a refused, failed or replaced review leaves no move behind. In
    # managed mode a review the vault holds opens the dialog at once; else the review is fresh.
    start = drift.index("async function allow(server, named, queue) {")
    body = drift[start : drift.index("\n  }\n", start)]
    assert body.index("moving = null;") < body.index('await queue(server, mode === "managed");')
    held = 'if (mode === "managed" && named.held) {\n      return allowSaved(server, named);'
    assert held in body
    assert "if (job === undefined) {\n      return;" in body
    assert "drawn !== null && drawn.job === job" in body
    assert "const asked = { job: job, server: server, named: named };" in body
    assert "moving = asked;" in body
    assert "asked !== null && asked.job === held.job" in drift
    start = drift.index("function then(asked, held) {")
    body = drift[start : drift.index("\n  }\n", start)]
    assert body.index('if (mode === "managed") {') < body.index("return allowReviewed(asked);")
    assert "return pollReview().then(() => job.job);" in code_of(read("review.js"))
    assert "entry.tool.classification !== APPROVE || entry.tool.consequential === true" in drift


def test_a_registrations_notes_are_worded() -> None:
    """Step 11's notes on a registration's answer (``grant_types_absent``): one wording each."""
    assert keys("CLIENT_NOTES") == set(dcr.NOTES)
    assert "CLIENT_NOTES[note] || note" in code_of(read("review.js"))


def test_a_fragment_at_any_indent_the_routes_take() -> None:
    """K.1, OPS-2: a fragment again at an indent the fragment and diff routes take (0 to 16, or
    the compose form); fragment 1's last line shows under fragment 1 only."""
    page = read("index.html")
    select = page[page.index('<select id="fragment-indent" class="z-select z-select--small">') :]
    values = re.findall(r'<option value="([a-z0-9]+)">', select[: select.index("</select>")])
    assert (values[0], values[-1]) == ("0", "compose")
    assert len(values) > 2
    assert {int(value) for value in values[:-1]} <= set(range(INDENT_MAX + 1))
    code = code_of(read("review.js"))
    assert 'value === "compose" ? "compose" : Number(value)' in code
    assert '$("fragment-carries").hidden = title !== FIRST;' in code


def test_the_review_screen_reads_what_the_vault_sends() -> None:
    """J4 against F.6's rows for the large fake's 96 tools: every field review.js reads of the
    answer, its counts and a tool row is one the vault sends, and the chips keep the tools the
    counts count (64 suggested read-only, 32 not annotated, 4 with a warning; the one with an
    error finding is counted apart)."""
    view = reviewview.rows(held(large()))
    code = code_of(read("review.js"))
    assert set(re.findall(r"\btool\.([a-z_]+)", code)) <= {*view["tools"][0], "consequential"}
    # drift.js draws a row's drift columns and controls from the same row (M6 J.2), a toolkit
    # row's consequential flag among them (J3's move never takes such a tool); "tool.clear" is
    # the action it prepares, not a row's field.
    drift = code_of(read("drift.js"))
    fields = set(re.findall(r'(?<!")\btool\.([a-z_]+)', drift))
    assert fields <= {*view["tools"][0], "consequential"}
    assert "tool.reviewed_lines" in drift
    assert "if (tool.proposed) {" in drift  # Q8's proposal is the vault's flag, not the page's
    # What the gateway reports of a server sits above its row's steps, Review among them, and
    # Clear the marks with it when a tool is marked (M6 J.4).
    assert 'const steps = list.children[index].querySelector("ul.steps");' in drift
    assert 'steps.before(make("p", "The gateway reports: " +' in drift
    assert "steps.before(button(ACTION_TEXT.clear, () => clear(row.server, () => queue(" in drift
    assert set(re.findall(r"\bcounts\.([a-z_]+)", code)) == set(view["counts"])
    assert reads("renderReview", "answer") <= set(view)
    tools = view["tools"]
    found = {key for tool in tools for finding in tool["findings"] for key in finding}
    assert reads("toolEntry", "finding") <= found == {"level", "pointer_shown", "message_shown"}
    assert "(tool) => tool.read_only_hint]" in code
    assert sum(tool["read_only_hint"] for tool in tools) == view["counts"]["read_only"]
    assert "(tool) => !tool.annotated]" in code
    unannotated = [tool for tool in tools if not tool["annotated"]]
    assert len(unannotated) == view["counts"]["not_annotated"]
    assert '(tool) => tool.findings.some((found) => found.level === "warning")]' in code
    warned = [tool for tool in tools if any(f["level"] == "warning" for f in tool["findings"])]
    assert len(warned) == view["counts"]["with_findings"]
    errors = [tool for tool in tools if any(f["level"] == "error" for f in tool["findings"])]
    assert len(errors) == view["counts"]["with_errors"] == 1


# --- Home's attention list (M6 M.4, M.7) ---------------------------------------------------------


def test_drift_js_clicks_go_through_app_js_guard() -> None:
    """drift.js draws its buttons with app.js's button(), shared through window.zoeyPortal, and
    listens for one thing only, the re-pin box of a proposed tool, which sets its row's choice
    and calls nothing (Q8); Clear the marks and Allow without asking are button()s too (M6
    J.4, J3), a clear through app.js's step-up (prepare); its one click handler of its own,
    Save, goes through app.js's on() (step 15a), and a managed save is prepared as each kind a
    draft can be, or as tool.allow from a server's row; it publishes window.zoeyDrift, frozen,
    and nothing else: Home's hooks (step 7) and review.js's (M6 J.2, step 8; a registration's
    confirm, step 15c). In managed mode an onboarding's Save is a draft's save, which review.js's
    runner calls from the row and the plan alike, and Give to clients is policy.js's, under every
    server's row, reviewed or not (step 15c)."""
    code = code_of(read("drift.js"))
    assert re.findall(r"(\S+)\.addEventListener\(", code) == ["entry.repin"]
    assert "onclick" not in code
    assert "onchange" not in code
    assert "function button(" not in code
    assert "function guard(" not in code
    taken = re.search(r"const \{([^}]*)\} = window\.zoeyPortal;", code)
    assert taken
    assert {word.strip() for word in taken.group(1).split(",")} == {
        "api",
        "fill",
        "afterFailure",
        "button",
        "prepare",
        "closeConfirm",
        "on",
    }
    assert re.findall(r"\bon\(\"([a-z-]+)\", (\w+)\)", code) == [("review-save", "save")]
    # Each new control is a button(): Clear the marks three times (Home's item through act(),
    # a server row, the review screen) and Allow without asking once per approve tool.
    assert re.findall(r'prepare\("([a-z.]+)"', code) == [
        "tool.clear",
        "policy.save",
        "tool.repin",
        "tool.allow",
        "tool.allow",
    ]
    assert code.count("button(ACTION_TEXT.clear, ") == 2
    assert 'button("Allow " + named.name_shown + " without asking",' in code
    # A clear job is read on a timer that runs a function, never a string (K.2).
    assert re.findall(r"setTimeout\((\w+)", code) == ["resolve"]
    assert re.findall(r"window\.(zoey\w+) =", code) == ["zoeyDrift"]
    shared = re.search(r"window\.zoeyDrift = Object\.freeze\(\{([^}]*)\}\);", code)
    assert shared
    members = [word.split(":")[0].strip() for word in shared.group(1).split(",") if word.strip()]
    assert members == [
        "home",
        "review",
        "servers",
        "row",
        "footer",
        "lists",
        "registered",
        "saveOnboarding",
    ]
    assert re.findall(r"window\.zoeyPolicy\.(\w+)\(", code) == ["give"]
    assert "await SAVES[draft.kind](draft, (done) => saved(savedText(done)));" in code
    start = code.index("async function servers(list, rows, queue) {")
    rows = code[start : code.index("\n  }\n", start)]
    assert 'if (mode === "managed" && typeof row.server === "string") {' in rows
    assert "saveOnboarding" not in rows
    assert '"reviewed"' not in rows
    for member in members:
        assert f"function {member}(" in code, member


def test_the_page_words_the_new_health_sections_and_the_review_action() -> None:
    """Q14: app.js's checklist words health's gateway and policy sections, else a finding would
    read "warning, undefined: ..."; a gateway finding's review action draws a button, and so does
    an attention item's in drift.js."""
    app = code_of(read("app.js"))
    section = app[app.index("const SECTION = {") :]
    section = section[: section.index("};")]
    assert 'gateway: "The gateway reports"' in section
    assert 'policy: "The policy"' in section
    texts = app[app.index("const ACTION_TEXT = {") :]
    assert 'review: "Review"' in texts[: texts.index("};")]
    runs = app[app.index("const runs = {") :]
    assert "review: () => window.zoeyDrift.review(action.server)," in runs[: runs.index("};")]
    drift = code_of(read("drift.js"))
    assert 'const ACTION_TEXT = { review: "Review", clear: "Clear the marks" };' in drift
    assert "act(item.action, home)" in drift
    # Each item is shown through textContent, from the vault's text_shown alone, and every field
    # the script reads of the answer and its items is one the vault sends: the list's by
    # drift.js, shown by the vault's rule (M8 CR-11), and the queue's own item by approvals.js.
    assert 'entry.textContent = item.text_shown + ". ";' in drift
    assert '$("attention-block").hidden = !answer.shown;' in drift
    sent = set(portal_app.attention_items({}))
    assert set(re.findall(r"\banswer\.([a-z_]+)", drift)) == sent - {"gateway", "approvals"}
    report = {"gateway": {"reported_ago": 1, "servers": [gateway_row()]}}
    [item] = portal_app.attention_items(report)["items"]
    assert set(re.findall(r"\bitem\.([a-z_]+)", drift)) == {"text_shown", "action"}
    # Home's button by the action's kind; the MCP servers rows take each server's items.
    assert re.findall(r"\bitem\.action\.([a-z_]+)", drift) == ["kind", "server"]
    assert item["action"] == {"kind": "review", "server": "notes"}
    assert set(item) == {"kind", "subject", "server_shown", "count", "text_shown", "action"}
    # A marked tool's one action is a clear of the server's marks (M6 J.4, J13), the only kind
    # besides review, and drift.js words both.
    marked = gateway_row()
    lists = ("drifted", "marked", "new", "changed_declined", "missing")
    marked["attention"] = {name: ["echo"] if name == "marked" else [] for name in lists}
    report = {"gateway": {"reported_ago": 1, "servers": [marked]}}
    [clear] = portal_app.attention_items(report)["items"]
    assert (clear["kind"], clear["action"]) == ("marked", {"kind": "clear", "server": "notes"})


def gateway_row() -> dict[str, object]:
    """A server row of health's gateway section with one tool nobody reviewed."""
    return {
        "name": "notes",
        "kind": "remote",
        "bridge": False,
        "state": ["ready"],
        "era": "modern",
        "attention": {
            "drifted": [],
            "marked": [],
            "new": ["purge"],
            "changed_declined": [],
            "missing": [],
        },
        "blocked": False,
        "invalid": [],
        "unnamed": 0,
    }


def test_record_the_rest_as_declined_is_ticked_by_default() -> None:
    """M6 J.3 (G-19): the review screen's box is on unless the operator unticks it, and drift.js
    reads it into the lists Generate sends."""
    parser = Inputs()
    parser.feed(read("index.html"))
    box = parser.inputs["review-decline-rest"]
    assert (box["type"], "checked" in box) == ("checkbox", True)
    assert 'decline_rest: $("review-decline-rest").checked' in code_of(read("drift.js"))


def test_a_confirms_values_keep_their_indentation() -> None:
    """M6 G.7 row 2: a definition's summary rows are its JSON lines, indented; the confirm draws
    each value as text in a ``dd``, which would collapse the leading spaces (manual item 20)."""
    css = read("app.css")
    start = css.index("#confirm-summary dd,\n#confirm-now dd {")
    assert "white-space: pre-wrap;" in css[start : css.index("}", start)]
    # A label wider than the dialog (the first row names a 71-character pin) wraps in a column
    # of at most 40%, so the values aren't squeezed to a character a line.
    start = css.index("\ndl {")
    assert (
        "grid-template-columns: fit-content(40%) minmax(0, 1fr);"
        in css[start : css.index("}", start)]
    )
    start = css.index("\ndt {")
    assert "overflow-wrap: anywhere;" in css[start : css.index("}", start)]
    assert "value.textContent = pair[1];" in code_of(read("app.js"))


def test_prompts_and_resources_are_rows_whose_choices_go_under_kinds() -> None:
    """M6 L.7 (BP-3): a server's prompts and resources are review.js's rows, drawn by its row
    renderer; drift.js's row hook draws the kind's heading over the first of each kind (the
    vault's ``heading``, as text) and takes away the classification, and the box is drift.js's
    alone, so review.js's lists stay the tools'; drift.js's lists() puts each kind's choices
    under ``kinds``, every kind shown named, and Generate and Save send what it holds; Clear
    unticks them too, and the footer counts only tools as tools."""
    drift = code_of(read("drift.js"))
    start = drift.index("function row(entry) {")
    body = drift[start : drift.index("\n  }\n", start)]
    head = body[: body.index('if (tool.state === "drift") {')]
    assert 'if (tool.kind !== "tool") {' in head
    assert 'place.prepend(...(tool.heading ? [make("h3", tool.heading)] : []));' in head
    removed = "[entry.choice?.nextSibling, entry.choice].forEach((node) => node?.remove());"
    taken = "[entry.pick, entry.box, entry.choice] = [entry.box, null, null];"
    assert head.index(removed) < head.index(taken)
    assert "if ((entry.box || entry.pick) && tool.pinnable && !tool.included) {" in body
    start = drift.index("function lists(held) {")
    lists = drift[start : drift.index("\n  }\n", start)]
    assert 'decline_rest: $("review-decline-rest").checked, kinds: {} };' in lists
    assert "found.kinds[entry.tool.kind] || { include: [], repin: [], decline: [] });" in lists
    assert lists.index("const into =") < lists.index("if (entry.pick && entry.pick.checked) {")
    assert "into.include.push(entry.tool.name);" in lists
    assert "into.repin.push(entry.tool.name);" in lists
    assert "into.decline.push(entry.tool.name);" in lists
    # Save posts every list picked() holds, each key named (test_portal_wire reads the body),
    # and approvals.js's held tools (M8 A.4; none in declarative mode, so the key isn't sent).
    assert "decline: c.decline, decline_rest: c.decline_rest, kinds: c.kinds });" in drift
    assert "repin: c.repin, held: vault," in drift
    assert "const c = picked(held), vault = window.zoeyApprovals?.held(held);" in drift
    # Clear unticks the kinds' boxes too (review.js's unticks the tools'), and the footer's
    # "tools changed" counts tools only.
    cleared = "drawn?.entries.forEach((e) => e.pick && (e.pick.checked = false)));"
    assert f'on("review-clear", () => {cleared}' in drift
    assert 'view.tools.filter((t) => t.kind === "tool" && t.state === "drift").length;' in drift
    review = code_of(read("review.js"))
    # And so does Generate.
    assert "decline_rest: lists.decline_rest,\n        kinds: lists.kinds });" in review
    # Save's held is managed mode's alone (M8 A.4): Generate sends none, so the fragment keeps
    # the policy's holds.
    optional = {"indent", "repin", "decline", "decline_rest", "kinds", "held"}
    assert set(REVIEW_DIFF.optional) == optional
    assert "held:" not in review
    assert "entry.pick" not in review


# --- the Policy page's managed half (M6 M.1, M.4, H.1-H.4; step 15b) -----------------------------


def test_policy_js_clicks_go_through_app_js_guard() -> None:
    """policy.js draws its buttons with app.js's button() and binds its two clicks through on():
    the Policy page's nav button, beside app.js's own, so the page's managed half draws as it
    opens, and Older revisions. It listens for nothing else, prepares policy.rollback, a
    connector's limits (twice: Pause or Resume, and Save limits) and client.servers (Give to
    clients, step 15c), publishes only Give to clients for drift.js, and words a next step and
    the export command as review.js does (M.7). Its clicks of its own are the nav buttons', after
    a rollback or a connector's save, so app.js's view and the history draw again at the new
    head, and after Give to clients, so the MCP servers rows do. Roll back is on every history
    entry but the head, so a revision
    whose changes can't be shown is still a target (D.8); a press first finds a head that moved
    since the page showed it, and draws the page again at the head now instead of preparing, and
    a refused prepare draws it again too, so pressing Roll back again plans on the head it finds
    (N.2's rollback wording). Give to clients plans on the revision the vault read the clients at,
    and a refused prepare draws its boxes again (G.10)."""
    code = code_of(read("policy.js"))
    assert "addEventListener(" not in code
    assert "function button(" not in code
    assert "function guard(" not in code
    taken = re.search(r"const \{([^}]*)\} = window\.zoeyPortal;", code)
    assert taken
    assert {word.strip() for word in taken.group(1).split(",")} == {
        "api",
        "fill",
        "afterFailure",
        "button",
        "prepare",
        "closeConfirm",
        "on",
    }
    assert re.findall(r"\bon\(\"([a-z-]+)\", ", code) == ["nav-policy", "policy-older"]
    assert re.findall(r'prepare\("([a-z.]+)"', code) == [
        "connector.limits",
        "connector.limits",
        "client.servers",
        "policy.rollback",
    ]
    assert re.findall(r"window\.(zoey\w+) =", code) == ["zoeyPolicy"]
    assert "window.zoeyPolicy = Object.freeze({ give: give });" in code
    assert re.findall(r"window\.zoeyReview\.(\w+)\(", code) == ["stepText"] * 3
    assert re.findall(r"\$\(\"([a-z-]+)\"\)\.click\(\)", code) == [
        "nav-policy",
        "nav-servers",
        "nav-policy",
    ]
    # A connector's save, like a rollback, is planned on the head the page showed: a head that
    # moved draws the page again first, and so does a refused prepare (G.3, N.2).
    start = code.index("async function limits(head, ask) {")
    body = code[start : code.index("\n  }\n", start)]
    asked = body.index('now = await api("GET", "/api/policy/revisions" + ONE)')
    assert asked < body.index("if (now.head !== head) {") < body.index("return draw();")
    assert body.index("return draw();") < body.index("await ask(") < body.index('$("confirm")')
    start = code.index("async function rollback(target, head) {")
    body = code[start : code.index("\n  }\n", start)]
    assert body.index("closeConfirm();") < body.index('$("nav-policy").click();')
    # A rollback is planned on the head the page showed, never on whatever the head is now.
    assert 'prepare("policy.rollback", { base: head, revision: target },' in body
    assert 'const ONE = "?limit=1";' in code
    asked = body.index('now = await api("GET", "/api/policy/revisions" + ONE);')
    moved = body.index("if (now.head !== head) {")
    assert asked < moved < body.index("return draw();") < body.index('prepare("policy.rollback"')
    assert body.index('prepare("policy.rollback"') < body.index('if (!$("confirm").open) {')
    assert body.rstrip().endswith("await draw();\n    }")
    start = code.index("function revision(entry, head) {")
    drawn = code[start : code.index("\n  }\n", start)]
    assert "if (entry.revision !== head) {" in drawn
    assert "() => rollback(entry.revision, head)));" in drawn
    # Give to clients: the boxes and the save's base are one answer's, never the head now.
    assert "each.box.checked !== each.client.servers.includes(server)), found.revision)));" in code
    assert "/api/session" not in code
    start = code.index("async function gave(server, block, changed, base) {")
    body = code[start : code.index("\n  }\n", start)]
    assert body.index('prepare("client.servers", { base: base,') < body.index('$("confirm")')
    assert body.rstrip().endswith("await give(server, block);\n    }")


def test_policy_js_reads_what_the_vault_sends() -> None:
    """H.1, H.2, M.1: every field policy.js reads of a history entry, a diff row and the
    answers is one the vault sends, and every kind a revision's header can name has its words."""
    code = code_of(read("policy.js"))
    kinds = code[code.index("const KIND_TEXT = {") :]
    kinds = kinds[: kinds.index("};")]
    assert set(re.findall(r'"([a-z._]+)":', kinds)) == set(typing.get_args(WriteKind))
    states = code[code.index("const GATEWAY_TEXT = {") :]
    states = states[: states.index("};")]
    assert set(re.findall(r"^\s+([a-z]+):", states, flags=re.M)) == {
        "applied",
        "pending",
        "unknown",
    }
    header = {
        "revision": 3,
        "created": 1_700_000_000,
        "origin": "rollback",
        "kind": "policy.rollback",
        "author": {"by": "passkey", "fingerprint": "ab" * 16},
        "base": 2,
        "target": 1,
        "jumped_from": None,
        "reason": None,
    }
    entry = portal_app._history_view(header)
    gap = portal_app._history_view({"revision": 2, "gap": True})
    assert set(re.findall(r"\bentry\.([a-z_]+)", code)) <= set(entry) | set(gap)
    change = Change(
        ("gateway", "servers", "notes", "path"), "changed", "/a", "/b", "RemoteServer", "path"
    )
    [row] = policydiffview.rows([change])
    assert set(re.findall(r"\bchange\.([a-z_]+)", code)) <= set(row)
    # The view's managed fields, a history page's and a diff's (tests/portal pins each set).
    assert set(re.findall(r"\bview\.([a-z_]+)", code)) == {
        "mode",
        "revision",
        "not_running",
        "gateway",
        "export",
        "connectors",
    }
    # A connector's row reads the fields connectors_view sends, each limit by its name (G.3).
    sent = portal_app.connectors_view(
        Policy.model_validate({"version": 1, "mode": "managed", "connectors": {"mail": MAIL}})
    )
    # "connector.limits" is the action's kind, not a field.
    found = set(re.findall(r'(?<!")\bconnector\.([a-z_]+)', code))
    assert found == {"name", "name_shown", "paused"}
    assert found <= set(sent[0])
    limits = code[code.index("const LIMIT_TEXT = {") :]
    limits = limits[: limits.index("};")]
    assert set(re.findall(r"^\s+([a-z_]+):", limits, flags=re.M)) == set(CONNECTOR_LIMITS) - {
        "paused"
    }
    assert set(re.findall(r"\bpage\.([a-z_]+)", code)) == {"revisions", "head", "next"}
    assert set(re.findall(r"\bnow\.([a-z_]+)", code)) == {"head"}
    assert set(re.findall(r"\banswer\.([a-z_]+)", code)) == {"revision", "against", "rows", "head"}
    assert set(re.findall(r"\bgateway\.([a-z_]+)", code)) == {"state", "revision"}


def test_policy_js_shows_a_count_old_to_new() -> None:
    """H.2: recipients, shown as a count, send both counts with ``hidden`` set; a hidden field
    sends only its marker, as ``new``, and no ``old``. policy.js keys on whether ``old`` came,
    not on ``hidden``, so a changed count reads old -> new (a removed row with an ``old`` shows
    it, never "null"), and a hidden field only its marker."""
    code = code_of(read("policy.js"))
    start = code.index("function row(change) {")
    body = code[start : code.index("\n  }\n", start)]
    assert "const marked = change.hidden && change.old === null;" in body
    assert body.count("change.hidden") == 1
    assert "values = marked ? change.new : value(change.old);" in body
    assert 'change.op === "changed" && !marked' in body
    to = ("connectors", "mail-out", "to")
    token = ("gateway", "clients", "agent", "token_sha256")
    hashes = ("sha256:" + "1" * 64, "sha256:" + "2" * 64)
    rows = policydiffview.rows(
        [
            Change(
                to,
                "changed",
                ["a@mail.example"],
                ["a@mail.example", "b@mail.example"],
                "SMTPConnector",
                "to",
            ),
            Change(token, "changed", *hashes, "Client", "token_sha256"),
            Change(token, "removed", hashes[0], None, "Client", "token_sha256"),
        ]
    )
    assert [(row["hidden"], row["old"], row["new"]) for row in rows] == [
        (True, "(1 address)", "(2 addresses)"),
        (True, None, "(changed)"),
        (True, None, "(removed)"),
    ]


# --- the Approvals queue (M8 design H.1, BP-12, CR-11; step 15) -----------------------------------


def test_approvals_js_clicks_go_through_app_js_guard() -> None:
    """approvals.js draws its buttons with app.js's button() and binds its four through on()
    (the nav entry, Approve, Deny, Close); it listens for nothing else. Approve is its one
    prepare, approval.decide with the literal keys the kind takes, decision only ever approve;
    Deny is its one POST, the text's digest alone: no control decides more than one. Its timers
    run functions, and it publishes window.zoeyApprovals, frozen, with Home's hook alone."""
    code = code_of(read("approvals.js"))
    assert "addEventListener(" not in code
    assert "function button(" not in code
    assert "function guard(" not in code
    taken = re.search(r"const \{([^}]*)\} = window\.zoeyPortal;", code)
    assert taken
    assert {word.strip() for word in taken.group(1).split(",")} == {
        "api",
        "fill",
        "visit",
        "afterFailure",
        "button",
        "prepare",
        "closeConfirm",
        "on",
    }
    assert re.findall(r"\bon\(\"([a-z-]+)\", ", code) == [
        "nav-approvals",
        "approvals-approve",
        "approvals-deny",
        "approvals-close",
    ]
    assert re.findall(r'prepare\("([a-z._]+)"', code) == [
        "approval.decide",
        "tool.vault_approval_off",
        "tool.vault_approval_off",
        "policy.save",
        "policy.save",
    ]
    assert (
        '{ approval: held.approval, text_sha256: held.text_sha256, decision: "approve" },' in code
    )
    assert re.findall(r'api\("POST", fill\("([^"]+)"', code) == ["/api/approvals/{approval}/deny"]
    assert code.count('api("POST"') == 1
    assert "{ text_sha256: held.text_sha256 });" in code
    assert re.findall(r"setInterval\((\w+), (\w+)\)", code) == [
        ("tickLists", "LISTS_EVERY"),
        ("tickCount", "COUNT_EVERY"),
    ]
    assert "const LISTS_EVERY = 5000;" in code
    assert "const COUNT_EVERY = 10000;" in code
    assert re.findall(r"window\.(zoey\w+) =", code) == ["zoeyApprovals"]
    assert (
        "window.zoeyApprovals = Object.freeze({ home: home, servers: servers, review: review,\n"
        "    held: heldNames });" in code
    )
    # The timers ask nothing before a full session's bar shows, and one ask at a time.
    start = code.index("async function quietly(work) {")
    body = code[start : code.index("\n  }\n", start)]
    assert "if (asking || !signedIn()) {" in body
    assert 'return !$("bar").hidden;' in code


def test_hold_in_the_vault_is_two_literal_forms_and_review_hooks() -> None:
    """M8 A.4 (step 18): a server row's Hold in the vault is a policy.save and Turn off vault
    approval tool.vault_approval_off, each prepared with one of the two forms' literal keys
    (``actions.VAULT_OFF_FORMS``); holding is disabled with no approver, with the design's line.
    review.js calls the two hooks once each, after drift.js's (its rows, its footer)."""
    code = code_of(read("approvals.js"))
    for kind in ("tool.vault_approval_off", "policy.save"):
        made = f'await prepare("{kind}", {{ base: base, '
        assert made + "connector: data.connector }, done);" in code
        assert made + "server: data.server," in code
    assert "control.disabled = !held && !listed.approver;" in code
    assert "entry.hold.disabled = !entry.hold.checked && !view.approver;" in code
    assert (
        'const NO_APPROVER = "Set up an approver first (Telegram or the Approvals queue): a host '
        'step, " +\n    "operations.md \\u00a736.2";' in code
    )
    review = code_of(read("review.js"))
    assert re.findall(r"window\.zoeyApprovals\?\.(\w+)\(", review) == ["servers", "review"]
    rows = review.index("await window.zoeyDrift.servers(list, rows, queueReview);")
    assert rows < review.index("window.zoeyApprovals?.servers(list, rows);")
    footer = review.index("window.zoeyDrift.footer(held, answer, queueReview);")
    assert footer < review.index("window.zoeyApprovals?.review(held, answer);")


def test_app_js_gains_the_nav_entry_and_one_call() -> None:
    """BP-12, Q19: app.js knows the Approvals page by name and calls Home's approvals hook once,
    after drift.js's list and before Home shows; everything else of the queue is approvals.js's."""
    app = code_of(read("app.js"))
    pages = app[app.index("const PAGES = [") :]
    assert '"approvals"' in pages[: pages.index("];")]
    assert re.findall(r"window\.zoeyApprovals\.(\w+)\(", app) == ["home"]
    assert "if (window.zoeyApprovals) await window.zoeyApprovals.home();" in app
    enter = app[app.index("async function enter() {") :]
    enter = enter[: enter.index("\n  }\n")]
    assert enter.index("zoeyDrift.home()") < enter.index("zoeyApprovals.home()")
    assert enter.index("zoeyApprovals.home()") < enter.index('show("home");')
    page = read("index.html")
    assert '<button type="button" id="nav-approvals" class="z-nav__item">Approvals</button>' in page


def test_approvals_js_reads_what_the_vault_sends() -> None:
    """H.1: every field approvals.js reads of a row, an opened hold, the lists' answer, the
    badge's and Home's item is one the vault sends; the text is drawn whole from its lines, as
    the vault split them, through textContent, and the decision sends the digest the vault sent
    (the page hashes nothing)."""
    code = code_of(read("approvals.js"))
    shown = approvalsview.detail(held_hold(), lambda at: at, lambda hold_id: True)
    sent = approvalsview.queue(
        [held_hold()],
        [closed_hold(2, "done", "portal", "ok")],
        lambda at: at,
        lambda hold_id: True,
        enabled=True,
        notice=None,
    )
    rows = set(sent["waiting"][0]) | set(sent["decided"][0])
    assert set(re.findall(r"\brow\.([a-z0-9_]+)", code)) <= rows
    assert set(re.findall(r"\bshown\.([a-z0-9_]+)", code)) <= set(shown)
    assert "text" not in re.findall(r"\bshown\.([a-z0-9_]+)", code)
    assert (
        '$("approvals-text").textContent =\n      shown.text_lines.map((line) => line.join(""))'
        '.join("\\n");' in code
    )
    assert "open = { approval: shown.approval, text_sha256: shown.text_sha256 };" in code
    assert "crypto" not in code
    answers = set(re.findall(r"\banswer\.([a-z0-9_]+)", code))
    item = approvals_item(1, 0.0)
    assert item is not None
    attention = set(portal_app.attention_items({}, item))
    assert answers <= set(sent) | attention | {"count"}
    assert "answer.approvals.text_shown" in code
    assert "ACTION_TEXT[answer.approvals.action.kind]" in code
    texts = code[code.index("const ACTION_TEXT = {") :]
    assert set(re.findall(r"(\w+):", texts[: texts.index("};")])) == {item["action"]["kind"]}
    assert '(await api("GET", "/api/approvals/count")).count' in code
    # The relay's badge, by the hold's kind, is the page's; the vault's line is in the text.
    assert "shown.kind !== RELAY" in code
    assert 'const RELAY = "relay";' in code
