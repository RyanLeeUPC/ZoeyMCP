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
from html.parser import HTMLParser
from pathlib import Path

import pytest

from zoeymcp.portal.refusals import CATALOGUE, WEBAUTHN, reasons
from zoeymcp.portal.routes import ROUTES, STATIC
from zoeymcp.portal.webauthn import ASSERTION_FIELDS, REGISTRATION_FIELDS

STATIC_DIR = Path(__file__).resolve().parents[2] / "src" / "zoeymcp" / "portal" / "static"
SCRIPTS = ("app.js", "webauthn.js")
MAX_ASSETS = 96 * 1024
# K.2 set 1,000 lines for app.js and webauthn.js together. Step 15's Ledger and Policy pages took
# them past it (998 before, 1,041 after) although every line they show is made by the server and
# the existing pages were folded onto one helper, so the cap moved by 50 lines rather than squeeze
# the script further.
MAX_SCRIPT_LINES = 1050

LT, GT, QUOTE = chr(0x3C), chr(0x3E), chr(0x22)
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
    # Every asset it loads is in the static map, and it loads both scripts and the stylesheet.
    assert sorted(page.assets) == ["/app.css", "/app.js", "/webauthn.js"]
    assert set(page.assets) <= set(STATIC)


@pytest.mark.parametrize("name", ["callback-received.html", "callback-refused.html"])
def test_the_callback_pages_run_no_script(name: str) -> None:
    """C.7, K.4: where the callback sends the tab, and the page a refusal answers in place.
    Fixed bytes with no script at all and no text from the query, the flow or the provider, so
    P14 holds without escaping; they load only the stylesheet."""
    html = read(name)
    page = parsed(html)
    assert page.problems == []
    assert page.assets == ["/app.css"]
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


def test_every_element_the_script_names_exists() -> None:
    ids = parsed(read("index.html")).ids
    named = set(re.findall(r"\$\(\"([a-z-]+)\"\)", read("app.js")))
    named |= set(re.findall(r"renderSummary\(\"([a-z-]+)\"", read("app.js")))
    named |= set(re.findall(r"on\(\"([a-z-]+)\"", read("app.js")))
    for listed in re.findall(r"PAGES = \[([^\]]*)\]|SETUP_STEPS = \[([^\]]*)\]", read("app.js")):
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


@pytest.mark.parametrize("name", [*SCRIPTS, "app.css"])
def test_no_sink_and_no_absolute_url(name: str) -> None:
    text = read(name)
    code = code_of(text) if name.endswith(".js") else text
    assert sinks_in(code) == []
    # The https check of the authorization link (C.4) compares the protocol only, so the page
    # holds no absolute URL at all.
    assert ABSOLUTE_URL.findall(code) == []
    if name.endswith(".css"):
        assert "@import" not in text
        assert "url(" not in text


def test_the_scripts_are_small_strict_and_hand_written() -> None:
    lines = sum(len(read(name).splitlines()) for name in SCRIPTS)
    assert lines < MAX_SCRIPT_LINES
    total = sum((STATIC_DIR / file.name).stat().st_size for file in STATIC.values())
    assert total <= MAX_ASSETS
    for name in SCRIPTS:
        assert '"use strict";' in read(name)
        assert "import " not in code_of(read(name))  # no module, no dependency


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
    assert re.search(r"function button\(label, handler\) \{[^}]*guard\(element, handler\);", code)
    # The others are the dialogs' Escape, which no click can repeat, and the connect dialog's
    # poll when the tab is shown again (C.4), which sends nothing while one is in flight.
    assert re.findall(r"addEventListener\(\"(\w+)\"", code) == [
        "click",
        "cancel",
        "visibilitychange",
    ]


class Anchors(HTMLParser):
    """Every <a>'s attributes, by its id."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.anchors: dict[str, dict[str, str | None]] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        found = dict(attrs)
        if tag == "a" and found.get("id"):
            self.anchors[str(found["id"])] = found


def test_the_authorization_link_opens_alone() -> None:
    """C.4, O.6 item 9: the provider's sign-in page opens from a link to a new tab with no
    opener and no referrer; the page sets its address by property, and only to an https URL
    the vault sent, never through a redirect or window.open."""
    parser = Anchors()
    parser.feed(read("index.html"))
    assert parser.anchors == {
        "connect-link": {
            "id": "connect-link",
            "target": "_blank",
            "rel": "noopener noreferrer",
        }
    }
    code = code_of(read("app.js"))
    check = code.index('const https = new URL(started.authorize_url).protocol === "https:";')
    assigned = code.index('$("connect-link").href = https ? started.authorize_url : "";')
    assert check < assigned
    assert code.count(".href =") == 1


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
    assert "sessionStorage" not in read("webauthn.js")


def test_every_fetch_is_same_origin_with_no_redirect_and_no_cache() -> None:
    """C.4: one fetch() in the page, with these options, and the session's header half."""
    code = code_of(read("app.js"))
    assert code.count("fetch(") == 1
    for option in ('credentials: "same-origin"', 'redirect: "error"', 'cache: "no-store"'):
        assert option in code
    assert 'const HEADER = "X-ZoeyMCP-Session";' in code
    assert "headers[HEADER] = saved" in code
    assert "fetch(" not in code_of(read("webauthn.js"))


def test_the_prompts_and_the_load_checks() -> None:
    """K.2: create() and get() only in webauthn.js; at load, the four checks in order."""
    app = code_of(read("app.js"))
    webauthn = code_of(read("webauthn.js"))
    assert "navigator.credentials" not in app
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
    code = code_of(read("app.js"))
    named = set(API_CALL.findall(code))
    # Every /api/ string is in a call this pattern sees, so none hides from the check.
    assert len(API_PATH.findall(code)) == len(API_CALL.findall(code))
    assert named == {(route.method, route.path) for route in ROUTES}


def test_every_reason_the_script_handles_is_catalogued() -> None:
    handled = set(HANDLED.findall(code_of(read("app.js"))))
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
