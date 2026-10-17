from __future__ import annotations

import re
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Any

import pytest

from zoeymcp.common.policy.schema import OAuth2Credential
from zoeymcp.vault.oauth import pkce
from zoeymcp.vault.oauth.pkce import (
    FLOW_TTL,
    MAX_FLOWS,
    Flow,
    FlowTable,
    Redirect,
    RedirectError,
    TooManyFlows,
    authorize_url,
    code_challenge,
    new_verifier,
    parse_redirect,
)
from zoeymcp.vault.store import Secret

REDIRECT = "http://127.0.0.1/callback"
STATE = "state-value-0123456789"
CODE = "code-value-1"


def cred(**fields: Any) -> OAuth2Credential:
    raw: dict[str, Any] = {
        "kind": "oauth2",
        "token_url": "https://accounts.example/oauth/token",
        "authorize_url": "https://accounts.example/authorize",
        "client_id": "app-1",
    }
    raw.update(fields)
    return OAuth2Credential.model_validate(raw)


def test_the_limits_are_pinned() -> None:
    assert FLOW_TTL == 600.0
    assert MAX_FLOWS == 8
    assert pkce.MAX_REDIRECT_QUERY == 4096
    assert pkce.MAX_DESCRIPTION == 200
    assert pkce.SECRET_BYTES == 32
    assert pkce.FLOW_ID_BYTES == 16


# --- verifier and challenge --------------------------------------------------------------------


def test_rfc_7636_appendix_b() -> None:
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert code_challenge(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


@pytest.mark.parametrize(
    "verifier",
    ["a" * 42, "a" * 129, "a" * 42 + "+", "a" * 42 + "/", "a" * 42 + "=", "a" * 42 + " ", ""],
)
def test_bad_verifiers_are_refused(verifier: str) -> None:
    with pytest.raises(ValueError, match=r"^a PKCE verifier is 43 to 128 unreserved characters$"):
        code_challenge(verifier)


@pytest.mark.parametrize("verifier", ["a" * 43, "a" * 128, "Az09-._~" * 6])
def test_good_verifiers(verifier: str) -> None:
    assert re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge(verifier))


def test_new_verifier() -> None:
    for _ in range(20):
        value = new_verifier().reveal()
        assert re.fullmatch(r"[A-Za-z0-9_-]{43}", value)
    sizes: list[int] = []

    def token(size: int) -> str:
        sizes.append(size)
        return "v" * 43

    assert new_verifier(token).reveal() == "v" * 43
    assert sizes == [32]
    with pytest.raises(ValueError, match=r"^a PKCE verifier is 43 to 128 unreserved characters$"):
        new_verifier(lambda size: "short")


def test_there_is_no_plain_method() -> None:
    text = Path(pkce.__file__ or "").read_text(encoding="utf-8")
    assert '"plain"' not in text
    assert "'plain'" not in text


# --- the authorization URL ---------------------------------------------------------------------


def test_authorize_url() -> None:
    credential = cred(
        scope="read write",
        authorize_params={
            "access_type": "offline",
            "prompt": "consent",
            "resource": ["https://a.example/", "https://b.example/"],
        },
    )
    url = authorize_url(credential, state=Secret(STATE), challenge="ch-1")
    assert url == (
        "https://accounts.example/authorize?response_type=code&client_id=app-1"
        "&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcallback&state=" + STATE + "&code_challenge=ch-1"
        "&code_challenge_method=S256&scope=read%20write&access_type=offline&prompt=consent"
        "&resource=https%3A%2F%2Fa.example%2F&resource=https%3A%2F%2Fb.example%2F"
    )


def test_authorize_url_without_scope() -> None:
    url = authorize_url(cred(), state=Secret(STATE), challenge="ch-1")
    assert url.endswith("&code_challenge=ch-1&code_challenge_method=S256")
    assert "scope" not in url


@pytest.mark.parametrize(
    ("credential", "message"),
    [
        (cred(authorize_url=None), "this credential has no authorize_url"),
        (cred(client_id="store:client-id"), "a client_id ref can't go in an authorization URL"),
        (cred(client_id="env:CLIENT_ID"), "a client_id ref can't go in an authorization URL"),
        (
            cred(authorize_params={"state": "x"}),
            "authorize_params can't set 'state'; the vault sets it",
        ),
        (
            cred(scope="a", authorize_params={"scope": "b"}),
            "authorize_params can't set 'scope'; the vault sets it",
        ),
        (
            cred(authorize_params={"code_challenge_method": "plain"}),
            "authorize_params can't set 'code_challenge_method'; the vault sets it",
        ),
    ],
)
def test_authorize_url_refuses(credential: OAuth2Credential, message: str) -> None:
    with pytest.raises(ValueError, match=f"^{message}$"):
        authorize_url(credential, state=Secret(STATE), challenge="ch-1")


# --- the redirect ------------------------------------------------------------------------------


def parse(pasted: str, *, issuer: str | None = None, state: str = STATE) -> tuple[str, str | None]:
    result = parse_redirect(pasted, redirect_uri=REDIRECT, state=Secret(state), issuer=issuer)
    return result.code.reveal(), result.iss


def refused(pasted: str, *, issuer: str | None = None) -> RedirectError:
    with pytest.raises(RedirectError) as caught:
        parse(pasted, issuer=issuer)
    return caught.value


def ok_url(extra: str = "") -> str:
    return f"{REDIRECT}?code={CODE}&state={STATE}{extra}"


def test_a_good_redirect() -> None:
    assert parse(ok_url()) == (CODE, None)
    assert parse("  " + ok_url() + "\n") == (CODE, None)
    assert parse(f"http://127.0.0.1:80/callback?state={STATE}&code={CODE}") == (CODE, None)
    assert parse(ok_url("&scope=a+b&iss=https%3A%2F%2Fa.example")) == (CODE, "https://a.example")
    assert parse(ok_url("#_=_")) == (CODE, None)


@pytest.mark.parametrize(
    "pasted",
    [
        f"http://127.0.0.2/callback?code={CODE}&state={STATE}",
        f"http://127.0.0.1:8080/callback?code={CODE}&state={STATE}",
        f"https://127.0.0.1/callback?code={CODE}&state={STATE}",
        f"http://127.0.0.1/callback/?code={CODE}&state={STATE}",
        f"http://127.0.0.1/?code={CODE}&state={STATE}",
        f"http://127.0.0.1?code={CODE}&state={STATE}",
        f"/callback?code={CODE}&state={STATE}",
        "not a url",
        "http://[::1",
        "",
    ],
)
def test_the_redirect_must_match(pasted: str) -> None:
    error = refused(pasted)
    assert error.reason == "redirect_mismatch"
    assert str(error) == f"that isn't an address under {REDIRECT}; paste the full URL"


@pytest.mark.parametrize("redirect_uri", ["http://127.0.0.1:8976", "http://127.0.0.1:8976/"])
@pytest.mark.parametrize("path", ["", "/"])
def test_an_empty_path_is_the_root(redirect_uri: str, path: str) -> None:
    pasted = f"http://127.0.0.1:8976{path}?code={CODE}&state={STATE}"
    result = parse_redirect(pasted, redirect_uri=redirect_uri, state=Secret(STATE), issuer=None)
    assert result.code.reveal() == CODE
    other = f"http://127.0.0.1:8976/callback?code={CODE}&state={STATE}"
    with pytest.raises(RedirectError) as caught:
        parse_redirect(other, redirect_uri=redirect_uri, state=Secret(STATE), issuer=None)
    assert caught.value.reason == "redirect_mismatch"


def test_the_query_size_limit_is_exact() -> None:
    base = ok_url("&pad=")
    fits = base + "x" * (4096 - len(base.split("?", 1)[1]))
    assert parse(fits) == (CODE, None)
    error = refused(fits + "x")
    assert (error.reason, str(error)) == ("redirect_mismatch", "the address's query is too long")


def test_an_unreadable_query() -> None:
    error = refused(ok_url("&x=%ff"))
    assert (error.reason, str(error)) == ("redirect_mismatch", "the address's query can't be read")


@pytest.mark.parametrize("name", ["code", "state", "error", "iss"])
def test_duplicates_are_refused(name: str) -> None:
    extra = f"&{name}=x" if name in ("code", "state") else f"&{name}=a&{name}=b"
    error = refused(ok_url(extra))
    assert (error.reason, str(error)) == (
        "duplicate_param",
        f"the address has more than one {name!r}",
    )


@pytest.mark.parametrize("extra", ["&code=", "&state=", "&code", "&iss=&iss="])
def test_a_blank_duplicate_is_still_a_duplicate(extra: str) -> None:
    assert refused(ok_url(extra)).reason == "duplicate_param"


def test_other_duplicates_are_fine() -> None:
    assert parse(ok_url("&scope=a&scope=b")) == (CODE, None)


@pytest.mark.parametrize(
    "fragment", ["code=x", "state=x", "error=x", "iss=x", "access_token=x", "id_token=x", "code"]
)
def test_a_response_in_the_fragment_is_refused(fragment: str) -> None:
    error = refused(f"{REDIRECT}?state={STATE}#{fragment}")
    assert (error.reason, str(error)) == (
        "redirect_mismatch",
        "the response is in the address's fragment; expected the query",
    )


@pytest.mark.parametrize(
    "pasted",
    [
        f"{REDIRECT}?code={CODE}",
        f"{REDIRECT}?code={CODE}&state=",
        f"{REDIRECT}?code={CODE}&state={STATE}x",
        f"{REDIRECT}?code={CODE}&state={STATE[:-1]}",
        f"{REDIRECT}?error=access_denied&state=other",
    ],
)
def test_the_state_must_match(pasted: str) -> None:
    error = refused(pasted)
    assert (error.reason, str(error)) == ("state_mismatch", "the address is for a different login")


def test_a_provider_error() -> None:
    error = refused(
        f"{REDIRECT}?state={STATE}&error=access_denied&error_description=The+user+said+no"
    )
    assert error.reason == "provider_error"
    assert error.error == "access_denied"
    assert error.description == "The user said no"
    assert str(error) == "the provider refused the authorization: access_denied"


def test_provider_error_text_is_filtered() -> None:
    error = refused(f"{REDIRECT}?state={STATE}&error=%3Cb%3E&error_description=a%0Ab")
    assert (error.error, error.description) == ("other", None)
    assert str(error) == "the provider refused the authorization: other"
    error = refused(f"{REDIRECT}?state={STATE}&error=x&error_description=a%E2%80%AEb")
    assert error.description is None
    error = refused(f"{REDIRECT}?state={STATE}&error=x")
    assert error.description is None
    long = refused(f"{REDIRECT}?state={STATE}&error=x&error_description=" + "d" * 250)
    assert long.description == "d" * 200
    exact = refused(f"{REDIRECT}?state={STATE}&error=x&error_description=" + "d" * 200)
    assert exact.description == "d" * 200
    # A bad character past the cap is cut off, not refused.
    tail = refused(f"{REDIRECT}?state={STATE}&error=x&error_description=" + "d" * 200 + "%0A")
    assert tail.description == "d" * 200


def test_the_issuer_must_match_when_both_are_known() -> None:
    issuer = "https://accounts.example"
    assert parse(ok_url("&iss=https%3A%2F%2Faccounts.example"), issuer=issuer) == (CODE, issuer)
    assert parse(ok_url(), issuer=issuer) == (CODE, None)
    error = refused(ok_url("&iss=https%3A%2F%2Fevil.example"), issuer=issuer)
    assert (error.reason, str(error)) == (
        "iss_mismatch",
        "the response came from a different issuer",
    )


@pytest.mark.parametrize(
    "query", [f"state={STATE}", f"state={STATE}&code=", f"state={STATE}&code=a+b"]
)
def test_no_usable_code(query: str) -> None:
    error = refused(f"{REDIRECT}?{query}")
    assert (error.reason, str(error)) == ("no_code", "the address has no usable authorization code")


def test_the_code_length_limit_is_exact() -> None:
    assert parse(f"{REDIRECT}?state={STATE}&code=" + "c" * 2048) == ("c" * 2048, None)
    error = refused(f"{REDIRECT}?state={STATE}&code=" + "c" * 2049)
    assert error.reason == "no_code"


# --- flows -------------------------------------------------------------------------------------


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
        return f"t{size:02d}x{self.count:040d}"


def table() -> tuple[FlowTable, Clock, Tokens]:
    clock, tokens = Clock(), Tokens()
    return FlowTable(clock, token=tokens), clock, tokens


def test_a_flow() -> None:
    flows, _, tokens = table()
    flow = flows.start("music", REDIRECT, rebind=True)
    assert tokens.sizes == [16, 32, 32]
    assert flow.id == "t16x" + "0" * 39 + "1"
    assert flow.state.reveal() == "t32x" + "0" * 39 + "2"
    assert flow.verifier.reveal() == "t32x" + "0" * 39 + "3"
    assert flow.credential == "music"
    assert flow.redirect_uri == REDIRECT
    assert flow.expires_at == 1600.0
    assert flow.rebind is True
    assert flow.state.reveal() != flow.verifier.reveal()
    assert flow.challenge == code_challenge(flow.verifier.reveal())
    assert flows.start("other", REDIRECT).rebind is False
    assert len(flows) == 2


def test_a_flow_never_shows_its_secrets() -> None:
    flows, _, _ = table()
    flow = flows.start("music", REDIRECT)
    text = repr(flow)
    assert text == "Flow(credential='music')"
    for value in (flow.id, flow.state.reveal(), flow.verifier.reveal()):
        assert value not in text


def test_take_removes_the_flow() -> None:
    flows, _, _ = table()
    flow = flows.start("music", REDIRECT)
    assert flows.take(flow.id, "music") is flow
    assert flows.take(flow.id, "music") is None
    assert flows.take("unknown", "music") is None
    assert len(flows) == 0


def test_a_foreign_flow_is_refused_and_removed() -> None:
    flows, _, _ = table()
    flow = flows.start("music", REDIRECT)
    assert flows.take(flow.id, "calendar") is None
    assert flows.take(flow.id, "music") is None


def test_flows_expire_exactly_at_the_ttl() -> None:
    flows, clock, _ = table()
    flow = flows.start("music", REDIRECT)
    clock.now = 1000.0 + FLOW_TTL - 0.001
    assert len(flows) == 1
    assert flows.take(flow.id, "music") is flow
    late = flows.start("music", REDIRECT)
    clock.now = late.expires_at
    assert flows.take(late.id, "music") is None
    third = flows.start("music", REDIRECT)
    clock.now = third.expires_at
    assert len(flows) == 0


def test_one_flow_per_credential() -> None:
    flows, _, _ = table()
    first = flows.start("music", REDIRECT)
    other = flows.start("calendar", REDIRECT)
    second = flows.start("music", REDIRECT)
    assert len(flows) == 2
    assert flows.take(first.id, "music") is None
    assert flows.take(second.id, "music") is second
    assert flows.take(other.id, "calendar") is other


def test_the_total_limit() -> None:
    flows, clock, _ = table()
    started = [flows.start(f"cred-{n}", REDIRECT) for n in range(MAX_FLOWS)]
    assert len(flows) == MAX_FLOWS
    with pytest.raises(
        TooManyFlows, match=f"^at most {MAX_FLOWS} logins can be pending$"
    ) as caught:
        flows.start("one-more", REDIRECT)
    assert caught.value.reason == "too_many_flows"
    # Replacing a credential's own flow is fine at the limit.
    flows.start("cred-0", REDIRECT)
    assert len(flows) == MAX_FLOWS
    # Expired flows make room.
    clock.now = started[0].expires_at
    flows.start("one-more", REDIRECT)
    assert len(flows) == 1


def test_cancel() -> None:
    flows, _, _ = table()
    flow = flows.start("music", REDIRECT)
    assert flows.cancel(flow.id) is True
    assert flows.cancel(flow.id) is False
    assert flows.take(flow.id, "music") is None


def test_flow_defaults() -> None:
    flow = Flow("id", "music", Secret("s"), Secret("v" * 43), REDIRECT, 1.0)
    assert flow.rebind is False


def test_redirects_and_flows_are_frozen() -> None:
    redirect = Redirect(Secret(CODE), None)
    with pytest.raises(FrozenInstanceError):
        redirect.code = Secret("other")  # type: ignore[misc]
    flow = Flow("id", "music", Secret("s"), Secret("v" * 43), REDIRECT, 1.0)
    with pytest.raises(FrozenInstanceError):
        flow.state = Secret("x")  # type: ignore[misc]
