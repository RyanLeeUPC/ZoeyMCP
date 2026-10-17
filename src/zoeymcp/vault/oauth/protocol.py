"""The OAuth 2.0 protocol as pure functions (design §4.3).

Token request builders and client authentication, token response parsing and classification,
lifetimes and skew, scopes, the seed-vs-live decision, the live-slot envelope, backoff, and the
filter for provider error codes.

Nothing here does I/O or reads a clock: the caller passes the times in. Every token is held as a
:class:`Secret` from parse to use, so it can't be logged by accident.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, replace
from email.utils import parsedate_to_datetime
from typing import Any, Final, Literal
from urllib.parse import parse_qsl, urlencode

from ... import __version__
from ...common.canonical import JSONRejected, dumps_canonical, loads_strict
from ...common.policy.schema import OAuth2Credential, param_values
from ..request import oauth_basic_credentials
from ..store import Secret

# --- limits and timings ------------------------------------------------------------------------

ATTEMPT_DEADLINE: Final = 20.0
CONNECT_TIMEOUT: Final = 5.0
REPLAY_DELAY: Final = 1.0
REFRESH_BUDGET: Final = 41.0
EXCHANGE_DEADLINE: Final = 20.0
DRAIN_TIMEOUT: Final = 45.0
MAX_TOKEN_BODY: Final = 64 * 1024
MIN_LIFETIME: Final = 60
MAX_LIFETIME: Final = 86400
MIN_401_AGE: Final = 30.0
BACKOFF: Final = (5.0, 15.0, 60.0, 300.0, 900.0)
JITTER: Final = (0.9, 1.1)
RETRY_AFTER_CAP: Final = 3600.0
RATE_LIMIT_DEFAULT: Final = 60.0
GRANT_WARN_DAYS: Final = 14

USER_AGENT: Final = f"zoeymcp/{__version__}"
FORM: Final = "application/x-www-form-urlencoded"

# --- stable codes ------------------------------------------------------------------------------

CREDENTIAL_UNAVAILABLE: Final = "credential_unavailable"
OAUTH_RECONSENT_NEEDED: Final = "oauth_reconsent_needed"
OAUTH_ROTATION_LOST: Final = "oauth_rotation_lost"
OAUTH_CLIENT_REJECTED: Final = "oauth_client_rejected"
OAUTH_MISCONFIGURED: Final = "oauth_misconfigured"
OAUTH_UNSUPPORTED: Final = "oauth_unsupported"
OAUTH_UNAVAILABLE: Final = "oauth_unavailable"

GRANT_ERRORS: Final = frozenset({"invalid_grant", "bad_refresh_token", "invalid_refresh_token"})
CLIENT_ERRORS: Final = frozenset(
    {"invalid_client", "unauthorized_client", "incorrect_client_credentials"}
)
CONFIG_ERRORS: Final = frozenset(
    {"invalid_scope", "invalid_target", "invalid_request", "unsupported_grant_type"}
)
UNSUPPORTED_ERRORS: Final = frozenset({"use_dpop_nonce"})
RETRY_ERRORS: Final = frozenset({"temporarily_unavailable", "slow_down", "server_error"})

_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
# No spaces or line breaks, so an access token can't inject a header.
_ACCESS_TOKEN = re.compile(r"[\x21-\x7E]{1,16384}")
_REFRESH_TOKEN = re.compile(r"[\x20-\x7E]{1,8192}")
_DIGITS = re.compile(r"[0-9]{1,10}")
# Retry-After seconds may be large; anything up to 32 digits is capped, not ignored.
_DELTA_SECONDS = re.compile(r"[0-9]{1,32}")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")

GrantKind = Literal["refresh_token", "authorization_code", "client_credentials"]
FailureKind = Literal["terminal", "backoff"]
SlotState = Literal["absent", "usable", "unusable"]
TokenSource = Literal["store", "live", "seed"]


def safe_error_code(value: object) -> str | None:
    """A provider's ``error`` or ``error_subtype``, safe to log: the code, ``other``, or None."""
    if value is None:
        return None
    if isinstance(value, str) and _ERROR_CODE.fullmatch(value):
        return value
    return "other"


def valid_access_token(value: object) -> bool:
    return isinstance(value, str) and _ACCESS_TOKEN.fullmatch(value) is not None


def valid_refresh_token(value: object) -> bool:
    """Printable ASCII, at most 8192 characters, with no space at either end."""
    if not isinstance(value, str) or _REFRESH_TOKEN.fullmatch(value) is None:
        return False
    return value == value.strip(" ")


# --- token requests ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Client:
    """How the vault identifies itself: the client ID (resolved if it's a ref) and the secret."""

    client_id: str
    secret: Secret | None = None


@dataclass(frozen=True, repr=False)
class TokenRequest:
    """A POST to the token endpoint. The body holds secrets, so ``repr`` leaves it out."""

    url: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def __repr__(self) -> str:
        names = [name for name, _ in self.headers]
        return f"TokenRequest(url={self.url!r}, headers={names!r})"


def build_refresh(cred: OAuth2Credential, client: Client, refresh_token: Secret) -> TokenRequest:
    """A refresh request. It never sends ``scope``: leaving it out means the original grant."""
    return _build(
        cred,
        client,
        [("grant_type", "refresh_token"), ("refresh_token", refresh_token.reveal())],
    )


def build_exchange(
    cred: OAuth2Credential, client: Client, *, code: Secret, verifier: Secret, redirect_uri: str
) -> TokenRequest:
    """A code exchange. ``redirect_uri`` must be the exact string the authorization sent."""
    return _build(
        cred,
        client,
        [
            ("grant_type", "authorization_code"),
            ("code", code.reveal()),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier.reveal()),
        ],
    )


def build_client_credentials(cred: OAuth2Credential, client: Client) -> TokenRequest:
    fields: list[tuple[str, str | list[str]]] = [("grant_type", "client_credentials")]
    if cred.scope is not None:
        fields.append(("scope", cred.scope))
    return _build(cred, client, fields)


def _build(
    cred: OAuth2Credential, client: Client, fields: Sequence[tuple[str, str | list[str]]]
) -> TokenRequest:
    items = list(fields)
    content_type = "application/json" if cred.token_body == "json" else FORM  # noqa: S105
    headers = [("accept", "application/json"), ("content-type", content_type)]
    auth = cred.effective_client_auth
    if auth == "basic":
        secret = _client_secret(client)
        credentials = oauth_basic_credentials(client.client_id, secret.reveal())
        headers.append(("authorization", "Basic " + credentials))
    elif auth == "post":
        secret = _client_secret(client)
        items += [("client_id", client.client_id), ("client_secret", secret.reveal())]
    else:
        items.append(("client_id", client.client_id))

    names = {name for name, _ in items}
    for name, value in cred.extra_params.items():
        if name in names:
            raise ValueError(f"extra_params can't set {name!r}; the vault sets it")
        items.append((name, value))

    set_by_vault = {name for name, _ in headers}
    user_agent = ("user-agent", USER_AGENT)
    extra: list[tuple[str, str]] = []
    for name, value in cred.token_headers.items():
        lower = name.lower()
        # Client authentication is the vault's, whichever form it takes.
        if lower in set_by_vault or lower == "authorization":
            raise ValueError(f"token_headers can't set {name!r}; the vault sets it")
        if lower == "user-agent":
            user_agent = (name, value)
        else:
            extra.append((name, value))
    headers.append(user_agent)
    headers += extra

    if cred.token_body == "json":  # noqa: S105
        body = dumps_canonical(dict(items))
    else:
        pairs = [(name, one) for name, value in items for one in param_values(value)]
        body = urlencode(pairs).encode("ascii")
    return TokenRequest(cred.token_url, tuple(headers), body)


def _client_secret(client: Client) -> Secret:
    if client.secret is None:
        raise ValueError("this client authentication needs the client secret")
    return client.secret


# --- token responses ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TokenResponse:
    """What came back from the token endpoint. ``body`` is at most ``MAX_TOKEN_BODY + 1`` bytes:
    the reader stops one byte past the cap, so an oversized body is seen as such."""

    status: int
    body: bytes
    content_type: str | None = None
    retry_after: str | None = None


@dataclass(frozen=True)
class Failure:
    """Why a token call failed. ``error`` and ``subtype`` are already filtered for logging."""

    kind: FailureKind
    code: str
    reason: str
    error: str | None = None
    subtype: str | None = None
    retry_after: float | None = None


@dataclass(frozen=True)
class Minted:
    """A usable access token from a successful response."""

    access_token: Secret
    lifetime: int
    # The parsed expires_in before clamping; None when it was missing or unusable.
    expires_in: int | None
    # None when the response didn't say: the granted set is unchanged.
    scope: tuple[str, ...] | None
    refresh_expires_in: int | None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Outcome:
    """One token call's result: exactly one of ``minted`` and ``failure`` is set.

    ``new_refresh_token`` is a successor to save before anything else, whichever it is.
    """

    status: int | None
    minted: Minted | None = None
    failure: Failure | None = None
    new_refresh_token: Secret | None = None


def transport_failure(reason: Literal["pre_send", "no_response"]) -> Outcome:
    """No usable response: the request wasn't sent, or nothing came back."""
    return Outcome(None, failure=Failure("backoff", OAUTH_UNAVAILABLE, reason))


def parse_token_body(body: bytes, content_type: str | None) -> dict[str, Any] | None:
    """The response as an object: JSON, or a form-encoded body when it's labeled as one."""
    if len(body) > MAX_TOKEN_BODY:
        return None
    try:
        value = loads_strict(body, max_bytes=MAX_TOKEN_BODY, safe_integers=False)
    except JSONRejected:
        value = None
    if isinstance(value, dict):
        return value
    media_type = (content_type or "").split(";", 1)[0].strip().lower()
    if media_type != FORM:
        return None
    try:
        pairs = parse_qsl(body.decode("ascii"), keep_blank_values=True, errors="strict")
    except (UnicodeDecodeError, ValueError):
        return None
    form = dict(pairs)
    if len(form) != len(pairs):
        return None
    return form


def parse_lifetime(value: object) -> int | None:
    """A lifetime in seconds: a JSON integer, a string of up to 10 digits, or an integral float."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value) if value.is_integer() else None
    if isinstance(value, str) and _DIGITS.fullmatch(value):
        return int(value)
    return None


def clamp_lifetime(seconds: int) -> int:
    return max(MIN_LIFETIME, min(MAX_LIFETIME, seconds))


def parse_scope(value: object, separator: str) -> tuple[str, ...] | None:
    """The granted scopes, or None when the response didn't say. ``""`` grants nothing."""
    if not isinstance(value, str):
        return None
    return tuple(dict.fromkeys(s for s in value.split(separator) if s))


def parse_retry_after(value: str | None, now: float) -> float | None:
    """Seconds to wait from a ``Retry-After`` header (seconds or an HTTP date), capped."""
    if value is None:
        return None
    text = value.strip()
    if _DELTA_SECONDS.fullmatch(text):
        seconds = float(text)
    else:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if when.tzinfo is None:
            return None
        seconds = when.timestamp() - now
    return min(max(seconds, 0.0), RETRY_AFTER_CAP)


def classify(
    response: TokenResponse,
    *,
    cred: OAuth2Credential,
    grant: GrantKind,
    presented: Secret | None,
    replayed: bool,
    now: float,
) -> Outcome:
    """Classify a token endpoint response (design D.7, D.9).

    ``presented`` is the refresh token sent, if any; ``replayed`` says this was the one replay
    after an ambiguous failure; ``now`` is the wall clock, for a ``Retry-After`` date.
    """
    status = response.status
    body = parse_token_body(response.body, response.content_type)
    if not 200 <= status < 300:
        failure = _error_failure(status, body, grant=grant, replayed=replayed)
        return Outcome(status, failure=_with_retry(failure, response, now))
    if body is None:
        failure = Failure("backoff", OAUTH_UNAVAILABLE, "unparseable_body")
        return Outcome(status, failure=_with_retry(failure, response, now))
    new_rt: Secret | None = None
    found = body.get("refresh_token")
    if grant != "client_credentials" and found is not None and found != "":
        if not valid_refresh_token(found):
            # Never re-present the old token: the provider may already have replaced it.
            failure = Failure("terminal", OAUTH_UNSUPPORTED, "unusable_refresh_token")
            return Outcome(status, failure=failure)
        if presented is None or found != presented.reveal():
            new_rt = Secret(found)
    result = _success_failure(status, body, grant=grant, replayed=replayed) or _mint(body, cred)
    if isinstance(result, Minted):
        return Outcome(status, minted=result, new_refresh_token=new_rt)
    return Outcome(status, failure=_with_retry(result, response, now), new_refresh_token=new_rt)


def _with_retry(failure: Failure, response: TokenResponse, now: float) -> Failure:
    """A backoff failure gets the provider's ``Retry-After``; a bare 429 a default."""
    if failure.kind != "backoff":
        return failure
    retry_after = parse_retry_after(response.retry_after, now)
    if retry_after is None and response.status == 429:
        retry_after = RATE_LIMIT_DEFAULT
    return replace(failure, retry_after=retry_after)


def _success_failure(
    status: int, body: dict[str, Any], *, grant: GrantKind, replayed: bool
) -> Failure | None:
    """A 2xx can still be an error (GitHub answers 200 with ``error``; Slack ``ok: false``)."""
    if body.get("error") is not None:
        return _error_failure(status, body, grant=grant, replayed=replayed)
    if body.get("ok") is False:
        return Failure("backoff", OAUTH_UNAVAILABLE, "not_ok")
    return None


def _error_failure(
    status: int, body: dict[str, Any] | None, *, grant: GrantKind, replayed: bool
) -> Failure:
    """The OAuth ``error`` decides first, the HTTP status second."""
    error = safe_error_code(body.get("error")) if body is not None else None
    subtype = safe_error_code(body.get("error_subtype")) if body is not None else None

    def fail(kind: FailureKind, code: str, reason: str) -> Failure:
        return Failure(kind, code, reason, error, subtype)

    if error in GRANT_ERRORS:
        if grant == "client_credentials":
            return fail("terminal", OAUTH_CLIENT_REJECTED, "provider_error")
        code = OAUTH_ROTATION_LOST if replayed else OAUTH_RECONSENT_NEEDED
        return fail("terminal", code, "provider_error")
    if error in CLIENT_ERRORS:
        return fail("terminal", OAUTH_CLIENT_REJECTED, "provider_error")
    if error in CONFIG_ERRORS:
        return fail("terminal", OAUTH_MISCONFIGURED, "provider_error")
    if error in UNSUPPORTED_ERRORS:
        return fail("terminal", OAUTH_UNSUPPORTED, "provider_error")
    if error in RETRY_ERRORS:
        return fail("backoff", OAUTH_UNAVAILABLE, "provider_error")
    if status == 429 or status >= 500:
        return fail("backoff", OAUTH_UNAVAILABLE, "http_status")
    if status == 401:
        return fail("terminal", OAUTH_CLIENT_REJECTED, "http_status")
    return fail("terminal", OAUTH_MISCONFIGURED, "http_status")


def _mint(body: dict[str, Any], cred: OAuth2Credential) -> Minted | Failure:
    notes: list[str] = []
    token_type = body.get("token_type")
    if token_type is None:
        notes.append("token_type_missing")
    elif not isinstance(token_type, str) or token_type.lower() != "bearer":
        # DPoP, MAC and the rest: nothing is forwarded.
        return Failure("terminal", OAUTH_UNSUPPORTED, "token_type")
    access_token = body.get("access_token")
    if not isinstance(access_token, str) or not valid_access_token(access_token):
        return Failure("backoff", OAUTH_UNAVAILABLE, "bad_access_token")
    expires_in = parse_lifetime(body.get("expires_in"))
    if expires_in is None:
        notes.append("expires_in_defaulted")
    requested = cred.default_expires_in if expires_in is None else expires_in
    lifetime = clamp_lifetime(requested)
    if lifetime != requested:
        notes.append("expires_in_clamped")
    return Minted(
        access_token=Secret(access_token),
        lifetime=lifetime,
        expires_in=expires_in,
        scope=parse_scope(body.get("scope"), cred.scope_separator),
        refresh_expires_in=parse_lifetime(body.get("refresh_token_expires_in")),
        notes=tuple(notes),
    )


# --- lifetime and skew -------------------------------------------------------------------------


@dataclass(frozen=True)
class Expiry:
    """When to refresh and when the token is dead, on the monotonic clock."""

    refresh_at: float
    hard_expiry: float
    skew: int


def schedule(sent_at: float, lifetime: int, refresh_skew: int) -> Expiry:
    """Times measured from when the request was sent. The skew is at most half the lifetime."""
    skew = min(refresh_skew, lifetime // 2)
    return Expiry(sent_at + lifetime - skew, sent_at + lifetime, skew)


# --- scopes ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class ScopeCheck:
    """Scopes granted outside the expected set, and scopes missing from what was expected."""

    unexpected: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        if self.unexpected:
            return "unexpected"
        if self.missing:
            return "missing"
        return "ok"


def check_login_scopes(granted: Iterable[str], expected: Iterable[str]) -> ScopeCheck:
    """At login: compared with the expected scopes. With none expected, nothing can be checked."""
    granted_set, expected_set = set(granted), set(expected)
    if not expected_set:
        return ScopeCheck()
    return ScopeCheck(
        unexpected=tuple(sorted(granted_set - expected_set)),
        missing=tuple(sorted(expected_set - granted_set)),
    )


def check_refresh_scopes(
    granted: Iterable[str], previous: Iterable[str], expected: Iterable[str]
) -> ScopeCheck:
    """On refresh: ``missing`` is what the grant narrowed by since last time."""
    granted_set, expected_set = set(granted), set(expected)
    unexpected = sorted(granted_set - expected_set) if expected_set else []
    return ScopeCheck(
        unexpected=tuple(unexpected), missing=tuple(sorted(set(previous) - granted_set))
    )


# --- seed vs live ------------------------------------------------------------------------------


@dataclass(frozen=True)
class SourceDecision:
    """Which refresh token to present, and why. No source means ``credential_unavailable``."""

    source: TokenSource | None
    reason: str


def seed_sha256(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()


def decide_source(
    cred: OAuth2Credential,
    *,
    slot: SlotState,
    live_seed_sha256: str | None,
    seed: str | None,
) -> SourceDecision:
    """Pick the refresh token for this refresh (design D.5).

    ``slot`` is the state of the entry holding the token: the ``store:`` entry, or the live slot
    of a credential seeded from ``env:``. ``seed`` is the env value, if it's set. A slot that
    exists but was refused never falls back to the seed: an unbound seed must not get around a
    binding that just refused.
    """
    if cred.refresh_token is None:
        raise ValueError("this credential has no refresh token")
    if slot == "unusable":
        return SourceDecision(None, "live_unusable")
    if cred.refresh_token.startswith("store:"):
        if slot == "absent":
            return SourceDecision(None, "no_token")
        return SourceDecision("store", "store")
    if slot == "absent":
        if seed is None:
            return SourceDecision(None, "no_token")
        return SourceDecision("seed", "no_live")
    if seed is None:
        return SourceDecision("live", "seed_absent")
    if cred.reseed == "never":
        return SourceDecision("live", "reseed_never")
    if live_seed_sha256 is not None and hmac.compare_digest(live_seed_sha256, seed_sha256(seed)):
        return SourceDecision("live", "seed_unchanged")
    return SourceDecision("seed", "seed_changed")


# --- the live-slot envelope --------------------------------------------------------------------

ENVELOPE_VERSION: Final = 1


class EnvelopeError(ValueError):
    """A live slot doesn't hold a valid envelope. The message never includes the value."""


@dataclass(frozen=True)
class Envelope:
    rt: Secret
    seed_sha256: str | None


def encode_envelope(rt: Secret, seed_hash: str | None) -> Secret:
    """``{"rt", "seed_sha256", "v"}`` as canonical JSON, the value of ``oauth.<cred>.live``."""
    if not valid_refresh_token(rt.reveal()):
        raise EnvelopeError("not a valid refresh token")
    if seed_hash is not None and not _SHA256_HEX.fullmatch(seed_hash):
        raise EnvelopeError("seed_sha256 must be 64 lowercase hex characters")
    value = {"v": ENVELOPE_VERSION, "rt": rt.reveal(), "seed_sha256": seed_hash}
    return Secret(dumps_canonical(value).decode("utf-8"))


def parse_envelope(value: Secret) -> Envelope:
    try:
        data = loads_strict(value.reveal())
    except JSONRejected:
        raise EnvelopeError("the live slot isn't JSON") from None
    if not isinstance(data, dict) or set(data) != {"v", "rt", "seed_sha256"}:
        raise EnvelopeError("the live slot doesn't hold an envelope")
    version = data["v"]
    if type(version) is not int or version != ENVELOPE_VERSION:
        raise EnvelopeError("unknown envelope version")
    if not valid_refresh_token(data["rt"]):
        raise EnvelopeError("the envelope's refresh token isn't valid")
    seed_hash = data["seed_sha256"]
    if seed_hash is not None and not (
        isinstance(seed_hash, str) and _SHA256_HEX.fullmatch(seed_hash)
    ):
        raise EnvelopeError("the envelope's seed_sha256 isn't valid")
    return Envelope(Secret(data["rt"]), seed_hash)


# --- backoff -----------------------------------------------------------------------------------


def backoff_delay(
    failures: int, *, retry_after: float | None, uniform: Callable[[float, float], float]
) -> float:
    """Seconds to wait after the ``failures``-th failure in a row. A longer ``Retry-After`` wins.

    ``uniform`` is ``random.uniform`` or a test's stand-in.
    """
    if failures < 1:
        raise ValueError("failures counts from 1")
    delay = BACKOFF[min(failures, len(BACKOFF)) - 1] * uniform(*JITTER)
    if retry_after is not None and retry_after > delay:
        return retry_after
    return delay
