"""Onboarding by URL, phase 1 (M7 design D.1-D.4, D.7, D.11, E.1-E.3, M.1, M.7). I/O, not mutated.

:class:`OnboardService` is the one set of onboardings the admin socket (and, later, the portal)
reaches, built once before them, like ``LoginService``. Its decisions are elsewhere and pure:
what an answer means in ``oauth/discovery.py``, the table, names, ``next`` lists and the second
run's comparison in ``onboarding.py``, the fragment in ``common/policy``; the requests go through
``oauth/fetch.py`` on the guarded onboarding client. Here they are put in order:

- **Discover**: the probe (and one legacy probe after a 400), the protected-resource metadata,
  or D.2a's legacy issuers when there is none, the authorization server's metadata, a
  resolution check of every endpoint host the vault will connect to, and the plan with its draft
  check (OPS-5). A given confidential client's issuer must be the one the operator named
  (TI-15). Without a given client ID the vault registers one (D.4) when the authorization server
  publishes a ``registration_endpoint`` with an authentication it speaks; else
  ``registration_unavailable``, or ``cimd_only`` for a server that registers clients by
  metadata document only.
- **An operator's own proxy** refusing a host blocks the onboarding (D.11): ``proxy_refused``
  with the hosts it needs and their Squid lines; the same discovery resumes it.
- **Register** (a given confidential client) stores the secret under the binding fragment 1 will
  derive, through ``secretops`` (D.7), after the draft check passes again, and deletes it again
  if anything fails after the write (OPS-5); **fragment** makes a given public client's
  fragment 1, sending and storing nothing, or renders a registered onboarding's again at any
  indent (OPS-2).
- **A registration** (DCR, register with no client ID) runs the draft check again, sends D.4's
  one request, checks the answer (``oauth/dcr.py``, X7), and writes what a run after a restart
  needs as register does for a given client: a confidential client's secret, or a public
  client's ID as ``<credential>-client-id`` (OPS-2), each with the registration's choices in
  its meta. The answer's registration access token and URI are never read.
- **After a restart** (D.7 step 6) the same discovery finds the client secret (or a registered
  public client's ID) an earlier run stored for this server by its entry's meta, and takes it
  on, registered at once, only if its authenticated binding is the one the fresh discovery
  predicts: fragment 1 again, with no second registration or write.
- **The second run** (D.12): a discovery of a URL a running oauth2 credential names starts no
  onboarding. It rediscovers (the probe and GETs), compares the committed credential, route and
  server with what it finds, by field name (``onboarding_mismatch``), checks a stored client
  secret's binding (D.7 step 5), and answers ``committed`` with whether the credential holds a
  refresh token and what to do next; the CLI signs in. A registered public client's
  ``<credential>-client-id`` entry is deleted then: nothing needs it once the policy names the
  credential (D.8). A URL a server reaches with another kind of credential is
  ``already_configured`` (OPS-14).
- **A re-registration** (``reregister``, OPS-3) skips that: it keeps the committed names and runs
  the first run again, its fragment 1 replacing the credential whole (``SetCredential``) and its
  secret replacing the stored one under the binding that fragment derives; a failure after that
  write puts the committed secret back rather than deleting it. A credential setting what a
  fragment can't carry (``token_headers``, a list in ``extra_params`` or ``authorize_params``) is
  refused ``reregister_by_hand`` at discovery, before anything is confirmed or stored (D-184).

Every refusal is the catalogue's (``portal/refusals.py``): one status and one text on every
surface. Nothing here logs an onboarding's ID, a secret, a URL path or query, or a body (X19);
M.4's events are ``onboard_started``, ``discovery_fetch``, ``onboard_planned``,
``onboard_refused``, ``onboard_registered``, ``onboard_blocked``, ``onboard_ended`` (``compared``
after a second run) and ``address_refused``.
"""

from __future__ import annotations

import re
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, replace
from typing import Any, Final, cast
from urllib.parse import urlsplit

import anyio
import httpx
from pydantic import ValidationError

from ..common import egresslist, netguard
from ..common.policy.change import (
    AddCredential,
    AddEgressPrivate,
    AddRoute,
    AddServer,
    ChangeRefused,
    Comment,
    PolicyChange,
    SetCredential,
    validate,
)
from ..common.policy.check import secret_references
from ..common.policy.emit import COMPOSE_INDENT, INDENT_MAX, EmitRefused, Target, emit
from ..common.policy.findings import Finding
from ..common.policy.schema import (
    _SCOPE_TOKEN,
    MAX_SCOPES,
    NAME_PATTERN,
    OAuth2Credential,
    Policy,
    RemoteServer,
    Route,
    _check_redirect_uri,
)
from ..portal.refusals import Refusal as Answer
from ..portal.refusals import refusal
from ..portal.refusals import secret as secret_refusal
from . import logs, netclient, secretops, secretplan
from .bindings import BindingError, client_secret_rebound, oauth_binding
from .oauth import dcr
from .oauth.dcr import SHARED_REDIRECT as SHARED_REDIRECT
from .oauth.dcr import application_type as application_type
from .oauth.discovery import (
    LEGACY_PROBE,
    MODERN_PROBE,
    PKCE_METHOD,
    SCOPE_TEXT_MAX,
    AsMetadata,
    Challenge,
    IssuerSource,
    Plan,
    Prm,
    PrmSource,
    Refusal,
    Scopes,
    as_candidates,
    as_exhausted,
    build_plan,
    check_as_metadata,
    check_prm,
    choose_issuer,
    legacy_candidates,
    origin_of,
    parse_challenge,
    prm_candidates,
    prm_exhausted,
    probe_next,
    typed_url,
)
from .oauth.fetch import Fetcher, FetchError, FetchRecord, ProxyRefused
from .oauth.pkce import CLI_OWNER
from .oauth.tokens import TokenManager
from .onboarding import (
    INLINE_SOURCE,
    NAME_SOURCES,
    STDIN_SOURCE,
    Client,
    Committed,
    Names,
    OnboardingRecord,
    OnboardingRefused,
    OnboardingTable,
    Options,
    Served,
    allow_hosts,
    choose_names,
    client_options,
    committed_for,
    committed_next,
    in_use,
    mismatches,
    name_taken,
    next_for,
    onboard_again,
    remove_first,
    secret_names,
    served_at,
    server_host_port,
    server_path,
    surface,
    token_state,
)
from .secretplan import SecretRefusal
from .store import EntryMeta, Secret, SecretStore, SecretUnavailable

# The body caps (K.2's discover; a secret; an indent).
DISCOVER_BODY_MAX: Final = 4 * 1024
REGISTER_BODY_MAX: Final = 8 * 1024
FRAGMENT_BODY_MAX: Final = 1024
# What a discovery may name: K.2's keys, the CLI's --name, the private tick (host access), and
# whether a confidential client's secret follows at register (D.7).
DISCOVER_KEYS: Final = frozenset(
    {
        "url",
        "name",
        "credential",
        "route",
        "server",
        "issuer",
        "scope",
        "client_id",
        "client_auth",
        "redirect_uri",
        "client_name",
        "allow_private",
        "secret_given",
        "reregister",
        "callback_origin",
    }
)
# The body keys that are true or false.
FLAG_KEYS: Final = frozenset({"allow_private", "secret_given", "reregister"})
# The client ID a registration's draft check is made with before the server issues one (D.8).
DRAFT_CLIENT_ID: Final = "zoeymcp-draft-client"
# A given client ID as fragment 1 can hold it: printable ASCII without a space, a quote, a
# backslash or a $ (TI-1), at most the schema's 512.
_CLIENT_ID = re.compile(r"[\x21\x23\x25-\x5b\x5d-\x7e]{1,512}")
_CLIENT_NAME = re.compile(rf"[\x20-\x7e]{{1,{dcr.CLIENT_NAME_MAX}}}")
_NAME = re.compile(NAME_PATTERN)
# The route's rules: the server's path, with what an MCP client sends (E.2).
MCP_METHODS: Final = ("POST", "GET", "DELETE")
BACKSTOP_OFF: Final = (
    "The redirect address isn't this credential's own, so an answer meant for another "
    "credential's sign-in isn't refused by its address (D.6's backstop is off for it)."
)

# The store name of a credential's client secret ends so (D.7 step 1), and a registered public
# client's ID so (D.8).
_SECRET_SUFFIX: Final = "-client-secret"  # noqa: S105 - a store name, not a secret
_CLIENT_ID_SUFFIX: Final = "-client-id"
# How a client authenticates, as an entry's meta may name it.
_AUTHS: Final = ("none", "basic", "post")
# What a re-registration replaces in the committed credential (D.12, OPS-3): the client and the
# endpoints a fresh discovery gives. Everything else the operator set stays.
REREGISTERED: Final = (
    "token_url",
    "authorize_url",
    "issuer",
    "require_iss",
    "revocation_url",
    "resource_metadata",
    "client_id",
    "client_secret",
    "client_auth",
    "redirect_uri",
)
# What a failure after the client secret's write does with it, as diff_invalid's detail says it.
_DELETED: Final = "the client secret this run stored was deleted"
_RESTORED: Final = "the client secret it replaced was put back"
# Why a fragment can't carry a field (emit's refusals), as reregister_by_hand says it (D-184).
_UNWRITABLE: Final = {
    "field": "a fragment never holds its values",
    "type": "a fragment writes each parameter as one string, not a list",
}

Resolver = netclient.Resolver


class OnboardError(Exception):
    """A refused step: the catalogue's answer, as every surface sends it."""

    def __init__(self, answer: Answer) -> None:
        self.answer = answer
        super().__init__(answer.reason)


@dataclass(frozen=True)
class _Kept:
    """A client secret an earlier run stored for this server and kept across a restart (D.7
    step 6), or a registered public client's ID (D.8), and the options a run that takes it on
    has: the client's, with the client ID from the entry's meta unless the run gives it
    (``from_meta``), and a registration's authentication and redirect address from it too."""

    name: str
    options: Options
    from_meta: bool

    @property
    def secret(self) -> bool:
        return self.name.endswith(_SECRET_SUFFIX)


def _bad_body(detail: str) -> OnboardError:
    return OnboardError(replace(refusal("bad_body"), more=(("detail", detail),)))


def policy_source(config: str | None) -> str:
    """The running policy's source as ``zoeymcp check`` names it (``load.read_source``)."""
    if config is None:
        return INLINE_SOURCE
    return STDIN_SOURCE if config == "-" else config


def _default_resolver() -> Resolver:
    hooks = netclient.HOOKS
    if hooks is not None and hooks.resolver is not None:
        return hooks.resolver
    return netclient.resolve


def _host_port(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    return str(parts.hostname).lower(), parts.port or 443


def _issuer_host(plan: Plan) -> str:
    return _host_port(plan.issuer)[0]


class OnboardService:
    """Onboardings in progress and their steps, shared by every surface. ``client`` is the
    onboarding client (``netclient.onboarding_client``); ``egress_proxy`` the startup one;
    ``source`` the running policy's source label, for the ``next`` lists; ``resolver`` answers
    names for the endpoint check (tests only)."""

    def __init__(
        self,
        store: SecretStore,
        tokens: TokenManager | None,
        policy: Callable[[], Policy],
        client: httpx.AsyncClient,
        *,
        egress_proxy: str | None = None,
        source: str = INLINE_SOURCE,
        clock: Callable[[], float] = time.monotonic,
        wall: Callable[[], float] = time.time,
        token: Callable[[int], str] = secrets.token_urlsafe,
        resolver: Resolver | None = None,
    ) -> None:
        self._store = store
        self._tokens = tokens
        self._policy = policy
        self._client = client
        self._egress_proxy = egress_proxy
        self._source = source
        self._clock = clock
        self._wall = wall
        self._resolver = resolver
        self._table = OnboardingTable(clock, token=token)

    # --- discover ------------------------------------------------------------------------------

    async def discover(self, body: Mapping[str, Any], *, owner: str = CLI_OWNER) -> dict[str, Any]:
        """Phase 1's discovery (D.1-D.3), or the owner's onboarding of the same URL and names
        carried on: a blocked one from the start, a discovered or registered one as it is."""
        self._sweep()
        policy = self._policy()
        url, given, options = _request(body)
        origins = [] if policy.admin is None else policy.admin.origins
        if options.callback_origin is not None and options.callback_origin not in origins:
            raise _bad_body("callback_origin isn't one of the policy's admin.origins")
        found = committed_for(policy, url)
        if not options.reregister:
            if found is not None:
                return await self._second_run(url, given, options, found, owner)
            served = served_at(policy, url)
            if served is not None:
                raise OnboardError(_already_configured(served))
        own = self._table.owned(owner)
        kept: _Kept | None = None
        if (
            own is not None
            and (own.server_url, own.options) == (url, options)
            and _names_match(url, given, own.names)
        ):
            # The same run again (--plan-only, a retry): its names, though it may have stored
            # an entry under them since.
            names = own.names
        elif options.reregister:
            names = _committed_names(url, given, found)
        else:
            names, kept = self._names(url, given, owner, policy, options)
            if kept is not None:
                options = kept.options
        try:
            started = self._table.start(owner, url, names, options)
        except OnboardingRefused as exc:
            raise OnboardError(_table_refusal(exc)) from None
        record = started.record
        if started.resumed and record.stage in ("discovered", "registered"):
            return self._plan_answer(record, policy, kept)
        host = server_host_port(url)[0]
        logs.event(
            "onboard_started", owner=surface(owner), host=host, allow_private=options.allow_private
        )
        try:
            plan = await self._discover(record, policy, kept=kept is not None)
            if kept is not None:
                self._check_kept(record, plan, kept)
            policy = self._policy()
            draft = self._draft_check(record, plan, policy)
            record = self._table.discovered(record.id, owner, plan, draft)
            if kept is not None:
                record = self._registered_again(record, owner)
        except ProxyRefused as exc:
            raise OnboardError(self._blocked(record, exc, policy)) from None
        except OnboardError as exc:
            self._table.cancel(record.id, owner)
            logs.event("onboard_refused", reason=exc.answer.reason, host=host)
            raise
        except (OnboardingRefused, ValueError):
            # Cancelled or replaced while it ran.
            raise OnboardError(refusal("onboarding_unknown")) from None
        meta = plan.metadata
        logs.event(
            "onboard_planned",
            host=host,
            issuer=_issuer_host(plan),
            require_iss=meta.require_iss,
            registration=_registration_method(options),
            auth=_client_auth(_planned_options(record)),
            scopes=len(plan.scopes.scopes),
        )
        if kept is not None:
            logs.event(
                "onboard_registered",
                credential=record.names.credential,
                issuer=_issuer_host(plan),
                auth=_client_auth(options),
                secret_stored=False,
            )
        return self._plan_answer(record, policy, kept)

    async def _second_run(
        self,
        url: str,
        given: Mapping[str, str],
        options: Options,
        found: Committed,
        owner: str,
    ) -> dict[str, Any]:
        """D.12 steps 1 and 2: rediscover (the probe and GETs; nothing is registered or stored)
        under the committed names, compare by field name, and check a stored client secret's
        binding. The onboarding exists only while it runs, or while a proxy blocks it (D.11)."""
        names = _committed_names(url, given, found)
        own = self._table.owned(owner)
        if own is not None and own.server_url == url and own.stage != "blocked":
            # The owner's own earlier run of this URL (--plan-only, say, before the policy named
            # it): its plan may be stale, and only a blocked fetch carries on (step 1).
            ended = self._table.cancel(own.id, owner)
            if ended is not None:
                logs.event("onboard_ended", why=ended.why)
        try:
            started = self._table.start(owner, url, names, options)
        except OnboardingRefused as exc:
            raise OnboardError(_table_refusal(exc)) from None
        record = started.record
        host = server_host_port(url)[0]
        policy = self._policy()
        logs.event(
            "onboard_started", owner=surface(owner), host=host, allow_private=options.allow_private
        )
        try:
            plan = await self._discover(record, policy, kept=False, committed=True)
        except ProxyRefused as exc:
            raise OnboardError(self._blocked(record, exc, policy)) from None
        except OnboardError as exc:
            self._table.cancel(record.id, owner)
            logs.event("onboard_refused", reason=exc.answer.reason, host=host)
            raise
        except (OnboardingRefused, ValueError):
            raise OnboardError(refusal("onboarding_unknown")) from None
        self._table.cancel(record.id, owner)
        try:
            answer = self._compared(url, plan)
        except OnboardError as exc:
            logs.event("onboard_refused", reason=exc.answer.reason, host=host)
            raise
        await self._client_id_entry_gone(names.credential, owner)
        logs.event("onboard_ended", why="compared")
        return answer

    async def _client_id_entry_gone(self, credential: str, owner: str) -> None:
        """D.8 (OPS-2): a registered public client's ``<credential>-client-id`` entry served
        only to show fragment 1 again before the commit. The policy names the credential now,
        so it goes, through ``secretops``, unless the policy itself uses the entry."""
        name = _entry_name(credential, secret=False)
        entry = self._store.entry(name)
        policy = self._policy()
        used = {ref.removeprefix("store:") for _, ref, _ in secret_references(policy)}
        if (
            entry is None
            or name in used
            or not isinstance((entry.meta or {}).get("onboarded"), str)
        ):
            return
        via: secretops.Via = "socket" if owner == CLI_OWNER else "portal"
        await secretops.delete(
            self._store, self._tokens, secretplan.plan_delete(name, policy), via=via
        )

    def _compared(self, url: str, plan: Plan) -> dict[str, Any]:
        """The committed credential, route and server against a fresh discovery (D.12 step 2),
        in the policy now: field names only, never values."""
        policy = self._policy()
        found = committed_for(policy, url)
        if found is None:
            # Reloaded while it ran: the policy names this URL no more.
            raise OnboardError(refusal("onboarding_unknown"))
        fields = mismatches(policy, plan)
        again = [onboard_again(url).answer()]
        if fields:
            answer = refusal("onboarding_mismatch", fields=", ".join(fields))
            raise OnboardError(replace(answer, more=(("fields", fields), ("next", again))))
        cred = policy.credentials[found.credential]
        assert isinstance(cred, OAuth2Credential)  # noqa: S101 - committed_for found an oauth2 one
        self._secret_bound(policy, cred, again)
        held = token_state(found.credential, cred, self._store.names())
        meta = plan.metadata
        return {
            "stage": "committed",
            "names": {
                "credential": found.credential,
                "route": found.route,
                "server": found.server,
                "source": "given",
            },
            "plan": {
                "server_url": plan.server_url,
                "resource": plan.resource,
                "issuer": plan.issuer,
                "authorization_endpoint": meta.authorization_endpoint,
                "token_endpoint": meta.token_endpoint,
                "revocation_endpoint": meta.revocation_endpoint,
                "require_iss": meta.require_iss,
                "client_auth": cred.effective_client_auth,
                "hosts": list(plan.hosts),
            },
            "rows": [list(row) for row in plan.rows()],
            "token": held,
            "next": [step.answer() for step in committed_next(found, held)],
        }

    def _secret_bound(
        self, policy: Policy, cred: OAuth2Credential, again: list[dict[str, Any]]
    ) -> None:
        """D.7 step 5 for the second run (D.12): a ``store:`` client secret's authenticated
        binding is still the one the committed policy derives, as login checks it."""
        try:
            rebound = client_secret_rebound(policy, cred, self._store.entry)
        except BindingError as exc:
            raise OnboardError(refusal("no_route", detail=str(exc))) from None
        if rebound is not None:
            answer = refusal("client_secret_binding_changed")
            raise OnboardError(replace(answer, more=(("next", again),)))

    def _names(
        self,
        url: str,
        given: Mapping[str, str],
        owner: str,
        policy: Policy,
        options: Options,
    ) -> tuple[Names, _Kept | None]:
        """The names given, each refused ``name_taken`` if the policy or the store has it, or
        the defaults, which are free (OPS-15). A client secret an earlier run stored for this
        server doesn't take the names it was stored under (D.7 step 6): they are this run's,
        and the secret comes back with them, for the discovery to check."""
        store_names = self._store.names()
        others = self._table.names_in_use(owner)
        for kept in self._kept(url, options):
            rest = [name for name in store_names if name != kept.name]
            names = choose_names(url, in_use(policy, rest, others), **given)
            if (
                _entry_name(names.credential, secret=kept.secret) == kept.name
                and name_taken(names, policy, rest) is None
            ):
                return names, kept
        names = choose_names(url, in_use(policy, store_names, others), **given)
        if given:  # _request checked each name given
            found = name_taken(names, policy, store_names)
            if found is not None:
                raise OnboardError(refusal("name_taken", name=found))
        return names, None

    def _kept(self, url: str, options: Options) -> list[_Kept]:
        """The client secrets, and registered public clients' IDs, an earlier run stored for
        this server, found by their entries' meta (D.7 step 4: it finds an entry and decides
        nothing; the binding is checked after discovery). A run that gives another client ID
        takes none on. One a registration wrote names its authentication and redirect address,
        which a run naming no client and no other redirect address takes on, so its fragment 1 is
        the one shown before."""
        origin = origin_of(url)
        resources = (url, origin, f"{origin}/")
        found = []
        for entry in self._store.metadata():
            meta = entry.meta or {}
            client_id = meta.get("client_id")
            secret = entry.name.endswith(_SECRET_SUFFIX)
            if (
                not (secret or entry.name.endswith(_CLIENT_ID_SUFFIX))
                or meta.get("resource") not in resources
                or not isinstance(client_id, str)
                or not _CLIENT_ID.fullmatch(client_id)
                # Clear meta: never a reference fragment 1 would read as a secret (X7).
                or client_id.startswith(dcr.SECRET_PREFIXES)
                or options.client_id not in (None, client_id)
            ):
                continue
            chosen: dict[str, Any] = {}
            auth, redirect = meta.get("client_auth"), meta.get("redirect_uri")
            if options.client_id is None and auth in _AUTHS and _usable_redirect(redirect):
                if options.redirect_uri not in (None, redirect):
                    # A registered client's redirect is fixed (X7's dcr_redirect_changed): with
                    # another, it isn't the fragment 1 shown before, so its names stay taken.
                    continue
                chosen = {"client_auth": options.client_auth or auth, "redirect_uri": redirect}
            elif not secret:
                # A public client's ID is written by a registration alone, with its choices.
                continue
            try:
                taken_on = replace(options, client_id=client_id, secret_given=secret, **chosen)
            except ValueError:  # the run's client authentication isn't the entry's kind
                continue
            found.append(_Kept(entry.name, taken_on, from_meta=options.client_id is None))
        return found

    def _check_kept(self, record: OnboardingRecord, plan: Plan, kept: _Kept) -> None:
        """D.7 step 6 (MISS-14): the kept entry names the resource this discovery found, and
        its authenticated binding is the one this discovery predicts, else its names stay
        taken; a public client's ID entry also holds the client ID its meta names. The clear
        meta only found it; the binding decides."""
        entry = self._store.entry(kept.name)
        same = entry is not None and (entry.meta or {}).get("resource") == plan.resource
        if same:
            try:
                value = self._store.get_for_binding(kept.name, _binding(record, plan))
            except SecretUnavailable:
                same = False
            else:
                same = kept.secret or value.reveal() == kept.options.client_id
        if not same:
            raise OnboardError(refusal("name_taken", name=record.names.credential))

    def _registered_again(self, record: OnboardingRecord, owner: str) -> OnboardingRecord:
        """A kept secret's onboarding, registered at once: fragment 1 as the earlier run made
        it, checked with the policy now, with nothing registered or written (GR-21)."""
        change = self._change(record)
        _passes(self._findings(self._policy(), change))
        return self._table.registered(record.id, owner, change)

    async def _discover(
        self, record: OnboardingRecord, policy: Policy, *, kept: bool, committed: bool = False
    ) -> Plan:
        """D.2, D.2a and D.3 in order, each answer judged by ``discovery``. A kept secret
        (``kept``, D.7 step 6) is sent nowhere and bound to nothing new, so it needs no named
        issuer: its binding decides. A second run (``committed``, D.12) registers nothing, so
        it needs no client."""
        fetcher = Fetcher(
            self._client,
            proxied=self._egress_proxy is not None,
            onboarding=record.id,
            private_target=record.private_target,
            clock=self._clock,
            report=_report,
        )
        url, options = record.server_url, record.options
        answer = await _fetched(fetcher.probe(url, MODERN_PROBE))
        step = probe_next(answer.status, legacy_sent=False)
        if step == "legacy":
            answer = await _fetched(fetcher.probe(url, LEGACY_PROBE))
            step = probe_next(answer.status, legacy_sent=True)
        challenge: Challenge | None = None
        if step == "challenge":
            challenge = _checked(parse_challenge(answer.challenges))
        tried: list[str] = []
        prm: Prm | None = None
        prm_url: str | None = None
        for candidate in prm_candidates(url, challenge):
            self._widen(record, candidate.url)
            tried.append(candidate.url)
            well_known = candidate.source != "challenge"
            fetched = await _fetched(fetcher.metadata(candidate.url, "prm", well_known=well_known))
            if fetched.document is not None:
                source = cast(PrmSource, candidate.source)  # prm_candidates' sources
                prm = _checked(check_prm(fetched.document, source, url))
                prm_url = candidate.url
                break
        issuer_source: IssuerSource
        if prm is not None:
            issuer = _checked(choose_issuer(prm.authorization_servers, options.issuer))
            if options.secret_given and options.issuer is None and not kept:
                # TI-15: a given secret goes only to the issuer the operator named.
                raise OnboardError(_discovery_refusal(Refusal("as_unknown", values=(issuer,))))
            issuer_source = "only" if options.issuer is None else "chosen"
            metadata_url, metadata = await self._as_metadata(record, fetcher, issuer)
        else:
            found = None
            for candidate in legacy_candidates(url, options.issuer):
                self._widen(record, candidate.url)
                tried.append(candidate.url)
                fetched = await _fetched(fetcher.metadata(candidate.url, "as", well_known=True))
                if fetched.document is not None:
                    assert candidate.issuer is not None  # noqa: S101 - legacy candidates name one
                    checked = _checked(check_as_metadata(fetched.document, candidate.issuer))
                    found = (candidate.url, checked, candidate.source)
                    break
            if found is None:
                raise OnboardError(
                    _discovery_refusal(prm_exhausted(tried, probe_status=answer.status))
                )
            metadata_url, metadata, legacy = found
            if options.secret_given and options.issuer is None and not kept:
                raise OnboardError(
                    _discovery_refusal(Refusal("as_unknown", values=(metadata.issuer,)))
                )
            issuer_source = cast(IssuerSource, legacy)  # legacy_candidates' sources
        await self._check_endpoints(record, metadata, policy)
        plan = _checked(
            build_plan(
                url,
                challenge=challenge,
                prm=prm,
                resource_metadata=prm_url,
                issuer_source=issuer_source,
                metadata_url=metadata_url,
                metadata=metadata,
            )
        )
        if options.scope is not None:
            plan = replace(plan, scopes=Scopes(tuple(options.scope.split(" ")), "given", False))
        if options.client_id is None and not committed:
            # D.4's order: a given client ID, else a registration, else a refusal, before the
            # operator is asked anything.
            if metadata.registration_endpoint is None and "cimd" in metadata.notes:
                raise OnboardError(refusal("cimd_only", host=_issuer_host(plan)))
            if metadata.registration_endpoint is None:
                raise OnboardError(refusal("registration_unavailable", host=_issuer_host(plan)))
            _checked_dcr(dcr.request_auth(metadata.token_auth_methods))
        return plan

    async def _as_metadata(
        self, record: OnboardingRecord, fetcher: Fetcher, issuer: str
    ) -> tuple[str, AsMetadata]:
        """The issuer's metadata from the first candidate that has it (D.3)."""
        tried = []
        for candidate in as_candidates(issuer):
            self._widen(record, candidate)
            tried.append(candidate)
            fetched = await _fetched(fetcher.metadata(candidate, "as", well_known=True))
            if fetched.document is not None:
                return candidate, _checked(check_as_metadata(fetched.document, issuer))
        raise OnboardError(_discovery_refusal(as_exhausted(tried)))

    async def _check_endpoints(
        self, record: OnboardingRecord, metadata: AsMetadata, policy: Policy
    ) -> None:
        """D.3's resolution check of each endpoint the vault will connect to, without
        ``egress_proxy`` (which checks for itself): a hostile token endpoint on a private
        address fails before the operator commits it. Private is allowed for a ``host:port`` the
        policy lists in ``egress_private``, or the typed server's own with ``allow_private``,
        which fragment 1 lists."""
        if self._egress_proxy is not None:
            return
        resolver = self._resolver or _default_resolver()
        for url in (
            metadata.token_endpoint,
            metadata.registration_endpoint,
            metadata.revocation_endpoint,
        ):
            if url is None:
                continue
            host, port = _host_port(url)
            try:
                with anyio.fail_after(netclient.RESOLVE_TIMEOUT):
                    addresses = await resolver(host, port)
            except (OSError, TimeoutError, UnicodeError):
                raise OnboardError(refusal("resolve_failed", host=host)) from None
            key = netguard.entry_key(host, port)
            private_ok = key in policy.egress_private or key == record.private_target
            verdict = netguard.addresses_allowed(addresses, private_ok=private_ok)
            if not verdict.allowed:
                logs.event(
                    "address_refused",
                    purpose="discovery",
                    host=host,
                    port=port,
                    verdict=verdict.reason,
                )
                raise OnboardError(refusal("address_refused", host=host))

    def _widen(self, record: OnboardingRecord, url: str) -> None:
        """The allowance with the host the next request goes to (I.3)."""
        self._table.widen(record.id, record.owner, [_host_port(url)])

    def _blocked(self, record: OnboardingRecord, exc: ProxyRefused, policy: Policy) -> Answer:
        """D.11: the onboarding blocks, keeping its allowance, and the answer names what the
        operator's proxy must allow."""
        try:
            record = self._table.block(record.id, record.owner, (exc.host, exc.port), policy)
        except (OnboardingRefused, ValueError):
            return refusal("onboarding_unknown")
        logs.event("onboard_blocked", host=exc.host, port=exc.port, needed=len(record.needed_hosts))
        return self._blocked_answer(record, policy, exc.status)

    def _blocked_answer(
        self, record: OnboardingRecord, policy: Policy, status: int | None
    ) -> Answer:
        assert record.blocked_on is not None  # noqa: S101 - a blocked record names its host
        host, port = record.blocked_on
        more = (
            ("host", host),
            ("port", port),
            ("status", status),
            ("next", self._next(record, policy)),
        )
        return replace(refusal("proxy_refused", host=host), more=more)

    # --- the change and its checks (E.2, OPS-5) -----------------------------------------------

    def _change(self, record: OnboardingRecord) -> PolicyChange:
        """Fragment 1 (E.2): the credential, its route to the server's origin, and the server
        with no tools; with ``allow_private``, the server's ``host:port`` in ``egress_private``.
        Every value is a validated URL, a scope token, or what the operator typed; a client the
        vault registered (or, for a draft, the one it predicts) stands in for a given one."""
        plan, names, options = record.plan, record.names, client_options(record)
        assert plan is not None  # noqa: S101 - a discovered record holds its plan
        meta = plan.metadata
        client_secret, _, refresh = secret_names(names.credential)
        auth = _client_auth(options)
        fields: dict[str, Any] = {
            "kind": "oauth2",
            "token_url": meta.token_endpoint,
            "authorize_url": meta.authorization_endpoint,
            "issuer": plan.issuer,
            "require_iss": meta.require_iss,
            "client_id": options.client_id,
            "client_auth": auth,
            "refresh_token": f"store:{refresh}",
            # A public client's refresh tokens rotate (RFC 9700 2.2.2), as check expects.
            "rotates": auth == "none",
            "redirect_uri": _redirect(record),
            "extra_params": {"resource": plan.resource},
            "authorize_params": {"resource": plan.resource},
        }
        if meta.revocation_endpoint is not None:
            fields["revocation_url"] = meta.revocation_endpoint
        if plan.resource_metadata is not None:
            fields["resource_metadata"] = plan.resource_metadata
        if options.secret_given:
            fields["client_secret"] = f"store:{client_secret}"
        if plan.scopes.scopes:
            fields["scope"] = " ".join(plan.scopes.scopes)
        if options.reregister:
            return self._reregistration(record, fields)
        url = record.server_url
        path = server_path(url)
        try:
            credential = OAuth2Credential.model_validate(fields)
            route = Route.model_validate(
                {
                    "name": names.route,
                    "prefix": f"/{names.route}",
                    "upstream": origin_of(url),
                    "credential": names.credential,
                    "callers": ["gateway"],
                    "stream": True,
                    "rules": [{"methods": list(MCP_METHODS), "paths": [path]}],
                }
            )
            server = RemoteServer.model_validate(
                {"kind": "remote", "route": names.route, "path": path, "tools": {"include": []}}
            )
        except ValidationError as exc:
            detail = "; ".join(error["msg"] for error in exc.errors(include_url=False))
            raise OnboardError(refusal("diff_invalid", detail=detail)) from None
        ops: list[Any] = [
            AddCredential(names.credential, credential),
            AddRoute(route),
            AddServer(names.server, server),
        ]
        if options.allow_private:
            ops.append(AddEgressPrivate(netguard.entry_key(*server_host_port(url))))
        title = (
            f"onboarding {names.server} (1 of 2). Merge into your policy; nothing here replaces "
            "a key you have."
        )
        return PolicyChange(title, tuple(ops))

    def _reregistration(self, record: OnboardingRecord, fields: Mapping[str, Any]) -> PolicyChange:
        """A re-registration's fragment 1 (D.12, OPS-3): the committed credential replaced whole
        (H.4), with the client and endpoints a fresh discovery gives and everything else the
        operator set kept, each changed field named in a comment, never its value."""
        names, options = record.names, client_options(record)
        old = self._policy().credentials.get(names.credential)
        if not isinstance(old, OAuth2Credential):
            # Reloaded while it ran: the policy has no such credential to replace.
            raise OnboardError(refusal("onboarding_unknown"))
        kept = old.model_dump(mode="json", exclude_unset=True, exclude_none=True)
        for params in ("extra_params", "authorize_params"):
            for key, value in kept.get(params, {}).items():
                if isinstance(value, list):
                    # D-184: several values (resources, say) that no fragment writes, and that
                    # the discovered resource would replace.
                    raise _by_hand(names.credential, f"{params}.{key}", _UNWRITABLE["type"])
        replaced = list(REREGISTERED)
        if options.scope is not None:
            # The operator's --scope replaces the committed scopes, as on a first run.
            replaced.append("scope")
        if old.effective_client_auth != fields["client_auth"]:
            # A public client's refresh tokens rotate, a confidential one's needn't (_change).
            replaced.append("rotates")
        new = {key: value for key, value in kept.items() if key not in replaced}
        new |= {key: fields[key] for key in replaced if key in fields}
        for params in ("extra_params", "authorize_params"):
            new[params] = {**kept.get(params, {}), **fields[params]}
        try:
            credential = OAuth2Credential.model_validate(new)
        except ValidationError as exc:
            detail = "; ".join(error["msg"] for error in exc.errors(include_url=False))
            raise OnboardError(refusal("diff_invalid", detail=detail)) from None
        # By effective value, defaults included: a default left unwritten that the fragment
        # writes out hasn't changed.
        before, after = old.model_dump(mode="json"), credential.model_dump(mode="json")
        changed = [
            key
            for key in (*REREGISTERED, "scope", "rotates", "extra_params", "authorize_params")
            if before.get(key) != after.get(key)
        ]
        ops: list[Any] = [Comment("changed_was", names.credential, key) for key in changed]
        ops.append(SetCredential(names.credential, credential))
        if options.allow_private:
            ops.append(AddEgressPrivate(netguard.entry_key(*server_host_port(record.server_url))))
        title = (
            f"re-registration of {names.server} (1 of 2). Replace credentials."
            f"{names.credential} with this one; nothing else changes."
        )
        change = PolicyChange(title, tuple(ops))
        try:
            emit(change)
        except EmitRefused as exc:
            # D-184: a field the fragment can't carry would be dropped, or the fragment never
            # made: refused now, before the operator confirms anything.
            field = exc.path.removeprefix(f"credentials.{names.credential}.")
            why = _UNWRITABLE.get(exc.reason, "it can't be written into a fragment")
            raise _by_hand(names.credential, field, why) from None
        return change

    def _findings(self, policy: Policy, change: PolicyChange) -> list[Finding]:
        """``check`` on the running policy with ``change`` merged; a merge the schema refuses
        is its errors (E.2)."""
        try:
            return validate(policy, change)
        except ChangeRefused as exc:
            if exc.reason == "name_taken":
                raise OnboardError(refusal("name_taken", name=exc.path)) from None
            messages = exc.messages or ("the merged policy doesn't load",)
            return [Finding(exc.path, "error", message) for message in messages]

    def _draft_check(self, record: OnboardingRecord, plan: Plan, policy: Policy) -> list[Finding]:
        """D.8's draft check: fragment 1 as it will be, merged into the running policy, so an
        error shows in the plan before anything is stored or registered (OPS-5); for a client
        the vault registers, with a placeholder client ID and the authentication it asks for."""
        drafted = replace(record, plan=plan)
        return self._findings(policy, self._change(replace(drafted, client=_predicted(drafted))))

    # --- register and fragment (D.7, E.2, OPS-2) -----------------------------------------------

    async def register(
        self, onboarding: str, body: Mapping[str, Any], *, owner: str = CLI_OWNER
    ) -> dict[str, Any]:
        """Store a given confidential client's secret and make fragment 1 (D.7); for a public
        client, fragment 1 alone; with no client ID, register one (D.4) and make its fragment 1.
        A registered onboarding answers its fragment 1 again."""
        if not set(body) <= {"client_secret"}:
            raise _bad_body("expected {client_secret?}")
        secret = body.get("client_secret")
        if secret is not None and not isinstance(secret, str):
            raise _bad_body("client_secret is a string")
        record = self._ready(onboarding, owner)
        if record.stage == "registered":
            if secret is not None:
                raise _bad_body("this onboarding is registered; its secret is stored")
            return self._fragment_answer(record, 0, "plain")
        if record.options.client_id is None:
            if secret is not None:
                raise _bad_body("a registered client's secret comes from its authorization server")
            return await self._registration(record, owner)
        if record.options.secret_given != (secret is not None):
            raise _bad_body(
                "a client secret comes here exactly when the onboarding was started with one"
            )
        return await self._finish(record, owner, secret)

    async def fragment(
        self, onboarding: str, body: Mapping[str, Any], *, owner: str = CLI_OWNER
    ) -> dict[str, Any]:
        """Fragment 1 for a given public client (nothing sent, nothing stored, PC-13), or a
        registered onboarding's again, at ``indent`` (0-16, or ``compose``; OPS-2)."""
        if not set(body) <= {"indent"}:
            raise _bad_body("expected {indent?}")
        indent, target = _indent(body.get("indent", 0))
        record = self._ready(onboarding, owner)
        if record.stage == "registered":
            return self._fragment_answer(record, indent, target)
        if record.options.client_id is None:
            raise _bad_body("this onboarding registers its client: register makes its fragment")
        if record.options.secret_given:
            raise _bad_body("this client's secret comes with register, which makes its fragment")
        return await self._finish(record, owner, None, indent, target)

    async def cancel(self, onboarding: str, *, owner: str = CLI_OWNER) -> None:
        """Drop the owner's onboarding; another owner's answers as an unknown one (X24)."""
        self._sweep()
        ended = self._table.cancel(onboarding, owner)
        if ended is None:
            raise OnboardError(refusal("onboarding_unknown"))
        logs.event("onboard_ended", why=ended.why)

    def cancel_owner(self, owner: str) -> None:
        """A portal session ended: its onboarding goes with it (D.8)."""
        for ended in self._table.cancel_owner(owner):
            logs.event("onboard_ended", why=ended.why)

    def _ready(self, onboarding: str, owner: str) -> OnboardingRecord:
        """The owner's onboarding, discovered or registered; a blocked one answers its
        refusal again, with the hosts its proxy needs."""
        self._sweep()
        try:
            record = self._table.get(onboarding, owner)
        except OnboardingRefused as exc:
            raise OnboardError(_table_refusal(exc)) from None
        if record.stage == "blocked":
            raise OnboardError(self._blocked_answer(record, self._policy(), None))
        if record.stage == "discovering":
            raise OnboardError(refusal("onboarding_unknown"))
        return record

    async def _registration(self, record: OnboardingRecord, owner: str) -> dict[str, Any]:
        """D.4's registration: the draft check again with the client the request asks for
        (OPS-5), the one POST of public metadata to the registration endpoint, its answer
        checked (X7), then D.7's write path with the client it made: a confidential client's
        secret, or a public client's ID as ``<credential>-client-id`` (OPS-2). A timeout is
        ``dcr_failed``: the server may have registered a client all the same (D-155), and a run
        again registers anew (FM-9)."""
        plan = _plan(record)
        meta = plan.metadata
        endpoint = meta.registration_endpoint
        assert endpoint is not None  # noqa: S101 - discovery refused a plan without one
        method: dcr.AuthMethod = _checked_dcr(dcr.request_auth(meta.token_auth_methods))
        drafted = replace(record, client=_predicted(record))
        _passes(self._findings(self._policy(), self._change(drafted)))
        choices = dcr.Choices(
            record.names.server, _redirect(record), method, record.options.client_name
        )
        request = dcr.registration_request(plan, choices)
        # Still this owner's and still discovered, so a run that has expired never registers.
        self._discovered(record, owner)
        fetcher = Fetcher(
            self._client,
            proxied=self._egress_proxy is not None,
            onboarding=record.id,
            clock=self._clock,
            report=_report,
        )
        try:
            fetched = await _fetched(
                fetcher.register(endpoint, dcr.request_body(request)), purpose="registration"
            )
        except ProxyRefused as exc:
            # The onboarding stays discovered: the same command again registers once the proxy
            # allows the host (D.11).
            raise OnboardError(self._registration_blocked(exc)) from None
        made = _checked_dcr(dcr.check_registration(fetched.status, fetched.document, request))
        client = Client(
            made.client_id, made.auth, made.expires_at, dcr.notes(fetched.document or {})
        )
        value = made.client_id if made.client_secret is None else made.client_secret.reveal()
        return await self._finish(record, owner, value, client=client)

    def _registration_blocked(self, exc: ProxyRefused) -> Answer:
        """An operator's own proxy refusing the registration endpoint (D.11): its host and the
        lines to allow it, the onboarding kept as it was."""
        policy = self._policy()
        emitted = {d.port for d in egresslist.derive(policy)[egresslist.VAULT]}
        step = allow_hosts([(exc.host, exc.port)], policy.egress_proxy_acls, emitted)
        more = (
            ("host", exc.host),
            ("port", exc.port),
            ("status", exc.status),
            ("next", [step.answer()]),
        )
        return replace(refusal("proxy_refused", host=exc.host), more=more)

    async def _finish(
        self,
        record: OnboardingRecord,
        owner: str,
        secret: str | None,
        indent: int = 0,
        target: Target = "plain",
        *,
        client: Client | None = None,
    ) -> dict[str, Any]:
        """D.7's write path: the draft check again, the secret under the predicted binding, the
        final check, then fragment 1. Whatever fails after the write deletes the secret again
        in the same run, and the answer says so, so a run again never meets ``name_taken`` on
        this run's own leftover (OPS-5). A re-registration's write replaced the committed
        credential's secret, which the running policy still uses: that one is put back. With
        the ``client`` a registration made, ``secret`` is its secret, or a public client's ID,
        written as its ``-client-id`` entry (D.8)."""
        plan = _plan(record)
        record = replace(record, client=client)
        change = self._change(record)
        _passes(self._findings(self._policy(), change))
        text = _emitted(change, indent, target)
        if secret is None:
            return self._register(record, owner, change, text)
        via: secretops.Via = "socket" if owner == CLI_OWNER else "portal"
        name = _entry_name(record.names.credential, secret=client_options(record).secret_given)
        planned = self._secret_plan(record, plan, name, secret)
        previous = self._previous(name) if record.options.reregister else None
        # Still this owner's and still discovered, so a run that has expired never writes.
        self._discovered(record, owner)
        written = await secretops.put(self._store, self._tokens, planned, via=via)
        undone = _DELETED if previous is None else _RESTORED
        try:
            if isinstance(written, SecretRefusal):
                # The store's only refusal of a plan without oauth: kept in memory alone, and
                # deleted or put back below, so nothing changed.
                raise OnboardError(refusal("not_written"))
            return self._register(record, owner, change, text, undone=undone)
        except OnboardError as exc:
            if previous is not None:
                entry, value = previous
                await secretops.restore(self._store, entry, value, via=via)
                raise OnboardError(_undone(exc.answer, "secret_restored")) from None
            deleting = secretplan.plan_delete(name, self._policy())
            await secretops.delete(self._store, self._tokens, deleting, via=via)
            raise OnboardError(_undone(exc.answer, "secret_deleted")) from None

    def _previous(self, name: str) -> tuple[EntryMeta, Secret] | None:
        """The committed client secret a re-registration's write replaces, as it is stored, for
        a failure after the write to put back. One the store can't read (or doesn't have) is
        already of no use to the running credential, so the failure deletes as a first run's
        does."""
        entry = self._store.entry(name)
        if entry is None:
            return None
        try:
            return entry, self._store.get_for_binding(name, entry.binding)
        except SecretUnavailable:
            return None

    def _discovered(self, record: OnboardingRecord, owner: str) -> None:
        """The onboarding as ``_ready`` found it, still: not expired, cancelled or replaced
        since."""
        try:
            current = self._table.get(record.id, owner)
        except OnboardingRefused as exc:
            raise OnboardError(_table_refusal(exc)) from None
        if current.stage != "discovered":
            raise OnboardError(refusal("onboarding_unknown"))

    def _register(
        self,
        record: OnboardingRecord,
        owner: str,
        change: PolicyChange,
        text: str,
        *,
        undone: str | None = None,
    ) -> dict[str, Any]:
        """The final check, then the onboarding registered with fragment 1 (E.2). ``undone``,
        after a secret was written, says what a failure does with it."""
        plan = _plan(record)
        policy = self._policy()
        findings = self._findings(policy, change)
        if any(finding.level == "error" for finding in findings):
            raise OnboardError(_diff_invalid(findings, undone=undone))
        try:
            record = self._table.registered(record.id, owner, change, record.client)
        except (OnboardingRefused, ValueError):
            # Expired, cancelled or replaced while the secret was written.
            raise OnboardError(refusal("onboarding_unknown")) from None
        options = client_options(record)
        logs.event(
            "onboard_registered",
            credential=record.names.credential,
            issuer=_issuer_host(plan),
            auth=_client_auth(options),
            secret_stored=undone is not None and options.secret_given,
        )
        return self._registered(record, text, findings, policy)

    def _secret_plan(
        self, record: OnboardingRecord, plan: Plan, name: str, secret: str
    ) -> secretplan.OnboardPutPlan:
        """The given secret's write, in the store under the binding fragment 1 will derive for
        it: the token endpoint, and the server's origin as its route's upstream (D.7 steps
        1-4). A registration's entry also names the client's authentication and redirect
        address, which a run after a restart takes on to show the same fragment 1 (step 6)."""
        binding = _binding(record, plan)
        client = record.client
        meta: dict[str, Any] = {
            "onboarded": _issuer_host(plan),
            "resource": plan.resource,
            "client_id": client_options(record).client_id,
            "client_secret_expires_at": None if client is None else client.expires_at,
        }
        if client is not None:
            meta |= {"client_auth": client.client_auth, "redirect_uri": _redirect(record)}
        store_names = self._store.names()
        if record.options.reregister:
            # A re-registration replaces the committed client's secret (D.7 step 1, OPS-3).
            store_names = [entry for entry in store_names if entry != name]
        planned = secretplan.plan_onboard_secret(
            name, secret, binding, meta, store_names=store_names
        )
        if isinstance(planned, SecretRefusal):
            raise OnboardError(secret_refusal(planned, name=name))
        return planned

    # --- answers -------------------------------------------------------------------------------

    def _next(self, record: OnboardingRecord, policy: Policy) -> list[dict[str, Any]]:
        # The ports the policy's emitted Squid file has an ACL for (I.6), so the blocked
        # answer defines only the others (D.11).
        emitted = {d.port for d in egresslist.derive(policy)[egresslist.VAULT]}
        steps = next_for(
            record,
            self._source,
            own_proxy=self._egress_proxy is not None,
            acl_names=policy.egress_proxy_acls,
            emitted_ports=emitted,
        )
        return [step.answer() for step in steps]

    def _expires(self, record: OnboardingRecord) -> int:
        return int(self._wall() + record.expires_at - self._clock())

    def _plan_answer(
        self, record: OnboardingRecord, policy: Policy, kept: _Kept | None = None
    ) -> dict[str, Any]:
        """The plan (D.8, M.1): every host, endpoint and choice, the names, the draft check and
        what to do next; for a kept secret (D.7 step 6), where its client ID came from; for a
        client the vault registers, where and with what authentication and name."""
        plan, names = _plan(record), record.names
        options = _planned_options(record)
        meta = plan.metadata
        redirect = _redirect(record)
        kind = application_type(redirect)
        method = _registration_method(record.options)
        notes = list(plan.notes)
        if not _own_redirect(redirect, names.credential):
            notes.append("backstop_off")
        if record.client is not None:
            notes += record.client.notes
        rows = [list(row) for row in plan.rows()]
        rows.append(
            [
                "Names",
                f"{names.credential}, {names.route}, {names.server} ({NAME_SOURCES[names.source]})",
            ]
        )
        if record.client is not None:
            rows.append(["Client", f"{record.client.client_id} (registered)"])
        elif method == "dcr":
            host = _host_port(str(meta.registration_endpoint))[0]
            rows += [
                ["Client", f"registered at {host} once you confirm (dynamic client registration)"],
                ["Client name", dcr.client_name(names.server, record.options.client_name)],
            ]
        else:
            rows.append(["Client", f"{options.client_id} ({_client_source(kept)})"])
        rows += [
            ["Client authentication", _client_auth(options)],
            ["Redirect", f"{redirect} ({kind})"],
        ]
        if kept is not None:
            label = "Client secret" if kept.secret else "Client ID entry"
            rows.append(
                [
                    label,
                    f"{kept.name}, stored by an earlier run; nothing is registered or stored again",
                ]
            )
        rows += [["Note", dcr.NOTES[note]] for note in notes if note in dcr.NOTES]
        if "backstop_off" in notes:
            rows.append(["Note", BACKSTOP_OFF])
        if options.reregister:
            rows.append(
                [
                    "Re-registration",
                    f"replaces credentials.{names.credential} and its stored client secret; "
                    "its route and server stay",
                ]
            )
        return {
            "onboarding": record.id,
            "stage": record.stage,
            "expires": self._expires(record),
            "names": {
                "credential": names.credential,
                "route": names.route,
                "server": names.server,
                "source": names.source,
            },
            "plan": {
                "server_url": plan.server_url,
                "resource": plan.resource,
                "resource_metadata": plan.resource_metadata,
                "resource_name": plan.resource_name,
                "issuer": plan.issuer,
                "issuer_source": plan.issuer_source,
                "metadata_url": plan.metadata_url,
                "authorization_endpoint": meta.authorization_endpoint,
                "token_endpoint": meta.token_endpoint,
                "registration_endpoint": meta.registration_endpoint,
                "revocation_endpoint": meta.revocation_endpoint,
                "require_iss": meta.require_iss,
                "pkce": PKCE_METHOD,
                "registration": method,
                "client_id": _shown_client_id(record, options),
                "client_auth": _client_auth(options),
                "secret_given": options.secret_given,
                "redirect_uri": redirect,
                "application_type": kind,
                "scopes": list(plan.scopes.scopes),
                "scope_source": plan.scopes.source,
                "offline_access_added": plan.scopes.offline_access_added,
                "hosts": list(plan.hosts),
                "notes": notes,
            },
            "rows": rows,
            "allowance": sorted(netguard.entry_key(h, p) for h, p in record.allowance),
            "draft_check": [finding.as_dict() for finding in record.draft_check],
            "next": self._next(record, policy),
        }

    def _registered(
        self, record: OnboardingRecord, text: str, findings: list[Finding], policy: Policy
    ) -> dict[str, Any]:
        """M.1's register answer: what was stored (never the value) and fragment 1; for a
        client the vault registered, its ID, when its secret expires, and the answer's notes."""
        options, client = client_options(record), record.client
        return {
            "onboarding": record.id,
            "stage": record.stage,
            "credential": record.names.credential,
            "client_id": options.client_id,
            "client_auth": _client_auth(options),
            "secret_stored": options.secret_given,
            "secret_name": secret_names(record.names.credential)[0]
            if options.secret_given
            else None,
            "client_secret_expires_at": None if client is None else client.expires_at,
            "notes": [] if client is None else list(client.notes),
            "diff": {"yaml": text, "check": [finding.as_dict() for finding in findings]},
            "next": self._next(record, policy),
        }

    def _fragment_answer(
        self, record: OnboardingRecord, indent: int, target: Target
    ) -> dict[str, Any]:
        """A registered onboarding's fragment 1 again (OPS-2), checked against the policy now."""
        change = record.change
        assert change is not None  # noqa: S101 - a registered record holds its change
        policy = self._policy()
        return self._registered(
            record, _emitted(change, indent, target), self._findings(policy, change), policy
        )

    def _sweep(self) -> None:
        """Log every onboarding that ended since the last call: replaced, expired, or registered
        with its credential now in the running policy."""
        for ended in self._table.sweep(self._policy().credentials):
            logs.event("onboard_ended", why=ended.why)


# --- the request ---------------------------------------------------------------------------------


def _request(body: Mapping[str, Any]) -> tuple[str, dict[str, str], Options]:
    """A discovery's body: the server URL (B.4's rule for a typed URL), the names given, and
    the options, each checked so fragment 1 can hold it."""
    unknown = set(body) - DISCOVER_KEYS
    if unknown:
        raise _bad_body(f"unknown keys: {', '.join(sorted(unknown))}")
    strings: dict[str, str] = {}
    for key, value in body.items():
        if key in FLAG_KEYS:
            if not isinstance(value, bool):
                raise _bad_body(f"{key} is true or false")
        elif not isinstance(value, str):
            raise _bad_body(f"{key} is a string")
        else:
            strings[key] = value
    allow_private = bool(body.get("allow_private", False))
    if "url" not in strings:
        raise _bad_body("url is required")
    url = typed_url(strings["url"], purpose="url", allow_private=allow_private)
    if isinstance(url, Refusal):
        raise OnboardError(_discovery_refusal(url))
    issuer = strings.get("issuer")
    if issuer is not None:
        checked = typed_url(issuer, purpose="issuer")
        if isinstance(checked, Refusal):
            raise OnboardError(_discovery_refusal(checked))
    given: dict[str, str] = {
        key: strings[key] for key in ("name", "credential", "route", "server") if key in strings
    }
    for key, value in given.items():
        if not _NAME.fullmatch(value):
            raise _bad_body(f"{key} isn't a policy name")
    scope = strings.get("scope")
    if scope is not None:
        tokens = scope.split(" ")
        if (
            len(tokens) > MAX_SCOPES
            or len(scope) > SCOPE_TEXT_MAX
            or not all(_SCOPE_TOKEN.fullmatch(t) and "$" not in t for t in tokens)
        ):
            raise _bad_body("scope is up to 64 scope tokens, one space apart, with no $")
    client_id = strings.get("client_id")
    if client_id is not None and not _CLIENT_ID.fullmatch(client_id):
        raise _bad_body("client_id is printable ASCII without a space, a quote, \\ or $")
    client_auth = strings.get("client_auth")
    if client_auth is not None and client_auth not in ("none", "basic", "post"):
        raise _bad_body("client_auth is none, basic or post")
    redirect = strings.get("redirect_uri")
    if redirect is not None:
        try:
            _check_redirect_uri(redirect)
        except ValueError as exc:
            raise _bad_body(f"redirect_uri: {exc}") from None
        if "$" in redirect:
            raise _bad_body("redirect_uri holds a $")
    client_name = strings.get("client_name")
    if client_name is not None and not _CLIENT_NAME.fullmatch(client_name):
        raise _bad_body("client_name is 1 to 64 printable ASCII characters")
    callback_origin = strings.get("callback_origin")
    if callback_origin is not None and (client_id is not None or redirect is not None):
        # D.4: the portal's callback is for a client the vault registers, unless told otherwise.
        raise _bad_body(
            "callback_origin goes with a registration, without client_id or redirect_uri"
        )
    try:
        options = Options(
            client_id=client_id,
            client_auth=client_auth,  # type: ignore[arg-type]
            redirect_uri=redirect,
            issuer=issuer,
            scope=scope,
            client_name=client_name,
            allow_private=allow_private,
            secret_given=bool(body.get("secret_given", False)),
            reregister=bool(body.get("reregister", False)),
            callback_origin=callback_origin,
        )
    except ValueError as exc:
        raise _bad_body(str(exc)) from None
    return url, given, options


def _names_match(url: str, given: Mapping[str, str], names: Names) -> bool:
    """Whether the names a run gives (none, or the same) are an onboarding's."""
    return not given or choose_names(url, lambda name: False, **given).same(names)


def _committed_names(url: str, given: Mapping[str, str], found: Committed | None) -> Names:
    """The names a second run or a re-registration works under: the committed credential's,
    route's and server's (D.12). Names given must be those."""
    if found is None:
        raise _bad_body("nothing in the running policy onboards this URL: run without --reregister")
    names = Names(found.credential, found.route, found.server)
    if not _names_match(url, given, names):
        raise _bad_body(
            f"this URL is onboarded as credential {found.credential}, route {found.route} and "
            f"server {found.server}: give those names, or none"
        )
    return names


def _indent(value: object) -> tuple[int, Target]:
    """A fragment's indent: 0 to 16 spaces, or ``compose`` (H.2)."""
    if value == "compose":
        return COMPOSE_INDENT, "compose"
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= INDENT_MAX:
        raise _bad_body(f"indent is 0 to {INDENT_MAX}, or compose")
    return value, "plain"


# --- helpers -------------------------------------------------------------------------------------


async def _fetched[T](call: Awaitable[T], *, purpose: str = "discovery") -> T:
    """A fetch's answer, or its refusal as the catalogue words it. A proxy's refusal passes
    through for D.11. A registration that gets no usable answer, a timeout among them, is
    ``dcr_failed`` (FM-9)."""
    try:
        result = await call
    except FetchError as exc:
        if exc.reason == "address_refused":
            logs.event(
                "address_refused",
                purpose=purpose,
                host=exc.host,
                port=exc.port,
                verdict=exc.why,
            )
        if purpose == "registration" and exc.reason == "fetch_failed":
            raise OnboardError(refusal("dcr_failed", detail=_failure(exc))) from None
        raise OnboardError(_fetch_refusal(exc)) from None
    return result


def _checked[T](value: T | Refusal) -> T:
    if isinstance(value, Refusal):
        raise OnboardError(_discovery_refusal(value))
    return value


def _report(record: FetchRecord) -> None:
    logs.event(
        "discovery_fetch",
        fetch_kind=record.kind,  # "kind" is the logger's own argument
        host=record.host,
        port=record.port,
        status=record.status,
        bytes=record.bytes,
        ms=record.ms,
        via=record.via,
    )


def _failure(exc: FetchError) -> str:
    return exc.why if exc.status is None else f"{exc.why}, HTTP {exc.status}"


def _fetch_refusal(exc: FetchError) -> Answer:
    if exc.reason == "fetch_failed":
        return refusal("fetch_failed", host=exc.host, detail=_failure(exc))
    return refusal(exc.reason, host=exc.host)


def _checked_dcr[T](value: T | dcr.Refusal) -> T:
    if isinstance(value, dcr.Refusal):
        raise OnboardError(_dcr_refusal(value))
    return value


def _dcr_refusal(found: dcr.Refusal) -> Answer:
    """A registration's refusal (D.4, X7) with what its text names: a ``dcr_refused``'s
    filtered error code, its cleaned description beside it for the operator (never logged),
    a ``dcr_failed``'s status, the member a ``dcr_answer_invalid`` is about. Nothing else of
    the answer is shown."""
    if found.reason == "dcr_refused":
        answer = refusal("dcr_refused", error=found.values[0])
        said = found.values[1:]
        return replace(answer, more=(("description", said[0]),)) if said else answer
    if found.reason == "dcr_failed":
        return refusal("dcr_failed", detail=f"HTTP {found.values[0]}")
    if found.reason == "dcr_answer_invalid":
        return refusal("dcr_answer_invalid", detail=found.field)
    return refusal(found.reason)


def _discovery_refusal(found: Refusal) -> Answer:
    """A discovery refusal with the fields its text names. Only values the vault built or
    validated go beside it: the URLs tried, the issuers, the two resources."""
    reason, values = found.reason, found.values
    detail = " ".join(part for part in (found.field, found.why) if part) or "invalid"
    fields: dict[str, str] = {}
    more: tuple[tuple[str, Any], ...] = ()
    if reason in ("url_invalid", "prm_invalid", "as_metadata_invalid"):
        fields = {"detail": detail}
    elif reason == "endpoint_invalid":
        fields = {"field": found.field, "detail": found.why}
    elif reason == "url_dollar":
        fields = {"field": found.field}
    elif reason == "prm_resource_mismatch":
        fields = {"resource": values[0], "expected": values[1]}
    elif reason in ("as_choice_needed", "as_unknown"):
        fields = {"issuers": ", ".join(values)}
        more = (("issuers", list(values)),)
    elif reason in ("prm_not_found", "as_metadata_not_found"):
        more = (("tried", list(values)),)
    answer = refusal(reason, **fields)
    return replace(answer, more=more) if more else answer


def _already_configured(served: Served) -> Answer:
    """D.12 (OPS-14): a server reaches this URL with a credential that isn't oauth2."""
    answer = refusal("already_configured", server=served.server, kind=served.kind)
    more = (
        ("server", served.server),
        ("route", served.route),
        ("credential", served.credential),
        ("kind", served.kind),
        ("next", [remove_first(served).answer()]),
    )
    return replace(answer, more=more)


def _by_hand(credential: str, field: str, why: str) -> OnboardError:
    """D-184: a re-registration whose fragment can't carry what the credential sets."""
    return OnboardError(refusal("reregister_by_hand", credential=credential, field=field, why=why))


def _table_refusal(exc: OnboardingRefused) -> Answer:
    if exc.reason == "name_taken":
        return refusal("name_taken", name=exc.values[0])
    return refusal(exc.reason)


def _undone(answer: Answer, key: str) -> Answer:
    """A refusal after the client secret was written, which this run then deleted
    (``secret_deleted``, OPS-5) or, a re-registration's, replaced by the committed one again
    (``secret_restored``)."""
    return replace(answer, more=(*answer.more, (key, True)))


def _diff_invalid(findings: list[Finding], *, undone: str | None) -> Answer:
    errors = [f"{f.path}: {f.message}" for f in findings if f.level == "error"]
    detail = "; ".join(errors[:5])
    if undone is not None:
        detail += f"; {undone}"
    answer = refusal("diff_invalid", detail=detail)
    return replace(answer, more=(("check", [f.as_dict() for f in findings]),))


def _passes(findings: list[Finding]) -> None:
    if any(finding.level == "error" for finding in findings):
        raise OnboardError(_diff_invalid(findings, undone=None))


def _emitted(change: PolicyChange, indent: int, target: Target) -> str:
    try:
        return emit(change, indent=indent, target=target)
    except EmitRefused as exc:
        raise OnboardError(refusal("diff_invalid", detail=f"{exc.path}: {exc.reason}")) from None


def _binding(record: OnboardingRecord, plan: Plan) -> dict[str, Any]:
    """The binding fragment 1 derives for the client secret (D.7 step 2): the token endpoint,
    and the server's origin as its route's upstream."""
    return oauth_binding(plan.metadata.token_endpoint, [origin_of(record.server_url)])


def _client_source(kept: _Kept | None) -> str:
    if kept is not None and kept.from_meta:
        return "from the stored client secret's entry"
    return "given"


def _plan(record: OnboardingRecord) -> Plan:
    assert record.plan is not None  # noqa: S101 - discovered and registered records hold one
    return record.plan


def _client_auth(options: Options) -> str:
    return options.client_auth or "none"


def _redirect(record: OnboardingRecord) -> str:
    """The onboarding's redirect address (D.4): the operator's, the shared one for a given
    client, else the credential's own, paste or on the portal origin named."""
    options = record.options
    return dcr.redirect_for(
        record.names.credential,
        options.callback_origin,
        options.redirect_uri,
        given=options.client_id is not None,
    )


def _registration_method(options: Options) -> str:
    """How the onboarding gets its client: ``given``, or ``dcr`` (D.4)."""
    return "given" if options.client_id is not None else "dcr"


def _predicted(record: OnboardingRecord) -> Client | None:
    """The client a registration the vault is still to make is expected to give (D.8's
    draft): a placeholder ID and the authentication the request asks for. None for a given
    client, or one already registered."""
    if record.client is not None or record.options.client_id is not None or record.plan is None:
        return None
    method = dcr.request_auth(record.plan.metadata.token_auth_methods)
    if isinstance(method, dcr.Refusal):
        return None
    return Client(DRAFT_CLIENT_ID, dcr.METHODS[method])


def _shown_client_id(record: OnboardingRecord, options: Options) -> str | None:
    """The client ID the plan shows: none yet for a client the vault is still to register."""
    if record.client is None and record.options.client_id is None:
        return None
    return options.client_id


def _planned_options(record: OnboardingRecord) -> Options:
    """The options the plan shows: a registered client's, or the one a registration predicts,
    in a given client's place."""
    return client_options(record, _predicted(record))


def _entry_name(credential: str, *, secret: bool) -> str:
    """The store entry an onboarding writes for its client: the secret (D.7 step 1), or a
    registered public client's ID (D.8)."""
    return secret_names(credential)[0 if secret else 1]


def _usable_redirect(value: object) -> bool:
    """Whether an entry's meta names a redirect address fragment 1 can hold, as discovery's
    request checks one: the meta is clear text, so it is checked before it is shown again."""
    if not isinstance(value, str) or "$" in value:
        return False
    try:
        _check_redirect_uri(value)
    except ValueError:
        return False
    return True


def _own_redirect(redirect: str, credential: str) -> bool:
    """Whether the redirect address is the credential's own (D.4, D.6's backstop): its path
    ends in a segment that is the credential's name, as login's per-credential addresses do
    (``/callback/<credential>``, ``/oauth/callback/<credential>``). The shared default never
    is, whatever the credential is called."""
    if redirect == SHARED_REDIRECT:
        return False
    return urlsplit(redirect).path.rsplit("/", 1)[-1] == credential
