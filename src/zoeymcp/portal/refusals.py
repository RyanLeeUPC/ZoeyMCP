"""The portal's refusals (M5 design M.2): every answer's ``reason`` and the sentence it shows.

Every refusal is ``{"error": "<plain text>", "reason": "<code>"}``. The deciding functions
elsewhere give a stable reason (a :class:`~.webauthn.WebAuthnError`'s, a ``SecretRefusal``'s, a
``LoginError``'s, admission's); this is where each becomes a sentence, so the texts are testable
and operations.md's troubleshooting table can be rendered from them. The page shows ``error`` as
it is; it words only what the browser itself refuses (K.2).

A text may name a value the portal didn't write (a secret name, a policy URL, a provider's error
code): each such field passes :func:`.display.shown` first.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from string import Formatter
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Final

from .display import SUMMARY_LIMIT, shown
from .webauthn import MAX_PASSKEYS, Reason

if TYPE_CHECKING:
    from ..vault.secretplan import SecretRefusal


@dataclass(frozen=True)
class Refusal:
    """An answer the portal refuses with: its status, and :meth:`body`, sent with C.3's
    headers. ``more`` adds fields beside the text, each already fit to show (a provider's
    description, the bindings a ``binding_changed`` compares)."""

    status: int
    reason: str
    error: str
    more: tuple[tuple[str, Any], ...] = ()

    def body(self) -> dict[str, Any]:
        return {**dict(self.more), "error": self.error, "reason": self.reason}


@dataclass(frozen=True)
class Entry:
    """A catalogued reason: its status and its text, whose ``{field}`` names are filled in."""

    status: int
    text: str


_SAME_PAGE: Final = "Refused: this request didn't come from the portal's own page."
_TOO_MANY: Final = "Too many requests right now. Wait a moment and try again."
_EXPIRED: Final = (
    "That confirmation, login or passkey prompt expired or was already used. Start again."
)
_FIX_POLICY: Final = "The policy can't bind it: {detail}. Fix the policy."
_CALLBACK: Final = (
    "The portal didn't take this sign-in. Copy this tab's address and paste it into the "
    "portal's Connect dialog, or into zoeymcp login if you started it there."
)

CATALOGUE: Final[Mapping[str, Entry]] = MappingProxyType(
    {
        # Admission (C.2).
        "wrong_host": Entry(
            421,
            "This portal doesn't answer to that address. Use one listed in admin.origins; "
            "behind a proxy, pass the original Host header.",
        ),
        "method": Entry(405, "The portal doesn't answer that method."),
        "not_found": Entry(404, "Nothing by that name exists here."),
        "cross_site": Entry(403, _SAME_PAGE),
        "bad_origin": Entry(403, _SAME_PAGE),
        "content_type": Entry(415, "The request wasn't JSON."),
        "length_required": Entry(411, "The request didn't say how long its body is."),
        "too_large": Entry(413, "The request was too large."),
        "busy": Entry(503, _TOO_MANY),
        "rate_limited": Entry(429, _TOO_MANY),
        "no_session": Entry(
            401, "You're signed out (the session ended, or the vault restarted). Sign in again."
        ),
        "scope": Entry(
            403, "A setup session can only enrol a passkey. Sign in with your passkey first."
        ),
        "too_slow": Entry(408, "The request was too slow."),
        "bad_json": Entry(400, "The request wasn't valid JSON."),
        "bad_body": Entry(400, "The request didn't have the expected fields."),
        # Sessions, passkeys and step-up (D, E, F).
        "setup_code_refused": Entry(
            401,
            "That setup code isn't valid. Codes work once, for 15 minutes. If you haven't used "
            "it, someone else may have: run zoeymcp setup-code --reset.",
        ),
        "passkey_refused": Entry(
            401,
            "That passkey wasn't accepted here. Passkeys belong to one address: use the one you "
            "enrolled it on, or a setup code.",
        ),
        "step_up_refused": Entry(
            401, "The passkey didn't confirm this. Nothing changed; prepare it again."
        ),
        "unavailable": Entry(
            503,
            "The passkey file can't be verified (edited, or written under another master key). "
            "Run zoeymcp setup-code --reset with host access.",
        ),
        "changed": Entry(
            409,
            "Something changed since you prepared this (shown below). Check it and prepare it "
            "again.",
        ),
        "action_unknown": Entry(404, _EXPIRED),
        "ceremony_unknown": Entry(404, _EXPIRED),
        "last_passkey": Entry(
            409, "This is the only passkey. Enrol another first, or use zoeymcp setup-code --reset."
        ),
        # Two credentials whose keyed fingerprints collide (D.4): neither is chosen.
        "ambiguous_fingerprint": Entry(
            409,
            "More than one passkey has that fingerprint, so nothing changed. Run zoeymcp "
            "setup-code --reset with host access.",
        ),
        "bad_name": Entry(
            400, "A passkey name is 1 to 64 characters on one line, with no hidden characters."
        ),
        "not_written": Entry(500, "Not written to disk; nothing changed; check the state volume."),
        "internal": Entry(500, "The portal failed to answer that; the vault's log has the cause."),
        # Secrets (G); the socket keeps its own texts.
        "invalid_name": Entry(
            400,
            "Names are lower case letters, digits and _ . -, up to 128, starting with a letter "
            "or a digit.",
        ),
        "vault_managed": Entry(
            409, "Tokens for this credential come from Connect, on the Credentials page."
        ),
        "empty_value": Entry(400, "Enter a value."),
        "bad_value": Entry(400, "The value has line breaks, control or invisible characters."),
        "value_too_large": Entry(409, "A secret can't be larger than 65536 bytes."),
        "origins_type": Entry(400, "Origins are a list of https URLs."),
        "origins_on_oauth": Entry(409, "OAuth secrets take the policy's binding."),
        "bad_origins": Entry(409, "That origin can't be used: {detail}."),
        "unbound": Entry(
            409,
            "No route or connector uses store:{name}, so give the origins it may be sent to.",
        ),
        "no_route": Entry(409, _FIX_POLICY),
        "orphan_slot": Entry(409, _FIX_POLICY),
        "binding_conflict": Entry(409, _FIX_POLICY),
        # OAuth connect (H); statuses as the socket answers them.
        "not_oauth": Entry(404, "That isn't an OAuth credential in the policy."),
        "flow_unknown": Entry(404, _EXPIRED),
        "no_authorize_url": Entry(
            409, "This credential has no authorize_url, so it can't connect in a browser."
        ),
        "authorize_misconfigured": Entry(
            409, "The policy's authorization settings can't make a sign-in link. Fix the policy."
        ),
        "binding_changed": Entry(
            409,
            "The policy now binds this grant differently (shown below). Connect again and "
            "accept the new binding.",
        ),
        "client_id_unavailable": Entry(
            409,
            "The client ID isn't set, or isn't bound to the token endpoint. Set it on the "
            "Secrets page.",
        ),
        "client_secret_unavailable": Entry(
            409,
            "The client secret isn't set, or isn't bound to the token endpoint. Set it on the "
            "Secrets page.",
        ),
        # An onboarded client's secret, bound before the commit (M7 D.7).
        "client_secret_binding_changed": Entry(
            409,
            "The committed token endpoint or server origin differs from the ones this client was "
            "registered with. Onboard again, or set the secret with zoeymcp secret set.",
        ),
        "not_configured": Entry(400, "The vault has no token settings for this credential."),
        "too_many_flows": Entry(
            429, "Too many sign-ins are pending. Finish or cancel one, or wait 10 minutes."
        ),
        "redirect_mismatch": Entry(
            400,
            "That isn't the address the provider sent you to; it starts with {redirect_uri}.",
        ),
        "state_mismatch": Entry(
            400, "That address belongs to another login; use the tab this login opened."
        ),
        "duplicate_param": Entry(
            400, "That address has a parameter twice. Copy it again from the address bar."
        ),
        "provider_error": Entry(400, "The answer said the provider refused: {error}"),
        "iss_mismatch": Entry(
            400, "The answer came from a different issuer; nothing was stored. Connect again."
        ),
        "no_code": Entry(400, "The provider's answer had no usable code. Connect again."),
        "exchange_failed": Entry(
            400, "The provider's token endpoint didn't take the sign-in ({code}). Connect again."
        ),
        "no_refresh_token": Entry(
            400,
            "The provider issued no refresh token. For Google keep access_type: offline and "
            "prompt: consent; some providers need an offline_access scope.",
        ),
        "flow_returned": Entry(
            409, "The provider already sent this sign-in back to the portal; confirm it here."
        ),
        "flow_conflict": Entry(
            409,
            "Two different answers came back for this sign-in. Nothing was stored. Connect again.",
        ),
        # The callback (C.7): one fixed page, never JSON, never naming the cause.
        "callback_not_taken": Entry(400, _CALLBACK),
        "not_navigation": Entry(403, _CALLBACK),
        "bad_query": Entry(400, _CALLBACK),
        # The reported ledger (J).
        "not_restartable": Entry(
            409, "The reported ledger isn't stuck, so there's nothing to restart."
        ),
        # M.2's 503 unavailable is the passkey file's: the copy has its own sentence.
        "copy_unavailable": Entry(
            503,
            "The vault's copy of the gateway's ledger can't be read: check the state volume. "
            "The proxy runs as before.",
        ),
        # Onboarding by URL: discovery (M7 B.4, D.2-D.5; vault/oauth/discovery.py).
        "url_invalid": Entry(
            400,
            "That address can't be onboarded ({detail}). Use an https URL without a query; a "
            "private host needs allow private.",
        ),
        "endpoint_invalid": Entry(
            502, "The server's {field} can't be used ({detail}), so nothing was sent to it."
        ),
        "url_dollar": Entry(
            502,
            "The server's {field} holds a $, which compose would read as a variable in the "
            "policy, so it isn't used.",
        ),
        "challenge_ambiguous": Entry(
            502,
            "The server's sign-in challenges name two different metadata addresses, so neither "
            "is used.",
        ),
        "scope_invalid": Entry(
            502,
            "The server names a scope a policy can't hold (a $, a quote, a backslash or a space "
            "in it, or too many), so nothing was registered.",
        ),
        "not_protected": Entry(
            409,
            "The server answered without asking for a sign-in and publishes no OAuth metadata. "
            "Add it to the policy by hand.",
        ),
        "prm_not_found": Entry(
            502,
            "The server publishes no protected-resource metadata, and no authorization server "
            "was found without it. Give its issuer, or add the server by hand.",
        ),
        "prm_invalid": Entry(
            502, "The server's protected-resource metadata can't be used ({detail})."
        ),
        "prm_resource_mismatch": Entry(
            502,
            "The server's metadata is for {resource}, not {expected}, so it isn't used (RFC 9728).",
        ),
        "dpop_required": Entry(
            502,
            "The server requires DPoP-bound tokens: the provider's tokens aren't Bearer tokens "
            "the vault can use.",
        ),
        "as_choice_needed": Entry(
            409, "The server names more than one authorization server. Choose one of {issuers}."
        ),
        "as_unknown": Entry(
            400, "That issuer isn't one the server names. Choose one of {issuers}."
        ),
        "as_metadata_not_found": Entry(
            502, "No metadata was found for the authorization server at the addresses tried."
        ),
        "as_metadata_invalid": Entry(
            502, "The authorization server's metadata can't be used ({detail})."
        ),
        "as_issuer_mismatch": Entry(
            502,
            "The authorization server's metadata names another issuer than the one it was "
            "fetched for, so it isn't used (RFC 8414).",
        ),
        "pkce_unsupported": Entry(
            502,
            "The authorization server doesn't advertise PKCE with S256, which MCP requires.",
        ),
        "code_flow_unsupported": Entry(
            502, "The authorization server doesn't advertise the authorization code flow."
        ),
        # A change to the policy (M7 H.1; common/policy/change.py), and an onboarding's names
        # (D.8; vault/onboarding.py).
        "name_taken": Entry(
            409,
            "The policy, the vault's store or another onboarding already has {name}. Choose "
            "another name.",
        ),
        "diff_invalid": Entry(
            422,
            "The running policy with this change merged fails check ({detail}), so no fragment "
            "is shown.",
        ),
        # Onboardings in progress (M7 D.8; vault/onboarding.py).
        "onboarding_unknown": Entry(
            404,
            "That onboarding isn't in progress: it finished, expired or was started elsewhere. "
            "Start it again.",
        ),
        "onboarding_busy": Entry(
            429,
            "At most 4 onboardings can be in progress. Finish or cancel one, or wait for one to "
            "expire (30 minutes).",
        ),
        "onboarding_options_changed": Entry(
            409,
            "The onboarding in progress for this URL and these names stopped at your proxy and "
            "was started with other options. Run it with the same options to carry on, or start "
            "again once it expires (30 minutes).",
        ),
        # The onboarding service (M7 D.4, D.11; vault/onboard.py).
        "registration_unavailable": Entry(
            409, "Register a client at {host} and run again with its client ID."
        ),
        "proxy_refused": Entry(
            502,
            "Your egress proxy refused the vault's connection to {host}. Allow the hosts listed "
            "here in it for the vault, then run the same command again.",
        ),
        # Phase 1's requests (M7 B.2, B.5; vault/oauth/fetch.py).
        "address_refused": Entry(
            502,
            "The vault doesn't connect to {host}: its name resolves to a private, loopback or "
            "reserved address. Nothing was sent to it.",
        ),
        "resolve_failed": Entry(502, "The name {host} didn't resolve, so nothing was sent to it."),
        "fetch_failed": Entry(502, "The host {host} didn't answer as needed ({detail})."),
        "fetch_redirect": Entry(
            502, "The host {host} answered with a redirect, which the vault doesn't follow."
        ),
        "fetch_too_large": Entry(
            502, "The answer from {host} is larger than the vault reads, so it isn't used."
        ),
        "fetch_not_json": Entry(
            502, "The answer from {host} isn't one JSON object, so it isn't used."
        ),
    }
)

# Enrolment refusals (D.3) go to a session that is already trusted, with their own sentence; a
# login answers passkey_refused and a step-up step_up_refused, whatever the reason.
WEBAUTHN: Final[Mapping[Reason, str]] = MappingProxyType(
    {
        "too_large": "The passkey's answer was too large.",
        "bad_field": "The browser's answer didn't have the passkey fields expected. Try another "
        "browser.",
        "client_data": "The browser's passkey data couldn't be read. Try another browser.",
        "wrong_type": "The browser answered a different kind of passkey prompt. Start again.",
        "wrong_challenge": "That passkey answer was for another prompt. Start again.",
        "wrong_origin": "The passkey answer names another address. Use the portal at the "
        "address you opened.",
        "cross_origin": "The passkey prompt ran inside another page. Open the portal directly.",
        "top_origin": "The passkey prompt ran inside another page. Open the portal directly.",
        "no_attested_data": "The authenticator didn't give a new key. Try again, or another "
        "authenticator.",
        "wrong_rp": "The passkey was made for another address. Use the one you enrolled it on.",
        "not_present": "The authenticator didn't confirm you were there. Try again.",
        "not_verified": "The passkey didn't verify you with a PIN or biometrics; the vault "
        "requires it.",
        "backup_flags": "The authenticator's backup flags contradict each other. Try another "
        "authenticator.",
        "credential_id": "The authenticator's credential ID can't be used. Try another "
        "authenticator.",
        "raw_id_mismatch": "The browser's credential ID doesn't match the authenticator's. Try "
        "another browser.",
        "key_encoding": "This authenticator's key encoding isn't supported.",
        "algorithm": "The browser reported another key type than the authenticator made. Try "
        "another browser.",
        "public_key": "The authenticator's key can't be used (ES256, Ed25519, or RSA of 2048 to "
        "4096 bits).",
        "key_mismatch": "The browser's copy of the new key doesn't match the authenticator's. "
        "Try another browser.",
        "duplicate_credential": "This passkey is already enrolled.",
        "too_many_passkeys": f"There are {MAX_PASSKEYS} passkeys already. Remove one first.",
        "not_allowed": "That passkey isn't one this prompt asked for.",
        "unknown_credential": "That passkey isn't enrolled here.",
        "user_handle": "That passkey belongs to another account.",
        "at_flag": "The authenticator's answer carried key data it shouldn't. Try again.",
        "trailing_bytes": "The authenticator's answer had bytes it shouldn't. Try again.",
        "backup_eligibility_changed": "This passkey's backup setting changed since it was "
        "enrolled. Enrol it again.",
        "signature": "The passkey's signature didn't verify.",
    }
)
_WEBAUTHN_CONFLICTS: Final = frozenset({"duplicate_credential", "too_many_passkeys"})

# A secret write that failed on disk is still in effect (G); a portal state write isn't.
KEPT_IN_MEMORY: Final = "Kept in memory, not written to disk; check the state volume."


def refusal(reason: str, **fields: str) -> Refusal:
    """The catalogued refusal for ``reason``, its text filled with exactly the ``fields`` it
    names. ``exchange_failed:<code>`` (M2) takes the ``exchange_failed`` text, with the code."""
    key, colon, code = reason.partition(":")
    if colon:
        fields = {**fields, "code": code}
    entry = CATALOGUE[key]
    return Refusal(entry.status, reason, _filled(entry.text, fields))


def enrolment(reason: Reason) -> Refusal:
    """The refusal of an enrolment the verifier refused (D.3): 409 when the passkey can't be
    added as things stand, else 400."""
    status = 409 if reason in _WEBAUTHN_CONFLICTS else 400
    return Refusal(status, reason, WEBAUTHN[reason])


def secret(plan: SecretRefusal, *, name: str) -> Refusal:
    """The portal's answer to a refused secret write or delete (G): the plan's status and reason,
    and the portal's text, which may name the secret or quote the policy's ``detail``."""
    text = KEPT_IN_MEMORY if plan.reason == "not_written" else CATALOGUE[plan.reason].text
    offered = {"name": name, "detail": plan.message}
    wanted = _names(text)
    return Refusal(
        plan.status, plan.reason, _filled(text, {k: v for k, v in offered.items() if k in wanted})
    )


def login(reason: str, *, detail: str, error: str | None = None, redirect_uri: str = "") -> Refusal:
    """A refused OAuth start, paste check or completion (H.3): the reason and status the socket
    answers (operations.md §2), and the portal's text, filled with what it names: ``detail``
    (the vault's own message, for a policy that can't bind the grant), the provider's filtered
    ``error`` code, or the credential's ``redirect_uri``. ``exchange_failed:<code>`` takes its
    code as :func:`refusal` does."""
    offered = {"detail": detail, "error": error or "no error code", "redirect_uri": redirect_uri}
    wanted = _names(CATALOGUE[reason.partition(":")[0]].text) - {"code"}
    return refusal(reason, **{k: v for k, v in offered.items() if k in wanted})


def wrong_host_literal(authority: str) -> Refusal:
    """C.2 row 1 for a ``Host`` that is a loopback IP literal: ``authority`` is ``localhost``
    with the literal's port."""
    return Refusal(
        421,
        "wrong_host",
        f"Passkeys don't work on IP addresses. Open http://{authority}/ instead.",
    )


def reasons() -> frozenset[str]:
    """Every reason an answer can carry, for the page's drift check (K.4)."""
    return frozenset(CATALOGUE) | frozenset(WEBAUTHN)


def _names(text: str) -> set[str]:
    return {name for _, name, _, _ in Formatter().parse(text) if name is not None}


def _filled(text: str, fields: Mapping[str, str]) -> str:
    if _names(text) != fields.keys():
        raise ValueError(f"the text names {sorted(_names(text))}, given {sorted(fields)}")
    return text.format_map({k: shown(v, SUMMARY_LIMIT) for k, v in fields.items()})
