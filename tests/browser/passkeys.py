"""Passkeys for the browser tests: the browser's own WebAuthn stack over a virtual authenticator.

:class:`Passkeys` is what a test asks of an authenticator. :class:`CdpAuthenticator` answers it
in Chromium, Chrome and Edge through the DevTools protocol's ``WebAuthn`` domain: a CTAP2 platform
authenticator with resident keys and user verification, attached to one page (a tab); the
browser's native ceremony runs against it, so the page's ``webauthn.js`` and the vault see what a
real authenticator's answers look like. The domain is per page target: a second tab, or a second
browser (context), gets a copy (:meth:`CdpAuthenticator.copy_to`). It can hold a second
authenticator, turn user verification off (the next ceremony then fails at once with
``NotAllowedError``, as a cancelled prompt does) and remove a credential, and it records the
domain's events (``credentialAdded``, ``credentialAsserted``, ...), so a test can say no prompt
was answered.

The virtual device makes P-256 keys only, so it proves nothing about which algorithm a real
authenticator picks (manual item 1 stays by hand).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from playwright.sync_api import CDPSession, Page

# A platform authenticator that verifies its user, as a passkey provider does; it answers each
# ceremony at once (presence simulated), with no browser UI.
OPTIONS = {
    "protocol": "ctap2",
    "transport": "internal",
    "hasResidentKey": True,
    "hasUserVerification": True,
    "isUserVerified": True,
    "automaticPresenceSimulation": True,
}
EVENTS = ("credentialAdded", "credentialAsserted", "credentialUpdated", "credentialDeleted")


class Passkeys(Protocol):
    """An authenticator a test drives: what it holds, whether it verifies its user, its events."""

    events: list[tuple[str, dict[str, Any]]]

    def credentials(self, authenticator: str | None = None) -> list[dict[str, Any]]: ...

    def set_user_verified(self, verified: bool, authenticator: str | None = None) -> None: ...

    def remove(self, credential_id: str, authenticator: str | None = None) -> None: ...

    def copy_to(self, page: Page) -> Passkeys: ...


class CdpAuthenticator:
    """A virtual authenticator on ``page``, through CDP's ``WebAuthn`` domain."""

    def __init__(self, page: Page, *, credentials: list[dict[str, Any]] | None = None) -> None:
        self.page = page
        self.events: list[tuple[str, dict[str, Any]]] = []
        self._cdp: CDPSession = page.context.new_cdp_session(page)
        self._cdp.send("WebAuthn.enable", {"enableUI": False})
        for event in EVENTS:
            self._cdp.on(f"WebAuthn.{event}", self._recorder(event))
        self.authenticator = self.add_authenticator()
        for credential in credentials or []:
            self._cdp.send(
                "WebAuthn.addCredential",
                {"authenticatorId": self.authenticator, "credential": credential},
            )

    def _recorder(self, event: str) -> Callable[[dict[str, Any]], None]:
        def record(params: dict[str, Any]) -> None:
            self.events.append((event, params))

        return record

    def add_authenticator(self, transport: str = "internal") -> str:
        """Another authenticator on the page (two passkeys, say): its id. The last one added
        with presence simulated answers; :meth:`answering` picks. Chrome takes one platform
        (``internal``) authenticator a page, so a second is a security key (``usb``)."""
        options = {**OPTIONS, "transport": transport}
        added = self._cdp.send("WebAuthn.addVirtualAuthenticator", {"options": options})
        identifier: str = added["authenticatorId"]
        return identifier

    def answering(self, authenticator: str, others: list[str]) -> None:
        """Only ``authenticator`` answers the next ceremony: presence is simulated on it alone."""
        for other in others:
            self._presence(other, False)
        self._presence(authenticator, True)

    def _presence(self, authenticator: str, enabled: bool) -> None:
        self._cdp.send(
            "WebAuthn.setAutomaticPresenceSimulation",
            {"authenticatorId": authenticator, "enabled": enabled},
        )

    def credentials(self, authenticator: str | None = None) -> list[dict[str, Any]]:
        """What the authenticator holds (the first one added, unless ``authenticator`` names
        another): each credential's id, RP ID, user handle, counter and private key (a throwaway
        one, from a virtual device)."""
        answer = self._cdp.send(
            "WebAuthn.getCredentials", {"authenticatorId": authenticator or self.authenticator}
        )
        found: list[dict[str, Any]] = answer["credentials"]
        return found

    def set_user_verified(self, verified: bool, authenticator: str | None = None) -> None:
        """With ``False``, a ceremony that requires user verification (every one the vault
        starts) fails with ``NotAllowedError`` and no answer: a cancelled prompt. On the first
        authenticator, unless ``authenticator`` names another."""
        self._cdp.send(
            "WebAuthn.setUserVerified",
            {"authenticatorId": authenticator or self.authenticator, "isUserVerified": verified},
        )

    def remove(self, credential_id: str, authenticator: str | None = None) -> None:
        """Removes a credential from the first authenticator, unless ``authenticator`` names
        another."""
        self._cdp.send(
            "WebAuthn.removeCredential",
            {"authenticatorId": authenticator or self.authenticator, "credentialId": credential_id},
        )

    def copy_to(self, page: Page) -> CdpAuthenticator:
        """The same credentials on another page (a tab, or a page of another context). The copy
        starts at the counter they have now: sign with one copy at a time from here on, or the
        vault sees the counter go back."""
        return CdpAuthenticator(page, credentials=self.credentials())

    def asserted(self) -> int:
        """How many assertions the authenticator answered (``credentialAsserted`` events)."""
        return sum(1 for event, _ in self.events if event == "credentialAsserted")
