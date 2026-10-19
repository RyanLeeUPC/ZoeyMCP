"""The SMTP send's decisions (M4 design J.4, J.5). Pure, so each can be tested exhaustively.

- AUTH goes out only over a TLS session whose handshake completed: never in cleartext, and never
  on a session a proxy stripped STARTTLS from.
- A failure's meaning depends on how far the send got. Until the final dot of ``DATA`` is
  written, nothing was sent. After it, with no reply, the message may have been delivered: the
  outcome is ``unknown``, and nothing ever retries it.
"""

from __future__ import annotations

from typing import Final, Literal

Phase = Literal[
    "tunnel",
    "tls",
    "greeting",
    "ehlo",
    "starttls",
    "auth",
    "mail",
    "rcpt",
    "data",
    "content",
    "final_reply",
]
Outcome = Literal["sent", "failed", "unknown"]
PHASES: Final[tuple[Phase, ...]] = (
    "tunnel",
    "tls",
    "greeting",
    "ehlo",
    "starttls",
    "auth",
    "mail",
    "rcpt",
    "data",
    "content",
    "final_reply",
)

# The answer code for a send that failed before anything was sent, by where it failed (J.5).
FAILED_CODES: Final[dict[Phase, str]] = {
    "tunnel": "smtp_unreachable",
    "tls": "smtp_tls_failed",
    "greeting": "smtp_failed",
    "ehlo": "smtp_failed",
    "starttls": "smtp_tls_failed",
    "auth": "smtp_auth_failed",
    "mail": "smtp_refused",
    "rcpt": "smtp_refused",
    "data": "smtp_refused",
    "content": "smtp_failed",
    "final_reply": "smtp_refused",
}


def may_authenticate(tls_active: bool, handshake_done: bool) -> bool:
    """AUTH only over an established TLS session."""
    return tls_active and handshake_done


def outcome(phase: Phase, final_dot_written: bool, reply_code: int | None) -> Outcome:
    """What a send that ended in ``phase`` did.

    ``reply_code`` is the final reply to ``DATA``'s content, if one came.
    """
    if phase != "final_reply":
        return "failed"  # an incomplete DATA is discarded by the server
    if not final_dot_written:
        return "failed"
    if reply_code is None:
        return "unknown"
    return "sent" if 200 <= reply_code < 300 else "failed"


def answer_code(phase: Phase, result: Outcome) -> str:
    """The connector's answer code for a send that didn't simply succeed."""
    if result == "unknown":
        return "smtp_outcome_unknown"
    return FAILED_CODES[phase]
