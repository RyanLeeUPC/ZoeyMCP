"""The Telegram approver's wire rules (M8 design G.1, G.4, G.5; O.3 ``test_telegramwire.py``; Z13,
Z14, FM-14, FM-37).

UTF-16 counting with astral characters and the 4,096 boundary; the prompt's exact parameters (one
``pre`` entity over the whole text, its offsets in UTF-16 units, previews off, no parse mode, Deny
then Approve) and the too-long notice or refusal; the callback data at 38 bytes and its MAC;
reading what ``sendMessage`` returned; every press check in order, 6b included, and MAC tamper;
and the URL that holds the bot token, redacted in ``str`` and ``repr`` and refused by the logger.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import io
from typing import Any, get_args

import pytest
from hypothesis import given
from hypothesis import settings as hypothesis_settings
from hypothesis import strategies as st

from zoeymcp.common import logs
from zoeymcp.common.approvaltext import ApprovalText
from zoeymcp.common.policy.schema import TELEGRAM_API
from zoeymcp.vault import telegramwire
from zoeymcp.vault.holds import Hold
from zoeymcp.vault.telegramwire import (
    ANSWERS,
    API,
    CALLBACK_BYTES,
    KEY_BYTES,
    LABELS,
    NOT_PENDING,
    REFUSED,
    STRANGER,
    TELEGRAM_MAX_UTF16,
    TEXT_CHANGED,
    TOO_LONG,
    Enrolled,
    Message,
    Press,
    PressReason,
    PressRefusal,
    SecretUrl,
    Sent,
    TextChanged,
    TooLong,
    callback_data,
    fits,
    keyboard,
    mac,
    markup,
    method_url,
    new_key,
    press,
    refused_too_long,
    sent,
    too_long,
    utf16_len,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(1, 33))
HOLD_ID = "AbCdEfGh_-012345"
OTHER_ID = "ZyXwVuTs_-987654"
USER = 7362915048
CHAT = 7362915048
ENROLLED = Enrolled(user_id=USER, chat_id=CHAT)
MESSAGE_ID = 41
TEXT = (
    "Approval request 0123456789abcdef\nTool: mail \N{RIGHTWARDS ARROW} send\n\n"
    "End of approval request x"
)
TOKEN = "123456789:AAH-token_sentinel-0000000000000000000"
ASTRAL = "\U0001f600"  # outside the Basic Multilingual Plane: two UTF-16 units


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hold(
    text: str = TEXT, *, surfaces: frozenset[Any] = frozenset({"telegram"}), id: str = HOLD_ID
) -> Hold:
    return Hold(
        id=id,
        ref="0123456789abcdef",
        kind="held",
        epoch=None,
        legacy_session=False,
        route="mail",
        server="mail",
        tool="send",
        client="agent",
        args_digest="d" * 64,
        text=ApprovalText(text, frozenset(), ((0, None),)),
        text_sha256=digest(text),
        surfaces=surfaces,
        wait="pending",
        asked_at=1.0,
        block_until=121.0,
        deadline=3601.0,
        held_bytes=len(text),
    )


def prompt() -> Message:
    found = telegramwire.message(hold(), KEY)
    assert isinstance(found, Message)
    return found


def stored(text: str = TEXT) -> dict[str, Sent]:
    return {HOLD_ID: Sent(MESSAGE_ID, CHAT, digest(text), keyboard(KEY, HOLD_ID, digest(text)))}


def update(decision: str = "a") -> dict[str, Any]:
    """A genuine press on the prompt :func:`stored` describes, as getUpdates returns it."""
    buttons = keyboard(KEY, HOLD_ID, digest(TEXT))
    data = dict(buttons)["Approve" if decision == "a" else "Deny"]
    return {
        "update_id": 900,
        "callback_query": {
            "id": "4382bfdwdsb323b2d9",
            "from": {"id": USER, "is_bot": False, "first_name": "Operator"},
            "message": {
                "message_id": MESSAGE_ID,
                "date": 1793000000,
                "chat": {"id": CHAT, "type": "private"},
                "text": TEXT,
                "entities": [{"type": "pre", "offset": 0, "length": utf16_len(TEXT)}],
                "reply_markup": markup(buttons),
            },
            "chat_instance": "-1",
            "data": data,
        },
    }


def query(found: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = found["callback_query"]
    return result


# --- UTF-16 counting -----------------------------------------------------------------------------


def test_utf16_counts_code_units() -> None:
    assert utf16_len("") == 0
    assert utf16_len("abc") == 3
    assert isinstance(utf16_len("abc"), int)  # an entity's length is a JSON integer
    # Outside ASCII, inside the BMP: one unit each.
    assert utf16_len("\N{LATIN SMALL LETTER E WITH ACUTE}\N{RIGHTWARDS ARROW}") == 2
    assert utf16_len(ASTRAL) == 2
    assert utf16_len(f"a{ASTRAL}b") == 4
    assert utf16_len("\ud800") == 1  # a lone surrogate, which JSON can carry: one unit


@hypothesis_settings(max_examples=50, deadline=None)
@given(st.text(max_size=40))
def test_utf16_is_one_unit_per_character_and_two_per_astral_one(text: str) -> None:
    assert utf16_len(text) == sum(2 if ord(c) > 0xFFFF else 1 for c in text)


BOUNDARY = [
    ("at_the_limit", "a" * 4096, True),
    ("one_over", "a" * 4097, False),
    ("astral_at_the_limit", "a" * 4094 + ASTRAL, True),
    # 4,096 characters but 4,097 units: the count Telegram makes, not len().
    ("astral_one_over", "a" * 4095 + ASTRAL, False),
]


@pytest.mark.parametrize(("name", "text", "fit"), BOUNDARY, ids=[row[0] for row in BOUNDARY])
def test_the_4096_boundary(name: str, text: str, fit: bool) -> None:
    assert TELEGRAM_MAX_UTF16 == 4096
    assert fits(text) is fit
    assert (too_long(hold(text)) is None) is fit
    assert isinstance(telegramwire.message(hold(text), KEY), Message) is fit


# --- a prompt ------------------------------------------------------------------------------------


def test_the_prompt_is_the_text_exactly_in_one_pre_entity() -> None:
    text = f"{TEXT}\n{ASTRAL} two units"
    found = telegramwire.message(hold(text), KEY)
    assert isinstance(found, Message)
    assert found.text == text
    deny, approve = keyboard(KEY, HOLD_ID, digest(text))
    assert found.params(CHAT) == {
        "chat_id": CHAT,
        "text": text,
        "entities": [{"type": "pre", "offset": 0, "length": len(text) + 1}],
        "link_preview_options": {"is_disabled": True},
        "protect_content": True,
        "reply_markup": {
            "inline_keyboard": [
                [
                    {"text": "Deny", "callback_data": deny[1]},
                    {"text": "Approve", "callback_data": approve[1]},
                ]
            ]
        },
    }
    assert "parse_mode" not in found.params(CHAT)


def test_two_buttons_deny_first_and_no_other() -> None:
    assert LABELS == (("Deny", "d"), ("Approve", "a"))
    buttons = prompt().buttons
    assert [label for label, _ in buttons] == ["Deny", "Approve"]
    assert [data.split(".")[2] for _, data in buttons] == ["d", "a"]


def test_the_callback_data_is_38_bytes() -> None:
    assert CALLBACK_BYTES == 38
    for _, data in prompt().buttons:
        assert len(data.encode()) == CALLBACK_BYTES < 64
        version, id, letter, given_mac = data.split(".")
        assert (version, id) == ("v1", HOLD_ID)
        assert given_mac == mac(KEY, HOLD_ID, letter, digest(TEXT))


def test_the_mac_is_hmac_sha256_over_the_hold_the_decision_and_the_text() -> None:
    message = b"zoeymcp/telegram/v1\n" + f"{HOLD_ID}a{digest(TEXT)}".encode()
    expected = hmac.new(KEY, message, hashlib.sha256).digest()[:12]
    assert mac(KEY, HOLD_ID, "a", digest(TEXT)) == base64.urlsafe_b64encode(expected).decode()
    assert len(mac(KEY, HOLD_ID, "a", digest(TEXT))) == 16
    # Each input changes it.
    macs = {
        mac(KEY, HOLD_ID, "a", digest(TEXT)),
        mac(OTHER_KEY, HOLD_ID, "a", digest(TEXT)),
        mac(KEY, OTHER_ID, "a", digest(TEXT)),
        mac(KEY, HOLD_ID, "d", digest(TEXT)),
        mac(KEY, HOLD_ID, "a", digest("other")),
    }
    assert len(macs) == 5


@pytest.mark.parametrize("bad", ["", "AbCdEfGh_-01234", "AbCdEfGh_-0123456", "AbCdEfGh_.012345"])
def test_callback_data_needs_a_holds_id(bad: str) -> None:
    with pytest.raises(ValueError, match="16 base64url") as caught:
        callback_data(KEY, bad, "a", digest(TEXT))
    assert str(caught.value) == "a hold's id is 16 base64url characters"


def test_a_too_long_text_is_a_notice_when_the_portal_takes_it() -> None:
    text = "a" * 4097
    found = telegramwire.message(hold(text, surfaces=frozenset({"telegram", "portal"})), KEY)
    assert isinstance(found, TooLong)
    assert found.notice is not None
    assert found.notice.text == (
        "Approval request 0123456789abcdef: mail \N{RIGHTWARDS ARROW} send. This one is too "
        "long for this "
        "chat; decide it in the portal."
    )
    assert found.notice.buttons == ()
    assert found.notice.params(CHAT) == {
        "chat_id": CHAT,
        "text": found.notice.text,
        "link_preview_options": {"is_disabled": True},
        "protect_content": True,
    }


def test_a_too_long_text_is_refused_when_telegram_is_the_only_surface() -> None:
    found = too_long(hold("a" * 4097))
    assert found == TooLong(None)
    assert (found.code, found.status) == (TOO_LONG, 422) == ("telegram_too_long", 422)
    assert telegramwire.message(hold("a" * 4097), KEY) == TooLong(None)


REFUSED_BEFORE_BEGIN = [
    ("telegram_alone_over", "a" * 4097, {"telegram"}, True),
    ("telegram_alone_astral_over", "a" * 4095 + ASTRAL, {"telegram"}, True),
    ("telegram_alone_at_the_limit", "a" * 4096, {"telegram"}, False),
    ("with_the_portal_over", "a" * 4097, {"telegram", "portal"}, False),
    ("portal_alone_over", "a" * 4097, {"portal"}, False),
    ("no_surface_over", "a" * 4097, set(), False),
]


@pytest.mark.parametrize(
    ("name", "text", "surfaces", "refused"),
    REFUSED_BEFORE_BEGIN,
    ids=[row[0] for row in REFUSED_BEFORE_BEGIN],
)
def test_a_text_only_telegram_would_take_is_refused_before_the_hold(
    name: str, text: str, surfaces: set[str], refused: bool
) -> None:
    """G.4's refusal needs no hold, so the vault applies it before anyone is asked; it agrees
    with what :func:`too_long` does with a hold on Telegram."""
    assert refused_too_long(text, frozenset(surfaces)) is refused
    if "telegram" in surfaces:
        found = too_long(hold(text, surfaces=frozenset(surfaces)))
        assert (found == TooLong(None)) is refused


# --- what sendMessage returned -------------------------------------------------------------------


def returned(**changes: Any) -> dict[str, Any]:
    result: dict[str, Any] = {
        "message_id": MESSAGE_ID,
        "date": 1793000000,
        "chat": {"id": CHAT, "type": "private"},
        "text": TEXT,
    }
    result.update(changes)
    return result


def test_the_text_returned_as_sent_is_stored() -> None:
    sent_message = prompt()
    assert sent(sent_message, CHAT, returned()) == Sent(
        MESSAGE_ID, CHAT, digest(TEXT), sent_message.buttons
    )


CHANGED: list[tuple[str, dict[str, Any], int | None]] = [
    ("trailing_space", {"text": TEXT + " "}, MESSAGE_ID),
    ("trimmed", {"text": TEXT[:-1]}, MESSAGE_ID),
    ("no_text", {"text": None}, MESSAGE_ID),
    ("other_chat", {"chat": {"id": CHAT + 1, "type": "private"}}, MESSAGE_ID),
    ("no_chat", {"chat": None}, MESSAGE_ID),
    ("no_message_id", {"message_id": None}, None),
    ("boolean_message_id", {"message_id": True}, None),
]


@pytest.mark.parametrize(("name", "changes", "message_id"), CHANGED, ids=[r[0] for r in CHANGED])
def test_another_message_returned_is_text_changed(
    name: str, changes: dict[str, Any], message_id: int | None
) -> None:
    found = sent(prompt(), CHAT, returned(**changes))
    assert found == TextChanged(message_id)
    assert (found.code, found.status) == (TEXT_CHANGED, 502) == ("telegram_text_changed", 502)


def test_a_result_that_isnt_an_object_is_text_changed() -> None:
    assert sent(prompt(), CHAT, [returned()]) == TextChanged(None)


# --- a press -------------------------------------------------------------------------------------


@pytest.mark.parametrize(("letter", "decision"), [("a", "approve"), ("d", "deny")])
def test_a_genuine_press(letter: str, decision: Any) -> None:
    found = press(update(letter), ENROLLED, stored(), KEY)
    assert found == Press("4382bfdwdsb323b2d9", HOLD_ID, decision, digest(TEXT), MESSAGE_ID)
    assert found.answer == {"approve": "Approved", "deny": "Denied"}[decision]


def test_the_earliest_accessible_date_is_accepted() -> None:
    found = update()
    query(found)["message"]["date"] = 1
    assert isinstance(press(found, ENROLLED, stored(), KEY), Press)


def _set(path: str, value: Any) -> dict[str, Any]:
    """A genuine update with the value at ``path`` (dotted, from the callback query) replaced;
    ``...`` removes it."""
    found = update()
    *parents, last = path.split(".")
    target: Any = query(found)
    for part in parents:
        target = target[part]
    if value is ...:
        del target[last]
    else:
        target[last] = value
    return found


def _swapped_labels() -> dict[str, Any]:
    found = update()
    row = query(found)["message"]["reply_markup"]["inline_keyboard"][0]
    row[0]["text"], row[1]["text"] = row[1]["text"], row[0]["text"]
    return found


def _swapped_order() -> dict[str, Any]:
    found = update()
    row = query(found)["message"]["reply_markup"]["inline_keyboard"][0]
    row.reverse()
    return found


def _extra_button() -> dict[str, Any]:
    found = update()
    rows = query(found)["message"]["reply_markup"]["inline_keyboard"]
    rows.append([{"text": "Always allow", "callback_data": "x"}])
    return found


def _button_field() -> dict[str, Any]:
    found = update()
    row = query(found)["message"]["reply_markup"]["inline_keyboard"][0]
    row[1]["url"] = "https://example.com/"
    return found


def _decision_flipped() -> dict[str, Any]:
    """The Approve button's data with its letter turned to a Deny, and the MAC kept."""
    found = update("a")
    query(found)["data"] = query(found)["data"].replace(".a.", ".d.")
    return found


def _mac_tampered() -> dict[str, Any]:
    found = update()
    data = query(found)["data"]
    query(found)["data"] = data[:-1] + ("A" if data[-1] != "A" else "B")
    return found


def _other_key() -> dict[str, Any]:
    """A press made under another process's key: a button from before a restart (C-3)."""
    found = update()
    query(found)["data"] = keyboard(OTHER_KEY, HOLD_ID, digest(TEXT))[1][1]
    return found


# Each row: a press failing one check, its reason, and how far it names the press.
REFUSED_PRESSES: list[tuple[str, Any, PressReason]] = [
    # 1.
    ("not_an_object", lambda: [update()], "not_callback"),
    ("a_message_update", lambda: {"update_id": 1, "message": {"text": "/start"}}, "not_callback"),
    ("no_query_id", lambda: _set("id", ...), "not_callback"),
    ("numeric_query_id", lambda: _set("id", 5), "not_callback"),
    ("no_sender", lambda: _set("from", ...), "wrong_user"),
    ("another_user", lambda: _set("from.id", USER + 1), "wrong_user"),
    ("user_id_as_text", lambda: _set("from.id", str(USER)), "wrong_user"),
    ("a_bot", lambda: _set("from.is_bot", True), "from_bot"),
    ("no_is_bot", lambda: _set("from.is_bot", ...), "from_bot"),
    ("is_bot_zero", lambda: _set("from.is_bot", 0), "from_bot"),
    # 2.
    ("no_message", lambda: _set("message", ...), "no_message"),
    ("inaccessible_message", lambda: _set("message.date", 0), "inaccessible"),
    ("no_date", lambda: _set("message.date", ...), "inaccessible"),
    ("another_chat", lambda: _set("message.chat.id", CHAT + 1), "wrong_chat"),
    ("no_chat", lambda: _set("message.chat", ...), "wrong_chat"),
    ("a_group", lambda: _set("message.chat.type", "group"), "not_private"),
    # 3.
    ("no_data", lambda: _set("data", ...), "bad_data"),
    ("data_not_text", lambda: _set("data", 7), "bad_data"),
    ("another_version", lambda: _set("data", "v2" + query(update())["data"][2:]), "bad_data"),
    (
        "another_letter",
        lambda: _set("data", query(update())["data"].replace(".a.", ".x.")),
        "bad_data",
    ),
    ("data_with_a_line_end", lambda: _set("data", query(update())["data"] + "\n"), "bad_data"),
    ("data_cut", lambda: _set("data", query(update())["data"][:-1]), "bad_data"),
    # 4.
    (
        "another_hold",
        lambda: _set("data", keyboard(KEY, OTHER_ID, digest(TEXT))[1][1]),
        "not_pending",
    ),
    ("another_message", lambda: _set("message.message_id", MESSAGE_ID + 1), "wrong_message"),
    ("no_message_id", lambda: _set("message.message_id", ...), "wrong_message"),
    # 5.
    ("edited", lambda: _set("message.edit_date", 1793000100), "edited"),
    # 6.
    ("changed_text", lambda: _set("message.text", TEXT.replace("send", "drop")), "text_changed"),
    ("no_text", lambda: _set("message.text", ...), "text_changed"),
    ("lone_surrogate", lambda: _set("message.text", TEXT + "\ud800"), "text_changed"),
    # 6b. (FM-37)
    ("swapped_labels", _swapped_labels, "markup_changed"),
    ("swapped_order", _swapped_order, "markup_changed"),
    ("extra_button", _extra_button, "markup_changed"),
    ("button_field", _button_field, "markup_changed"),
    ("no_markup", lambda: _set("message.reply_markup", ...), "markup_changed"),
    # 7.
    ("decision_flipped", _decision_flipped, "bad_mac"),
    ("mac_tampered", _mac_tampered, "bad_mac"),
    ("another_key", _other_key, "bad_mac"),
]


@pytest.mark.parametrize(
    ("name", "make", "reason"), REFUSED_PRESSES, ids=[row[0] for row in REFUSED_PRESSES]
)
def test_every_press_check(name: str, make: Any, reason: PressReason) -> None:
    """FM-14, FM-37: each check refuses by its reason, says nothing to a stranger, and names the
    query from check 1, the pressed message from check 3 and the hold from check 4 on."""
    made = make()
    found = press(made, ENROLLED, stored(), KEY)
    assert isinstance(found, PressRefusal)
    assert found.reason == reason
    named: Any = made.get("callback_query") if isinstance(made, dict) else None
    order = get_args(PressReason)
    stage = order.index(reason)
    assert found.query_id == (None if reason == "not_callback" else named["id"])
    shown = named["message"].get("message_id") if stage >= order.index("bad_data") else None
    assert found.message_id == shown
    hold_id = named["data"].split(".")[1] if stage >= order.index("not_pending") else None
    assert found.hold_id == hold_id
    assert found.answer == (
        None if reason in STRANGER else NOT_PENDING if reason == "not_pending" else REFUSED
    )


def test_every_reason_has_a_row() -> None:
    assert {row[2] for row in REFUSED_PRESSES} == set(get_args(PressReason))


def test_a_refusal_names_what_the_press_named() -> None:
    """From check 3 the pressed message, from check 4 the hold: for G.6's edit."""
    assert press(_set("from.id", 1), ENROLLED, stored(), KEY) == PressRefusal(
        "wrong_user", "4382bfdwdsb323b2d9"
    )
    assert press(_set("data", "x"), ENROLLED, stored(), KEY) == PressRefusal(
        "bad_data", "4382bfdwdsb323b2d9", MESSAGE_ID
    )
    assert press(update(), ENROLLED, {}, KEY) == PressRefusal(
        "not_pending", "4382bfdwdsb323b2d9", MESSAGE_ID, HOLD_ID
    )
    assert press(_mac_tampered(), ENROLLED, stored(), KEY) == PressRefusal(
        "bad_mac", "4382bfdwdsb323b2d9", MESSAGE_ID, HOLD_ID
    )


def test_the_first_failing_check_refuses() -> None:
    """In order: a press failing checks 5, 6 and 7 at once is refused by check 5."""
    found = _mac_tampered()
    query(found)["message"]["edit_date"] = 1793000100
    query(found)["message"]["text"] = "other"
    assert press(found, ENROLLED, stored(), KEY).reason == "edited"  # type: ignore[union-attr]
    query(found)["from"]["id"] = USER + 1
    assert press(found, ENROLLED, stored(), KEY).reason == "wrong_user"  # type: ignore[union-attr]


def test_the_mac_binds_the_stored_texts_digest() -> None:
    """A button whose MAC was made over another text fails check 7, though the message's text
    is the stored one."""
    found = update()
    query(found)["data"] = keyboard(KEY, HOLD_ID, digest("another text"))[1][1]
    assert press(found, ENROLLED, stored(), KEY) == PressRefusal(
        "bad_mac", "4382bfdwdsb323b2d9", MESSAGE_ID, HOLD_ID
    )


def test_strangers_are_the_first_two_checks() -> None:
    reasons = get_args(PressReason)
    assert frozenset(reasons[: reasons.index("not_private") + 1]) == STRANGER
    assert ANSWERS == {"approve": "Approved", "deny": "Denied"}
    assert NOT_PENDING == "This request is no longer pending"
    assert REFUSED == "Refused: this button doesn't match the request the vault sent"


def test_a_press_leaves_the_update_alone() -> None:
    found = update()
    before = copy.deepcopy(found)
    press(found, ENROLLED, stored(), KEY)
    assert found == before


# --- the URL and the key -------------------------------------------------------------------------


def test_the_url_hides_the_token() -> None:
    url = method_url(TOKEN, "getUpdates")
    assert isinstance(url, SecretUrl)
    assert url.method == "getUpdates"
    assert url.reveal() == f"https://api.telegram.org/bot{TOKEN}/getUpdates"
    shown = "https://api.telegram.org/bot<redacted>/getUpdates"
    assert str(url) == f"{url}" == "%s" % url == shown  # noqa: UP031
    assert repr(url) == f"SecretUrl({shown})"
    assert "token_sentinel" not in repr([url]) + str({"url": url})
    with pytest.raises(TypeError):
        vars(url)


def test_the_logger_refuses_the_url_and_a_prompt() -> None:
    log = logs.Log("vault")
    stream = io.StringIO()
    logs.set_stream(stream)
    try:
        found = stored()[HOLD_ID]
        for value in (method_url(TOKEN, "getMe"), prompt(), {"nested": [prompt()]}, found):
            with pytest.raises(TypeError):
                log.event("probe", value=value)
    finally:
        logs.set_stream(None)
    assert stream.getvalue() == ""
    assert repr(prompt()) == f"Message(<{len(TEXT)} characters>, buttons=2)"
    # A stored prompt's buttons carry their MACs (a leak-sweep sentinel, O.6).
    assert repr(found) == f"Sent(message_id={MESSAGE_ID})"


BAD_TOKENS = [
    ("empty", ""),
    ("no_secret", "123456789"),
    ("no_bot_id", ":secret_sentinel"),
    ("bot_id_not_digits", "abc:secret_sentinel"),
    ("empty_secret", "123456789:"),
    ("a_path", "123456789:secret_sentinel/../x"),
    ("a_query", "123456789:secret_sentinel?x=1"),
    ("a_line_end", "123456789:secret_sentinel\n"),
    ("secret_too_long", "123456789:" + "a" * 129),
    ("bot_id_too_long", "1" * 21 + ":secret_sentinel"),
]


@pytest.mark.parametrize(("name", "bad"), BAD_TOKENS, ids=[row[0] for row in BAD_TOKENS])
def test_a_token_that_isnt_one_is_refused_without_showing_it(name: str, bad: str) -> None:
    with pytest.raises(ValueError, match="bot token") as caught:
        method_url(bad, "getMe")
    assert str(caught.value) == "the bot token isn't <bot id>:<secret>"


BAD_METHODS = [
    ("empty", ""),
    ("a_path", "get/Me"),
    ("a_query", "getMe?x=1"),
    ("a_line_end", "getMe\n"),
    ("too_long", "a" * 65),
    ("an_underscore", "get_me"),
]


@pytest.mark.parametrize(("name", "bad"), BAD_METHODS, ids=[row[0] for row in BAD_METHODS])
def test_a_method_is_a_name_of_letters(name: str, bad: str) -> None:
    with pytest.raises(ValueError, match="letters") as caught:
        method_url(TOKEN, bad)
    assert str(caught.value) == "a Bot API method is a name of letters"


@pytest.mark.parametrize(("name", "bad"), BAD_TOKENS, ids=[row[0] for row in BAD_TOKENS])
def test_a_value_that_isnt_a_token_has_no_bot_id(name: str, bad: str) -> None:
    assert telegramwire.bot_id(bad) is None


def test_a_tokens_bot_id_is_its_digits_before_the_colon() -> None:
    """G.7: another secret holding the same bot is found by this id (approver_token_shared)."""
    assert telegramwire.bot_id(TOKEN) == TOKEN.partition(":")[0]
    assert telegramwire.bot_id("123456789:another-secret_1") == "123456789"
    assert telegramwire.bot_id("1" * 20 + ":" + "a" * 128) == "1" * 20


def test_the_longest_token_and_method_are_taken() -> None:
    token = "1" * 20 + ":" + "a" * 128
    assert method_url(token, "a" * 64).reveal() == f"{API}/bot{token}/{'a' * 64}"


def test_the_api_is_the_policys_bot_api_origin() -> None:
    assert API == TELEGRAM_API == "https://api.telegram.org"


def test_a_key_is_32_fresh_bytes() -> None:
    assert KEY_BYTES == 32
    first, second = new_key(), new_key()
    assert len(first) == len(second) == 32
    assert first != second
