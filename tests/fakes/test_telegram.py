"""The fake Bot API answers as Telegram's does, and each switch, person and runner works."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest

from tests.acceptance.fakes import TelegramFake
from tests.acceptance.tls import issue_cert, make_ca

from . import run_telegram
from .harness import serve
from .telegram import (
    ATTACKER,
    BOT_USERNAME,
    CONFLICT_POLL,
    CONFLICT_WEBHOOK,
    FIRST_UPDATE_ID,
    FOREIGN_WEBHOOK,
    MAX_TEXT,
    NOT_MODIFIED,
    OPERATOR,
    QUERY_INVALID,
    RETRY_AFTER,
    BotApi,
    Person,
    Switch,
    keyboard,
    utf16_len,
)

pytestmark = pytest.mark.anyio

# Every effect test bounds itself (M8 design P.2).
LIMIT = 10
TOKEN = "123456789:AAH-fake-bot-token_0001"
# The approval prompt's shape (M8 design G.4): Deny first, then Approve.
PROMPT = "Approval request 0123456789abcdef: notes \u2192 delete_note\nend of request"
DENY = ("Deny", "v1.AAAAAAAAAAAAAAAA.d.BBBBBBBBBBBBBBBB")
APPROVE = ("Approve", "v1.AAAAAAAAAAAAAAAA.a.CCCCCCCCCCCCCCCC")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


def client(app: Any) -> httpx.AsyncClient:
    """A client for the fake in this process; nothing leaves it."""
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://bot.example")


async def call(api: BotApi, method: str, token: str = TOKEN, **params: Any) -> httpx.Response:
    async with client(api.app()) as http:
        return await http.post(f"/bot{token}/{method}", json=params)


def result(response: httpx.Response) -> Any:
    body = response.json()
    assert body["ok"] is True, body
    return body["result"]


def refused(response: httpx.Response) -> tuple[int, str]:
    body = response.json()
    assert body["ok"] is False
    assert body["error_code"] == response.status_code
    return response.status_code, str(body["description"])


def prompt_params(chat_id: int = OPERATOR.id, text: str = PROMPT) -> dict[str, Any]:
    """``sendMessage`` as the vault sends a prompt (G.4)."""
    return {
        "chat_id": chat_id,
        "text": text,
        "entities": [{"type": "pre", "offset": 0, "length": utf16_len(text)}],
        "link_preview_options": {"is_disabled": True},
        "protect_content": True,
        "reply_markup": keyboard(DENY, APPROVE),
    }


async def send_prompt(api: BotApi, **params: Any) -> dict[str, Any]:
    sent: dict[str, Any] = result(await call(api, "sendMessage", **prompt_params(**params)))
    return sent


# --- the token and the methods --------------------------------------------------------------------


async def test_the_token_is_checked_in_the_path() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        assert refused(await call(api, "getMe", token="123456789:other")) == (401, "Unauthorized")
        missing = await call(api, "getChat")
        assert refused(missing) == (404, f"Not Found: /bot{TOKEN}/getChat")
        assert [(c.method, c.status) for c in api.calls] == [("getMe", 401), ("getChat", 404)]


async def test_get_me_names_the_bot_by_its_token() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        me = result(await call(api, "getMe"))
        assert (me["id"], me["is_bot"], me["username"]) == (123456789, True, BOT_USERNAME)
        assert me["can_manage_bots"] is False
        odd = BotApi("not-a-real-token")
        assert result(await call(odd, "getMe", token="not-a-real-token"))["id"] == 42


async def test_parameters_come_from_a_query_or_a_form() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN, flood_interval=None)
        markup = '{"inline_keyboard": [[{"text": "Deny", "callback_data": "d"}]]}'
        async with client(api.app()) as http:
            by_query = await http.get(
                f"/bot{TOKEN}/sendMessage",
                params={"chat_id": "7", "text": "hi", "reply_markup": markup},
            )
            by_form = await http.post(
                f"/bot{TOKEN}/sendMessage", data={"chat_id": "7", "text": "there"}
            )
        assert result(by_query)["reply_markup"]["inline_keyboard"][0][0]["text"] == "Deny"
        assert result(by_form)["text"] == "there"
        assert [stored.message_id for stored in api.sent()] == [1, 2]


async def test_a_sent_text_comes_back_exactly_and_the_send_is_recorded() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN, flood_interval=None)
        spaced = "  leading and trailing spaces, caf\u00e9, \U0001f600  "
        sent = await send_prompt(api, text=spaced)
        plain = result(await call(api, "sendMessage", chat_id=OPERATOR.id, text="plain"))
        assert sent["text"] == spaced
        assert sent["entities"] == [{"type": "pre", "offset": 0, "length": len(spaced) + 1}]
        assert sent["link_preview_options"] == {"is_disabled": True}
        assert sent["has_protected_content"] is True
        assert sent["chat"] == OPERATOR.chat()
        assert sent["from"]["id"] == 123456789
        assert [s.labels() for s in api.sent()] == [["Deny", "Approve"], []]
        flags = [(s.previews_off, s.protected, s.single_pre) for s in api.sent()]
        assert flags == [(True, True, True), (False, False, False)]
        assert "link_preview_options" not in plain


@pytest.mark.parametrize(
    "change",
    [
        "parse_mode",
        "two_entities",
        "short_entity",
    ],
)
async def test_single_pre_means_exactly_one_pre_over_the_text_and_no_parse_mode(
    change: str,
) -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        params = prompt_params()
        length = utf16_len(PROMPT)
        if change == "parse_mode":
            params["parse_mode"] = "HTML"
        elif change == "two_entities":
            params["entities"] = [*params["entities"], {"type": "bold", "offset": 0, "length": 1}]
        else:
            params["entities"] = [{"type": "pre", "offset": 0, "length": length - 1}]
        result(await call(api, "sendMessage", **params))
        assert api.sent()[0].single_pre is False


@pytest.mark.parametrize(
    ("params", "description"),
    [
        ({"text": "hi"}, "Bad Request: chat_id is empty"),
        ({"chat_id": 1, "text": ""}, "Bad Request: message text is empty"),
        # One astral character counts two UTF-16 code units.
        (
            {"chat_id": 1, "text": "x" * (MAX_TEXT - 1) + "\U0001f600"},
            "Bad Request: message is too long",
        ),
        (
            {"chat_id": 1, "text": "hi", "entities": [{"type": "pre", "offset": 0, "length": 3}]},
            "Bad Request: can't parse entities",
        ),
        (
            {"chat_id": 1, "text": "hi", "reply_markup": keyboard(("Deny", "d" * 65))},
            "Bad Request: BUTTON_DATA_INVALID",
        ),
        (
            {"chat_id": 1, "text": "hi", "reply_markup": keyboard(("Deny", ""))},
            "Bad Request: BUTTON_DATA_INVALID",
        ),
    ],
    ids=["no_chat", "empty", "too_long", "entity_outside", "data_too_long", "data_empty"],
)
async def test_send_message_refuses_what_telegram_does(
    params: dict[str, Any], description: str
) -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        assert refused(await call(api, "sendMessage", **params)) == (400, description)
        assert api.sent() == []


async def test_the_longest_text_is_sent() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        text = "x" * (MAX_TEXT - 2) + "\U0001f600"
        assert result(await call(api, "sendMessage", chat_id=1, text=text))["text"] == text


# --- getUpdates -----------------------------------------------------------------------------------


async def test_offset_confirms_and_limit_caps() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        for code in ("one", "two", "three"):
            api.operator.start(code)
        first = result(await call(api, "getUpdates", limit=2))
        assert [u["update_id"] for u in first] == [FIRST_UPDATE_ID, FIRST_UPDATE_ID + 1]
        # Not confirmed yet: the same again.
        again = result(await call(api, "getUpdates"))
        assert [u["message"]["text"] for u in again] == ["/start one", "/start two", "/start three"]
        rest = result(await call(api, "getUpdates", offset=FIRST_UPDATE_ID + 2))
        assert [u["update_id"] for u in rest] == [FIRST_UPDATE_ID + 2]
        assert [u.update_id for u in api.updates] == [FIRST_UPDATE_ID + 2]
        assert result(await call(api, "getUpdates", offset=FIRST_UPDATE_ID + 3)) == []
        assert api.updates == []


async def test_a_negative_offset_keeps_the_last_and_forgets_the_rest() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        for code in ("one", "two", "three"):
            api.operator.start(code)
        last = result(await call(api, "getUpdates", offset=-1, timeout=0))
        assert [u["message"]["text"] for u in last] == ["/start three"]
        assert [u.update_id for u in api.updates] == [FIRST_UPDATE_ID + 2]
        # Only a later call with a higher offset confirms it.
        assert len(result(await call(api, "getUpdates"))) == 1


async def test_allowed_updates_apply_only_to_later_updates_and_persist() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN, flood_interval=None)
        message_id = (await send_prompt(api))["message_id"]
        api.operator.start("early")
        first = result(await call(api, "getUpdates", allowed_updates=["callback_query"]))
        # Made before the call: still delivered.
        assert [next(iter(set(u) - {"update_id"})) for u in first] == ["message"]
        assert api.operator.start("late") is None
        assert api.operator.press(message_id, "Approve") is not None
        # Named no types: the last setting stays.
        later = result(await call(api, "getUpdates", offset=first[-1]["update_id"] + 1))
        assert [sorted(u) for u in later] == [["callback_query", "update_id"]]
        assert [u.body["text"] for u in api.dropped] == ["/start late"]
        # An empty list is every type again.
        result(await call(api, "getUpdates", allowed_updates=[]))
        assert api.operator.start("again") is not None
        assert [p.allowed_updates for p in api.polls] == [["callback_query"], None, []]


async def test_a_long_poll_answers_when_an_update_arrives() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN, flood_interval=None)
        message_id = (await send_prompt(api))["message_id"]
        answers: list[httpx.Response] = []

        async def poll() -> None:
            answers.append(await call(api, "getUpdates", timeout=50))

        async with anyio.create_task_group() as group:
            group.start_soon(poll)
            await api.poll_began()
            api.operator.press(message_id, "Approve")
        [update] = result(answers[0])
        assert update["callback_query"]["data"] == APPROVE[1]
        assert api.polls[0].returned == [update["update_id"]]


async def test_a_long_poll_with_nothing_answers_empty_at_its_timeout() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN, second=0.01)
        assert result(await call(api, "getUpdates", timeout=5)) == []
        assert api.polls[0].returned == []


async def test_a_second_poll_ends_the_waiting_one_with_409() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        answers: list[httpx.Response] = []

        async def poll() -> None:
            answers.append(await call(api, "getUpdates", timeout=50))

        async with anyio.create_task_group() as group:
            group.start_soon(poll)
            await api.poll_began()
            second = await call(api, "getUpdates", timeout=0)
        assert refused(answers[0]) == (409, CONFLICT_POLL)
        assert result(second) == []
        assert [p.returned for p in api.polls] == [None, []]


# --- edits, deletes and answers -------------------------------------------------------------------


async def test_an_edit_replaces_the_text_drops_the_keyboard_and_dates_it() -> None:
    with anyio.fail_after(LIMIT):
        clock = Clock()
        api = BotApi(TOKEN, clock=clock, flood_interval=None)
        message_id = (await send_prompt(api))["message_id"]
        clock.now += 5
        edited = result(
            await call(
                api,
                "editMessageText",
                chat_id=OPERATOR.id,
                message_id=message_id,
                text="Approval request 0123456789abcdef: denied. Nothing was sent.",
            )
        )
        assert (edited["edit_date"], edited["date"]) == (1005, 1000)
        assert "reply_markup" not in edited
        same = await call(
            api, "editMessageText", chat_id=OPERATOR.id, message_id=message_id, text=edited["text"]
        )
        assert refused(same) == (400, NOT_MODIFIED)


async def test_a_keyboard_edit_is_dated_as_telegram_dates_it() -> None:
    """D-255: M8's live check saw Telegram set ``edit_date`` on a buttons-only edit."""
    with anyio.fail_after(LIMIT):
        clock = Clock()
        api = BotApi(TOKEN, clock=clock, flood_interval=None)
        message_id = (await send_prompt(api))["message_id"]
        swapped = keyboard(("Approve", DENY[1]), ("Deny", APPROVE[1]))
        edited = result(
            await call(
                api,
                "editMessageReplyMarkup",
                chat_id=OPERATOR.id,
                message_id=message_id,
                reply_markup=swapped,
            )
        )
        assert edited["reply_markup"] == swapped
        assert edited["edit_date"] == 1000


async def test_a_deleted_message_cant_be_edited_or_deleted_again() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN, flood_interval=None)
        message_id = (await send_prompt(api))["message_id"]
        target = {"chat_id": OPERATOR.id, "message_id": message_id}
        assert result(await call(api, "deleteMessage", **target)) is True
        assert refused(await call(api, "deleteMessage", **target)) == (
            400,
            "Bad Request: message to delete not found",
        )
        assert refused(await call(api, "editMessageText", **target, text="x")) == (
            400,
            "Bad Request: message to edit not found",
        )
        assert api.operator.prompts() == []


async def test_a_callback_query_is_answered_once() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN, flood_interval=None)
        message_id = (await send_prompt(api))["message_id"]
        update = api.operator.press(message_id, "Deny")
        assert update is not None
        query = update.body["id"]
        denied = await call(api, "answerCallbackQuery", callback_query_id=query, text="Denied")
        assert result(denied)
        again = await call(api, "answerCallbackQuery", callback_query_id=query)
        assert refused(again) == (400, QUERY_INVALID)
        assert refused(await call(api, "answerCallbackQuery", callback_query_id="1")) == (
            400,
            QUERY_INVALID,
        )
        assert [(a.query_id, a.text) for a in api.answers] == [(query, "Denied")]


async def test_flood_control_is_per_chat_across_writes() -> None:
    with anyio.fail_after(LIMIT):
        clock = Clock()
        api = BotApi(TOKEN, clock=clock)
        message_id = (await send_prompt(api))["message_id"]
        clock.now += 0.4
        target = {"chat_id": OPERATOR.id, "message_id": message_id}
        for response in (
            await call(api, "sendMessage", chat_id=OPERATOR.id, text="again"),
            await call(api, "editMessageText", **target, text="edited"),
            await call(api, "deleteMessage", **target),
        ):
            assert refused(response) == (429, "Too Many Requests: retry after 1")
            assert response.json()["parameters"] == {"retry_after": 1}
        # Another chat, and answering a press, aren't held.
        assert result(await call(api, "sendMessage", chat_id=ATTACKER.id, text="elsewhere"))
        update = api.operator.press(message_id, "Approve")
        assert update is not None
        assert result(await call(api, "answerCallbackQuery", callback_query_id=update.body["id"]))
        clock.now += 0.6
        assert result(await call(api, "editMessageText", **target, text="edited"))


# --- the switch table -----------------------------------------------------------------------------


async def conflict(api: BotApi, clock: Clock) -> None:
    assert refused(await call(api, "getUpdates")) == (409, CONFLICT_POLL)


async def foreign_webhook(api: BotApi, clock: Clock) -> None:
    assert result(await call(api, "getWebhookInfo"))["url"] == FOREIGN_WEBHOOK
    assert refused(await call(api, "getUpdates")) == (409, CONFLICT_WEBHOOK)


async def rate_limited_send(api: BotApi, clock: Clock) -> None:
    response = await call(api, "sendMessage", **prompt_params())
    assert refused(response) == (429, f"Too Many Requests: retry after {RETRY_AFTER}")
    assert Switch.RATE_LIMITED_SEND not in api.switches
    clock.now += RETRY_AFTER - 1
    assert refused(await call(api, "sendMessage", **prompt_params()))[0] == 429
    clock.now += 1
    assert result(await call(api, "sendMessage", **prompt_params()))


async def rate_limited_edit(api: BotApi, clock: Clock) -> None:
    message_id = (await send_prompt(api))["message_id"]
    clock.now += 2
    edit = {"chat_id": OPERATOR.id, "message_id": message_id, "text": "decided"}
    response = await call(api, "editMessageText", **edit)
    assert refused(response) == (429, f"Too Many Requests: retry after {RETRY_AFTER}")
    assert Switch.RATE_LIMITED_EDIT not in api.switches
    clock.now += RETRY_AFTER
    assert result(await call(api, "editMessageText", **edit))["text"] == "decided"


async def forbidden_send(api: BotApi, clock: Clock) -> None:
    response = await call(api, "sendMessage", **prompt_params())
    assert refused(response) == (403, "Forbidden: bot was blocked by the user")
    assert api.sent() == []


async def outage(api: BotApi, clock: Clock) -> None:
    response = await call(api, "getMe")
    assert response.status_code == 502
    assert response.headers["content-type"].startswith("text/html")


async def text_changed(api: BotApi, clock: Clock) -> None:
    sent = await send_prompt(api)
    assert sent["text"] == PROMPT[:-1]
    assert api.sent()[0].single_pre is True  # it judges what was sent


async def markup_edit_undated(api: BotApi, clock: Clock) -> None:
    message_id = (await send_prompt(api))["message_id"]
    clock.now += 2
    markup = keyboard(("Approve", APPROVE[1]))
    edit = {"chat_id": OPERATOR.id, "message_id": message_id, "reply_markup": markup}
    assert "edit_date" not in result(await call(api, "editMessageReplyMarkup", **edit))


async def manages_bots(api: BotApi, clock: Clock) -> None:
    assert result(await call(api, "getMe"))["can_manage_bots"] is True


SWITCHES: dict[Switch, Callable[[BotApi, Clock], Any]] = {
    Switch.CONFLICT: conflict,
    Switch.FOREIGN_WEBHOOK: foreign_webhook,
    Switch.RATE_LIMITED_SEND: rate_limited_send,
    Switch.RATE_LIMITED_EDIT: rate_limited_edit,
    Switch.FORBIDDEN_SEND: forbidden_send,
    Switch.OUTAGE: outage,
    Switch.TEXT_CHANGED: text_changed,
    Switch.MARKUP_EDIT_UNDATED: markup_edit_undated,
    Switch.MANAGES_BOTS: manages_bots,
}


def test_the_switch_table_covers_every_switch() -> None:
    assert set(SWITCHES) == set(Switch)


@pytest.mark.parametrize("switch", list(Switch), ids=[switch.value for switch in Switch])
async def test_each_switch(switch: Switch) -> None:
    with anyio.fail_after(LIMIT):
        clock = Clock()
        api = BotApi(TOKEN, switches={switch}, clock=clock)
        await SWITCHES[switch](api, clock)


async def test_a_webhook_a_token_holder_sets_is_foreign() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        assert result(await call(api, "setWebhook", url=FOREIGN_WEBHOOK)) is True
        assert result(await call(api, "getWebhookInfo"))["url"] == FOREIGN_WEBHOOK
        assert refused(await call(api, "getUpdates")) == (409, CONFLICT_WEBHOOK)
        assert result(await call(api, "deleteWebhook")) is True
        assert result(await call(api, "getUpdates")) == []


# --- the operator ---------------------------------------------------------------------------------


async def test_the_operator_presses_starts_and_reads_the_code() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN, flood_interval=None)
        message_id = (await send_prompt(api))["message_id"]
        pressed = api.operator.press(message_id, "Approve")
        assert pressed is not None
        query = pressed.body
        assert query["from"] == OPERATOR.user()
        assert query["data"] == APPROVE[1]
        assert query["message"]["text"] == PROMPT
        assert query["message"]["reply_markup"] == keyboard(DENY, APPROVE)
        assert "edit_date" not in query["message"]
        with pytest.raises(LookupError):
            api.operator.press(message_id, "Always allow")
        started = api.operator.start("enrolment-code-0001")
        assert started is not None
        assert started.body["text"] == "/start enrolment-code-0001"
        assert started.body["entities"] == [{"type": "bot_command", "offset": 0, "length": 6}]
        assert started.body["chat"] == OPERATOR.chat()
        with pytest.raises(LookupError):
            api.operator.confirmation_code()
        result(await call(api, "sendMessage", chat_id=OPERATOR.id, text="Your code is 482913."))
        assert api.operator.confirmation_code() == "482913"


async def test_an_inaccessible_message_comes_with_date_zero() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        message_id = (await send_prompt(api))["message_id"]
        update = api.press(message_id, "Deny", by=OPERATOR, inaccessible=True)
        assert update is not None
        inaccessible = {"chat": OPERATOR.chat(), "message_id": message_id, "date": 0}
        assert update.body["message"] == inaccessible


# --- the attacker ---------------------------------------------------------------------------------


async def test_the_attacker_edits_a_prompt_text_or_keyboard() -> None:
    with anyio.fail_after(LIMIT):
        clock = Clock()
        api = BotApi(TOKEN, clock=clock)
        message_id = (await send_prompt(api))["message_id"]
        clock.now += 1
        edited = api.attacker.edit_text(message_id, PROMPT.replace("delete_note", "read_note"))
        assert edited["edit_date"] == 1001
        assert edited["reply_markup"] == keyboard(DENY, APPROVE)
        pressed = api.operator.press(message_id, "Approve")
        assert pressed is not None
        assert pressed.body["message"]["text"].endswith("read_note\nend of request")
        # A keyboard swap alone leaves no edit_date only with MARKUP_EDIT_UNDATED.
        other = BotApi(TOKEN, switches={Switch.MARKUP_EDIT_UNDATED})
        other_id = (await send_prompt(other))["message_id"]
        swapped = keyboard(("Deny", APPROVE[1]), ("Approve", DENY[1]))
        assert "edit_date" not in other.attacker.edit_markup(other_id, swapped)
        assert other.operator.prompts()[0].labels() == ["Deny", "Approve"]
        assert other.operator.prompts()[0].data_for("Approve") == DENY[1]


async def test_the_attacker_presses_from_another_user_or_chat_and_replays() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        message_id = (await send_prompt(api))["message_id"]
        in_victims_chat = api.attacker.press(message_id, "Approve")
        assert in_victims_chat is not None
        assert in_victims_chat.body["from"] == ATTACKER.user()
        assert in_victims_chat.body["message"]["chat"] == OPERATOR.chat()
        copied = api.attacker.copy(message_id)
        from_own_chat = api.attacker.press(copied.message_id, "Approve", own_chat=True)
        assert from_own_chat is not None
        assert from_own_chat.body["message"]["chat"] == ATTACKER.chat()
        assert from_own_chat.body["data"] == APPROVE[1]
        stale = "v1.ZZZZZZZZZZZZZZZZ.a.YYYYYYYYYYYYYYYY"
        replayed = api.press(message_id, by=OPERATOR, data=stale)
        assert replayed is not None
        assert replayed.body["data"] == stale


async def test_the_attacker_sends_a_look_alike_prompt() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        forged = api.attacker.look_alike(PROMPT, keyboard(DENY, APPROVE))
        assert forged.chat_id == OPERATOR.id
        assert forged.from_bot  # it came through the bot's own token
        assert [s.message_id for s in api.operator.prompts()] == [forged.message_id]
        pressed = api.operator.press(forged.message_id, "Approve")
        assert pressed is not None


async def test_the_attacker_steals_a_code_from_a_waiting_poll_and_presents_it() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        answers: list[httpx.Response] = []

        async def enrolment_poll() -> None:
            answers.append(await call(api, "getUpdates", timeout=50, allowed_updates=["message"]))

        async with anyio.create_task_group() as group:
            group.start_soon(enrolment_poll)
            await api.poll_began()
            api.operator.start("enrolment-code-0001")
            # Taken before the poll's next look, as a racing token holder may.
            assert api.attacker.steal_code() == "enrolment-code-0001"
        # Overlapping: the waiting poll ended with 409, and the operator's /start is confirmed away.
        assert refused(answers[0]) == (409, CONFLICT_POLL)
        assert api.updates == []
        presented = api.attacker.present("enrolment-code-0001")
        assert presented is not None
        assert presented.body["from"] == ATTACKER.user()
        assert presented.body["chat"]["first_name"] == OPERATOR.first_name
        later = result(await call(api, "getUpdates"))
        assert [u["message"]["from"]["id"] for u in later] == [ATTACKER.id]


async def test_the_attacker_steals_a_code_in_a_gap_unnoticed() -> None:
    with anyio.fail_after(LIMIT):
        api = BotApi(TOKEN)
        api.operator.start("enrolment-code-0001")
        assert api.attacker.steal_code() == "enrolment-code-0001"
        assert result(await call(api, "getUpdates")) == []
        with pytest.raises(LookupError):
            api.attacker.steal_code()


async def test_a_bot_presser_and_a_custom_operator() -> None:
    with anyio.fail_after(LIMIT):
        other = Person(3003, "Someone Else")
        api = BotApi(TOKEN, operator_account=other)
        message_id = (await send_prompt(api, chat_id=other.id))["message_id"]
        pressed = api.operator.press(message_id, "Deny")
        assert pressed is not None
        assert pressed.body["from"] == {"id": 3003, "is_bot": False, "first_name": "Someone Else"}
        robot = Person(4004, "Robot", "robot_bot", is_bot=True)
        by_bot = api.press(message_id, "Deny", by=robot, chat_id=other.id)
        assert by_bot is not None
        assert by_bot.body["from"]["is_bot"] is True


# --- the S3 shape's delegate, and the runner ------------------------------------------------------


async def test_the_s3_fake_delegates_and_records() -> None:
    with anyio.fail_after(LIMIT):
        fake = TelegramFake(token=TOKEN)
        async with client(fake.app()) as http:
            me = await http.get(f"/bot{TOKEN}/getMe")
            sent = await http.post(f"/bot{TOKEN}/sendMessage", json={"chat_id": 1, "text": "hi"})
            missing = await http.get(f"/bot{TOKEN}/getChat")
        assert result(me)["username"] == BOT_USERNAME
        assert result(sent)["text"] == "hi"
        assert refused(missing) == (404, f"Not Found: /bot{TOKEN}/getChat")
        assert [seen.path for seen in fake.received] == [
            f"/bot{TOKEN}/getMe",
            f"/bot{TOKEN}/sendMessage",
            f"/bot{TOKEN}/getChat",
        ]
        assert fake.bot.sent()[0].text == "hi"


def test_the_runner_parses_its_options() -> None:
    plain = run_telegram.parse(["cert.pem", "key.pem", "--token", TOKEN])
    assert (plain.cert, plain.key, plain.port) == ("cert.pem", "key.pem", run_telegram.PORT)
    assert plain.host == run_telegram.HOST == "127.0.0.1"
    assert run_telegram.fake_for(plain).switches == set()
    argv = ["cert.pem", "key.pem", "--token", TOKEN, "--host", "192.0.2.7", "--port", "9001"]
    argv += ["--switch", "conflict", "--switch", "manages_bots"]
    args = run_telegram.parse(argv)
    fake = run_telegram.fake_for(args)
    assert (args.host, args.port, fake.token) == ("192.0.2.7", 9001, TOKEN)
    assert fake.switches == {Switch.CONFLICT, Switch.MANAGES_BOTS}


def test_the_fake_over_https_and_its_control_routes(tmp_path: Path) -> None:
    """As the runner serves it: HTTPS with a throwaway CA's certificate for the Bot API's name,
    reached here on loopback, and the operator driven from outside."""
    ca = make_ca(tmp_path)
    cert, key = issue_cert(ca, "api.telegram.org", tmp_path)
    api = BotApi(TOKEN, flood_interval=None)
    with serve(api.app(), tls=(cert, key)) as base:
        port = base.rsplit(":", 1)[1]
        context = ca.client_context()
        context.check_hostname = False  # the name is the Bot API's; the address is loopback
        with httpx.Client(base_url=f"https://127.0.0.1:{port}", verify=context) as http:
            sent = http.post(f"/bot{TOKEN}/sendMessage", json=prompt_params()).json()["result"]
            listed = http.get("/_fake/messages").json()["messages"]
            pressed = http.post(
                "/_fake/press", json={"message_id": sent["message_id"], "label": "Approve"}
            )
            unknown = http.post("/_fake/press", json={"message_id": 99, "label": "Approve"})
            started = http.post("/_fake/start", json={"code": "enrolment-code-0001"})
            updates = http.get(f"/bot{TOKEN}/getUpdates").json()["result"]
    [record] = listed
    assert (record["previews_off"], record["protected"], record["single_pre"]) == (
        True,
        True,
        True,
    )
    assert record["labels"] == ["Deny", "Approve"]
    assert (pressed.json(), unknown.status_code, started.json()) == (
        {"queued": True},
        404,
        {"queued": True},
    )
    assert [sorted(set(u) - {"update_id"}) for u in updates] == [["callback_query"], ["message"]]
