"""Acceptance: shapes S1-S4, S7 and S8, end to end over real HTTPS (design §8.1).

Agent -> vault (real socket) -> fake provider (real TLS, verified against a test CA), using the
shipped profile for each shape with only its upstream swapped.
"""

from __future__ import annotations

import base64
import time
from pathlib import Path

import httpx

from .conftest import Deployment, serve_tls
from .fakes import AtlassianFake, GitHubFake, GristFake, InferenceFake, LastFmFake, TelegramFake
from .tls import ProviderCA

KEY = "sk-test-5f7c1b2e9a8d4c3b"


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --- S1 ----------------------------------------------------------------------------------------


def test_s1_inference(tmp_path: Path, ca: ProviderCA) -> None:
    fake = InferenceFake(key=KEY)
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path, "openai-compatible.yaml", upstream, ca, secrets={"inference-key": KEY}
        )
        with d.running() as agent:
            ok = agent.post(
                "/inference/v1/chat/completions",
                headers=bearer(d.placeholder),
                json={"model": "m", "messages": []},
            )
            assert ok.status_code == 200
            assert ok.json()["choices"][0]["message"]["content"] == "Hello"
            assert fake.received[-1].headers["authorization"] == f"Bearer {KEY}"

            assert (
                agent.get("/inference/v1/models", headers=bearer(d.placeholder)).status_code == 200
            )

            before = len(fake.received)
            assert (
                agent.delete("/inference/v1/files/x", headers=bearer(d.placeholder)).status_code
                == 403
            )
            assert agent.post("/inference/v1/chat/completions", json={}).status_code == 403
            assert len(fake.received) == before


def test_s1_streaming_arrives_as_it_is_produced(tmp_path: Path, ca: ProviderCA) -> None:
    fake = InferenceFake(key=KEY, chunk_delay=0.25)
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path, "openai-compatible.yaml", upstream, ca, secrets={"inference-key": KEY}
        )
        with d.running() as agent:
            arrivals: list[float] = []
            with agent.stream(
                "POST",
                "/inference/v1/chat/completions",
                headers=bearer(d.placeholder),
                json={"model": "m", "stream": True},
            ) as response:
                assert response.status_code == 200
                start = time.monotonic()
                lines = []
                for line in response.iter_lines():
                    if line.startswith("data:"):
                        arrivals.append(time.monotonic() - start)
                        lines.append(line)
    assert lines[-1] == "data: [DONE]"
    assert len(lines) == 4
    assert arrivals[0] < 0.2, arrivals  # not buffered until the end
    assert arrivals[-1] > 0.6, arrivals


def test_s1_an_echoed_key_is_scrubbed(tmp_path: Path, ca: ProviderCA) -> None:
    fake = InferenceFake(key="the-provider-expects-another-key")
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path, "openai-compatible.yaml", upstream, ca, secrets={"inference-key": KEY}
        )
        with d.running() as agent:
            refused = agent.post(
                "/inference/v1/chat/completions", headers=bearer(d.placeholder), json={"model": "m"}
            )
    assert refused.status_code == 401
    assert KEY not in refused.text
    assert "Incorrect API key provided: [REDACTED]" in refused.text


# --- S2 ----------------------------------------------------------------------------------------


def test_s2_query_key_with_forced_user(tmp_path: Path, ca: ProviderCA) -> None:
    fake = LastFmFake(key=KEY)
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path,
            "lastfm.yaml",
            upstream,
            ca,
            secrets={"lastfm-key": KEY},
            replace={"your-username": "alice"},
        )
        with d.running() as agent:
            # The script sends its placeholder as api_key, exactly as it would send the key.
            ok = agent.get(
                "/lastfm/2.0/",
                params={"method": "user.getinfo", "user": "mallory", "api_key": d.placeholder},
            )
            assert ok.status_code == 200
            assert ok.json()["user"]["name"] == "alice"
            sent = dict(fake.received[-1].query)
            assert sent["api_key"] == KEY
            assert sent["user"] == "alice"
            assert sent["format"] == "json"

            echoed = agent.get("/lastfm/2.0/", params={"method": "nope", "api_key": d.placeholder})
            assert echoed.status_code == 400
            assert KEY not in echoed.text
            assert "[REDACTED]" in echoed.text

            before = len(fake.received)
            assert (
                agent.get(
                    "/lastfm/2.0/", params={"method": "user.getinfo", "api_key": "guess-0000000000"}
                ).status_code
                == 403
            )
            assert agent.get("/lastfm/3.0/", params={"api_key": d.placeholder}).status_code == 403
            assert len(fake.received) == before


# --- S3 ----------------------------------------------------------------------------------------

BOT_TOKEN = "123456789:AAH-test-token_value"


def test_s3_path_token(tmp_path: Path, ca: ProviderCA) -> None:
    fake = TelegramFake(token=BOT_TOKEN)
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path, "telegram-bot.yaml", upstream, ca, secrets={"telegram-bot": BOT_TOKEN}
        )
        with d.running() as agent:
            me = agent.get("/telegram/getMe", headers=bearer(d.placeholder))
            assert me.status_code == 200
            assert me.json()["result"]["username"] == "example_bot"
            assert fake.received[-1].path == f"/bot{BOT_TOKEN}/getMe"
            assert BOT_TOKEN not in me.text

            sent = agent.post(
                "/telegram/sendMessage",
                headers=bearer(d.placeholder),
                json={"chat_id": 1, "text": "hi"},
            )
            assert sent.status_code == 200

            before = len(fake.received)
            assert (
                agent.get("/telegram/deleteWebhook", headers=bearer(d.placeholder)).status_code
                == 403
            )
            assert (
                agent.get("/telegram/sendMessage", headers=bearer(d.placeholder)).status_code == 403
            )
            assert len(fake.received) == before


def test_s3_a_path_echo_is_scrubbed(tmp_path: Path, ca: ProviderCA) -> None:
    fake = TelegramFake(token=BOT_TOKEN)
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path,
            "telegram-bot.yaml",
            upstream,
            ca,
            secrets={"telegram-bot": BOT_TOKEN},
            replace={"[/getMe, /getUpdates]": "[/getMe, /getUpdates, /getChat]"},
        )
        with d.running() as agent:
            missing = agent.get("/telegram/getChat", headers=bearer(d.placeholder))
    assert missing.status_code == 404
    assert BOT_TOKEN not in missing.text
    assert "Not Found: /bot[REDACTED]/getChat" in missing.text


# --- S4 ----------------------------------------------------------------------------------------


def test_s4_basic_auth(tmp_path: Path, ca: ProviderCA) -> None:
    fake = AtlassianFake(user="bot@example.com", token=KEY)
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path,
            "atlassian-basic.yaml",
            upstream,
            ca,
            secrets={"atlassian": KEY},
            replace={"you@example.com": "bot@example.com"},
        )
        with d.running() as agent:
            me = agent.get("/jira/rest/api/3/myself", headers=bearer(d.placeholder))
            assert me.status_code == 200
            assert me.json()["emailAddress"] == "bot@example.com"
            expected = base64.b64encode(f"bot@example.com:{KEY}".encode()).decode()
            assert fake.received[-1].headers["authorization"] == f"Basic {expected}"
            assert expected not in me.text

            before = len(fake.received)
            assert (
                agent.put("/jira/rest/api/3/myself", headers=bearer(d.placeholder)).status_code
                == 403
            )
            assert len(fake.received) == before


# --- S7 ----------------------------------------------------------------------------------------

DOC = "d7Q2xkPm"


def test_s7_one_document_and_no_deletes(tmp_path: Path, ca: ProviderCA) -> None:
    fake = GristFake(key=KEY)
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path,
            "grist-document.yaml",
            upstream,
            ca,
            secrets={"grist-key": KEY},
            replace={"replace-with-your-doc-id": DOC},
        )
        h = bearer(d.placeholder)
        records = f"/grist/api/docs/{DOC}/tables/Health_Log/records"
        with d.running() as agent:
            assert agent.get(f"/grist/api/docs/{DOC}/tables", headers=h).status_code == 200
            assert agent.get(records, headers=h).status_code == 200
            assert agent.post(records, headers=h, json={"records": []}).status_code == 200
            assert agent.patch(records, headers=h, json={"records": []}).status_code == 200
            allowed = len(fake.received)
            assert allowed == 4

            refused = [
                agent.delete(records, headers=h),
                agent.delete(f"/grist/api/docs/{DOC}", headers=h),
                agent.get("/grist/api/docs/OTHERDOC/tables/Health_Log/records", headers=h),
                agent.get(f"/grist/api/docs/{DOC}/tables/1bad/records", headers=h),
                agent.get(f"/grist/api/docs/{DOC}/tables/a.b/records", headers=h),
            ]
            assert [r.status_code for r in refused] == [403] * 5
            assert len(fake.received) == allowed


# --- S8 ----------------------------------------------------------------------------------------


def test_s8_read_only_and_no_cookies(tmp_path: Path, ca: ProviderCA) -> None:
    fake = GitHubFake(token=KEY)
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path,
            "github-readonly.yaml",
            upstream,
            ca,
            secrets={"github-token": KEY},
            replace={"your-org": "example-org"},
        )
        h = {**bearer(d.placeholder), "User-Agent": "agent-script/1.0"}
        with d.running() as agent:
            issues = agent.get("/github/repos/example-org/r/issues", headers=h)
            assert issues.status_code == 200
            assert issues.json()[0]["title"] == "First issue"
            assert "set-cookie" not in issues.headers
            assert 'rel="next"' in issues.headers["link"]
            assert issues.headers["x-ratelimit-remaining"] == "4999"
            assert fake.received[-1].headers["user-agent"] == "agent-script/1.0"
            assert agent.get("/github/user", headers=h).status_code == 200

            before = len(fake.received)
            assert (
                agent.post(
                    "/github/repos/example-org/r/issues", headers=h, json={"title": "x"}
                ).status_code
                == 403
            )
            assert agent.get("/github/repos/other-org/r/issues", headers=h).status_code == 403
            assert len(fake.received) == before


def test_tls_is_verified(tmp_path: Path, ca: ProviderCA) -> None:
    """The vault refuses an upstream whose certificate it can't verify."""
    fake = GitHubFake(token=KEY)
    with serve_tls(fake.app(), ca) as upstream:
        d = Deployment(
            tmp_path,
            "github-readonly.yaml",
            upstream,
            ca,
            secrets={"github-token": KEY},
            replace={"your-org": "example-org"},
        )
        # The default trust store, which doesn't include the test CA.
        d.app._client = httpx.AsyncClient(
            trust_env=False, limits=httpx.Limits(max_keepalive_connections=0)
        )
        with d.running() as agent:
            response = agent.get(
                "/github/user", headers={**bearer(d.placeholder), "User-Agent": "x"}
            )
    assert response.status_code == 502
    assert fake.received == []
