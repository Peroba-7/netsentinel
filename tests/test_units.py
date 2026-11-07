import httpx
import pytest
import redis

from app.agents.graph import parse_analysis
from app.core import rate_limit
from app.services import notification_service as notifications


@pytest.mark.parametrize(
    "raw,expected",
    [
        ('{"risk_level": "CRÍTICO", "analysis": "x"}', "CRÍTICO"),
        ('{"risk_level": "critico", "analysis": "x"}', "CRÍTICO"),
        ('{"risk_level": " Médio ", "analysis": "x"}', "MÉDIO"),
        ('{"risk_level": "ENORME", "analysis": "x"}', "INDETERMINADO"),
        ('{"analysis": "x"}', "INDETERMINADO"),
    ],
)
def test_parse_risk_level(raw, expected):
    assert parse_analysis(raw)[0] == expected


def test_parse_ignores_risk_words_in_analysis():
    raw = '{"risk_level": "BAIXO", "analysis": "Não é crítico nem alto."}'
    assert parse_analysis(raw) == ("BAIXO", "Não é crítico nem alto.")


@pytest.mark.parametrize("raw", ["texto livre", "[1, 2]"])
def test_parse_keeps_unstructured_text(raw):
    assert parse_analysis(raw) == ("INDETERMINADO", raw)


def test_rate_limit_allows_requests_when_redis_is_down(monkeypatch):
    class BrokenRedis:
        def pipeline(self):
            raise redis.ConnectionError

    monkeypatch.setattr(rate_limit, "redis_client", BrokenRedis())

    class Request:
        client = None

    rate_limit.enforce_rate_limit(Request())


@pytest.fixture
def posts(monkeypatch):
    calls = []

    def fake_post(url, json, timeout):
        calls.append((url, json))
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(notifications.httpx, "post", fake_post)
    monkeypatch.setattr(notifications.settings, "N8N_WEBHOOK_URL", "http://n8n/hook")
    monkeypatch.setattr(notifications.settings, "DISCORD_WEBHOOK_URL", "http://discord/hook")
    return calls


THREAT = {"ip_address": "10.0.0.1", "threat_type": "DDoS"}


def test_high_risk_goes_to_n8n_and_chat(posts):
    notifications.notify_threat({**THREAT, "risk_level": "CRÍTICO"})

    assert [url for url, _ in posts] == ["http://n8n/hook", "http://discord/hook"]
    assert posts[1][1]["allowed_mentions"] == {"parse": []}


def test_low_risk_goes_only_to_n8n(posts):
    notifications.notify_threat({**THREAT, "risk_level": "BAIXO"})

    assert [url for url, _ in posts] == ["http://n8n/hook"]


def test_block_is_not_dispatched_without_n8n(posts, monkeypatch):
    monkeypatch.setattr(notifications.settings, "N8N_WEBHOOK_URL", "")

    assert notifications.dispatch_block("10.0.0.1", None) is None


@pytest.mark.parametrize(
    "response,expected",
    [
        (httpx.Response(200, json={"status": "bloqueado (simulado)"}), "bloqueado (simulado)"),
        (httpx.Response(200, json={"message": "Workflow was started"}), notifications.UNCONFIRMED),
        (httpx.Response(200, json=[1]), notifications.UNCONFIRMED),
        (httpx.Response(200, text="OK"), notifications.UNCONFIRMED),
    ],
)
def test_block_result_comes_from_n8n_response(monkeypatch, response, expected):
    monkeypatch.setattr(notifications.settings, "N8N_WEBHOOK_URL", "http://n8n/hook")
    monkeypatch.setattr(notifications, "_post", lambda *_args: response)

    assert notifications.dispatch_block("10.0.0.1", None) == expected


def test_notification_failure_does_not_raise(monkeypatch):
    def fail(*_args, **_kwargs):
        raise httpx.ConnectError("sem ligação")

    monkeypatch.setattr(notifications.httpx, "post", fail)
    monkeypatch.setattr(notifications.settings, "N8N_WEBHOOK_URL", "http://n8n/hook")

    assert notifications.dispatch_block("10.0.0.1", None) is None
