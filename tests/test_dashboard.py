from pathlib import Path

import pandas as pd
import pytest
import requests
from streamlit.testing.v1 import AppTest

import dashboard_api

PAGES = Path(__file__).resolve().parent.parent / "app_pages"

THREAT = {
    "id": 1,
    "ip_address": "10.0.0.1",
    "threat_type": "DDoS",
    "description": "=cmd|' /C calc'!A0",
    "risk_level": "ALTO",
    "ai_analysis": "Bloquear a origem.",
    "timestamp": "2026-11-06T12:00:00Z",
    "status": "ANALISADO",
}


class FakeResponse:
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code
        self.ok = status_code < 400

    def json(self):
        return self.body


@pytest.fixture
def api(monkeypatch):
    """Simula a API; os testes alteram `routes` e consultam `calls`."""
    state = {
        "routes": {
            ("GET", "/threats/"): FakeResponse([THREAT]),
            ("GET", "/threats/blocked"): FakeResponse([]),
            ("POST", "/threats/analyze"): FakeResponse(THREAT, 201),
            ("POST", "/threats/block"): FakeResponse(
                {
                    "ip_address": "10.0.0.1",
                    "reason": None,
                    "created_at": "2026-11-06T12:00:00Z",
                    "dispatched": True,
                }
            ),
        },
        "calls": [],
    }

    def fake_request(method, url, **kwargs):
        path = url.removeprefix(dashboard_api.settings.API_URL)
        state["calls"].append((method, path, kwargs))
        return state["routes"][(method, path)]

    monkeypatch.setattr(dashboard_api.requests, "request", fake_request)
    return state


def open_page(name):
    return AppTest.from_file(PAGES / name, default_timeout=10).run()


def test_every_request_sends_the_api_key(api):
    dashboard_api.list_threats()

    headers = api["calls"][0][2]["headers"]
    assert headers["X-API-Key"] == dashboard_api.settings.API_KEY


def test_api_error_detail_reaches_the_user(api):
    api["routes"][("GET", "/threats/")] = FakeResponse({"detail": "Sem acesso."}, 403)

    with pytest.raises(dashboard_api.ApiError, match="Sem acesso."):
        dashboard_api.list_threats()


def test_connection_failure_becomes_api_error(monkeypatch):
    def fail(*_args, **_kwargs):
        raise requests.ConnectionError

    monkeypatch.setattr(dashboard_api.requests, "request", fail)

    with pytest.raises(dashboard_api.ApiError):
        dashboard_api.list_threats()


def test_submit_shows_analysis(api):
    page = open_page("submit.py")
    page.text_input[0].set_value("10.0.0.1")
    page.text_area[0].set_value("Tráfego anormal.")
    page.button[0].click().run()

    assert not page.exception
    assert [metric.value for metric in page.metric] == ["ALTO", "ANALISADO"]


def test_submit_requires_fields(api):
    page = open_page("submit.py")
    page.button[0].click().run()

    assert len(page.warning) == 1
    assert api["calls"] == []


def test_history_shows_metrics(api):
    page = open_page("history.py")

    assert not page.exception
    assert [metric.value for metric in page.metric] == ["1", "1", "0"]


def test_history_handles_empty_database(api):
    api["routes"][("GET", "/threats/")] = FakeResponse([])

    page = open_page("history.py")

    assert not page.exception
    assert len(page.info) == 1


def test_history_warns_about_undispatched_block(api):
    api["routes"][("GET", "/threats/blocked")] = FakeResponse(
        [{"ip_address": "10.0.0.1", "reason": None, "created_at": "x", "dispatched": False}]
    )

    page = open_page("history.py")

    assert "10.0.0.1" in page.warning[0].value
    assert page.selectbox[0].options == ["10.0.0.1"]


def test_history_requests_block(api):
    page = open_page("history.py")
    page.button[0].click().run()

    assert not page.exception
    assert ("POST", "/threats/block") in [call[:2] for call in api["calls"]]


def test_csv_neutralizes_formulas():
    source = (PAGES / "history.py").read_text(encoding="utf-8")
    start = source.index("def to_safe_csv")
    namespace = {"pd": pd}
    exec(source[start : source.index("st.subheader")], namespace)  # noqa: S102

    csv = namespace["to_safe_csv"](pd.DataFrame({"description": ["=1+1", "normal"]}))

    assert "'=1+1" in csv.decode("utf-8-sig")
