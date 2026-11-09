from pathlib import Path

import pandas as pd
import pytest
import requests
from streamlit.testing.v1 import AppTest

import dashboard_api
from app.schemas.threat import THREAT_TYPES

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
    "ip_blocked": False,
    "ip_block_result": None,
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
            ("DELETE", "/threats/block/10.0.0.1"): FakeResponse(
                {"ip_address": "10.0.0.1", "result": "desbloqueado (simulado)"}
            ),
            ("POST", "/threats/analyze"): FakeResponse(THREAT, 201),
            ("POST", "/threats/block"): FakeResponse(
                {
                    "ip_address": "10.0.0.1",
                    "reason": None,
                    "expires_at": None,
                    "created_at": "2026-11-06T12:00:00Z",
                    "dispatched": True,
                    "result": "bloqueado (simulado)",
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


@pytest.mark.parametrize(
    "ip_address,description,expected",
    [
        ("", "", "endereço IP"),
        ("", "Tráfego anormal.", "endereço IP"),
        ("10.0.0.1", "   ", "descrição"),
        ("999.0.0.1", "Tráfego anormal.", "não é válido"),
    ],
)
def test_submit_explains_rejection_and_sends_nothing(api, ip_address, description, expected):
    page = open_page("submit.py")
    page.text_input[0].set_value(ip_address)
    page.text_area[0].set_value(description)
    page.button[0].click().run()

    assert expected in page.error[0].value
    assert api["calls"] == []


def test_submit_fields_have_no_placeholder_that_looks_filled(api):
    page = open_page("submit.py")

    assert not page.text_input[0].placeholder
    assert not page.text_area[0].placeholder


def test_submit_rejection_is_logged(api, caplog):
    page = open_page("submit.py")
    page.button[0].click().run()

    assert "Envio rejeitado" in caplog.text


def test_submit_confirms_saved_incident(api):
    page = open_page("submit.py")
    page.text_input[0].set_value("10.0.0.1")
    page.text_area[0].set_value("Tráfego anormal.")
    page.button[0].click().run()

    assert "Incidente 1 guardado" in page.success[0].value


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
        [
            {
                "ip_address": "10.0.0.1",
                "reason": None,
                "expires_at": None,
                "created_at": "x",
                "dispatched": False,
                "result": None,
            }
        ]
    )

    page = open_page("history.py")

    assert "10.0.0.1" in page.warning[0].value
    assert page.selectbox[0].options == ["10.0.0.1"]


def test_history_flags_simulated_blocks(api):
    api["routes"][("GET", "/threats/blocked")] = FakeResponse(
        [
            {
                "ip_address": "10.0.0.1",
                "reason": None,
                "expires_at": None,
                "created_at": "x",
                "dispatched": True,
                "result": "bloqueado (simulado)",
            }
        ]
    )

    page = open_page("history.py")

    assert "simulados" in page.info[0].value


def test_history_requests_block(api):
    page = open_page("history.py")
    page.button[0].click().run()

    assert not page.exception
    block_call = next(call for call in api["calls"] if call[:2] == ("POST", "/threats/block"))
    assert block_call[2]["json"] == {
        "ip_address": "10.0.0.1",
        "reason": "DDoS, risco ALTO",
        "duration_minutes": None,
    }


@pytest.mark.parametrize("label,minutes", [("30 min", 30), ("1 hora", 60), ("24 horas", 1440)])
def test_history_sends_chosen_block_duration(api, label, minutes):
    page = open_page("history.py")
    duration = next(box for box in page.selectbox if box.label == "Duração do bloqueio")

    assert duration.options == ["30 min", "1 hora", "24 horas", "Permanente"]
    assert duration.value == "Permanente"
    duration.set_value(label).run()
    page.button[0].click().run()

    block_call = next(call for call in api["calls"] if call[:2] == ("POST", "/threats/block"))
    assert block_call[2]["json"]["duration_minutes"] == minutes


def test_history_shows_block_expiry(api):
    entry = {
        "ip_address": "10.0.0.1",
        "reason": "DDoS, risco ALTO",
        "created_at": "2026-11-08T12:00:00Z",
        "dispatched": True,
        "result": "bloqueado (simulado)",
    }
    api["routes"][("GET", "/threats/blocked")] = FakeResponse(
        [
            {**entry, "expires_at": "2026-11-08T12:30:00Z"},
            {**entry, "ip_address": "10.0.0.2", "expires_at": None},
        ]
    )

    page = open_page("history.py")

    table = page.dataframe[-1].value
    assert list(table["expira em"]) == ["08/11/2026 12:30 UTC", "Permanente"]


def test_history_block_reason_uses_latest_incident_of_ip(api):
    older = {**THREAT, "id": 1, "threat_type": "ssh brute force", "risk_level": "MÉDIO"}
    newer = {**THREAT, "id": 2, "threat_type": "Port Scan", "risk_level": "CRÍTICO"}
    api["routes"][("GET", "/threats/")] = FakeResponse([newer, older])

    page = open_page("history.py")
    page.button[0].click().run()

    block_call = next(call for call in api["calls"] if call[:2] == ("POST", "/threats/block"))
    assert block_call[2]["json"]["reason"] == "Port Scan, risco CRÍTICO"


def test_submit_offers_only_known_threat_types(api):
    page = open_page("submit.py")

    assert page.selectbox[0].options == list(THREAT_TYPES)


def test_history_filters_table_without_changing_metrics(api):
    other = {**THREAT, "id": 2, "ip_address": "10.0.0.2", "risk_level": "BAIXO"}
    api["routes"][("GET", "/threats/")] = FakeResponse([THREAT, other])

    page = open_page("history.py")
    assert [metric.value for metric in page.metric] == ["2", "1", "0"]

    page.sidebar.multiselect[0].set_value(["BAIXO"]).run()

    assert not page.exception
    assert "1 de 2" in page.caption[0].value
    assert [metric.value for metric in page.metric] == ["2", "1", "0"]


def test_history_text_filter_without_match_shows_message(api):
    page = open_page("history.py")
    page.sidebar.text_input[0].set_value("não existe").run()

    assert not page.exception
    assert "Nenhum incidente" in page.info[0].value


def test_history_unblocks_ip(api):
    api["routes"][("GET", "/threats/blocked")] = FakeResponse(
        [
            {
                "ip_address": "10.0.0.1",
                "reason": None,
                "expires_at": None,
                "created_at": "x",
                "dispatched": True,
                "result": "bloqueado (simulado)",
            }
        ]
    )
    page = open_page("history.py")
    unblock = next(button for button in page.button if button.label == "Retirar bloqueio")

    unblock.click().run()

    assert not page.exception
    assert ("DELETE", "/threats/block/10.0.0.1") in [call[:2] for call in api["calls"]]


def test_csv_neutralizes_formulas():
    source = (PAGES / "history.py").read_text(encoding="utf-8")
    start = source.index("def to_safe_csv")
    namespace = {"pd": pd}
    exec(source[start : source.index("st.subheader")], namespace)  # noqa: S102

    csv = namespace["to_safe_csv"](pd.DataFrame({"description": ["=1+1", "normal"]}))

    assert "'=1+1" in csv.decode("utf-8-sig")


def test_history_shows_ip_block_apart_from_incident_status(api):
    blocked_ip = {
        **THREAT,
        "risk_level": "BAIXO",
        "ip_blocked": True,
        "ip_block_result": "bloqueado (simulado)",
    }
    other = {**THREAT, "id": 2, "ip_address": "10.0.0.2"}
    api["routes"][("GET", "/threats/")] = FakeResponse([blocked_ip, other])

    page = open_page("history.py")

    table = page.dataframe[0].value
    assert list(table["status"]) == ["ANALISADO", "ANALISADO"]
    assert list(table["IP bloqueado"]) == ["Sim (simulado)", ""]
    assert "ip_blocked" not in table.columns


@pytest.mark.parametrize(
    "typed,sent",
    [
        ('"Tráfego anormal."', "Tráfego anormal."),
        ("  “Tráfego anormal.”  \n", "Tráfego anormal."),
        ("'Login com \"admin\" falhou'", 'Login com "admin" falhou'),
        ("«Varrimento de portas»", "Varrimento de portas"),
    ],
)
def test_submit_removes_quotes_and_spaces_around_description(api, typed, sent):
    page = open_page("submit.py")
    page.text_input[0].set_value("10.0.0.1")
    page.text_area[0].set_value(typed)
    page.button[0].click().run()

    analyze_call = next(call for call in api["calls"] if call[1] == "/threats/analyze")
    assert analyze_call[2]["json"]["description"] == sent


def test_submit_rejects_description_made_only_of_quotes(api):
    page = open_page("submit.py")
    page.text_input[0].set_value("10.0.0.1")
    page.text_area[0].set_value('  ""  ')
    page.button[0].click().run()

    assert "descrição" in page.error[0].value
    assert api["calls"] == []
