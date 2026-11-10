from pathlib import Path

import pandas as pd
import pytest
import requests
from streamlit.testing.v1 import AppTest

import dashboard_api
from app.schemas.threat import THREAT_TYPES
from dashboard_nav import pages_for_role

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


def session(role="admin", expires_at="2999-01-01T00:00:00+00:00"):
    return {
        "token": "token-de-teste",
        "username": f"{role}1",
        "role": role,
        "expires_at": expires_at,
    }


class FakeResponse:
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code
        self.ok = status_code < 400
        self.content = b"" if body is None else b"..."

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


def open_page(name, role="admin"):
    """Abre uma página com uma sessão desse perfil; role=None abre sem sessão."""
    page = AppTest.from_file(PAGES / name, default_timeout=10)
    if role is not None:
        page.session_state[dashboard_api.AUTH_KEY] = session(role)
    return page.run()


@pytest.fixture
def signed_in(monkeypatch):
    """Para chamar o cliente da API fora de uma página do Streamlit."""
    monkeypatch.setattr(dashboard_api, "current_user", lambda: session("analista"))


def test_every_request_sends_the_session_token_and_no_api_key(api, signed_in):
    dashboard_api.list_threats()

    headers = api["calls"][0][2]["headers"]
    assert headers == {"Authorization": "Bearer token-de-teste"}


def test_api_error_detail_reaches_the_user(api, signed_in):
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
    exec(source[start : source.index("user = require_role")], namespace)  # noqa: S102

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


# --- Login e perfis no dashboard --------------------------------------------------------------

ROOT = PAGES.parent


def open_dashboard(auth=None):
    app = AppTest.from_file(ROOT / "dashboard.py", default_timeout=10)
    if auth is not None:
        app.session_state[dashboard_api.AUTH_KEY] = auth
    return app.run()


def button_labels(page):
    return {button.label for button in page.button}


def test_without_session_only_login_is_shown_and_no_data_is_loaded(api):
    app = open_dashboard()

    assert not app.exception
    assert app.subheader[0].value == "Iniciar sessão"
    assert api["calls"] == []


def test_expired_session_goes_back_to_login(api):
    app = open_dashboard(session("admin", expires_at="2000-01-01T00:00:00+00:00"))

    assert app.subheader[0].value == "Iniciar sessão"
    assert api["calls"] == []


def test_login_opens_the_history(api):
    api["routes"][("POST", "/auth/login")] = FakeResponse(session("leitor"))
    app = open_dashboard()

    app.text_input[0].set_value("leitor1")
    app.text_input[1].set_value("palavra-passe-forte")
    app.button[0].click().run()

    assert not app.exception
    assert app.session_state[dashboard_api.AUTH_KEY]["role"] == "leitor"
    assert ("GET", "/threats/") in [call[:2] for call in api["calls"]]
    login_call = api["calls"][0]
    assert "Authorization" not in login_call[2]["headers"]


def test_failed_login_shows_api_message_and_keeps_user_out(api):
    api["routes"][("POST", "/auth/login")] = FakeResponse(
        {"detail": "Utilizador ou palavra-passe inválidos."}, 401
    )
    app = open_dashboard()

    app.text_input[0].set_value("ana")
    app.text_input[1].set_value("errada")
    app.button[0].click().run()

    assert "inválidos" in app.error[0].value
    assert dashboard_api.AUTH_KEY not in app.session_state
    assert [call[:2] for call in api["calls"]] == [("POST", "/auth/login")]


def test_logout_ends_session_in_api_and_dashboard(api):
    api["routes"][("POST", "/auth/logout")] = FakeResponse(None, 204)
    app = open_dashboard(session("analista"))

    next(button for button in app.sidebar.button if button.label == "Sair").click().run()

    assert ("POST", "/auth/logout") in [call[:2] for call in api["calls"]]
    assert dashboard_api.AUTH_KEY not in app.session_state
    assert app.subheader[0].value == "Iniciar sessão"


@pytest.mark.parametrize(
    "role,titles",
    [
        ("leitor", ["Histórico"]),
        ("analista", ["Histórico", "Submeter incidente"]),
        ("admin", ["Histórico", "Submeter incidente", "Utilizadores"]),
    ],
)
def test_menu_lists_only_the_pages_of_the_role(role, titles):
    assert [title for _path, title, _icon in pages_for_role(role)] == titles


@pytest.mark.parametrize(
    "role,can_block,can_unblock",
    [("leitor", False, False), ("analista", True, False), ("admin", True, True)],
)
def test_history_controls_follow_the_role(api, role, can_block, can_unblock):
    api["routes"][("GET", "/threats/blocked")] = FakeResponse(
        [
            {
                "ip_address": "10.0.0.9",
                "reason": None,
                "expires_at": None,
                "created_at": "x",
                "dispatched": True,
                "result": "bloqueado (simulado)",
            }
        ]
    )

    page = open_page("history.py", role=role)

    assert not page.exception
    assert len(page.metric) == 3  # todos os perfis veem o histórico e os gráficos
    assert ("Pedir bloqueio" in button_labels(page)) is can_block
    assert ("Retirar bloqueio" in button_labels(page)) is can_unblock


@pytest.mark.parametrize("name,role", [("submit.py", "leitor"), ("users.py", "analista")])
def test_pages_above_the_role_show_nothing_and_call_nothing(api, name, role):
    page = open_page(name, role=role)

    assert "não tem acesso" in page.error[0].value
    assert api["calls"] == []


@pytest.mark.parametrize("name", ["history.py", "submit.py", "users.py"])
def test_pages_without_session_show_no_data(api, name):
    page = open_page(name, role=None)

    assert api["calls"] == []
    assert not page.metric and not page.dataframe


def test_expired_session_reported_by_api_returns_to_login(api):
    api["routes"][("GET", "/threats/")] = FakeResponse({"detail": "Sessão inválida."}, 401)

    page = open_page("history.py", role="leitor")

    assert dashboard_api.AUTH_KEY not in page.session_state
    assert "Inicie sessão" in page.info[0].value


def test_admin_sees_and_creates_users(api):
    api["routes"][("GET", "/users/")] = FakeResponse(
        [{"id": 1, "username": "admin1", "role": "admin", "is_active": True, "created_at": "x"}]
    )
    api["routes"][("POST", "/users/")] = FakeResponse(
        {"id": 2, "username": "joao", "role": "leitor", "is_active": True, "created_at": "x"}, 201
    )
    page = open_page("users.py", role="admin")
    assert not page.exception
    assert list(page.dataframe[0].value["username"]) == ["admin1"]

    page.text_input[0].set_value("Joao")
    page.text_input[1].set_value("palavra-passe-forte")
    page.text_input[2].set_value("palavra-passe-forte")
    next(button for button in page.button if button.label == "Criar").click().run()

    create_call = next(call for call in api["calls"] if call[:2] == ("POST", "/users/"))
    assert create_call[2]["json"] == {
        "username": "joao",
        "password": "palavra-passe-forte",
        "role": "leitor",
    }


# --- Origem do IP ---------------------------------------------------------------------------

PUBLIC_THREAT = {
    **THREAT,
    "id": 2,
    "ip_address": "8.8.8.8",
    "ip_scope": "publico",
    "country_code": "US",
    "country_name": "Estados Unidos",
    "asn": 15169,
    "as_org": "=HYPERLINK(\"http://x\")",
}
RESERVED_THREAT = {**THREAT, "ip_scope": "reservado"}


def test_history_shows_country_and_organization_with_attribution(api):
    api["routes"][("GET", "/threats/")] = FakeResponse([PUBLIC_THREAT, RESERVED_THREAT])

    page = open_page("history.py")

    assert not page.exception
    table = page.dataframe[0].value
    columns = list(table.columns)
    assert columns[columns.index("ip_address") + 1 : columns.index("ip_address") + 3] == [
        "País",
        "Organização",
    ]
    assert list(table["País"]) == ["US · Estados Unidos", "Rede reservada"]
    assert list(table["Organização"]) == ['AS15169 · =HYPERLINK("http://x")', ""]
    assert not {"country_code", "asn", "as_org", "ip_scope"} & set(columns)
    assert any("IP Geolocation by DB-IP" in caption.value for caption in page.caption)


def test_history_without_origin_data_has_empty_columns_and_no_attribution(api):
    page = open_page("history.py")  # THREAT antigo, sem campos de origem

    table = page.dataframe[0].value
    assert list(table["País"]) == [""] and list(table["Organização"]) == [""]
    assert not any("DB-IP" in caption.value for caption in page.caption)


def test_csv_includes_origin_and_neutralizes_organization_formula():
    source = (PAGES / "history.py").read_text(encoding="utf-8")
    start = source.index("def to_safe_csv")
    namespace = {"pd": pd}
    exec(source[start : source.index("user = require_role")], namespace)  # noqa: S102
    frame = pd.DataFrame({"País": ["US · Estados Unidos"], "Organização": ["=HYPERLINK(1)"]})

    csv = namespace["to_safe_csv"](frame).decode("utf-8-sig")

    assert csv.splitlines()[0] == "País,Organização"
    assert "'=HYPERLINK(1)" in csv


def test_submit_shows_origin_as_plain_text_with_attribution(api):
    api["routes"][("POST", "/threats/analyze")] = FakeResponse(
        {**PUBLIC_THREAT, "as_org": "**Org** [link](http://x)"}, 201
    )
    page = open_page("submit.py")
    page.text_input[0].set_value("8.8.8.8")
    page.text_area[0].set_value("Tráfego anormal.")
    page.button[0].click().run()

    assert not page.exception
    assert page.text[0].value == (
        "Origem do IP: US · Estados Unidos — AS15169 · **Org** [link](http://x)"
    )
    assert any("IP Geolocation by DB-IP" in caption.value for caption in page.caption)


def test_submit_reserved_ip_shows_reserved_without_attribution(api):
    api["routes"][("POST", "/threats/analyze")] = FakeResponse(RESERVED_THREAT, 201)
    page = open_page("submit.py")
    page.text_input[0].set_value("10.0.0.1")
    page.text_area[0].set_value("Tráfego anormal.")
    page.button[0].click().run()

    assert page.text[0].value == "Origem do IP: Rede reservada"
    assert not any("DB-IP" in caption.value for caption in page.caption)
