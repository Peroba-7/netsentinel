"""Cliente da API NetSentinel usado pelas páginas do dashboard.

Cada pedido leva o token da sessão de quem entrou; o dashboard não tem chave própria.
É a API que decide o que cada perfil pode fazer.
"""

from datetime import UTC, datetime
from typing import NoReturn
from urllib.parse import quote

import requests
import streamlit as st

from app.config import settings
from app.schemas.user import role_at_least

AUTH_KEY = "auth"


class ApiError(Exception):
    """Falha ao comunicar com a API; a mensagem pode ser mostrada ao utilizador."""


class SessionExpiredError(ApiError):
    """A API recusou a sessão (expirou, terminou ou a conta foi desativada)."""


def current_user() -> dict | None:
    """Sessão de quem está no dashboard: {"token", "username", "role", "expires_at"}.

    Uma sessão cujo prazo já passou é esquecida aqui, sem esperar pela recusa da API.
    """
    user = st.session_state.get(AUTH_KEY)
    if user is None:
        return None
    try:
        expired = datetime.fromisoformat(user["expires_at"]) <= datetime.now(UTC)
    except (KeyError, TypeError, ValueError):
        expired = True
    if expired:
        clear_session()
        return None
    return user


def clear_session() -> None:
    st.session_state.pop(AUTH_KEY, None)


def require_role(minimum: str) -> dict:
    """Pára a página se ninguém entrou ou se o perfil não chega. A API aplica a mesma regra;
    isto só evita mostrar ecrãs que dariam erro."""
    user = current_user()
    if user is None:
        st.info("Inicie sessão para continuar.")
        st.stop()
    if not role_at_least(user["role"], minimum):
        st.error("O seu perfil não tem acesso a esta página.")
        st.stop()
    return user


def show_api_error(exc: ApiError, title: str) -> NoReturn:
    """Mostra o erro e pára a página; com a sessão expirada, volta ao ecrã de login."""
    if isinstance(exc, SessionExpiredError):
        st.rerun()
    st.error(str(exc), title=title)
    st.stop()


def _request(method: str, path: str, timeout: float = 15, auth: bool = True, **kwargs):
    headers = {}
    if auth:
        user = current_user()
        if user is None:
            raise SessionExpiredError("Inicie sessão para continuar.")
        headers["Authorization"] = f"Bearer {user['token']}"
    try:
        response = requests.request(
            method, f"{settings.API_URL}{path}", headers=headers, timeout=timeout, **kwargs
        )
    except requests.RequestException as exc:
        raise ApiError(f"Não foi possível ligar à API em {settings.API_URL}.") from exc

    if not response.ok:
        try:
            detail = response.json().get("detail")
        except (ValueError, AttributeError):
            detail = None
        if not isinstance(detail, str):
            detail = f"A API devolveu o erro {response.status_code}."
        if auth and response.status_code == 401:
            clear_session()
            raise SessionExpiredError(detail)
        raise ApiError(detail)
    return response.json() if response.content else None


def login(username: str, password: str) -> dict:
    """Inicia sessão e guarda-a no estado do Streamlit (só neste separador do navegador)."""
    data = _request(
        "POST", "/auth/login", auth=False, json={"username": username, "password": password}
    )
    st.session_state[AUTH_KEY] = data
    return data


def logout() -> None:
    """Termina a sessão na API (o token deixa de valer) e esquece-a no dashboard."""
    try:
        _request("POST", "/auth/logout")
    except ApiError:
        pass  # mesmo sem resposta da API, a sessão local é apagada
    finally:
        clear_session()


def analyze_threat(ip_address: str, threat_type: str, description: str) -> dict:
    return _request(
        "POST",
        "/threats/analyze",
        # Um pouco acima do limite da API, para receber o erro dela e não um timeout.
        timeout=settings.OLLAMA_TIMEOUT_SECONDS + 15,
        json={
            "ip_address": ip_address,
            "threat_type": threat_type,
            "description": description,
        },
    )


def list_threats() -> list[dict]:
    return _request("GET", "/threats/")


def list_blocked() -> list[dict]:
    return _request("GET", "/threats/blocked")


def block_ip(
    ip_address: str, reason: str | None = None, duration_minutes: int | None = None
) -> dict:
    """Pede o bloqueio; sem `duration_minutes`, o bloqueio é permanente."""
    return _request(
        "POST",
        "/threats/block",
        json={"ip_address": ip_address, "reason": reason, "duration_minutes": duration_minutes},
    )


def unblock_ip(ip_address: str) -> dict:
    return _request("DELETE", f"/threats/block/{quote(ip_address, safe=':.')}")


def list_users() -> list[dict]:
    return _request("GET", "/users/")


def create_user(username: str, password: str, role: str) -> dict:
    return _request(
        "POST", "/users/", json={"username": username, "password": password, "role": role}
    )


def update_user(user_id: int, **changes) -> dict:
    return _request("PATCH", f"/users/{user_id}", json=changes)
