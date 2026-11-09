"""Cliente da API NetSentinel usado pelas páginas do dashboard."""

from urllib.parse import quote

import requests

from app.config import settings


class ApiError(Exception):
    """Falha ao comunicar com a API; a mensagem pode ser mostrada ao utilizador."""


def _request(method: str, path: str, timeout: float = 15, **kwargs):
    try:
        response = requests.request(
            method,
            f"{settings.API_URL}{path}",
            headers={"X-API-Key": settings.API_KEY},
            timeout=timeout,
            **kwargs,
        )
    except requests.RequestException as exc:
        raise ApiError(f"Não foi possível ligar à API em {settings.API_URL}.") from exc

    if not response.ok:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = None
        if not isinstance(detail, str):
            detail = f"A API devolveu o erro {response.status_code}."
        raise ApiError(detail)
    return response.json()


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
