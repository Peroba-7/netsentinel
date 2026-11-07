import logging

import httpx

from app.config import settings
from app.schemas.threat import ALERT_LEVELS

logger = logging.getLogger(__name__)

TIMEOUT_SECONDS = 10.0


def _post(name: str, url: str, payload: dict) -> bool:
    try:
        response = httpx.post(url, json=payload, timeout=TIMEOUT_SECONDS)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        # Só o tipo do erro: a mensagem pode conter o URL, com o token do bot.
        logger.warning("Falha ao notificar %s: %s", name, type(exc).__name__)
        return False
    return True


def _send_to_n8n(payload: dict) -> bool:
    if not settings.N8N_WEBHOOK_URL:
        return False
    return _post("n8n", settings.N8N_WEBHOOK_URL, payload)


def _send_chat_alert(message: str) -> None:
    if settings.DISCORD_WEBHOOK_URL:
        _post(
            "Discord",
            settings.DISCORD_WEBHOOK_URL,
            # Sem menções: o texto inclui dados enviados por terceiros.
            {"content": message, "allowed_mentions": {"parse": []}},
        )
    if settings.TELEGRAM_BOT_TOKEN and settings.TELEGRAM_CHAT_ID:
        _post(
            "Telegram",
            f"https://api.telegram.org/bot{settings.TELEGRAM_BOT_TOKEN}/sendMessage",
            {"chat_id": settings.TELEGRAM_CHAT_ID, "text": message},
        )


def notify_threat(threat: dict) -> None:
    """Envia todas as ameaças ao n8n e alerta o chat apenas nas de risco alto."""
    _send_to_n8n({"event": "threat.analyzed", **threat})
    if threat["risk_level"] in ALERT_LEVELS:
        _send_chat_alert(
            f"🚨 NetSentinel: risco {threat['risk_level']}\n"
            f"IP: {threat['ip_address']}\n"
            f"Tipo: {threat['threat_type']}"
        )


def dispatch_block(ip_address: str, reason: str | None) -> bool:
    """Pede o bloqueio ao n8n. Devolve True se o pedido foi aceite."""
    return _send_to_n8n({"event": "ip.block", "ip_address": ip_address, "reason": reason})
