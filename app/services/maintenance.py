"""Tarefa periódica da API: bloqueios com prazo vencido e limpeza das sessões."""

import asyncio
import logging

from sqlmodel import Session

from app.services import auth_service
from app.services.block_expiry import expire_blocks

logger = logging.getLogger(__name__)


def run_maintenance_once(engine) -> None:
    """Uma volta completa. Cada trabalho é independente: o erro de um não impede o outro."""
    try:
        with Session(engine) as db:
            expire_blocks(db)
    except Exception:
        logger.exception("Falha ao verificar bloqueios expirados.")
    try:
        with Session(engine) as db:
            auth_service.cleanup(db)
    except Exception:
        logger.exception("Falha ao limpar sessões e tentativas de login antigas.")


async def maintenance_loop(engine, interval_seconds: float) -> None:
    """Corre ao arrancar e depois a cada `interval_seconds`, até ser cancelada."""
    while True:
        # Numa thread: as chamadas ao n8n e à base de dados são bloqueantes.
        await asyncio.to_thread(run_maintenance_once, engine)
        await asyncio.sleep(interval_seconds)
