"""Retira automaticamente os bloqueios cujo prazo acabou."""

import logging
from datetime import datetime

from sqlmodel import Session, col, select

from app.db.models import BlockedIPModel, utcnow
from app.services.notification_service import dispatch_unblock

logger = logging.getLogger(__name__)


def expire_blocks(db: Session, now: datetime | None = None) -> int:
    """Desbloqueia os IPs com prazo vencido e devolve quantos registos foram removidos.

    Segue a mesma regra do desbloqueio manual: um bloqueio aceite pelo n8n só é removido se
    o n8n aceitar também o desbloqueio. Se falhar, o registo fica e é tentado na volta seguinte,
    para a API nunca indicar como livre um IP que pode continuar bloqueado.
    """
    now = now or utcnow()
    expired = db.exec(
        select(BlockedIPModel).where(
            col(BlockedIPModel.expires_at).is_not(None), col(BlockedIPModel.expires_at) <= now
        )
    ).all()

    removed = 0
    for record in expired:
        if record.dispatched and dispatch_unblock(record.ip_address) is None:
            logger.warning(
                "Prazo do bloqueio de %s acabou, mas o n8n não aceitou o desbloqueio. "
                "Nova tentativa na próxima verificação.",
                record.ip_address,
            )
            continue
        db.delete(record)
        db.commit()
        removed += 1
        logger.info("Bloqueio de %s expirou e foi retirado.", record.ip_address)
    return removed

