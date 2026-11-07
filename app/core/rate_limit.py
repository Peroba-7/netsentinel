import logging
import time

import redis
from fastapi import HTTPException, Request, status

from app.config import settings

logger = logging.getLogger(__name__)

redis_client = redis.Redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,
    socket_connect_timeout=0.5,
    socket_timeout=0.5,
)


def enforce_rate_limit(request: Request) -> None:
    """Limita pedidos por cliente/minuto, protegendo o modelo de IA de sobrecarga.

    Se o Redis estiver em baixo, o pedido passa: uma falha da proteção não deve
    impedir a análise de incidentes.
    """
    limit = settings.RATE_LIMIT_PER_MINUTE
    if limit <= 0:
        return

    client = request.client.host if request.client else "unknown"
    key = f"ratelimit:{client}:{int(time.time() // 60)}"
    try:
        pipe = redis_client.pipeline()
        pipe.incr(key)
        pipe.expire(key, 60)
        count = pipe.execute()[0]
    except redis.RedisError:
        logger.warning("Redis indisponível; limite de pedidos não aplicado.")
        return

    if count > limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiados pedidos. Tente novamente dentro de um minuto.",
            headers={"Retry-After": "60"},
        )
