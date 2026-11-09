import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx
import redis
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.api import auth, threats, users
from app.config import settings
from app.core.rate_limit import redis_client
from app.db.database import engine
from app.services.maintenance import maintenance_loop

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    # Retira os bloqueios com prazo vencido e limpa sessões antigas. Corre neste processo:
    # com vários workers do uvicorn, cada um teria a sua tarefa.
    task = None
    if settings.BLOCK_EXPIRY_INTERVAL_SECONDS > 0:
        task = asyncio.create_task(
            maintenance_loop(engine, settings.BLOCK_EXPIRY_INTERVAL_SECONDS)
        )
    yield
    if task is not None:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


# As tabelas não são criadas aqui: o Alembic aplica as migrações antes de a API arrancar.
app = FastAPI(
    title="NetSentinel API",
    version="3.0.0",
    description="Plataforma de análise de ameaças com LangGraph, Ollama e PostgreSQL.",
    lifespan=lifespan,
)
app.include_router(auth.router)
app.include_router(threats.router)
app.include_router(users.router)


def _database_ok() -> bool:
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError:
        return False
    return True


def _redis_ok() -> bool:
    try:
        return bool(redis_client.ping())
    except redis.RedisError:
        return False


def _ollama_ok() -> bool:
    try:
        response = httpx.get(f"{settings.OLLAMA_URL}/api/tags", timeout=2.0)
        response.raise_for_status()
    except httpx.HTTPError:
        return False
    names = {model["name"] for model in response.json().get("models", [])}
    return settings.OLLAMA_MODEL in names or f"{settings.OLLAMA_MODEL}:latest" in names


@app.get("/", tags=["Health"])
def liveness():
    return {"system": "NetSentinel API", "status": "online"}


@app.get("/health", tags=["Health"])
def health():
    """Estado das dependências. Sem base de dados, o serviço não funciona (503)."""
    checks = {"database": _database_ok(), "redis": _redis_ok(), "ollama": _ollama_ok()}
    return JSONResponse(
        status_code=(
            status.HTTP_200_OK if checks["database"] else status.HTTP_503_SERVICE_UNAVAILABLE
        ),
        content={"status": "ok" if all(checks.values()) else "degraded", "checks": checks},
    )
