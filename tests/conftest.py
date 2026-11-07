import os

# Tem de vir antes de qualquer import de `app`; as variáveis reais do .env não são usadas.
os.environ.update(
    API_KEY="test-api-key-1234567890",
    DATABASE_URL="sqlite://",
    N8N_WEBHOOK_URL="",
    DISCORD_WEBHOOK_URL="",
    TELEGRAM_BOT_TOKEN="",
    TELEGRAM_CHAT_ID="",
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine  # noqa: E402

from app.agents import graph  # noqa: E402
from app.api import threats  # noqa: E402
from app.core import rate_limit  # noqa: E402
from app.db.database import get_db  # noqa: E402
from app.main import app  # noqa: E402

HEADERS = {"X-API-Key": os.environ["API_KEY"]}
LLM_RESPONSE = '{"risk_level": "ALTO", "analysis": "Bloquear a origem."}'


class FakeRedis:
    def __init__(self):
        self.count = 0

    def pipeline(self):
        return self

    def incr(self, _key):
        self.count += 1

    def expire(self, _key, _seconds):
        pass

    def execute(self):
        return [self.count]


@pytest.fixture
def client(monkeypatch):
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)

    def override_db():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    monkeypatch.setattr(graph, "generate_analysis", lambda _prompt: LLM_RESPONSE)
    monkeypatch.setattr(rate_limit, "redis_client", FakeRedis())
    monkeypatch.setattr(threats, "notify_threat", lambda _threat: None)
    monkeypatch.setattr(threats, "dispatch_block", lambda _ip, _reason: "bloqueado (simulado)")
    with TestClient(app, headers=HEADERS) as test_client:
        yield test_client
    app.dependency_overrides.clear()
