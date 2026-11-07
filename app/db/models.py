from datetime import UTC, datetime

from sqlmodel import Field, SQLModel


def utcnow() -> datetime:
    return datetime.now(UTC)


class ThreatModel(SQLModel, table=True):
    __tablename__ = "threat_records"

    id: int | None = Field(default=None, primary_key=True)
    ip_address: str
    threat_type: str
    description: str | None = None
    risk_level: str
    ai_analysis: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)


class BlockedIPModel(SQLModel, table=True):
    __tablename__ = "blocked_ips"

    ip_address: str = Field(primary_key=True)
    reason: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    # True quando o pedido de bloqueio foi aceite pelo n8n.
    dispatched: bool = False
    # Resposta do workflow, por exemplo "bloqueado (simulado)".
    result: str | None = None
