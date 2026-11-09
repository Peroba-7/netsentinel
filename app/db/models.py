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
    # Fim do bloqueio; None é permanente. A tarefa de expiração retira-o depois desta hora.
    expires_at: datetime | None = None


class UserModel(SQLModel, table=True):
    __tablename__ = "users"

    id: int | None = Field(default=None, primary_key=True)
    # Sempre em minúsculas, para "Ana" e "ana" serem a mesma conta.
    username: str = Field(index=True, unique=True)
    # Hash argon2id; a palavra-passe nunca é guardada.
    password_hash: str
    role: str  # leitor, analista ou admin
    is_active: bool = True
    created_at: datetime = Field(default_factory=utcnow)


class UserSessionModel(SQLModel, table=True):
    __tablename__ = "user_sessions"

    # SHA-256 do token: quem ler a base de dados não consegue usar as sessões.
    token_hash: str = Field(primary_key=True)
    user_id: int = Field(foreign_key="users.id", index=True, ondelete="CASCADE")
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime


class LoginAttemptModel(SQLModel, table=True):
    __tablename__ = "login_attempts"

    # Nome de utilizador tentado, exista ou não: tratar ambos igual não revela quem existe.
    username: str = Field(primary_key=True)
    failed_count: int = 0
    window_started_at: datetime = Field(default_factory=utcnow)
    locked_until: datetime | None = None
