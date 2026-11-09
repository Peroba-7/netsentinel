from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    # utf-8-sig: um BOM no início do .env faria a primeira variável ser ignorada.
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8-sig",
        extra="ignore",
    )

    # Chave de serviço com acesso total, para scripts e curl. Vazia, fica desativada.
    # O dashboard não a usa: cada pessoa entra com o seu utilizador.
    API_KEY: str = ""
    # Obrigatória na API e no Alembic; o dashboard não liga à base de dados.
    DATABASE_URL: str = ""

    # Sessões e proteção do login.
    SESSION_TTL_MINUTES: int = Field(default=480, ge=5)
    LOGIN_MAX_ATTEMPTS: int = Field(default=5, ge=1)
    LOGIN_LOCK_MINUTES: int = Field(default=15, ge=1)

    REDIS_URL: str = "redis://localhost:6379/0"
    RATE_LIMIT_PER_MINUTE: int = 10  # 0 desativa o limite

    OLLAMA_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3"
    OLLAMA_TIMEOUT_SECONDS: float = 300.0  # o primeiro pedido carrega o modelo

    N8N_WEBHOOK_URL: str = ""
    # Segredo enviado ao n8n no cabeçalho X-NetSentinel-Secret; o webhook rejeita o resto.
    N8N_WEBHOOK_SECRET: str = ""
    DISCORD_WEBHOOK_URL: str = ""
    TELEGRAM_BOT_TOKEN: str = ""
    TELEGRAM_CHAT_ID: str = ""

    # Intervalo da tarefa que retira bloqueios com prazo vencido; 0 desativa a tarefa.
    BLOCK_EXPIRY_INTERVAL_SECONDS: int = Field(default=60, ge=0)

    API_URL: str = "http://127.0.0.1:8000"  # usado pelo dashboard

    @field_validator("API_KEY")
    @classmethod
    def _api_key_is_strong_or_disabled(cls, value: str) -> str:
        if value and len(value) < 16:
            raise ValueError("API_KEY deve ter pelo menos 16 caracteres, ou ficar vazia.")
        return value


settings = Settings()
