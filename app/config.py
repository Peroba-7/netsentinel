from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    # utf-8-sig: um BOM no início do .env faria a primeira variável ser ignorada.
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8-sig",
        extra="ignore",
    )

    API_KEY: str = Field(min_length=16)
    DATABASE_URL: str

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

    API_URL: str = "http://127.0.0.1:8000"  # usado pelo dashboard


settings = Settings()
