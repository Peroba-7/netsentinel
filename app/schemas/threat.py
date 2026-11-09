from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator

RISK_LEVELS = ("BAIXO", "MÉDIO", "ALTO", "CRÍTICO", "INDETERMINADO")
RiskLevel = Literal["BAIXO", "MÉDIO", "ALTO", "CRÍTICO", "INDETERMINADO"]
ALERT_LEVELS = {"ALTO", "CRÍTICO"}

STATUS_ANALYZED = "ANALISADO"

THREAT_TYPES = ("Brute Force", "DDoS", "Port Scan", "Malware", "Phishing", "Outro")

# Chave de comparação (só letras e números, em minúsculas) -> nome padrão.
_THREAT_TYPE_ALIASES = {
    **{"".join(filter(str.isalnum, name.lower())): name for name in THREAT_TYPES},
    "sshbruteforce": "Brute Force",
    "other": "Outro",
}


def normalize_threat_type(value: str) -> str:
    """Devolve o nome padrão de um tipo conhecido, ignorando espaços, hífens e maiúsculas.

    Assim "brute-force", "SSH Brute Force" e " Brute  Force " contam como uma só categoria.
    Um tipo desconhecido mantém o texto original, só com os espaços arrumados.
    """
    text = " ".join(value.split())
    key = "".join(filter(str.isalnum, text.lower()))
    return _THREAT_TYPE_ALIASES.get(key, text)


class ThreatCreate(BaseModel):
    ip_address: IPvAnyAddress
    threat_type: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=5000)

    @field_validator("threat_type")
    @classmethod
    def _normalize_threat_type(cls, value: str) -> str:
        normalized = normalize_threat_type(value)
        if not normalized:
            raise ValueError("O tipo de ameaça não pode estar vazio.")
        return normalized


class ThreatResponse(BaseModel):
    id: int
    ip_address: str
    threat_type: str
    description: str | None
    risk_level: str
    ai_analysis: str | None
    timestamp: datetime
    # Estado do próprio incidente.
    status: str
    # Se o IP tem um bloqueio aceite pelo n8n, venha ele deste incidente ou de outro do mesmo IP.
    ip_blocked: bool = False
    # Resposta do n8n ao bloqueio do IP, por exemplo "bloqueado (simulado)".
    ip_block_result: str | None = None


MAX_BLOCK_MINUTES = 7 * 24 * 60  # 7 dias


class BlockRequest(BaseModel):
    ip_address: IPvAnyAddress
    reason: str | None = Field(default=None, max_length=500)
    # Sem duração, o bloqueio é permanente.
    duration_minutes: int | None = Field(default=None, ge=1, le=MAX_BLOCK_MINUTES)


class BlockResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip_address: str
    reason: str | None
    created_at: datetime
    dispatched: bool
    result: str | None
    expires_at: datetime | None


class UnblockResponse(BaseModel):
    ip_address: str
    # Resposta do workflow, ou None quando o bloqueio nunca chegou a ser aceite pelo n8n.
    result: str | None
