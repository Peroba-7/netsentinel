from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

RISK_LEVELS = ("BAIXO", "MÉDIO", "ALTO", "CRÍTICO", "INDETERMINADO")
ALERT_LEVELS = {"ALTO", "CRÍTICO"}

STATUS_ANALYZED = "ANALISADO"


class ThreatCreate(BaseModel):
    ip_address: IPvAnyAddress
    threat_type: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=5000)


class ThreatResponse(BaseModel):
    id: int
    ip_address: str
    threat_type: str
    description: str | None
    risk_level: str
    ai_analysis: str | None
    timestamp: datetime
    status: str


class BlockRequest(BaseModel):
    ip_address: IPvAnyAddress
    reason: str | None = Field(default=None, max_length=500)


class BlockResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip_address: str
    reason: str | None
    created_at: datetime
    dispatched: bool
    result: str | None
