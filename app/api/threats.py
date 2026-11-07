import logging

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from sqlmodel import Session, col, select

from app.agents.graph import threat_graph
from app.core.rate_limit import enforce_rate_limit
from app.core.security import verify_api_key
from app.db.database import get_db
from app.db.models import BlockedIPModel, ThreatModel
from app.schemas.threat import (
    STATUS_ANALYZED,
    BlockRequest,
    BlockResponse,
    ThreatCreate,
    ThreatResponse,
)
from app.services.notification_service import dispatch_block, notify_threat
from app.services.ollama_service import LLMUnavailableError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threats", tags=["Threats"], dependencies=[Depends(verify_api_key)])


def _to_response(threat: ThreatModel, block_results: dict[str, str]) -> ThreatResponse:
    result = block_results.get(threat.ip_address)
    return ThreatResponse(
        **threat.model_dump(), status=result.upper() if result else STATUS_ANALYZED
    )


def _block_results(db: Session) -> dict[str, str]:
    # O estado vem da resposta do workflow, que sabe se o bloqueio foi real ou simulado.
    # Sem aceitação do n8n, nada foi bloqueado: o incidente não pode aparecer como tal.
    query = select(BlockedIPModel.ip_address, BlockedIPModel.result).where(
        col(BlockedIPModel.dispatched)
    )
    return {ip_address: result for ip_address, result in db.exec(query).all() if result}


@router.post(
    "/analyze",
    response_model=ThreatResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_rate_limit)],
)
def analyze_threat(
    threat: ThreatCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    ip_address = str(threat.ip_address)
    try:
        result = threat_graph.invoke(
            {
                "ip_address": ip_address,
                "threat_type": threat.threat_type,
                "description": threat.description,
                "risk_level": "INDETERMINADO",
                "ai_analysis": "",
            }
        )
    except LLMUnavailableError as exc:
        logger.error("Modelo de IA indisponível: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Modelo de IA indisponível. Tente novamente mais tarde.",
        ) from exc

    record = ThreatModel(
        ip_address=ip_address,
        threat_type=threat.threat_type,
        description=threat.description,
        risk_level=result["risk_level"],
        ai_analysis=result["ai_analysis"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    response = _to_response(record, _block_results(db))
    background_tasks.add_task(notify_threat, response.model_dump(mode="json"))
    return response


@router.get("/", response_model=list[ThreatResponse])
def list_threats(
    limit: int = Query(default=500, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    threats = db.exec(
        select(ThreatModel).order_by(col(ThreatModel.id).desc()).offset(offset).limit(limit)
    ).all()
    block_results = _block_results(db)
    return [_to_response(threat, block_results) for threat in threats]


@router.get("/blocked", response_model=list[BlockResponse])
def list_blocked(db: Session = Depends(get_db)):
    return db.exec(select(BlockedIPModel).order_by(col(BlockedIPModel.created_at).desc())).all()


@router.post("/block", response_model=BlockResponse)
def block_ip(request: BlockRequest, db: Session = Depends(get_db)):
    """Regista o bloqueio e pede a sua execução ao n8n.

    A API não altera nenhuma firewall: `dispatched` indica se o n8n aceitou o pedido e
    `result` guarda a resposta dele, por exemplo "bloqueado (simulado)".
    Repetir o pedido volta a tentar o envio, se ainda não tiver sido aceite.
    """
    ip_address = str(request.ip_address)
    record = db.get(BlockedIPModel, ip_address)
    if record and record.dispatched:
        return record

    if record is None:
        record = BlockedIPModel(ip_address=ip_address, reason=request.reason)
    record.result = dispatch_block(ip_address, record.reason)
    record.dispatched = record.result is not None
    db.add(record)
    db.commit()
    db.refresh(record)
    return record
