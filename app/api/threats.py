import logging
from datetime import timedelta

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from pydantic import IPvAnyAddress
from sqlalchemy import func
from sqlmodel import Session, col, select

from app.agents.graph import threat_graph
from app.core.rate_limit import enforce_rate_limit
from app.core.security import verify_api_key
from app.db.database import get_db
from app.db.models import BlockedIPModel, ThreatModel, utcnow
from app.schemas.threat import (
    STATUS_ANALYZED,
    BlockRequest,
    BlockResponse,
    RiskLevel,
    ThreatCreate,
    ThreatResponse,
    UnblockResponse,
)
from app.services.notification_service import dispatch_block, dispatch_unblock, notify_threat
from app.services.ollama_service import LLMUnavailableError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/threats", tags=["Threats"], dependencies=[Depends(verify_api_key)])


def _to_response(threat: ThreatModel, block_results: dict[str, str]) -> ThreatResponse:
    # O estado é do incidente; o bloqueio é do IP e pode vir de outro incidente com o mesmo IP.
    result = block_results.get(threat.ip_address)
    return ThreatResponse(
        **threat.model_dump(),
        status=STATUS_ANALYZED,
        ip_blocked=result is not None,
        ip_block_result=result,
    )


def _block_results(db: Session) -> dict[str, str]:
    # O resultado vem da resposta do workflow, que sabe se o bloqueio foi real ou simulado.
    # Sem aceitação do n8n, nada foi bloqueado: o IP não pode aparecer como bloqueado.
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
    risk_level: RiskLevel | None = Query(default=None, description="Filtra por nível de risco"),
    ip_address: IPvAnyAddress | None = Query(default=None, description="Filtra por IP exato"),
    search: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
        description="Texto contido no tipo ou na descrição, sem distinguir maiúsculas",
    ),
    db: Session = Depends(get_db),
):
    query = select(ThreatModel)
    if risk_level:
        query = query.where(ThreatModel.risk_level == risk_level)
    if ip_address:
        query = query.where(ThreatModel.ip_address == str(ip_address))
    if search:
        text = search.lower()
        query = query.where(
            func.lower(ThreatModel.threat_type).contains(text, autoescape=True)
            | func.lower(func.coalesce(ThreatModel.description, "")).contains(
                text, autoescape=True
            )
        )
    threats = db.exec(query.order_by(col(ThreatModel.id).desc()).offset(offset).limit(limit)).all()
    block_results = _block_results(db)
    return [_to_response(threat, block_results) for threat in threats]


@router.get("/blocked", response_model=list[BlockResponse])
def list_blocked(db: Session = Depends(get_db)):
    return db.exec(select(BlockedIPModel).order_by(col(BlockedIPModel.created_at).desc())).all()


@router.get("/{threat_id}", response_model=ThreatResponse)
def get_threat(threat_id: int, db: Session = Depends(get_db)):
    threat = db.get(ThreatModel, threat_id)
    if threat is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Incidente não encontrado."
        )
    return _to_response(threat, _block_results(db))


@router.post("/block", response_model=BlockResponse)
def block_ip(request: BlockRequest, db: Session = Depends(get_db)):
    """Regista o bloqueio e pede a sua execução ao n8n.

    A API não altera nenhuma firewall: `dispatched` indica se o n8n aceitou o pedido e
    `result` guarda a resposta dele, por exemplo "bloqueado (simulado)".
    Com `duration_minutes`, o bloqueio é retirado automaticamente quando o prazo acaba;
    sem ele, é permanente.
    Repetir o pedido volta a tentar o envio, se ainda não tiver sido aceite. Um bloqueio já
    aceite não muda: para alterar o prazo, retire-o e peça-o de novo.
    """
    ip_address = str(request.ip_address)
    record = db.get(BlockedIPModel, ip_address)
    if record and record.dispatched:
        return record

    if record is None:
        record = BlockedIPModel(ip_address=ip_address)
    # Numa nova tentativa, um motivo enviado agora substitui o anterior; sem motivo, mantém-se.
    if request.reason:
        record.reason = request.reason
    record.expires_at = (
        utcnow() + timedelta(minutes=request.duration_minutes)
        if request.duration_minutes
        else None
    )
    record.result = dispatch_block(ip_address, record.reason)
    record.dispatched = record.result is not None
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.delete("/block/{ip_address}", response_model=UnblockResponse)
def unblock_ip(ip_address: IPvAnyAddress, db: Session = Depends(get_db)):
    """Retira o bloqueio de um IP.

    Se o n8n já tinha aceite o bloqueio, o desbloqueio também tem de ser aceite por ele; senão
    o registo mantém-se, para a API não indicar um IP como livre quando pode continuar bloqueado.
    Um pedido que nunca foi aceite é apenas apagado.
    """
    ip = str(ip_address)
    record = db.get(BlockedIPModel, ip)
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Este IP não tem pedido de bloqueio."
        )

    result = None
    if record.dispatched:
        result = dispatch_unblock(ip)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="O n8n não aceitou o desbloqueio. O bloqueio mantém-se registado.",
            )

    db.delete(record)
    db.commit()
    return UnblockResponse(ip_address=ip, result=result)
