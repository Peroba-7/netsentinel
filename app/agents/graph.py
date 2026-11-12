import json
import logging
import unicodedata
from typing import NotRequired, TypedDict

from langgraph.graph import END, StateGraph

from app.agents.prompt import build_messages
from app.agents.risk_floor import apply_risk_floor, floor_note
from app.agents.text_fixes import fix_ip_gender
from app.schemas.threat import RISK_LEVELS
from app.services.geoip_service import IpOrigin
from app.services.ollama_service import generate_analysis

logger = logging.getLogger(__name__)

UNKNOWN_RISK = "INDETERMINADO"


class ThreatState(TypedDict):
    ip_address: str
    threat_type: str
    description: str
    risk_level: str
    ai_analysis: str
    # Origem do IP na base local; ausente nas avaliações e em quem chama o fluxo sem ela.
    origin: NotRequired[IpOrigin | None]
    # Nível dado pelo modelo, antes das regras de nível mínimo.
    model_risk_level: NotRequired[str]


def _strip_accents(text: str) -> str:
    return "".join(
        char for char in unicodedata.normalize("NFD", text) if unicodedata.category(char) != "Mn"
    )


_RISK_BY_KEY = {_strip_accents(level): level for level in RISK_LEVELS}


def parse_analysis(raw: str) -> tuple[str, str]:
    """Extrai (risco, parecer) da resposta do modelo.

    Uma resposta fora do formato fica INDETERMINADO: inventar um nível esconderia
    o erro, e procurar palavras no texto confunde "não é crítico" com CRÍTICO.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return UNKNOWN_RISK, raw.strip()
    if not isinstance(data, dict):
        return UNKNOWN_RISK, raw.strip()

    key = _strip_accents(str(data.get("risk_level", "")).strip().upper())
    analysis = data.get("analysis")
    analysis = analysis.strip() if isinstance(analysis, str) else ""
    return _RISK_BY_KEY.get(key, UNKNOWN_RISK), analysis or raw.strip()


def analyze_node(state: ThreatState) -> ThreatState:
    messages = build_messages(
        state["ip_address"], state["threat_type"], state["description"], state.get("origin")
    )
    risk_level, analysis = parse_analysis(generate_analysis(messages))
    return {**state, "risk_level": risk_level, "ai_analysis": analysis}


def guard_node(state: ThreatState) -> ThreatState:
    """Regras fixas depois do modelo: nível mínimo por sinais objetivos e correção do texto."""
    result = apply_risk_floor(state["description"], state["risk_level"])
    analysis = state["ai_analysis"]
    if result.adjusted:
        logger.warning(
            "Nível de risco ajustado de %s para %s pelas regras: %s",
            result.model_risk_level,
            result.risk_level,
            ", ".join(signal.rule for signal in result.signals),
        )
        analysis = f"{analysis}\n\n{floor_note(result)}".strip()
    return {
        **state,
        "risk_level": result.risk_level,
        "model_risk_level": result.model_risk_level,
        # O prompt pede "o IP", mas o modelo nem sempre cumpre: corrige-se antes de guardar.
        "ai_analysis": fix_ip_gender(analysis),
    }


def build_graph():
    workflow = StateGraph(ThreatState)
    workflow.add_node("analyzer", analyze_node)
    workflow.add_node("guard", guard_node)
    workflow.set_entry_point("analyzer")
    workflow.add_edge("analyzer", "guard")
    workflow.add_edge("guard", END)
    return workflow.compile()


threat_graph = build_graph()
