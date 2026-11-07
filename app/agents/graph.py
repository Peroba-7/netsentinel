import json
import unicodedata
from typing import TypedDict

from langgraph.graph import END, StateGraph

from app.schemas.threat import RISK_LEVELS
from app.services.ollama_service import generate_analysis

UNKNOWN_RISK = "INDETERMINADO"


class ThreatState(TypedDict):
    ip_address: str
    threat_type: str
    description: str
    risk_level: str
    ai_analysis: str


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
    prompt = (
        "Analisa a seguinte ameaça de segurança.\n\n"
        "<incidente>\n"
        f"IP: {state['ip_address']}\n"
        f"Tipo: {state['threat_type']}\n"
        f"Descrição: {state['description']}\n"
        "</incidente>"
    )
    risk_level, analysis = parse_analysis(generate_analysis(prompt))
    return {**state, "risk_level": risk_level, "ai_analysis": analysis}


def build_graph():
    workflow = StateGraph(ThreatState)
    workflow.add_node("analyzer", analyze_node)
    workflow.set_entry_point("analyzer")
    workflow.add_edge("analyzer", END)
    return workflow.compile()


threat_graph = build_graph()
