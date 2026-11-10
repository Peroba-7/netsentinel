import ipaddress
import logging

import streamlit as st

from app.schemas.threat import THREAT_TYPES
from dashboard_api import ApiError, analyze_threat, require_role, show_api_error
from dashboard_format import DBIP_ATTRIBUTION, has_origin_data, origin_label

logger = logging.getLogger("netsentinel.dashboard")

# Aspas retas, tipográficas e angulares, e espaços em branco.
_EDGE_CHARACTERS = "\"'“”‘’«» \t\r\n"


def clean_description(text: str) -> str:
    """Remove aspas e espaços sobrando no início e no fim, comuns ao colar texto.

    As aspas no meio do texto ficam como estão.
    """
    return text.strip(_EDGE_CHARACTERS)


def find_problems(ip_address: str, description: str) -> list[str]:
    """Devolve o que impede o envio, para o analista saber exatamente o que corrigir."""
    problems = []
    if not ip_address:
        problems.append("Preencha o endereço IP.")
    else:
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            problems.append(f"O endereço IP {ip_address!r} não é válido.")
    if not description:
        problems.append("Preencha a descrição do incidente.")
    return problems


require_role("analista")

st.subheader("Submeter novo incidente", anchor=False)

# Sem placeholders: num campo vazio, parecem texto escrito e o envio era rejeitado.
with st.form("threat_form", border=True):
    ip_address = st.text_input("Endereço IP (obrigatório)", help="Por exemplo: 203.0.113.7")
    threat_type = st.selectbox("Tipo de ameaça", THREAT_TYPES)
    description = st.text_area("Descrição do incidente (obrigatória)", max_chars=5000)
    # Fica junto ao botão, para o aviso nunca aparecer fora do ecrã.
    feedback = st.container()
    submitted = st.form_submit_button("Executar análise", type="primary", icon=":material/search:")

if submitted:
    ip_address = ip_address.strip()
    description = clean_description(description)
    problems = find_problems(ip_address, description)

    if problems:
        logger.warning("Envio rejeitado no formulário: %s", " ".join(problems))
        feedback.error(" ".join(problems), title="O incidente não foi enviado")
        st.stop()

    try:
        with st.spinner("A analisar o incidente. Pode demorar alguns minutos..."):
            result = analyze_threat(ip_address, threat_type, description)
    except ApiError as exc:
        logger.warning("Análise falhou: %s", exc)
        show_api_error(exc, "O incidente não foi guardado")
    else:
        st.success(f"Incidente {result['id']} guardado.")
        with st.container(horizontal=True):
            st.metric("Nível de risco", result["risk_level"], border=True)
            st.metric("Estado", result["status"], border=True)
        origin = origin_label(result)
        if origin:
            # st.text e não markdown: o nome da organização é texto de terceiros.
            st.text(f"Origem do IP: {origin}")
            if has_origin_data([result]):
                st.caption(DBIP_ATTRIBUTION)
        with st.container(border=True):
            st.markdown("**Parecer técnico da IA**")
            st.write(result["ai_analysis"] or "Sem análise detalhada disponível.")
