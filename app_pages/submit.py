import ipaddress
import logging

import streamlit as st

from app.schemas.threat import THREAT_TYPES
from dashboard_api import ApiError, analyze_threat

logger = logging.getLogger("netsentinel.dashboard")


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
    description = description.strip()
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
        st.error(str(exc), title="O incidente não foi guardado")
    else:
        st.success(f"Incidente {result['id']} guardado.")
        with st.container(horizontal=True):
            st.metric("Nível de risco", result["risk_level"], border=True)
            st.metric("Estado", result["status"], border=True)
        with st.container(border=True):
            st.markdown("**Parecer técnico da IA**")
            st.write(result["ai_analysis"] or "Sem análise detalhada disponível.")
