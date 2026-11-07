import streamlit as st

from dashboard_api import ApiError, analyze_threat

THREAT_TYPES = ["Brute Force", "Port Scan", "DDoS", "Malware", "Acesso Não Autorizado"]

st.subheader("Submeter novo incidente", anchor=False)

with st.form("threat_form", border=True):
    ip_address = st.text_input("Endereço IP", placeholder="192.168.1.100")
    threat_type = st.selectbox("Tipo de ameaça", THREAT_TYPES)
    description = st.text_area(
        "Descrição do incidente",
        placeholder="Múltiplas tentativas de login inválidas a partir da origem.",
        max_chars=5000,
    )
    submitted = st.form_submit_button("Executar análise", type="primary", icon=":material/search:")

if submitted:
    if not ip_address.strip() or not description.strip():
        st.warning("Preencha o endereço IP e a descrição do incidente.")
        st.stop()

    try:
        with st.spinner("A analisar o incidente com a IA..."):
            result = analyze_threat(ip_address.strip(), threat_type, description.strip())
    except ApiError as exc:
        st.error(str(exc), title="Não foi possível concluir a análise")
    else:
        with st.container(horizontal=True):
            st.metric("Nível de risco", result["risk_level"], border=True)
            st.metric("Estado", result["status"], border=True)
        with st.container(border=True):
            st.markdown("**Parecer técnico da IA**")
            st.write(result["ai_analysis"] or "Sem análise detalhada disponível.")
