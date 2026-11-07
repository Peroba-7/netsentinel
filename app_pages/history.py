import pandas as pd
import streamlit as st

from app.schemas.threat import ALERT_LEVELS, RISK_LEVELS
from dashboard_api import ApiError, block_ip, list_blocked, list_threats


def to_safe_csv(frame: pd.DataFrame) -> bytes:
    """Exporta CSV sem fórmulas: as descrições vêm de terceiros e o Excel executaria "=..."."""

    def neutralize(value):
        if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
            return f"'{value}"
        return value

    return frame.map(neutralize).to_csv(index=False).encode("utf-8-sig")


st.subheader("Histórico e métricas de segurança", anchor=False)

try:
    threats = list_threats()
    blocked = list_blocked()
except ApiError as exc:
    st.error(str(exc), title="Não foi possível carregar o histórico")
    st.stop()

if not threats:
    st.info("Ainda não existem incidentes registados.")
    st.stop()

df = pd.DataFrame(threats)

with st.container(horizontal=True):
    st.metric("Incidentes", len(df), border=True)
    st.metric("Risco alto ou crítico", int(df["risk_level"].isin(ALERT_LEVELS).sum()), border=True)
    st.metric("Bloqueios enviados", sum(b["dispatched"] for b in blocked), border=True)

by_type, by_risk = st.columns(2, border=True)
with by_type:
    st.markdown("**Ameaças por tipo**")
    st.bar_chart(
        df["threat_type"].value_counts(),
        x_label="Tipo",
        y_label="Incidentes",
        alt="Número de incidentes por tipo de ameaça",
    )
with by_risk:
    st.markdown("**Níveis de risco**")
    st.bar_chart(
        df["risk_level"].value_counts().reindex(RISK_LEVELS, fill_value=0),
        x_label="Risco",
        y_label="Incidentes",
        sort=False,
        alt="Número de incidentes por nível de risco",
    )

st.subheader("Incidentes registados", anchor=False)
st.dataframe(df, hide_index=True, alt="Lista de incidentes registados")
st.download_button(
    "Descarregar relatório (CSV)",
    data=to_safe_csv(df),
    file_name="netsentinel_relatorio.csv",
    mime="text/csv",
    icon=":material/download:",
)

st.subheader("Resposta a incidentes", anchor=False)

pending = [entry["ip_address"] for entry in blocked if not entry["dispatched"]]
if pending:
    st.warning(
        f"Registado, mas não enviado ao n8n: {', '.join(pending)}. "
        "A firewall não foi alterada; selecione o IP para tentar de novo.",
        title="Bloqueios por executar",
    )

dispatched = {entry["ip_address"] for entry in blocked if entry["dispatched"]}
candidates = [ip for ip in df["ip_address"].unique() if ip not in dispatched]

if not candidates:
    st.info("Todos os IPs registados já têm um pedido de bloqueio enviado.")
    st.stop()

selected_ip = st.selectbox("IP a bloquear", candidates)
if st.button("Pedir bloqueio", type="primary", icon=":material/block:"):
    try:
        result = block_ip(selected_ip)
    except ApiError as exc:
        st.error(str(exc), title="Não foi possível registar o bloqueio")
    else:
        if result["dispatched"]:
            st.toast(f"Pedido de bloqueio de {selected_ip} enviado ao n8n.")
        else:
            st.toast(f"{selected_ip} registado, mas o n8n não aceitou o pedido.")
        st.rerun()
