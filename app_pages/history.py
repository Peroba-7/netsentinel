import altair as alt
import pandas as pd
import streamlit as st

from app.schemas.threat import ALERT_LEVELS, RISK_LEVELS, normalize_threat_type
from app.schemas.user import role_at_least
from dashboard_api import (
    ApiError,
    block_ip,
    list_blocked,
    list_threats,
    require_role,
    show_api_error,
    unblock_ip,
)
from dashboard_format import DBIP_ATTRIBUTION, country_label, has_origin_data, organization_label

ORIGIN_FIELDS = ["ip_scope", "country_code", "country_name", "asn", "as_org"]


def to_safe_csv(frame: pd.DataFrame) -> bytes:
    """Exporta CSV sem fórmulas: as descrições vêm de terceiros e o Excel executaria "=..."."""

    def neutralize(value):
        if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
            return f"'{value}"
        return value

    return frame.map(neutralize).to_csv(index=False).encode("utf-8-sig")


# Opções da duração do bloqueio, em minutos; None é permanente.
BLOCK_DURATIONS = {"30 min": 30, "1 hora": 60, "24 horas": 24 * 60, "Permanente": None}


def format_expiry(value) -> str:
    """Data de fim do bloqueio em UTC, ou "Permanente" quando não tem prazo."""
    # O pandas transforma o None da API em NaN/NaT dentro da tabela.
    if value is None or pd.isna(value):
        return "Permanente"
    return pd.Timestamp(value).tz_convert("UTC").strftime("%d/%m/%Y %H:%M UTC")


def block_reason(incidents: pd.DataFrame, ip_address: str) -> str:
    """Motivo do bloqueio a partir do incidente mais recente do IP, ex.: "DDoS, risco ALTO"."""
    latest = incidents[incidents["ip_address"] == ip_address].sort_values("id").iloc[-1]
    return f"{normalize_threat_type(latest['threat_type'])}, risco {latest['risk_level']}"


def ip_block_label(threat: dict) -> str:
    """Texto da coluna "IP bloqueado": vazio, "Sim" ou "Sim (simulado)"."""
    if not threat["ip_blocked"]:
        return ""
    return "Sim (simulado)" if "simulado" in (threat["ip_block_result"] or "") else "Sim"


user = require_role("leitor")
# Só esconde os controlos; a API recusa estas ações a quem não tiver o perfil.
can_block = role_at_least(user["role"], "analista")
can_unblock = role_at_least(user["role"], "admin")

st.subheader("Histórico e métricas de segurança", anchor=False)

try:
    threats = list_threats()
    blocked = list_blocked()
except ApiError as exc:
    show_api_error(exc, "Não foi possível carregar o histórico")

if not threats:
    st.info("Ainda não existem incidentes registados.")
    st.stop()

df = pd.DataFrame(threats)
# O bloqueio é do IP, não do incidente: fica numa coluna própria, ao lado do estado.
df.insert(
    df.columns.get_loc("status") + 1,
    "IP bloqueado",
    [ip_block_label(threat) for threat in threats],
)
df = df.drop(columns=["ip_blocked", "ip_block_result"])
# Origem do IP ao lado do endereço, em duas colunas legíveis em vez dos cinco campos da API.
position = df.columns.get_loc("ip_address") + 1
df.insert(position, "País", [country_label(threat) for threat in threats])
df.insert(position + 1, "Organização", [organization_label(threat) for threat in threats])
df = df.drop(columns=ORIGIN_FIELDS, errors="ignore")


def count_chart(counts: pd.Series, x_label: str, order: list[str] | None = None) -> alt.Chart:
    """Gráfico de barras de contagens, com o eixo a começar em 0 e passos inteiros."""
    frame = counts.rename_axis(x_label).reset_index(name="Incidentes")
    return (
        alt.Chart(frame)
        .mark_bar()
        .encode(
            x=alt.X(f"{x_label}:N", sort=order or "-y", title=x_label),
            y=alt.Y(
                "Incidentes:Q",
                scale=alt.Scale(domainMin=0),
                axis=alt.Axis(tickMinStep=1),
            ),
            tooltip=[x_label, "Incidentes"],
        )
    )


with st.container(horizontal=True):
    st.metric("Incidentes", len(df), border=True)
    st.metric("Risco alto ou crítico", int(df["risk_level"].isin(ALERT_LEVELS).sum()), border=True)
    st.metric("Bloqueios enviados", sum(b["dispatched"] for b in blocked), border=True)

by_type, by_risk = st.columns(2, border=True)
with by_type:
    st.markdown("**Ameaças por tipo**")
    st.altair_chart(
        # Agrupa também registos antigos gravados antes da normalização ("SSH Brute Force"...).
        count_chart(df["threat_type"].map(normalize_threat_type).value_counts(), "Tipo"),
        width="stretch",
        alt="Número de incidentes por tipo de ameaça",
    )
with by_risk:
    st.markdown("**Níveis de risco**")
    st.altair_chart(
        count_chart(
            df["risk_level"].value_counts().reindex(RISK_LEVELS, fill_value=0),
            "Risco",
            order=list(RISK_LEVELS),
        ),
        width="stretch",
        alt="Número de incidentes por nível de risco",
    )

with st.sidebar:
    st.markdown("**Filtros dos incidentes**")
    risk_filter = st.multiselect("Nível de risco", RISK_LEVELS)
    text_filter = st.text_input("Pesquisar por IP, tipo ou descrição").strip()

view = df
if risk_filter:
    view = view[view["risk_level"].isin(risk_filter)]
if text_filter:
    haystack = view[["ip_address", "threat_type", "description"]].fillna("").agg(" ".join, axis=1)
    view = view[haystack.str.contains(text_filter, case=False, regex=False)]

st.subheader("Incidentes registados", anchor=False)
if len(view) != len(df):
    st.caption(f"A mostrar {len(view)} de {len(df)} incidentes.")
if view.empty:
    st.info("Nenhum incidente corresponde aos filtros.")
else:
    st.dataframe(view, hide_index=True, alt="Lista de incidentes registados")
if has_origin_data(threats):
    st.caption(DBIP_ATTRIBUTION)
st.download_button(
    "Descarregar relatório (CSV)",
    data=to_safe_csv(view),
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

if any("simulado" in (entry["result"] or "") for entry in blocked):
    st.info(
        "Os bloqueios marcados como simulados foram apenas registados.",
        title="Modo de simulação: nenhuma firewall foi alterada",
    )

dispatched = {entry["ip_address"] for entry in blocked if entry["dispatched"]}
candidates = [ip for ip in df["ip_address"].unique() if ip not in dispatched]

if not can_block:
    st.caption("O seu perfil (leitor) permite consultar, mas não pedir bloqueios.")
elif not candidates:
    st.info("Todos os IPs registados já têm um pedido de bloqueio enviado.")
else:
    selected_ip = st.selectbox("IP a bloquear", candidates)
    duration = st.selectbox(
        "Duração do bloqueio",
        list(BLOCK_DURATIONS),
        index=list(BLOCK_DURATIONS).index("Permanente"),
        help="No fim do prazo, o IP é desbloqueado automaticamente.",
    )
    if st.button("Pedir bloqueio", type="primary", icon=":material/block:"):
        try:
            result = block_ip(
                selected_ip, block_reason(df, selected_ip), BLOCK_DURATIONS[duration]
            )
        except ApiError as exc:
            show_api_error(exc, "Não foi possível registar o bloqueio")
        else:
            if result["dispatched"]:
                st.toast(f"{selected_ip}: {result['result']}")
            else:
                st.toast(f"{selected_ip} registado, mas o n8n não aceitou o pedido.")
            st.rerun()

if blocked:
    st.subheader("Bloqueios ativos", anchor=False)
    blocked_view = pd.DataFrame(blocked)
    blocked_view["expira em"] = blocked_view["expires_at"].map(format_expiry)
    st.dataframe(
        blocked_view[["ip_address", "reason", "created_at", "expira em", "dispatched", "result"]],
        hide_index=True,
        alt="Lista de IPs com pedido de bloqueio",
    )

if blocked and can_unblock:
    unblock_target = st.selectbox(
        "IP a desbloquear", [entry["ip_address"] for entry in blocked], key="unblock_target"
    )
    if st.button("Retirar bloqueio", icon=":material/lock_open:"):
        try:
            result = unblock_ip(unblock_target)
        except ApiError as exc:
            show_api_error(exc, "Não foi possível retirar o bloqueio")
        else:
            st.toast(f"{unblock_target}: {result['result'] or 'pedido de bloqueio removido'}")
            st.rerun()
