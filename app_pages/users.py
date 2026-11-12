import pandas as pd
import streamlit as st

from app.schemas.user import MIN_PASSWORD_LENGTH, ROLES
from dashboard_api import (
    ApiError,
    create_user,
    list_users,
    require_role,
    show_api_error,
    update_user,
)

# Colunas da tabela de usuários, por ordem, com os rótulos mostrados (os campos da API não mudam).
USER_COLUMN_LABELS = {
    "username": "Usuário",
    "role": "Perfil",
    "is_active": "Ativo",
    "created_at": "Criado em",
}


def format_created(value) -> str:
    """Data no formato "dd/mm/aaaa HH:MM UTC"; intacta se não for uma data."""
    timestamp = pd.to_datetime(value, utc=True, errors="coerce")
    return str(value) if pd.isna(timestamp) else timestamp.strftime("%d/%m/%Y %H:%M UTC")


me = require_role("admin")

st.subheader("Usuários", anchor=False)
st.caption(
    "leitor: consulta o histórico · analista: também envia incidentes e pede bloqueios · "
    "admin: também retira bloqueios e gerencia usuários"
)

try:
    users = list_users()
except ApiError as exc:
    show_api_error(exc, "Não foi possível carregar os usuários")

if users:
    users_view = pd.DataFrame(users)[list(USER_COLUMN_LABELS)]
    users_view["created_at"] = users_view["created_at"].map(format_created)
    st.dataframe(
        users_view.rename(columns=USER_COLUMN_LABELS),
        hide_index=True,
        alt="Lista de usuários",
    )

create_tab, edit_tab = st.tabs(["Criar usuário", "Alterar usuário"])

with create_tab, st.form("create_user", border=True, clear_on_submit=True):
    username = st.text_input(
        "Usuário", help="3 a 50 letras minúsculas, números, '.', '_' ou '-'"
    )
    role = st.selectbox("Perfil", ROLES)
    password = st.text_input(
        f"Senha (mínimo {MIN_PASSWORD_LENGTH} caracteres)", type="password"
    )
    confirm = st.text_input("Repita a senha", type="password")
    feedback = st.container()
    if st.form_submit_button("Criar", type="primary", icon=":material/person_add:"):
        if password != confirm:
            feedback.error("As senhas não coincidem.")
        else:
            try:
                created = create_user(username.strip().lower(), password, role)
            except ApiError as exc:
                show_api_error(exc, "O usuário não foi criado")
            else:
                st.toast(f"Usuário {created['username']} criado.")
                st.rerun()

with edit_tab:
    if not users:
        st.info("Ainda não há usuários.")
    else:
        by_name = {user["username"]: user for user in users}
        target = by_name[st.selectbox("Usuário a alterar", list(by_name))]
        with st.form("edit_user", border=True, clear_on_submit=True):
            new_role = st.selectbox("Perfil", ROLES, index=ROLES.index(target["role"]))
            active = st.toggle("Conta ativa", value=target["is_active"])
            new_password = st.text_input(
                "Nova senha (deixe em branco para manter)", type="password"
            )
            st.caption("Desativar a conta ou trocar a senha encerra as sessões dela.")
            feedback = st.container()
            if st.form_submit_button("Salvar", type="primary", icon=":material/save:"):
                changes = {}
                if new_role != target["role"]:
                    changes["role"] = new_role
                if active != target["is_active"]:
                    changes["is_active"] = active
                if new_password:
                    changes["password"] = new_password
                if not changes:
                    feedback.info("Nada para alterar.")
                else:
                    try:
                        update_user(target["id"], **changes)
                    except ApiError as exc:
                        show_api_error(exc, "O usuário não foi alterado")
                    else:
                        st.toast(f"Usuário {target['username']} atualizado.")
                        st.rerun()
