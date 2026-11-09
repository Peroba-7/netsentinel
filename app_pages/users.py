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

me = require_role("admin")

st.subheader("Utilizadores", anchor=False)
st.caption(
    "leitor: consulta o histórico · analista: também submete incidentes e pede bloqueios · "
    "admin: também retira bloqueios e gere utilizadores"
)

try:
    users = list_users()
except ApiError as exc:
    show_api_error(exc, "Não foi possível carregar os utilizadores")

if users:
    st.dataframe(
        pd.DataFrame(users)[["username", "role", "is_active", "created_at"]],
        hide_index=True,
        alt="Lista de utilizadores",
    )

create_tab, edit_tab = st.tabs(["Criar utilizador", "Alterar utilizador"])

with create_tab, st.form("create_user", border=True, clear_on_submit=True):
    username = st.text_input(
        "Utilizador", help="3 a 50 letras minúsculas, números, '.', '_' ou '-'"
    )
    role = st.selectbox("Perfil", ROLES)
    password = st.text_input(
        f"Palavra-passe (mínimo {MIN_PASSWORD_LENGTH} caracteres)", type="password"
    )
    confirm = st.text_input("Repita a palavra-passe", type="password")
    feedback = st.container()
    if st.form_submit_button("Criar", type="primary", icon=":material/person_add:"):
        if password != confirm:
            feedback.error("As palavras-passe não coincidem.")
        else:
            try:
                created = create_user(username.strip().lower(), password, role)
            except ApiError as exc:
                show_api_error(exc, "O utilizador não foi criado")
            else:
                st.toast(f"Utilizador {created['username']} criado.")
                st.rerun()

with edit_tab:
    if not users:
        st.info("Ainda não existem utilizadores.")
    else:
        by_name = {user["username"]: user for user in users}
        target = by_name[st.selectbox("Utilizador a alterar", list(by_name))]
        with st.form("edit_user", border=True, clear_on_submit=True):
            new_role = st.selectbox("Perfil", ROLES, index=ROLES.index(target["role"]))
            active = st.toggle("Conta ativa", value=target["is_active"])
            new_password = st.text_input(
                "Nova palavra-passe (deixe vazio para manter)", type="password"
            )
            st.caption("Desativar a conta ou trocar a palavra-passe termina as sessões dela.")
            feedback = st.container()
            if st.form_submit_button("Guardar", type="primary", icon=":material/save:"):
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
                        show_api_error(exc, "O utilizador não foi alterado")
                    else:
                        st.toast(f"Utilizador {target['username']} atualizado.")
                        st.rerun()
