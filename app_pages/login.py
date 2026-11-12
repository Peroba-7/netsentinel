import logging

import streamlit as st

from dashboard_api import ApiError, login

logger = logging.getLogger("netsentinel.dashboard")

st.subheader("Entrar", anchor=False)

with st.form("login_form", border=True):
    username = st.text_input("Usuário", autocomplete="username")
    password = st.text_input("Senha", type="password", autocomplete="current-password")
    feedback = st.container()
    submitted = st.form_submit_button("Entrar", type="primary", icon=":material/login:")

if submitted:
    if not username.strip() or not password:
        feedback.error("Preencha o usuário e a senha.")
        st.stop()
    try:
        login(username.strip(), password)
    except ApiError as exc:
        # A mensagem vem da API e é a mesma para qualquer falha, exista a conta ou não.
        logger.warning("Login recusado.")
        feedback.error(str(exc))
    else:
        st.rerun()
