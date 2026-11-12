import logging

import streamlit as st

from dashboard_api import current_user, logout
from dashboard_nav import pages_for_role

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

st.set_page_config(page_title="NetSentinel", page_icon=":material/shield:", layout="wide")

# O Streamlit declara lang="en", e o navegador se oferece para traduzir o texto em português.
st.html(
    "<script>document.documentElement.lang='pt-BR';"
    "document.documentElement.translate=false;</script>",
    unsafe_allow_javascript=True,
)

user = current_user()

if user is None:
    # Sem sessão só existe a tela de login: nenhuma página com dados é sequer registrada.
    page = st.navigation(
        [st.Page("app_pages/login.py", title="Entrar", icon=":material/login:")],
        position="hidden",
    )
else:
    page = st.navigation(
        [
            st.Page(path, title=title, icon=icon)
            for path, title, icon in pages_for_role(user["role"])
        ]
    )
    with st.sidebar:
        st.markdown(f"**{user['username']}** · {user['role']}")
        if st.button("Sair", icon=":material/logout:"):
            logout()
            st.rerun()

st.title("NetSentinel", anchor=False)
st.caption("Centro de operações de segurança")

page.run()
