import logging

import streamlit as st

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

st.set_page_config(page_title="NetSentinel", page_icon=":material/shield:", layout="wide")

# O Streamlit declara lang="en", e o navegador oferece-se para traduzir o texto em português.
st.html(
    "<script>document.documentElement.lang='pt';"
    "document.documentElement.translate=false;</script>",
    unsafe_allow_javascript=True,
)

page = st.navigation(
    [
        st.Page("app_pages/submit.py", title="Submeter incidente", icon=":material/add_alert:"),
        st.Page("app_pages/history.py", title="Histórico", icon=":material/monitoring:"),
    ]
)

st.title("NetSentinel", anchor=False)
st.caption("Centro de operações de segurança")

page.run()
