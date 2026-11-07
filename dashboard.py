import streamlit as st

st.set_page_config(page_title="NetSentinel", page_icon=":material/shield:", layout="wide")

page = st.navigation(
    [
        st.Page("app_pages/submit.py", title="Submeter incidente", icon=":material/add_alert:"),
        st.Page("app_pages/history.py", title="Histórico", icon=":material/monitoring:"),
    ]
)

st.title("NetSentinel", anchor=False)
st.caption("Centro de operações de segurança")

page.run()
