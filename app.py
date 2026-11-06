"""DataLeak Sentinel - entry point.  Run with:  streamlit run app.py"""
import streamlit as st

from sentinel.database import SentinelDB
from sentinel.ui import pages, styles

st.set_page_config(
    page_title="DataLeak Sentinel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)
styles.inject()


@st.cache_resource
def get_db() -> SentinelDB:
    database = SentinelDB()
    database.init_schema()
    return database


db = get_db()

NAV = {
    "Dashboard": pages.dashboard,
    "User Activity": pages.user_activity,
    "Security Alerts": pages.security_alerts,
    "Audit Logs": pages.audit_logs,
    "Detection Rules": pages.detection_rules,
    "Demo Simulation": pages.demo_control,
}

with st.sidebar:
    st.markdown(
        '<div class="brand"><div class="brand-name">🛡️ DataLeak Sentinel</div>'
        '<div class="brand-sub">Bulk data extraction detection</div></div>',
        unsafe_allow_html=True,
    )
    page = st.radio("Navigation", list(NAV), label_visibility="collapsed")
    counts = db.table_counts()
    st.write("")
    st.markdown(
        f'<div class="side-note">{counts["access_logs"]:,} access events and {counts["alerts"]:,} alerts stored.<br><br>'
        "Synthetic data only. This app does not connect to or monitor any real production database.</div>",
        unsafe_allow_html=True,
    )

NAV[page](db)
