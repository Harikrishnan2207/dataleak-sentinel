"""Dark navy theme for the Streamlit app."""
import streamlit as st

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&display=swap');

html, body, [class*="css"], .stApp { font-family: 'IBM Plex Sans', 'Segoe UI', system-ui, sans-serif; }
.stApp { background: #07111F; }
.block-container { padding-top: 2.6rem; padding-bottom: 3rem; max-width: 1400px; }

/* Sidebar */
[data-testid="stSidebar"] { background: #0B1B2E; border-right: 1px solid #1E3652; }
[data-testid="stSidebar"] .stRadio > div { gap: 2px; }
[data-testid="stSidebar"] .stRadio label { padding: 8px 12px; border-radius: 8px; width: 100%; }
[data-testid="stSidebar"] .stRadio label:hover { background: #10263D; }
.brand { padding: 4px 4px 14px 4px; border-bottom: 1px solid #1E3652; margin-bottom: 14px; }
.brand-name { font-size: 1.25rem; font-weight: 600; color: #E6EDF7; }
.brand-sub { font-size: .8rem; color: #8CA3BF; margin-top: 2px; }
.side-note { font-size: .78rem; color: #8CA3BF; border: 1px solid #1E3652; border-radius: 8px;
             padding: 10px 12px; background: #0A1626; line-height: 1.45; }

/* Page header */
.page-title { font-size: 1.9rem; font-weight: 600; color: #E6EDF7; margin: 0; }
.page-sub { color: #8CA3BF; margin: 2px 0 1.2rem 0; font-size: .95rem; }
.section-title { font-size: 1.05rem; font-weight: 600; color: #E6EDF7; margin: 1.4rem 0 .6rem 0; }

/* KPI cards */
.kpi { background: #0F2038; border: 1px solid #1E3652; border-left: 4px solid var(--c, #38BDF8);
       border-radius: 8px; padding: 14px 16px; height: 100%; }
.kpi-label { color: #8CA3BF; font-size: .85rem; }
.kpi-value { color: #E6EDF7; font-size: 2rem; font-weight: 600; line-height: 1.2; margin-top: 2px; }
.kpi-sub { color: #8CA3BF; font-size: .8rem; margin-top: 2px; }

/* Risk chips + alert cards */
.chip { display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: .78rem;
        font-weight: 600; border: 1px solid transparent; }
.chip-high   { color: #F87171; background: rgba(248,113,113,.12); border-color: rgba(248,113,113,.45); }
.chip-medium { color: #FBBF24; background: rgba(251,191,36,.12);  border-color: rgba(251,191,36,.45); }
.chip-low    { color: #34D399; background: rgba(52,211,153,.12);  border-color: rgba(52,211,153,.45); }
.alert-card { background: #0F2038; border: 1px solid #1E3652; border-left: 4px solid var(--c, #F87171);
              border-radius: 8px; padding: 12px 16px; margin-bottom: 8px; }
.alert-top { display: flex; flex-wrap: wrap; gap: 6px 16px; align-items: center; }
.alert-user { color: #E6EDF7; font-weight: 600; }
.alert-meta { color: #8CA3BF; font-size: .85rem; }
.alert-reason { color: #C5D3E5; font-size: .88rem; margin-top: 6px; }
.empty-box { border: 1px dashed #2A4668; border-radius: 10px; padding: 22px; color: #8CA3BF;
             background: #0A1626; margin: 8px 0 14px 0; }
</style>
"""


def inject() -> None:
    st.markdown(CSS, unsafe_allow_html=True)
