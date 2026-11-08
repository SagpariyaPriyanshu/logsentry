"""LogSentry dashboard. Run from the project folder:  streamlit run dashboard/app.py"""
import sys
from pathlib import Path

# Streamlit runs this file from the dashboard folder, so make the project
# folder importable too (that's where the logsentry package lives).
PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import streamlit as st

from logsentry.config import load_config
from logsentry.storage import init_db, load_alerts_df, load_events_df

st.set_page_config(page_title="LogSentry", page_icon="🛡️", layout="wide")


@st.cache_data(ttl=30)
def load_data():
    """Read every event and alert from the database. Cached for 30 seconds."""
    cfg = load_config(PROJECT_DIR / "config.yaml")
    conn = init_db(PROJECT_DIR / cfg["database"]["path"])
    events = load_events_df(conn)
    alerts = load_alerts_df(conn)
    conn.close()
    return events, alerts


st.title("🛡️ LogSentry")
st.caption("Mini SIEM: log analysis and intrusion alerts")

events, alerts = load_data()

if events.empty:
    st.info("No data yet. Run `python main.py analyze sample_logs/auth.log` first.")
    st.stop()

st.write(f"Loaded **{len(events):,}** events and **{len(alerts)}** alerts, "
         f"from {events['ts'].min():%d %b %Y} to {events['ts'].max():%d %b %Y}.")

st.subheader("Alerts")
st.dataframe(alerts[["ts", "severity", "rule", "ip", "user", "message"]],
             hide_index=True, width="stretch")