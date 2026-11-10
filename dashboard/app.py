"""LogSentry dashboard. Run from the project folder:  streamlit run dashboard/app.py"""
import sys
from pathlib import Path

# Streamlit runs this file from the dashboard folder, so make the project
# folder importable too (that's where the logsentry package lives).
PROJECT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_DIR))

import pandas as pd
import plotly.express as px
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

# Alerts don't store which log they came from, so work it out from the rule.
WEB_RULES = {"web_scan", "web_attack_signature"}
alerts["source"] = alerts["rule"].map(lambda rule: "web" if rule in WEB_RULES else "auth")

# ---- Sidebar filters ----
st.sidebar.header("Filters")

first_day, last_day = events["ts"].min().date(), events["ts"].max().date()
picked = st.sidebar.date_input("Date range", value=(first_day, last_day),
                               min_value=first_day, max_value=last_day)
# While you're choosing, the date picker briefly returns just one date.
start, end = picked if len(picked) == 2 else (picked[0], picked[0])

severities = st.sidebar.multiselect("Severity", ["high", "medium", "low"],
                                    default=["high", "medium", "low"])
sources = st.sidebar.multiselect("Log source", ["auth", "web"], default=["auth", "web"])


def in_range(df):
    """True for each row whose date is inside the chosen range."""
    day = df["ts"].dt.date
    return (day >= start) & (day <= end)


events = events[in_range(events) & events["source"].isin(sources)]
alerts = alerts[in_range(alerts) & alerts["severity"].isin(severities)
                & alerts["source"].isin(sources)]

st.write(f"Showing **{len(events):,}** events and **{len(alerts)}** alerts "
         f"from {start:%d %b %Y} to {end:%d %b %Y}.")

# ---- Metric cards ----
failed_logins = (events["event_type"] == "login_failed").sum()
high_alerts = (alerts["severity"] == "high").sum()
alert_ips = alerts["ip"].dropna().nunique()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Events", f"{len(events):,}")
col2.metric("Failed logins", f"{failed_logins:,}")
col3.metric("Alerts", len(alerts), f"{high_alerts} high", delta_color="inverse")
col4.metric("IPs in alerts", alert_ips)

# ---- Charts ----
left, right = st.columns(2)

with left:
    st.subheader("Failed logins over time")
    failed = events[events["event_type"] == "login_failed"]
    if failed.empty:
        st.caption("No failed logins in this view.")
    else:
        # Count failures per hour, including the hours with none, so a
        # sudden attack stands out against a flat line of zeros.
        hours = pd.date_range(start, pd.Timestamp(end) + pd.Timedelta(days=1),
                              freq="1h", inclusive="left")
        per_hour = (failed.set_index("ts").resample("1h").size()
                    .reindex(hours, fill_value=0)
                    .rename_axis("ts").reset_index(name="count"))
        fig = px.line(per_hour, x="ts", y="count",
                      labels={"ts": "Time", "count": "Failed logins per hour"})
        st.plotly_chart(fig, width="stretch")

with right:
    st.subheader("Top 10 IPs by events")
    top_ips = events["ip"].value_counts().head(10).reset_index()
    top_ips.columns = ["ip", "events"]
    top_ips["in an alert"] = top_ips["ip"].isin(alerts["ip"]).map({True: "yes", False: "no"})
    fig = px.bar(top_ips, x="events", y="ip", orientation="h", color="in an alert",
                 color_discrete_map={"yes": "#d62728", "no": "#7f7f7f"},
                 labels={"ip": "IP address", "events": "Events"})
    fig.update_layout(yaxis={"categoryorder": "total ascending"})
    st.plotly_chart(fig, width="stretch")
    
st.subheader("Alerts")
st.dataframe(alerts[["ts", "severity", "rule", "source", "ip", "user", "message"]],
             hide_index=True, width="stretch")