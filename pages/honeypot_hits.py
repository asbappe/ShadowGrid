import streamlit as st
import pandas as pd
import requests
import plotly.express as px

st.set_page_config(page_title="Honeypot Hits", layout="wide")

st.title("🪤 Honeypot Hits Dashboard")

HONEYPOT_URL = "http://67.205.131.5:8080/all_hits"

# -- Load data
try:
    resp = requests.get(HONEYPOT_URL, timeout=5)
    resp.raise_for_status()
    hits = resp.json()
    df = pd.DataFrame(hits)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.sort_values("timestamp", ascending=False)
except Exception as e:
    st.error(f"Failed to load honeypot hits: {e}")
    st.stop()

# -- Optional filters
with st.sidebar:
    st.subheader("🔍 Filter")
    ip_filter = st.text_input("Search IP")
    date_range = st.date_input("Date Range", [])

if ip_filter:
    df = df[df["ip"].str.contains(ip_filter)]

if len(date_range) == 2:
    df = df[df["timestamp"].dt.date.between(date_range[0], date_range[1])]

# -- Display
st.metric("💥 Total Hits", len(df))

st.dataframe(df[["timestamp", "ip", "path", "user_agent"]])

# -- Timeline chart
df["date"] = df["timestamp"].dt.date
daily_hits = df.groupby("date").size().reset_index(name="Hits")

st.markdown("### 📈 Daily Attack Volume")
st.plotly_chart(
    px.bar(daily_hits, x="date", y="Hits", title="Honeypot Hits per Day"),
    use_container_width=True
)
