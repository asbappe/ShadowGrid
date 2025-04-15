import sys
import os
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

# Add ./src to the module search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))

from agents.rss_agent import analyze_rss_feeds
from agents.portfolio_manager import run_agents

st.set_page_config(page_title="ShadowGrid Dashboard", layout="wide")

df = pd.read_csv("output/ioc_results.csv", parse_dates=["timestamp"])
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

tab1, tab2 = st.tabs(["Honeypot Dashboard", "Threat Fusion"])

with tab2:
    st.title("ShadowGrid Threat Fusion")
    st.markdown("Live threat intelligence synthesized from news and vulnerability feeds.")

    threats = run_agents(show_reasoning=False)
    news = analyze_rss_feeds()

    if not threats and not news:
        st.info("No threats or news available.")
    else:
        if threats:
            st.markdown("### CVE + Agent Intelligence")
            for threat in threats:
                st.markdown(f"**{threat['Threat']}**")
                st.text(f"Score: {threat['Score']} | Impact: {threat.get('Impact')}")
                st.text(threat['Reasoning'])
                st.markdown("---")

        if news:
            st.markdown("### Live Security Headlines")
            for item in news:
                st.markdown(f"**{item['Threat']}**")
                st.markdown(f"[{item['Source']}]({item.get('link', '#')})")
                st.markdown("---")
