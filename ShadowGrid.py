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
with tab1:
    st.title("ShadowGrid Honeypot Dashboard")
    st.markdown("Honeypot threat feed, enriched with threat intel from OTX, VirusTotal, and AbuseIPDB.")

    # Global Threat Map
    st.markdown("### Global Threat Map")
    map_df = df.dropna(subset=["latitude", "longitude"])

    fig = px.scatter_geo(
        map_df,
        lat="latitude",
        lon="longitude",
        hover_name="ip",
        hover_data=["country", "asn", "threat_score", "source", "timestamp"],
        size="threat_score",
        color="threat_score",
        color_continuous_scale="YlOrRd",
        projection="natural earth"
    )

    fig.update_layout(
        paper_bgcolor="#111111",
        plot_bgcolor="#111111",
        geo=dict(bgcolor="#111111"),
        font=dict(color="white"),
        title="Global Threat Map",
        margin={"r":0,"t":40,"l":0,"b":0},
    )

    st.plotly_chart(fig, use_container_width=True)

    # Honeypot Events Table
    honeypot_df = df[df["source"].str.contains("Honeypot", na=False)].copy()
    if not honeypot_df.empty:
        st.markdown("### Honeypot Events")
        st.dataframe(honeypot_df.sort_values("timestamp", ascending=False))
    else:
        st.info("No honeypot events found.")

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
