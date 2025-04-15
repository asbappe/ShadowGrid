import sys
import os
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import requests

# Fetch latest CVEs for Threat Fusion
def fetch_latest_cves(limit=5):
    import requests
    try:
        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0", timeout=10)
        response.raise_for_status()
        data = response.json()
        cve_items = data.get("vulnerabilities", [])[:limit]
        result = []
        for item in cve_items:
            cve_id = item["cve"]["id"]
            descriptions = item["cve"]["descriptions"]
            description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available")
            metrics = item["cve"].get("metrics", {})
            score = 0.0
            if "cvssMetricV31" in metrics:
                score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
            result.append({
                "Threat": cve_id,
                "Score": score,
                "Impact": description,
                "Reasoning": ""
            })
        return result
    except Exception as e:
        return [{
            "Threat": "Error fetching CVEs",
            "Score": "N/A",
            "Impact": str(e),
            "Reasoning": ""
        }]

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

    # Load and filter
    honeypot_df = df[df["source"].str.contains("Honeypot", na=False)].copy()

    # Global Threat Map
    st.markdown("### Global Threat Map")
    map_df = honeypot_df.dropna(subset=["latitude", "longitude"])
    if not map_df.empty:
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
    else:
        st.info("No geolocated honeypot events.")

     # Honeypot Table
    if not honeypot_df.empty:
        st.markdown("### Honeypot Event Table")
        st.dataframe(honeypot_df.sort_values("timestamp", ascending=False))
    else:
        st.info("No honeypot events found.")
        
    # Bar Chart - Daily Honeypot Hits
    if not honeypot_df.empty:
        honeypot_df["date"] = pd.to_datetime(honeypot_df["timestamp"]).dt.date
        daily_hits = honeypot_df.groupby("date").size().reset_index(name="Hits")

        st.markdown("### Daily Honeypot Hits")
        fig_hits = px.bar(daily_hits, x="date", y="Hits", labels={"date": "Date", "Hits": "Hits"})
        fig_hits.update_layout(
            paper_bgcolor="#111111",
            plot_bgcolor="#111111",
            font=dict(color="white"),
            margin=dict(l=40, r=40, t=60, b=60),
            xaxis_title="Date",
            yaxis_title="Hits"
        )
        st.plotly_chart(fig_hits, use_container_width=True)

    # Line Chart - Timeline of All IOCs
    if "timestamp" in df.columns:
        df["date"] = pd.to_datetime(df["timestamp"]).dt.date
        daily_iocs = df.groupby("date").size().reset_index(name="New IOCs")

        st.markdown("### Daily IOC Timeline")
        fig_timeline = px.line(daily_iocs, x="date", y="New IOCs", markers=True)
        fig_timeline.update_layout(
            paper_bgcolor="#111111",
            plot_bgcolor="#111111",
            font=dict(color="white")
        )
        st.plotly_chart(fig_timeline, use_container_width=True)


with tab2:
    st.title("ShadowGrid Threat Fusion")
    st.markdown("Live threat intelligence synthesized from news and vulnerability feeds.")

    threats = fetch_latest_cves(limit=10)
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
