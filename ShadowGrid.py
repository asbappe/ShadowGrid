import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import sys
import os
import requests

# Set page config - must be the first Streamlit command
st.set_page_config(page_title="ShadowGrid Dashboard", layout="wide")

# Add path to the threat fusion repo (peer directory)
sys.path.append(os.path.expanduser("../shadowgrid-threat-fusion/src"))

# Import Threat Fusion agent
from agents.portfolio_manager import run_agents
try:
    from agents.rss_agent import analyze_rss_feeds
except ModuleNotFoundError:
    def analyze_rss_feeds():
        return []

# Function to fetch filtered CVEs
def fetch_filtered_cves(query=None):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    today = datetime.utcnow()
    seven_days_ago = today - timedelta(days=7)
    params = {
        "cvssV3Severity": "HIGH",
        "pubStartDate": seven_days_ago.strftime("%Y-%m-%dT00:00:00.000Z"),
        "pubEndDate": today.strftime("%Y-%m-%dT23:59:59.999Z"),
        "resultsPerPage": 10
    }
    if query:
        params["keywordSearch"] = query

    try:
        response = requests.get(base_url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        cve_items = data.get("vulnerabilities", [])
        result = []
        for item in cve_items:
            cve_id = item["cve"]["id"]
            descriptions = item["cve"].get("descriptions", [])
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

# Load the enriched threat data
df = pd.read_csv("output/ioc_results.csv", parse_dates=["timestamp"])
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

# Tabs for different views
tab1, tab2 = st.tabs(["Honeypot Dashboard", "Threat Fusion"])

# === Honeypot Dashboard === #
with tab1:
    st.title("ShadowGrid Honeypot Dashboard")
    st.markdown("Honeypot threat feed, enriched with threat intel from OTX, VirusTotal, and AbuseIPDB.")

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
    fig.update_geos(
        showland=True, landcolor="#1e1e1e",
        oceancolor="#111111", showocean=True,
        showcoastlines=True, coastlinecolor="white",
        showcountries=True, countrycolor="white",
        showframe=False, bgcolor="#111111"
    )
    fig.update_layout(
        geo_bgcolor="#111111",
        paper_bgcolor="#111111",
        plot_bgcolor="#111111",
        font=dict(color="white"),
        margin={"r":0,"t":40,"l":0,"b":0},
        title={"text": "Global Threat Map", "x": 0.5, "xanchor": "center"}
    )
    fig.update_traces(
        marker=dict(sizemode="area", sizeref=2.*max(map_df["threat_score"])/(20**2),
                    line=dict(width=1, color="rgba(255,255,255,0.3)"), opacity=0.6)
    )
    st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Honeypot Hits Details")
    honeypot_df = df[df["source"].str.contains("Honeypot", na=False)].copy()
    honeypot_df["path"] = honeypot_df["path"].fillna("(no path logged)")
    columns_to_show = ["ip", "path", "country", "region", "city", "asn", "abuse_score", "vt_detections", "threat_score", "timestamp"]
    if not honeypot_df.empty:
        st.dataframe(honeypot_df[columns_to_show].sort_values("timestamp", ascending=False), use_container_width=True)
    else:
        st.info("No honeypot events to display.")

    if not honeypot_df.empty:
        honeypot_df["date"] = pd.to_datetime(honeypot_df["timestamp"]).dt.date
        daily_hits = honeypot_df.groupby("date").size().reset_index(name="Hits")
        fig_hits = px.bar(daily_hits, x="date", y="Hits", title="Daily Honeypot Hits", labels={"date": "Date", "Hits": "Hits"})
        fig_hits.update_layout(paper_bgcolor="#111111", plot_bgcolor="#111111", font=dict(color="white"), margin=dict(l=40, r=40, t=60, b=60))
        fig_hits.update_xaxes(type='category')
        st.plotly_chart(fig_hits, use_container_width=True)

    if "timestamp" in df.columns:
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        daily_counts = df.groupby('date').size().reset_index(name='New IOCs')
        st.markdown("### Daily IOC Timeline")
        fig = px.line(daily_counts, x="date", y="New IOCs", markers=True)
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Filter Indicators")
    with st.container():
        col1, col2, col3 = st.columns(3)
        with col1:
            selected_countries = st.multiselect("Filter by Country", sorted(df["country"].dropna().unique()))
        with col2:
            selected_asns = st.multiselect("Filter by ASN/Org", sorted(df["asn"].dropna().unique()))
        with col3:
            min_score, max_score = st.slider("Threat Score Range", 0, 100, (0, 100), step=1)

    filtered_df = df.copy()
    if selected_countries:
        filtered_df = filtered_df[filtered_df["country"].isin(selected_countries)]
    if selected_asns:
        filtered_df = filtered_df[filtered_df["asn"].isin(selected_asns)]
    filtered_df = filtered_df[(filtered_df["threat_score"] >= min_score) & (filtered_df["threat_score"] <= max_score)]

    st.markdown(f"### Showing {len(filtered_df)} Threat Indicators")
    for _, row in filtered_df.iterrows():
        with st.expander(f"{row['ip']}  |  Score: {row['threat_score']}"):
            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Location Details**")
                st.write(f"- Country: {row['country']}")
                st.write(f"- Region: {row['region']}")
                st.write(f"- City: {row['city']}")
                st.markdown("**Network Info**")
                st.write(f"- ASN: {row['asn']}")
            with col2:
                st.markdown("**Threat Intelligence**")
                st.write(f"- Threat Score: {row['threat_score']}")
                st.write(f"- Abuse Score: {row['abuse_score']}")
                st.write(f"- VT Detections: {row['vt_detections']}")
                st.write(f"- Source Feeds: {row['source']}")
                st.write(f"- Last Seen: {row['timestamp']}")

# === Threat Fusion Tab === #
with tab2:
    st.title("ShadowGrid Threat Fusion")
    st.markdown("Live threat intelligence synthesized from news and vulnerability feeds.")

    search_term = st.text_input("Search CVEs (optional keyword)", "")
    threats = fetch_filtered_cves(query=search_term if search_term else None)
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
