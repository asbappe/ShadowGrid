import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import sys
import os
import requests
import re
from collections import defaultdict

# Set page config - must be the first Streamlit command
st.set_page_config(page_title="ShadowGrid Dashboard", layout="wide")

# Hide the sidebar completely
hide_streamlit_style = """
    <style>
    [data-testid="stSidebar"] {
        display: none !important;
    }
    [data-testid="collapsedControl"] {
        display: none !important;
        visibility: hidden !important;
        width: 0px !important;
        height: 0px !important;
        position: absolute !important;
        z-index: -9999 !important;
    }
    </style>
"""
st.markdown(hide_streamlit_style, unsafe_allow_html=True)


# Make links white via CSS
st.markdown("""
    <style>
    a {
        color: white !important;
        text-decoration: none;
    }
    a:hover {
        text-decoration: underline;
    }
    </style>
""", unsafe_allow_html=True)

# Load SpaCy model once
from collections import defaultdict
import spacy

nlp = spacy.load("en_core_web_sm")

def auto_tag_articles(articles):
    tag_to_articles = defaultdict(list)

    for article in articles:
        doc = nlp(article["Threat"])
        tags = set(ent.text for ent in doc.ents if ent.label_ in ("ORG", "PRODUCT", "GPE"))

        if not tags:
            tags = {"Other"}

        for tag in tags:
            tag_to_articles[tag].append(article)

    return tag_to_articles
    
# Add path to the threat fusion repo (peer directory)
sys.path.append(os.path.expanduser("../shadowgrid-threat-fusion/src"))

# Import Threat Fusion agent
from src.agents.portfolio_manager import run_agents
try:
   from src.agents.rss_agent import analyze_rss_feeds

except ModuleNotFoundError:
    def analyze_rss_feeds():
        return []

# Function to sanitize search input
def sanitize_input(user_input):
    return re.sub(r'[^a-zA-Z0-9\-_. ]+', '', user_input)

# Function to fetch filtered CVEs
def fetch_filtered_cves(query=None, start_date=None, end_date=None, severity=None):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    today = datetime.utcnow()
    default_start = today - timedelta(days=7)
    pub_start = start_date or default_start
    pub_end = end_date or today
    default_severity = "CRITICAL"

    params = {
        "pubStartDate": pub_start.strftime("%Y-%m-%dT00:00:00.000Z"),
        "pubEndDate": pub_end.strftime("%Y-%m-%dT23:59:59.999Z"),
        "resultsPerPage": 25
    }
    if query:
        params["keywordSearch"] = sanitize_input(query)
    if severity and severity.upper() in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        params["cvssV3Severity"] = severity
    else:
        params["cvssV3Severity"] = default_severity

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
            published = item["cve"].get("published", "Unknown Date")
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
                "Published": published,
                "Reasoning": ""
            })
        return result
    except Exception as e:
        return [{
            "Threat": "Error fetching CVEs",
            "Score": "N/A",
            "Impact": str(e),
            "Published": "N/A",
            "Reasoning": ""
        }]

# Load the enriched threat data
df = pd.read_csv("output/ioc_results.csv", parse_dates=["timestamp"])
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

# Tabs for different views
tab1, tab2, tab3 = st.tabs(["Honeypot Dashboard", "Threat Fusion", "ShadowWire News"])

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
    fig.update_layout(paper_bgcolor="#111111", plot_bgcolor="#111111", font=dict(color="white"), margin={"r":0,"t":40,"l":0,"b":0})
    st.plotly_chart(fig, use_container_width=True)

    honeypot_df = df[df["source"].str.contains("Honeypot", na=False)].copy()
    honeypot_df["path"] = honeypot_df["path"].fillna("(no path logged)")
    columns_to_show = ["ip", "path", "country", "region", "city", "asn", "abuse_score", "vt_detections", "threat_score", "timestamp"]
    if not honeypot_df.empty:
        st.markdown("### Honeypot Hits Details")
        st.dataframe(honeypot_df[columns_to_show].sort_values("timestamp", ascending=False), use_container_width=True)

    if not honeypot_df.empty:
        honeypot_df["date"] = pd.to_datetime(honeypot_df["timestamp"]).dt.date
        daily_hits = honeypot_df.groupby("date").size().reset_index(name="Hits")
        fig_hits = px.bar(daily_hits, x="date", y="Hits")
        fig_hits.update_layout(paper_bgcolor="#111111", plot_bgcolor="#111111", font=dict(color="white"))
        st.plotly_chart(fig_hits, use_container_width=True)

    if "timestamp" in df.columns:
        df['date'] = pd.to_datetime(df['timestamp']).dt.date
        daily_counts = df.groupby('date').size().reset_index(name='New IOCs')
        st.markdown("### Daily IOC Timeline")
        fig = px.line(daily_counts, x="date", y="New IOCs", markers=True)
        st.plotly_chart(fig, use_container_width=True)

# === Threat Fusion Tab === #
with tab2:
    st.title("ShadowGrid Threat Fusion")
    st.markdown("Live threat intelligence synthesized from recent CVE activity and AI agents.")

    col1, col2, col3 = st.columns(3)
    with col1:
        search_term = st.text_input("Search CVEs (optional keyword)", "")
    with col2:
        start = st.date_input("Start Date", value=datetime.utcnow() - timedelta(days=7))
        end = st.date_input("End Date", value=datetime.utcnow())
    with col3:
        severity = st.selectbox("Severity", options=["", "LOW", "MEDIUM", "HIGH", "CRITICAL"], index=4)

    search_query = search_term if search_term.strip() else None
    severity_filter = severity if severity.strip() else None

    threats = fetch_filtered_cves(query=search_query, start_date=start, end_date=end, severity=severity_filter)

    if not threats:
        st.info("No threats available.")
    else:
        st.markdown("### CVE + Agent Intelligence")
        for threat in threats:
            st.markdown(f"**{threat['Threat']}**")
            st.text(f"Score: {threat['Score']} | Published: {threat.get('Published')} | Impact: {threat.get('Impact')}")
            st.text(threat['Reasoning'])
            st.markdown("---")

# === ShadowWire News Tab === #
with tab3:
    st.title("ShadowWire News")
    st.markdown("Curated cybersecurity headlines from global sources.")

    news = analyze_rss_feeds()

    if not news:
        st.info("No news available.")
    else:
        st.markdown("### 🔍 Filter by Topic")
        topic_articles = auto_tag_articles(news)
        selected_tag = st.selectbox("Filter by Topic", ["All"] + sorted(topic_articles.keys()))

        display_articles = news if selected_tag == "All" else topic_articles[selected_tag]

        for item in display_articles:
            source = item.get('Source', 'Unknown Source')
            title = item.get('Threat', 'No Title')
            link = item.get('link', '#')
            st.markdown(f"[{source} – {title}]({link})")


