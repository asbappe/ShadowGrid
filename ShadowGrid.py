import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

# This MUST be the first Streamlit command
st.set_page_config(page_title="ShadowGrid Dashboard", layout="wide")

# Load the enriched threat data
df = pd.read_csv("output/ioc_results.csv", parse_dates=["timestamp"])
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

# Title & Description
st.title("ShadowGrid Dashboard")
st.markdown("Real-time threat feed intelligence from honeypots, OTX, and AbuseIPDB.")

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
    color_continuous_scale="YlOrRd", #glow effect
    projection="natural earth"
)

fig.update_geos(
    showland=True,
    landcolor="#1e1e1e",        # dark land
    oceancolor="#111111",       # dark ocean
    showocean=True,
    showcoastlines=True,
    coastlinecolor="white",
    showcountries=True,
    countrycolor="white",
    showframe=False,
    bgcolor="#111111" 
)

fig.update_layout(
    geo_bgcolor="#111111",
    paper_bgcolor="#111111",    # dark outer background
    plot_bgcolor="#111111",     # dark plot background
    font=dict(color="white"),
    margin={"r":0,"t":40,"l":0,"b":0},
    title={
        "text": "Global Threat Map",
        "x": 0.5,
        "xanchor": "center"
    }
)

fig.update_traces(
    marker=dict(
        sizemode="area",
        sizeref=2.*max(map_df["threat_score"])/(20**2),  # size scaling
        line=dict(width=1, color="rgba(255,255,255,0.3)"),  #  white glow ring
        opacity=0.6
    )
)

st.plotly_chart(fig, use_container_width=True)

# 🪤 Honeypot Hits Dashboard (moved from separate page)
st.markdown("### 🪤 Honeypot Hits Details")
honeypot_df = df[df["source"].str.contains("Honeypot", na=False)].copy()
columns_to_show = [
    "ip", "country", "region", "city", "asn", 
    "abuse_score", "vt_detections", "threat_score", 
    "timestamp"
]

if not honeypot_df.empty:
    st.dataframe(
        honeypot_df[columns_to_show].sort_values("timestamp", ascending=False),
        use_container_width=True
    )
else:
    st.info("No honeypot events to display.")

###HoneyPot Hits Bar Chart (considering deleting)

if not honeypot_df.empty:
    honeypot_df["date"] = pd.to_datetime(honeypot_df["timestamp"]).dt.date
    daily_hits = honeypot_df.groupby("date").size().reset_index(name="Hits")

    fig_hits = px.bar(
        daily_hits,
        x="date",
        y="Hits",
        title="Daily Honeypot Hits",
        labels={"date": "Date", "Hits": "Hits"},
    )
    fig_hits.update_xaxes(type='category')
    fig_hits.update_layout(width=100)
    
    fig_hits.update_layout(
        paper_bgcolor="#111111",
        plot_bgcolor="#111111",
        font=dict(color="white"),
        margin=dict(l=40, r=40, t=60, b=60),
        xaxis_title="Date",
        yaxis_title="Hits"
    )


    st.plotly_chart(fig_hits, use_container_width=True)
else:
    st.info("No Honeypot hits to display.")



# Filters (moved to main page)
st.markdown("### 🔍 Filter Indicators")
with st.container():
    col1, col2, col3 = st.columns(3)

    with col1:
        selected_countries = st.multiselect(
            "Filter by Country", sorted(df["country"].dropna().unique())
        )

    with col2:
        selected_asns = st.multiselect(
            "Filter by ASN/Org", sorted(df["asn"].dropna().unique())
        )

    with col3:
        min_score, max_score = st.slider(
            "Threat Score Range", 0, 100, (0, 100), step=1
        )

# Apply filters
filtered_df = df.copy()

if selected_countries:
    filtered_df = filtered_df[filtered_df["country"].isin(selected_countries)]

if selected_asns:
    filtered_df = filtered_df[filtered_df["asn"].isin(selected_asns)]

filtered_df = filtered_df[
    (filtered_df["threat_score"] >= min_score)
    & (filtered_df["threat_score"] <= max_score)
]

# Main Data Table with Expanders
st.markdown(f"### 📋 Showing {len(filtered_df)} Threat Indicators")
for _, row in filtered_df.iterrows():
    with st.expander(f"ℹ️ {row['ip']}  |  Score: {row['threat_score']}"):
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("**📍 Location Details**")
            st.write(f"- **Country:** {row['country']}")
            st.write(f"- **Region:** {row['region']}")
            st.write(f"- **City:** {row['city']}")

            st.markdown("**🌐 Network Info**")
            st.write(f"- **ASN:** {row['asn']}")

        with col2:
            st.markdown("**🚨 Threat Intelligence**")
            st.write(f"- **Threat Score:** `{row['threat_score']}`")
            st.write(f"- **Abuse Score:** {row['abuse_score']}")
            st.write(f"- **VT Detections:** {row['vt_detections']}")
            st.write(f"- **Source Feeds:** {row['source']}")
            st.write(f"- **Last Seen:** {row['timestamp']}")

# Timeline Chart of Daily IOC Counts
if "timestamp" in df.columns:
    df['date'] = pd.to_datetime(df['timestamp']).dt.date
    daily_counts = df.groupby('date').size().reset_index(name='New IOCs')

    st.markdown("### 📈 Daily IOC Timeline")
    fig = px.line(daily_counts, x="date", y="New IOCs", markers=True)
    st.plotly_chart(fig, use_container_width=True)
