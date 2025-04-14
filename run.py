import pandas as pd
from feeds.otx_feed import get_otx_ips
from feeds.abuseipdb_feed import get_abuseipdb_ips
from feeds.remote_honeypot import get_remote_honeypot_hits
from enrichment.geoip import enrich_geoip
from enrichment.reputation import enrich_reputation
from enrichment.scoring import calculate_threat_score
from utils.config import OTX_API_KEY, ABUSEIPDB_API_KEY, VT_API_KEY
import os

print("Fetching IOCs from threat feeds...")

# Dictionaries to store sources and timestamps
ip_sources = {}
ip_timestamps = {}

# OTX Feed
print(" → Fetching IPs from OTX...")
otx_ips = get_otx_ips(OTX_API_KEY)
print(f"   Found {len(otx_ips)} IPs from OTX.")
for ip in otx_ips:
    ip_sources.setdefault(ip, set()).add('OTX')

# AbuseIPDB Feed
print(" → Fetching IPs from AbuseIPDB...")
abuse_ips = get_abuseipdb_ips(ABUSEIPDB_API_KEY)
print(f"   Found {len(abuse_ips)} IPs from AbuseIPDB.")
for ip in abuse_ips:
    ip_sources.setdefault(ip, set()).add('AbuseIPDB')

# Remote Honeypot Feed
print(" → Fetching hits from remote honeypot...")
honeypot_df = get_remote_honeypot_hits("http://67.205.131.5:8080/all_hits")
honeypot_ips = honeypot_df["ip"].unique().tolist()
print(f"   Found {len(honeypot_ips)} IPs from honeypot.")
for _, row in honeypot_df.iterrows():
    ip = row["ip"]
    timestamp = row["timestamp"]
    ip_sources.setdefault(ip, set()).add('Honeypot')
    if ip not in ip_timestamps or ip_timestamps[ip] < timestamp:
        ip_timestamps[ip] = timestamp

# Aggregate all unique IPs
all_ips = list(ip_sources.keys())
print(f"Fetched {len(all_ips)} unique IPs.")

# Enrichment
print("Enriching IPs and calculating threat scores...")
records = []
for ip in all_ips:
    geo = enrich_geoip(ip)
    rep = enrich_reputation(ip, ABUSEIPDB_API_KEY, VT_API_KEY)
    score = calculate_threat_score(rep)

    records.append({
        "ip": ip,
        "country": geo.get("country"),
        "region": geo.get("region"),
        "city": geo.get("city"),
        "latitude": geo.get("latitude"),   
        "longitude": geo.get("longitude"), 
        "asn": geo.get("asn"),
        "abuse_score": rep.get("abuse_score"),
        "vt_detections": rep.get("vt_detections"),
        "threat_score": score,
        "source": ', '.join(ip_sources[ip]),
        "timestamp": ip_timestamps.get(ip, pd.NaT)
})

# Convert to DataFrame
output_df = pd.DataFrame(records)

# Save CSV
os.makedirs("output", exist_ok=True)
csv_path = "output/ioc_results.csv"
output_df.to_csv(csv_path, index=False)
print(f"Enriched data saved to {csv_path}")