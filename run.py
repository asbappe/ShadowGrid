
import pandas as pd
from datetime import datetime, timedelta

CSV_PATH = "output/ShadowGrid_results.csv"
MAX_AGE = timedelta(weeks=4)

def trim_old_entries(path: str, timestamp_col="timestamp"):
    df = pd.read_csv(path, parse_dates=[timestamp_col])
    cutoff = datetime.utcnow() - MAX_AGE
    df = df[df[timestamp_col] >= cutoff]
    df.to_csv(path, index=False)

def main():
    # 1) fetch & enrich feeds, append to CSV
    # … your existing logic …

    # 2) then trim
    trim_old_entries(CSV_PATH)

if __name__ == "__main__":
    main()
from feeds.remote_honeypot import get_remote_honeypot_hits
from feeds.otx_feed import get_otx_ips
from enrichment.geoip import enrich_geoip
from enrichment.reputation import enrich_reputation
from enrichment.scoring import calculate_threat_score
from utils.config import OTX_API_KEY, ABUSEIPDB_API_KEY, VT_API_KEY
import os

print("🪤 Fetching IPs from honeypot...")
honeypot_df = get_remote_honeypot_hits("http://67.205.131.5:8080/all_hits")

if honeypot_df.empty:
    print("No honeypot hits found.")
    exit()

print("🔍 Loading OTX feed for enrichment...")
otx_ips = set(get_otx_ips(OTX_API_KEY))
print(f"OTX feed loaded: {len(otx_ips)} IPs")

# Load existing IOCs if present
output_path = "output/ioc_results.csv"
existing_entries = set()

if os.path.exists(output_path):
    existing_df = pd.read_csv(output_path, parse_dates=["timestamp"])
    existing_entries = set(zip(existing_df["ip"], existing_df["timestamp"].astype(str)))

records = []
for _, row in honeypot_df.iterrows():
    ip = row["ip"]
    timestamp = str(row["timestamp"])

    if (ip, timestamp) in existing_entries:
        continue  # Skip already processed entries

    geo = enrich_geoip(ip)
    rep = enrich_reputation(ip, ABUSEIPDB_API_KEY, VT_API_KEY)
    score = calculate_threat_score(rep)

    sources = ["Honeypot"]
    if ip in otx_ips:
        sources.append("OTX")
    if rep.get("abuse_score", 0) > 0:
        sources.append("AbuseIPDB")

    print(f"[+] {ip} → Score: {score} | Enriched from: {', '.join(sources)}")

    records.append({
        "ip": ip,
        "path": row.get("path"), 
        "country": geo.get("country"),
        "region": geo.get("region"),
        "city": geo.get("city"),
        "latitude": geo.get("latitude"),   
        "longitude": geo.get("longitude"), 
        "asn": geo.get("asn"),
        "abuse_score": rep.get("abuse_score"),
        "vt_detections": rep.get("vt_detections"),
        "threat_score": score,
        "source": ", ".join(sources),
        "timestamp": timestamp
    })

enriched_df = pd.DataFrame(records)

# Load and merge with existing data
output_path = "output/ioc_results.csv"
os.makedirs("output", exist_ok=True)

if os.path.exists(output_path):
    existing_df = pd.read_csv(output_path, parse_dates=["timestamp"])
    if not enriched_df.empty:
        combined_df = pd.concat([existing_df, enriched_df], ignore_index=True)
        combined_df.drop_duplicates(subset=["ip", "timestamp"], inplace=True)
    else:
        combined_df = existing_df
else:
    combined_df = enriched_df

combined_df["timestamp"] = pd.to_datetime(combined_df["timestamp"], errors="coerce")
combined_df.sort_values("timestamp", ascending=False, inplace=True)
combined_df.to_csv(output_path, index=False)
print(f"✅ Enriched honeypot IOCs saved to {output_path}")
