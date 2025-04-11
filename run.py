import pandas as pd
from dotenv import load_dotenv
import os

# Local modules
from feeds.otx_feed import get_otx_ips
from feeds.abuseipdb_feed import get_abuseipdb_ips
from enrichment.geoip import enrich_geoip
from enrichment.reputation import enrich_reputation
from enrichment.scoring import calculate_threat_score

# Load .env for API keys
load_dotenv()

OTX_API_KEY = os.getenv("OTX_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")

if not OTX_API_KEY or not ABUSEIPDB_API_KEY or not VT_API_KEY:
    raise Exception("Missing one or more required API keys in .env file.")

# === Step 1: Fetch IPs from Threat Feeds ===
print("Fetching IOCs from threat feeds...")

otx_ips = get_otx_ips(OTX_API_KEY)
abuse_ips = get_abuseipdb_ips(ABUSEIPDB_API_KEY)

all_ips = set(otx_ips + abuse_ips)
print(f"Fetched {len(all_ips)} unique IPs.")

# === Step 2: Enrich & Score ===
enriched_data = []

print("Enriching IPs and calculating threat scores...")
for ip in all_ips:
    geo_data = enrich_geoip(ip)
    rep_data = enrich_reputation(ip, ABUSEIPDB_API_KEY, VT_API_KEY)
    threat_score = calculate_threat_score(rep_data)

    row = {
        "ip": ip,
        **geo_data,
        **rep_data,
        "threat_score": threat_score
    }
    enriched_data.append(row)

# === Step 3: Save to CSV ===
os.makedirs("output", exist_ok=True)
output_file = "output/threatfeedvalidator_results.csv"

df = pd.DataFrame(enriched_data)
df.to_csv(output_file, index=False)

print(f"\n✅ Done! Data saved to {output_file}")
