import os
import requests
import pandas as pd

# Load .env if present
from pathlib import Path
env = Path(__file__).parent.parent / ".env"
if env.exists():
    for line in env.read_text().splitlines():
        if line and not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)

def get_remote_honeypot_hits() -> pd.DataFrame:
    """
    Fetch attacker IPs and timestamps from your remote honeypot's /all_hits API,
    reading the URL from REMOTE_HONEYPOT_URL (or falling back to localhost tunnel).
    """
    url = os.getenv("REMOTE_HONEYPOT_URL", "http://127.0.0.1:8080/all_hits")
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        hits = response.json()

        df = pd.DataFrame(hits)
        if "timestamp" in df:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df

    except Exception as e:
        print(f"[!] Failed to fetch remote honeypot hits ({url}): {e}")
        return pd.DataFrame(columns=["ip", "timestamp"])
