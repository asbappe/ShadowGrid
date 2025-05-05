import os
import requests
import pandas as pd

# Read from REMOTE_HONEYPOT_URL; default to localhost tunnel
HONEYPOT_URL = os.getenv(
    "REMOTE_HONEYPOT_URL",
    "http://127.0.0.1:8080/all_hits"
)

def get_remote_honeypot_hits(url: str = None) -> pd.DataFrame:
    """
    Fetch attacker IPs and timestamps from your remote honeypot's /all_hits API.
    """
    target = url or HONEYPOT_URL

    try:
        response = requests.get(target, timeout=5)
        response.raise_for_status()
        hits = response.json()

        df = pd.DataFrame(hits)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df

    except Exception as e:
        print(f"[!] Failed to fetch remote honeypot hits ({target}): {e}")
        return pd.DataFrame(columns=["ip", "timestamp"])
