import requests
import pandas as pd

def get_remote_honeypot_hits(url="http://67.205.131.5:8080/all_hits"):
    """
    Fetch attacker IPs and timestamps from your remote honeypot's /all_hits API.

    Returns:
        pd.DataFrame with columns: ip, timestamp
    """
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        hits = response.json()

        df = pd.DataFrame(hits)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df

    except Exception as e:
        print(f"[!] Failed to fetch remote honeypot hits: {e}")
        return pd.DataFrame(columns=["ip", "timestamp"])
