import requests

def get_abuseipdb_ips(api_key, min_confidence=90, limit=250):
    """
    Fetch IPs from AbuseIPDB's blacklist API. Skip on failure or rate limit.
    """
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    params = {"confidenceMinimum": str(min_confidence)}
    headers = {"Accept": "text/plain", "Key": api_key}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        ip_list = [line.strip() for line in response.text.splitlines() if line]
        return ip_list[:limit]

    except requests.exceptions.HTTPError as e:
        if response.status_code == 429:
            print("[!] AbuseIPDB: Rate limit hit. Skipping feed.")
        else:
            print(f"[!] AbuseIPDB: HTTP error {response.status_code}. Skipping feed.")
        return []

    except Exception as e:
        print(f"[!] AbuseIPDB: Failed to fetch blacklist: {e}")
        return []
