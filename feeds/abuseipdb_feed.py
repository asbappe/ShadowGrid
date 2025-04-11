import requests

def get_abuseipdb_ips(api_key, min_confidence=90):
    """
    Fetches a list of malicious IPs from AbuseIPDB using the /blacklist endpoint.
    Returns a list of IP address strings.
    """
    print(" → Fetching IPs from AbuseIPDB...")
    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Key": api_key,
        "Accept": "text/plain"
    }
    params = {
        "confidenceMinimum": min_confidence
    }

    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()

    ip_list = [line.strip() for line in response.text.splitlines() if line]
    print(f"   Found {len(ip_list)} IPs from AbuseIPDB.")
    return ip_list
