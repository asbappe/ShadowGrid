import requests
import time

def enrich_reputation(ip, abuseipdb_api_key, vt_api_key):
    """Try both AbuseIPDB and VirusTotal. Fail gracefully if one fails."""
    abuse_score = None
    vt_detections = 0

    # --- AbuseIPDB ---
    try:
        abuse_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": abuseipdb_api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        response = requests.get(abuse_url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        json_data = response.json()
        abuse_score = json_data.get("data", {}).get("abuseConfidenceScore", None)
    except requests.exceptions.HTTPError as e:
        if response.status_code == 429:
            print(f"[AbuseIPDB] Rate limit hit for IP {ip}. Skipping.")
        else:
            print(f"[AbuseIPDB] HTTP error for {ip}: {e}")
    except Exception as e:
        print(f"[AbuseIPDB] Failed to enrich {ip}: {e}")

    # --- VirusTotal ---
    try:
        vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": vt_api_key}
        response = requests.get(vt_url, headers=headers, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            vt_detections = json_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        elif response.status_code == 429:
            print(f"[VT] Rate limit hit for IP {ip}. Skipping.")
        else:
            print(f"[VT] Error {response.status_code} on {ip}")
    except Exception as e:
        print(f"[VT] Failed to enrich {ip}: {e}")

    return {
        "abuse_score": abuse_score,
        "vt_detections": vt_detections
    }
