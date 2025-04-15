import requests
from datetime import datetime, timedelta

def fetch_recent_cves(days=3):
    url = f"https://cve.circl.lu/api/last"
    try:
        response = requests.get(url, timeout=5)
        if response.ok:
            return response.json()
    except Exception as e:
        return [{"id": "CVE-0000-0000", "summary": f"Failed to fetch CVEs: {e}", "cvss": 0.0}]
    return []

def run_agents(show_reasoning=False):
    cves = fetch_recent_cves()
    threats = []

    for cve in cves:
        threat = {
            "Threat": cve.get("id", "Unknown CVE"),
            "Score": round(cve.get("cvss", 0.0), 1),
            "Impact": cve.get("summary", "No summary available"),
            "Reasoning": f"CVSS score of {cve.get('cvss', 0.0)} from CIRCL API"
        }
        threats.append(threat)

    return threats[:10]  # Limit to 10 most recent
