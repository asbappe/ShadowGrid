import requests

def fetch_recent_cves():
    url = "https://cve.circl.lu/api/last"
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
        cve_id = cve.get("id") or "Unknown CVE"
        summary = cve.get("summary") or "No description available"
        score = cve.get("cvss")
        if score is None:
            score = 0.0

        # Skip obviously broken CVEs with no info
        if cve_id == "Unknown CVE" and summary.startswith("No description"):
            continue

        threats.append({
            "Threat": cve_id,
            "Score": round(score, 1),
            "Impact": summary,
            "Reasoning": f"CVSS score of {score} from CIRCL API"
        })

    return threats[:10] if threats else [{
        "Threat": "No CVEs found",
        "Score": 0.0,
        "Impact": "CIRCL returned no usable data",
        "Reasoning": "Check internet access or API status"
    }]
