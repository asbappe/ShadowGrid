def calculate_threat_score(enriched):
    """
    Calculates a composite threat score (0-100) based on:
    - abuseConfidenceScore from AbuseIPDB
    - number of VT detections
    """
    abuse_score = enriched.get("abuse_score", 0)
    vt_detections = enriched.get("vt_detections", 0)

    # Normalize VT detections: let's assume 10+ is very bad
    vt_score = min(vt_detections * 10, 100)

    # Weighted average: 60% AbuseIPDB, 40% VirusTotal
    threat_score = int((abuse_score * 0.6) + (vt_score * 0.4))
    return threat_score
