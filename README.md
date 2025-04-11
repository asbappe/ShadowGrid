# ThreatFeedValidator

An open-source threat intelligence dashboard built in Python + Streamlit. Fetches IP indicators from public feeds, enriches them with GeoIP + VirusTotal, and scores threats with a clean, interactive UI.

---

## Features

- Pulls live malicious IPs from **OTX** and **AbuseIPDB**
- Enriches each IP with:
  - Country & ASN (GeoIP)
  - Abuse score (AbuseIPDB)
  - VirusTotal detections
- Assigns a **threat score**
- Saves results to CSV/SQLite
- Visualizes results in a slick Streamlit dashboard

---

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/ThreatFeedValidator.git
   cd ThreatFeedValidator
