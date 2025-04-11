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

2. Install dependecies
   ```bash
   pip install -r requirements.txt

3. Add your API keys:
   - Copy .env.example -> .env
   - Fill in your keys
  
4. Run the pipeline:
   ```bash
   python run.py

5. Launch the dashboard:
   ```bash
   streamlit run dashboard/app.py

---

## Output
Creates a CSV and (optionally) a SQLite DB of enriched threat intel. Looks like:

| IP       | Country | ASN      | Abuse Score | VT Hits | Threat Score |
|----------|---------|----------|-------------|---------|---------------|
| 8.8.8.8  | US      | AS15169  | 90          | 5       | 95            |

---

## License
MIT - free to use, modify, and learn from
