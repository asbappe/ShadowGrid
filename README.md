# 🚨 ShadowGrid: Intelligent Threat Feed Aggregator & Visualizer

**ShadowGrid** is a cybersecurity analytics dashboard that aggregates, enriches, and visualizes malicious IP data from multiple sources — including your own honeypot. It's built for blue teams, threat analysts, and curious hackers looking to gain real-time insight into hostile traffic and IOCs.

---

## 📊 Features

✅ **Multiple Threat Feeds Aggregated**
- 🔍 [AbuseIPDB](https://www.abuseipdb.com/)
- 🦪 [AlienVault OTX](https://otx.alienvault.com/)
- 🕵️‍♂️ Custom **remote honeypot** hosted on a DigitalOcean VPS

✅ **Data Enrichment**
- 🌍 GeoIP lookups (Country, City, ASN)
- 📡 Threat scoring (Abuse/VT reputation)
- 🕒 IOC freshness with timestamps

✅ **Interactive Dashboard (Streamlit)**
- 🌐 Real-time map of threat activity
- 📈 IOC timeline chart
- 📂 Expandable table with IOC metadata
- 🎛️ Filters: Country, Threat Score, ASN, Feed Source
- 🌑 Clean dark theme

---

## 📁 Project Structure

```
ShadowGrid/
├── run.py                        ← Data pipeline: fetch, enrich, export
├── app.py                        ← Main Streamlit dashboard
├── feeds/
│   ├── otx_feed.py
│   ├── abuseipdb_feed.py
│   └── remote_honeypot.py
├── enrichment/
│   ├── geoip.py
│   ├── reputation.py
│   └── scoring.py
├── utils/
│   └── config.py                ← API key management
├── output/
│   └── ShadowGrid_results.csv  ← Auto-generated results
├── honeypot/ (on VPS)
│   └── honeypot_server.py       ← Flask app + TCP listener
└── README.md
```

---

## 🚀 Getting Started

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/ShadowGrid.git
cd ShadowGrid
```

### 2. Install requirements

```bash
pip install -r requirements.txt
```

### 3. Set up your API keys

Create a `.env` file in the root folder with:

```
OTX_API_KEY=your_otx_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
VT_API_KEY=your_virustotal_key
```

Or set them directly in `utils/config.py`.

---

### 4. Run the pipeline

Fetch + enrich data:

```bash
python run.py
```

This will update `output/ShadowGrid_results.csv`.

---

### 5. Launch the dashboard

```bash
streamlit run app.py
```

Navigate to `http://localhost:8501`.

---

## 🧚 Honeypot Setup (DigitalOcean VPS)

Run this on your cloud droplet:

```bash
python3 honeypot_server.py
```

Ensure port `8080` (Flask API) and `2222` (honeypot listener) are open to inbound traffic. Data is automatically synced to the dashboard.

---

## 🗕️ Features In Progress

- IOC tagging & threat categories  
- Automated VT enrichment fallback  
- Graph-based attacker clustering  
- Export to STIX or MISP

---

## 💼 Ideal Use Cases

- Blue team dashboards
- Threat intel enrichment
- SOC analyst tooling
- Resume portfolio showcase

---

## 🛡️ License

MIT — Free for personal, academic, or professional use.

---

## 🤝 Credits

Built by Austin Bappe —  Seasoned Cybersecurity Professional.  
Special thanks to [Streamlit](https://streamlit.io/), [Plotly](https://plotly.com/), [MaxMind](https://www.maxmind.com/), and the open-source community.

---

**🔗 Let's connect on [LinkedIn]([https://linkedin.com/in/yourprofile](https://www.linkedin.com/in/austinbappe/)** — open to security roles!
