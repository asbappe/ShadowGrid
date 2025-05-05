🚨 **ShadowGrid**: Intelligent Threat Feed Aggregator & Visualizer

ShadowGrid is a cybersecurity analytics platform that combines a custom honeypot with multiple external threat feeds, enriches the data, and visualizes it in real time via a Streamlit dashboard. Built for blue teams, threat analysts, and curious hackers, ShadowGrid delivers actionable insights into hostile traffic and IOCs.

---

## 🏗️ Project Structure

```
ShadowGrid/
├── ShadowGrid.py             ← Streamlit dashboard application
├── requirements.txt          ← Python dependencies
├── honeypot/                 ← Honeypot engine and configuration
│   ├── honeypot.py           ← Custom network listener + ingest client
│   └── config.yaml           ← Ports, logging, and API settings
├── feeds/                    ← Threat feed adapters
│   ├── abuseipdb_feed.py     ← AbuseIPDB ingestion adapter
│   ├── otx_feed.py           ← AlienVault OTX ingestion adapter
│   └── remote_honeypot.py    ← Internal honeypot ingestion stub
├── enrichment/               ← Data enrichment modules
│   ├── geoip.py              ← GeoIP lookup module
│   ├── reputation.py         ← Threat reputation scoring
│   └── scoring.py            ← IOC freshness and scoring
├── systemd/                  ← Example systemd unit files
│   ├── streamlit.service     ← Streamlit dashboard systemd service
│   └── honeypot.service      ← Honeypot systemd service
└── refresh.sh                ← Auto-update & restart script
```

## 📊 Key Features

### 1. Multiple Threat Feeds Aggregated

* 🔍 **AbuseIPDB**
* 🦪 **AlienVault OTX**
* 🕵️‍♂️ **Custom Honeypot** (DigitalOcean/AWS VPS)

### 2. Data Enrichment

* 🌍 **GeoIP Lookups** (Country, City, ASN)
* 📡 **Threat Scoring** (AbuseIPDB, VT reputation)
* 🕒 **IOC Freshness** (Timestamps & age)

### 3. Interactive Streamlit Dashboard

* 🌐 **Real-time Map** of threat activity
* 📈 **IOC Timeline** chart
* 📂 **Expandable Table** with metadata & filters
* 🎛️ **Filters** by Country, Score, ASN, Feed Source
* 🌑 **Clean Dark Theme**

### 4. Features In Progress

* 🏷️ IOC Tagging & Threat Categories
* ⚙️ Automated VT Enrichment Fallback
* 🔗 Attacker Graph Clustering
* 📦 Export to STIX / MISP

---

## 🚀 Getting Started

### Prerequisites

* **OS:** Ubuntu 20.04+ (systemd)
* **Python:** 3.8+
* **Ports:** Open inbound ports for honeypot (e.g., 22, 80, 443, custom) and outbound TCP/443

### 1. Clone and Install

```bash
git clone https://github.com/asbappe/ShadowGrid.git
cd ShadowGrid
pip install -r requirements.txt
```

### 2. Configure API Keys & Settings

* Copy `honeypot/config.example.yaml → honeypot/config.yaml` and adjust.
* Alternatively create a `.env` in root:

  ```ini
  OTX_API_KEY=<your_otx_key>
  ABUSEIPDB_API_KEY=<your_abuseipdb_key>
  VT_API_KEY=<your_virustotal_key>
  DASHBOARD_URL=https://shadowgridlabs.com/api/ingest
  LOG_LEVEL=INFO
  ```

### 3. Initial Pipeline Run

```bash
python run.py
```

(This will fetch & enrich feeds, outputting `output/ShadowGrid_results.csv`.)

### 4. Launch Dashboard

```bash
streamlit run ShadowGrid.py --server.port 8501
```

Navigate to `http://<EC2_IP>:8501` or via reverse-proxy domain.

---

## 🛡️ Honeypot Deployment (DigitalOcean or AWS)

1. SSH into your droplet/instance
2. Ensure ports (e.g. 8080 for API, 22/80/443 for honeypot) are open
3. Run:

   ```bash
   python3 honeypot/honeypot.py --config honeypot/config.yaml
   ```
4. The honeypot will post JSON to your dashboard API for real-time ingestion.

---

## ⚙️ Automation & Services

### Systemd Services

Copy service files from `systemd/` → `/etc/systemd/system/`:

```ini
# streamlit.service
[Unit]
Description=ShadowGrid Streamlit Dashboard
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/ShadowGrid
ExecStart=/usr/local/bin/streamlit run ShadowGrid.py --server.port 8501
Restart=on-failure
Environment="PATH=/usr/local/bin:/usr/bin"

[Install]
WantedBy=multi-user.target
```

```ini
# honeypot.service
[Unit]
Description=ShadowGrid Honeypot
After=network.target

[Service]
User=ubuntu
ExecStart=/usr/bin/python3 /home/ubuntu/ShadowGrid/honeypot/honeypot.py --config /home/ubuntu/ShadowGrid/honeypot/config.yaml
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Enable & start both:

```bash
sudo systemctl daemon-reload
sudo systemctl enable streamlit.service honeypot.service
sudo systemctl start  streamlit.service honeypot.service
```

### Refresh Script

`refresh.sh` automates:

1. `git pull`
2. `python run.py`
3. Restart Streamlit
4. Tail last 20 lines of `streamlit.log`
5. Echo dashboard URL

Add alias:

```bash
echo "alias refreshgrid='$(pwd)/refresh.sh'" >> ~/.bashrc
source ~/.bashrc
```

---

## 📜 Logs & Monitoring

* Streamlit: `sudo journalctl -u streamlit.service -f`
* Honeypot: `sudo journalctl -u honeypot.service -f`
* Local files (if enabled in `config.yaml`)

---

## 🐞 Troubleshooting

* **Port Conflicts**: `lsof -i TCP:8501`
* **AWS Security Groups**: Verify inbound/outbound rules
* **Dependencies**: `pip install -r requirements.txt`
* **Config Issues**: Check `config.yaml` and `.env`

---

## 🤝 Contributing

1. Fork this repo
2. Create a branch (`git checkout -b feature-name`)
3. Commit changes (`git commit -m "Add feature"`)
4. Push (`git push origin feature-name`)
5. Open a PR

Please follow code style and include tests.

---

## 📄 License & Credits

Released under the **MIT License**. See [LICENSE](LICENSE).
Built by **Austin Bappe** — seasoned cybersecurity professional.

Thanks to Streamlit, Plotly, MaxMind, and the open-source community!
