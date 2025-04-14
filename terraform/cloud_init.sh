#!/bin/bash

# Update and install deps
apt-get update -y
apt-get install -y python3 python3-pip git

# Clone the ShadowGrid repo
cd /home/ubuntu
git clone https://github.com/asbappe/ShadowGrid.git
cd ShadowGrid

# Install Python dependencies
pip3 install -r requirements.txt

# Run once on startup
python3 run.py

# Set cron to run every 12 hours
(crontab -l ; echo "0 */12 * * * cd /home/ubuntu/ShadowGrid && /usr/bin/python3 run.py >> run.log 2>&1") | crontab -

# Start Streamlit app in background
nohup streamlit run ShadowGrid.py --server.port 8501 > streamlit.log 2>&1 &
