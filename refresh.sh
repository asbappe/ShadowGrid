#!/bin/bash

# ShadowGrid full auto-refresh
echo "🔫 Killing any running Streamlit..."
pkill -f streamlit

echo "📥 Pulling latest code from GitHub..."
cd ~/ShadowGrid || { echo '❌ ShadowGrid directory not found'; exit 1; }
git pull

echo "🧠 Running threat enrichment pipeline (run.py)..."
python3 run.py

echo "🚀 Restarting Streamlit dashboard..."
nohup streamlit run ShadowGrid.py --server.port 8501 > streamlit.log 2>&1 &

sleep 2
echo "📄 Streaming last 20 lines of log:"
tail -n 20 streamlit.log

echo "🌐 Dashboard should now be available at: http://$(curl -s ifconfig.me):8501"
