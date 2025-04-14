import os
from dotenv import load_dotenv

# Load variables from .env file if it exists
load_dotenv()

# Read API keys from environment variables
OTX_API_KEY = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")
