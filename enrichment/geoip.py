import requests

def enrich_geoip(ip):
    """
    Uses ipinfo.io to enrich IP with geo + ASN + coordinates
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        response.raise_for_status()
        data = response.json()

        loc = data.get("loc", "0,0").split(",")
        latitude = float(loc[0]) if len(loc) == 2 else None
        longitude = float(loc[1]) if len(loc) == 2 else None

        return {
            "country": data.get("country", "N/A"),
            "region": data.get("region", "N/A"),
            "city": data.get("city", "N/A"),
            "asn": data.get("org", "N/A"),
            "latitude": latitude,
            "longitude": longitude
        }
    except Exception as e:
        print(f"GeoIP error for {ip}: {e}")
        return {
            "country": "N/A",
            "region": "N/A",
            "city": "N/A",
            "asn": "N/A",
            "latitude": None,
            "longitude": None
        }
