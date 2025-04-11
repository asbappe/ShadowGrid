import requests

def enrich_geoip(ip):
    """
    Returns GeoIP + ASN data from ipinfo.io for a given IP address.
    Returns a dict with country, region, city, ASN.
    """
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        response.raise_for_status()
        data = response.json()

        return {
            "country": data.get("country", "N/A"),
            "region": data.get("region", "N/A"),
            "city": data.get("city", "N/A"),
            "asn": data.get("org", "N/A")
        }
    except Exception as e:
        print(f"GeoIP error for {ip}: {e}")
        return {
            "country": "N/A",
            "region": "N/A",
            "city": "N/A",
            "asn": "N/A"
        }
