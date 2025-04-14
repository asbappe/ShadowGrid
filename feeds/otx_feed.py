from OTXv2 import OTXv2, IndicatorTypes
import requests

class OTXv2NoSSL(OTXv2):
    def session(self):
        sess = super().session()
        sess.verify = False  # This disables SSL cert validation
        return sess

def get_otx_ips(api_key, max_pulses=50):
    print(" → Fetching IPs from OTX... (SSL CERT CHECK DISABLED)")
    try:
        otx = OTXv2NoSSL(api_key)
        all_pulses = otx.get_my_pulses()
        pulses = all_pulses[:max_pulses]
    except Exception as e:
        print(f"OTX API failed: {e}")
        return []

    ip_list = []
    for pulse in pulses:
        for indicator in pulse.get("indicators", []):
            if indicator.get("type") == IndicatorTypes.IPv4:
                ip_list.append(indicator.get("indicator"))

    unique_ips = list(set(ip_list))
    print(f"   Found {len(unique_ips)} IPs from OTX.")
    return unique_ips
