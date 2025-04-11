from OTXv2 import OTXv2, IndicatorTypes

def get_otx_ips(api_key, max_pulses=50):
    """
    Fetches IPv4 indicators from the user's OTX subscription feed.
    Returns a list of IP address strings.
    """
    print(" → Fetching IPs from OTX...")
    otx = OTXv2(api_key)

    # Get latest pulses from the feed
    pulses = otx.get_pulses(limit=max_pulses)

    ip_list = []
    for pulse in pulses:
        for indicator in pulse.get("indicators", []):
            if indicator.get("type") == IndicatorTypes.IPv4:
                ip_list.append(indicator.get("indicator"))

    unique_ips = list(set(ip_list))
    print(f"   Found {len(unique_ips)} IPs from OTX.")
    return unique_ips
