from tools.rss_parser import fetch_rss_headlines

def analyze_rss_feeds():
    headlines = fetch_rss_headlines()
    threats = []
    for h in headlines:
        threats.append({
            "Threat": h["title"],
            "Score": 6.0,
            "Reasoning": f"Headline from {h['source']}: {h['title']}",
            "Source": h["source"],
            "link": h["link"]  # <<< Add this line
        })
    return threats

