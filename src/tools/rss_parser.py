import feedparser
import requests

def fetch_rss_headlines():
    feeds = {
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "HackerNews": "https://hnrss.org/frontpage",
        "DarkReading": "https://www.darkreading.com/rss.xml",
        "Threatpost": "https://feeds.feedburner.com/Threatpost",
        "Schneier on Security": "https://www.schneier.com/feed/atom/",
        "CISA News": "https://www.cisa.gov/news.xml",
        "US-CERT": "https://us-cert.cisa.gov/ncas/all.xml",
        "Cisco Talos": "https://blog.talosintelligence.com/feeds/posts/default",
        "Kaspersky Securelist": "https://securelist.com/feed/",
        "Recorded Future": "https://www.recordedfuture.com/blog/rss",
        "Palo Alto Unit 42": "https://unit42.paloaltonetworks.com/feed/",
        "McAfee Blogs": "https://www.mcafee.com/blogs/feed/",
        "Trend Micro": "https://www.trendmicro.com/en_us/rss/enterprise.html"
    }

    headlines = []
    for name, url in feeds.items():
        try:
            response = requests.get(url, timeout=5)  # Add timeout here
            feed = feedparser.parse(response.content)
            for entry in feed.entries[:5]:
                headlines.append({
                    "title": entry.title,
                    "link": entry.link,
                    "source": name
                })
        except Exception as e:
            print(f"[!] Failed to load feed from {name} ({url}): {e}")
    return headlines
