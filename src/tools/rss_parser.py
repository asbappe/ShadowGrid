import feedparser

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
            feed = feedparser.parse(url)
            for entry in feed.entries[:5]:  # Limit to top 5 per feed
                headlines.append({
                    "title": entry.title,
                    "link": entry.link,
                    "source": name
                })
        except Exception as e:
            print(f"Failed to parse feed: {name} ({url}) - {e}")
    return headlines
