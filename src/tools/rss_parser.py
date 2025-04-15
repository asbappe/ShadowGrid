import feedparser

def fetch_rss_headlines():
    feeds = {
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "HackerNews": "https://hnrss.org/frontpage"
    }

    headlines = []
    for source, url in feeds.items():
        parsed = feedparser.parse(url)
        for entry in parsed.entries[:5]:
            headlines.append({
                "title": entry.title,
                "link": entry.link,
                "source": source
            })
    return headlines
