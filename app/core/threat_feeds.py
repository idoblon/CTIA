import os
import requests
from datetime import datetime
from tqdm import tqdm


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, '..', 'raw_feeds')
RAW_DIR = os.path.abspath(RAW_DIR)
os.makedirs(RAW_DIR, exist_ok=True)


FEEDS = {
    'feodotracker': 'https://feodotracker.abuse.ch/blocklist.php?download=ipblocklist',
    'urlhaus_csv': 'https://urlhaus.abuse.ch/downloads/csv/',
    'malwaredomains': 'https://mirror.cedia.org.ec/malwaredomains/justdomains'
}


HEADERS = {'User-Agent': 'ctia-fetcher/1.0'}




def fetch_feed(name, url, timeout=20):
    try:
        r = requests.get(url, headers=HEADERS, timeout=timeout)
        r.raise_for_status()
        text = r.text
        out = os.path.join(RAW_DIR, f"{name}.txt")
        with open(out, 'w', encoding='utf-8') as fh:
            fh.write(text)
        return out
    except Exception as e:
        print(f"Failed fetching {name}: {e}")
        return None




def fetch_all_feeds():
    print('Fetching feeds...')
    total = 0
    for name, url in FEEDS.items():
        out = fetch_feed(name, url)
        if out:
            print(f"Saved {out}")
            total += 1
    print(f"Fetched {total} feeds")
    return total