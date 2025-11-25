import requests
import os
from dotenv import load_dotenv

load_dotenv()

# Example public threat feeds
THREAT_FEEDS = {
    "blocklist_de": "https://lists.blocklist.de/lists/all.txt",
    "emerging_threats": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "abuse_ch_malware": "https://urlhaus.abuse.ch/downloads/text/"
}

def fetch_feed(name, url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        print(f"[+] Fetched: {name} ({len(response.text.splitlines())} entries)")
        return response.text
    except Exception as e:
        print(f"[!] Error fetching {name}: {e}")
        return ""
