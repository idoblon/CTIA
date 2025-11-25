import os
import json
import re
from urllib.parse import urlparse

# Directory setup
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, '..', 'raw_feeds')
RAW_DIR = os.path.abspath(RAW_DIR)
NORM_DIR = os.path.join(BASE_DIR, '..', 'normalized_feeds')
NORM_DIR = os.path.abspath(NORM_DIR)
os.makedirs(NORM_DIR, exist_ok=True)


# Regex patterns for IOC extraction
RE_IP = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
RE_DOMAIN = re.compile(r'\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)
RE_URL = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)

# Hash patterns (MD5, SHA1, SHA256)
HASH_PATTERNS = [
    ('md5', re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE)),
    ('sha1', re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE)),
    ('sha256', re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE))
]


def extract_iocs_from_text(text):
    """
    Extract IOCs (IPs, domains, URLs, hashes) from text.
    Returns a list of dicts with 'type', 'value', and 'hash_algo' keys.
    """
    found = []
    
    # Extract URLs first
    for m in RE_URL.finditer(text):
        url = m.group(0).strip(' ,;"\'()')
        found.append((url, 'url', None))
    
    # Extract IPs
    for m in RE_IP.finditer(text):
        found.append((m.group(0), 'ip', None))
    
    # Extract domains (but avoid duplicates from URLs)
    urls = {u for (u, t, h) in found if t == 'url'}
    domains_in_urls = set()
    for u in urls:
        try:
            hostname = urlparse(u).hostname
            if hostname:
                domains_in_urls.add(hostname)
        except Exception:
            pass
    
    for m in RE_DOMAIN.finditer(text):
        dom = m.group(0).lower()
        if dom not in domains_in_urls:
            found.append((dom, 'domain', None))
    
    # Extract hashes
    for algo, regex in HASH_PATTERNS:
        for m in regex.finditer(text):
            found.append((m.group(0).lower(), 'hash', algo))
    
    # Deduplicate
    seen = set()
    deduped = []
    for ioc, typ, algo in found:
        key = (ioc, typ, algo)
        if key not in seen:
            seen.add(key)
            deduped.append({'type': typ, 'value': ioc, 'hash_algo': algo})
    
    return deduped


def normalize_file(path):
    """
    Read a raw feed file and extract all IOCs from it.
    Returns a list of IOC dicts.
    """
    with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
        lines = fh.read().splitlines()
    
    out = []
    for ln in lines:
        ln = ln.strip()
        # Skip empty lines and comments
        if not ln or ln.startswith('#') or ln.startswith(';'):
            continue
        out.extend(extract_iocs_from_text(ln))
    
    return out


def normalize_all_feeds():
    """
    Process all .txt files in RAW_DIR and save normalized JSON files to NORM_DIR.
    """
    if not os.path.exists(RAW_DIR):
        print(f"Raw feeds directory not found: {RAW_DIR}")
        return False
    
    files = [f for f in os.listdir(RAW_DIR) if f.endswith('.txt')]
    
    if not files:
        print(f"No .txt files found in {RAW_DIR}")
        return False
    
    for f in files:
        p = os.path.join(RAW_DIR, f)
        items = normalize_file(p)
        outp = os.path.join(NORM_DIR, f.replace('.txt', '.json'))
        
        with open(outp, 'w', encoding='utf-8') as fh:
            json.dump(items, fh, indent=2)
        
        print(f"Normalized {p} -> {outp} ({len(items)} IOCs)")
    
    return True