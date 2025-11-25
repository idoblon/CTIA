#!/usr/bin/env python3
"""
cti_initial.py

Initial-phase Cyber Threat Intelligence automation:
- Project scaffolding + SQLite storage
- Feed fetcher (HTTP) for public feeds
- IOC extraction (IP, domain, URL, MD5/SHA1/SHA256)
- Normalization, deduplication, and storage
- Simple CLI: fetch, list, export

Usage:
    python cti_initial.py fetch        # fetch all configured feeds and ingest IOCs
    python cti_initial.py list [type]  # list IOCs in DB; optional type: ip|domain|url|hash
    python cti_initial.py export file.csv  # export DB to CSV

Notes:
- This is Phase 1: collection + storage + parsing.
- Add feed URLs to FEEDS list or configure via environment / config file in future.
"""

import os
import re
import sys
import csv
import json
import sqlite3
import logging
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Iterable, Tuple
import requests
from dateutil import parser as dparser
from tqdm import tqdm

# -------------------------
# Configuration / Constants
# -------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
DB_PATH = os.path.join(DATA_DIR, "cti.db")
LOG_PATH = os.path.join(PROJECT_ROOT, "cti.log")

# public example feeds (plain text / csv / ip blocklists). Add or replace as needed.
FEEDS = [
    # Feodo Tracker IP blocklist (public)
    "https://feodotracker.abuse.ch/blocklist.php?download=ipblocklist",
    # Abuse.ch URLhaus: distribution URL (text)
    "https://urlhaus.abuse.ch/downloads/csv/",
    # Abuse.ch blocklist for malware domains (example)
    "https://mirror.cedia.org.ec/malwaredomains/justdomains",
    # Optional: add more plain-text feeds or CSVs; API-based feeds need keys and specialized handling
]

# Setup logging
logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
console.setFormatter(formatter)
logging.getLogger("").addHandler(console)

# -------------------------
# Regex patterns for IOCs
# -------------------------
RE_IP = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")
RE_DOMAIN = re.compile(
    r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63})\b"
)
RE_URL = re.compile(
    r"\b(?:https?://|http?://)?(?:[A-Za-z0-9\-\.]+)(?:\.[A-Za-z]{2,63})(?:[:/\?\#][^\s]*)?\b"
)
RE_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

HASH_PATTERNS = [("sha256", RE_SHA256), ("sha1", RE_SHA1), ("md5", RE_MD5)]


# -------------------------
# Database helpers
# -------------------------
def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


def get_db_conn():
    ensure_data_dir()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if not exist."""
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS ioc (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc TEXT NOT NULL,
            type TEXT NOT NULL,    -- ip, domain, url, hash
            hash_algo TEXT,        -- md5/sha1/sha256 for type=hash
            first_seen TEXT,       -- ISO datetime when inserted
            last_seen TEXT,        -- ISO datetime when updated
            sources TEXT           -- JSON list of source URLs
        );
        """
    )
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_ioc_type ON ioc(ioc, type, hash_algo);")
    conn.commit()
    conn.close()


def upsert_ioc(ioc: str, ioc_type: str, source: str, hash_algo: str = None) -> None:
    """Insert or update an IOC record with source and timestamps."""
    now = datetime.utcnow().isoformat()
    conn = get_db_conn()
    cur = conn.cursor()

    # Try update
    cur.execute(
        "SELECT id, sources FROM ioc WHERE ioc=? AND type=? AND (hash_algo IS ? OR hash_algo=?)",
        (ioc, ioc_type, None if hash_algo is None else hash_algo, hash_algo),
    )
    row = cur.fetchone()
    if row:
        existing_sources = json.loads(row["sources"]) if row["sources"] else []
        if source not in existing_sources:
            existing_sources.append(source)
        cur.execute(
            "UPDATE ioc SET last_seen=?, sources=? WHERE id=?",
            (now, json.dumps(existing_sources), row["id"]),
        )
    else:
        cur.execute(
            "INSERT INTO ioc (ioc, type, hash_algo, first_seen, last_seen, sources) VALUES (?,?,?,?,?,?)",
            (ioc, ioc_type, hash_algo, now, now, json.dumps([source])),
        )
    conn.commit()
    conn.close()


# -------------------------
# Extraction / Normalization
# -------------------------
def extract_iocs_from_text(text: str) -> List[Tuple[str, str, str]]:
    """
    Return list of tuples: (ioc, type, hash_algo)
    type: ip|domain|url|hash
    hash_algo: None or md5/sha1/sha256
    """
    found = []

    if not text:
        return found

    # URLs first (so domains inside URLs are not double-captured)
    for m in RE_URL.finditer(text):
        url = m.group(0).strip(" ,;\"'()[]")
        # basic normalization: ensure scheme if missing
        if url.startswith("http://") or url.startswith("https://"):
            normalized = url
        else:
            # treat as URL if contains slash after domain
            if "/" in url:
                normalized = "http://" + url
            else:
                normalized = url
        found.append((normalized, "url", None))

    # IPs
    for m in RE_IP.finditer(text):
        ip = m.group(0)
        found.append((ip, "ip", None))

    # Domains (exclude domains that are part of URLs we've already captured)
    urls = {u for (u, t, h) in found if t == "url"}
    domains_in_urls = set()
    for u in urls:
        try:
            hostname = urlparse(u).hostname
            if hostname:
                domains_in_urls.add(hostname)
        except Exception:
            pass

    for m in RE_DOMAIN.finditer(text):
        dom = m.group(1).lower()
        if dom not in domains_in_urls:
            found.append((dom, "domain", None))

    # Hashes (sha256, sha1, md5)
    for algo, regex in HASH_PATTERNS:
        for m in regex.finditer(text):
            found.append((m.group(0).lower(), "hash", algo))

    # Deduplicate keeping order
    seen = set()
    deduped = []
    for ioc, typ, algo in found:
        key = (ioc, typ, algo)
        if key not in seen:
            seen.add(key)
            deduped.append((ioc, typ, algo))
    return deduped


# -------------------------
# Feed Fetcher
# -------------------------
def fetch_text(url: str, timeout=20) -> Tuple[str, Dict]:
    """
    Fetch URL and return (text, meta) where meta includes: status_code, content_type, final_url
    """
    logging.info(f"Fetching {url}")
    headers = {"User-Agent": "cti-initial/1.0 (+https://example.local)"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        content_type = resp.headers.get("Content-Type", "")
        return resp.text, {"status_code": resp.status_code, "content_type": content_type, "final_url": resp.url}
    except requests.RequestException as e:
        logging.error(f"Failed to fetch {url}: {e}")
        return "", {"status_code": None, "error": str(e), "final_url": url}


def ingest_feed(url: str):
    text, meta = fetch_text(url)
    if not text:
        logging.warning(f"No content from {url}")
        return 0

    # Some feeds are CSVs - try simple cleaning
    lines = []
    if "\r\n" in text or "\n" in text:
        # Basic heuristic: split lines and remove comment lines starting with # or ;
        for raw in text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#") or line.startswith(";"):
                continue
            lines.append(line)
    else:
        lines = [text.strip()]

    total = 0
    for ln in lines:
        iocs = extract_iocs_from_text(ln)
        for ioc, typ, algo in iocs:
            upsert_ioc(ioc, typ, url, hash_algo=algo)
            total += 1
    logging.info(f"Ingested {total} IOCs from {url}")
    return total


# -------------------------
# Utilities: listing / export
# -------------------------
def list_iocs(ioc_type: str = None, limit: int = 200):
    conn = get_db_conn()
    cur = conn.cursor()
    if ioc_type:
        cur.execute("SELECT * FROM ioc WHERE type=? ORDER BY last_seen DESC LIMIT ?", (ioc_type, limit))
    else:
        cur.execute("SELECT * FROM ioc ORDER BY last_seen DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    return rows


def export_csv(outfile: str):
    rows = list_iocs(None, limit=1000000)
    with open(outfile, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ioc", "type", "hash_algo", "first_seen", "last_seen", "sources"])
        for r in rows:
            writer.writerow([r["ioc"], r["type"], r["hash_algo"], r["first_seen"], r["last_seen"], r["sources"]])
    logging.info(f"Exported {len(rows)} rows to {outfile}")


# -------------------------
# Main CLI
# -------------------------
def cmd_fetch():
    init_db()
    total_all = 0
    for feed in FEEDS:
        try:
            added = ingest_feed(feed)
            total_all += added
        except Exception as e:
            logging.exception(f"Error ingesting {feed}: {e}")
    logging.info(f"Total IOCs ingested this run: {total_all}")
    print(f"Total IOCs ingested: {total_all}")


def cmd_list(ioc_type: str = None):
    init_db()
    rows = list_iocs(ioc_type, limit=1000)
    if not rows:
        print("No IOCs found.")
        return
    print(f"{'IOC':<60} {'TYPE':<8} {'ALGO':<7} {'FIRST_SEEN':<20} {'SOURCES'}")
    print("-" * 120)
    for r in rows:
        sources = json.loads(r["sources"]) if r["sources"] else []
        print(f"{r['ioc']:<60.60} {r['type']:<8} {str(r['hash_algo'] or ''):<7} {r['first_seen']:<20} {', '.join(sources)[:60]}")


def cmd_export(path: str):
    init_db()
    export_csv(path)
    print(f"Exported DB to {path}")


def usage():
    print("Usage:")
    print("  python cti_initial.py fetch")
    print("  python cti_initial.py list [ip|domain|url|hash]")
    print("  python cti_initial.py export out.csv")
    sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
    action = sys.argv[1].lower()
    if action == "fetch":
        cmd_fetch()
    elif action == "list":
        typ = None
        if len(sys.argv) >= 3:
            t = sys.argv[2].lower()
            if t in ("ip", "domain", "url", "hash"):
                typ = t
        cmd_list(typ)
    elif action == "export":
        if len(sys.argv) != 3:
            usage()
        cmd_export(sys.argv[2])
    else:
        usage()
