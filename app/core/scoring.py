"""
scoring.py

Phase 5: Threat scoring and prioritization engine.

Usage examples:
    python -m app.core.scoring score_all             # score all IOCs in DB
    python -m app.core.scoring top 50                # show top 50 prioritized IOCs
    python -m app.core.scoring score_one <ioc_value> # score a single IOC (value must match DB)
"""

import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from app.config import DB_PATH

# ---------- Scoring parameters (tune as needed) ----------
WEIGHTS = {
    "vt_positive": 8.0,        # per positive engine (hash)
    "abuseipdb": 0.4,         # abuse score multiplier (IP)
    "local_severity": 6.0,    # local correlation severity multiplier
    "feed_count": 4.0,        # number of feeds that observed this IOC
}

MAX_SCORE = 100

# ---------- DB helpers ----------
def get_conn(path: str = DB_PATH):
    if not os.path.exists(path):
        raise FileNotFoundError(f"DB not found at {path}")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn

def ensure_score_columns():
    """
    Add columns to store score and timestamp if they don't exist.
    """
    conn = get_conn()
    cur = conn.cursor()
    # Add columns if not present
    cur.execute("PRAGMA table_info(iocs)")
    cols = [r["name"] for r in cur.fetchall()]
    if "score" not in cols:
        cur.execute("ALTER TABLE iocs ADD COLUMN score INTEGER DEFAULT 0")
    if "score_updated_at" not in cols:
        cur.execute("ALTER TABLE iocs ADD COLUMN score_updated_at TEXT DEFAULT NULL")
    if "metadata" not in cols:
        # metadata: optional JSON column to store enrichment payloads or feed list
        cur.execute("ALTER TABLE iocs ADD COLUMN metadata TEXT DEFAULT NULL")
    conn.commit()
    conn.close()

# ---------- Scoring function ----------
def compute_score(enrichment: Dict[str, Any], meta: Optional[Dict[str,Any]] = None) -> int:
    """
    Compute a score from an enrichment dict and optional metadata.
    enrichment: dictionary with keys depending on IOC type, e.g.:
      - enrichment["vt"]["malicious_count"]
      - enrichment["abuseip"]["abuse_score"]
      - enrichment["otx"]["pulse_count"]
      - enrichment["correlation"]["severity"]
    meta: optional metadata like feed_count (how many feeds reported this IOC)
    Returns integer score [0..MAX_SCORE]
    """
    score = 0.0
    # VirusTotal
    try:
        vt = enrichment.get("vt")
        if vt and isinstance(vt, dict):
            positives = int(vt.get("malicious_count", 0))
            score += positives * WEIGHTS["vt_positive"]
    except Exception:
        pass

    # AbuseIPDB
    try:
        abuse = enrichment.get("abuseip")
        if abuse and isinstance(abuse, dict):
            abuse_score = float(abuse.get("abuse_score", 0.0))
            # normalize 0-100 scale * multiplier
            score += abuse_score * WEIGHTS["abuseipdb"]
    except Exception:
        pass

    # Local correlation severity
    try:
        corr = enrichment.get("correlation")
        if corr and isinstance(corr, dict):
            local_sev = float(corr.get("severity", 0.0))
            score += local_sev * WEIGHTS["local_severity"]
    except Exception:
        pass

    # feed count metadata (how many feeds observed this IOC)
    feed_count = 0
    if meta and "feed_count" in meta:
        try:
            feed_count = int(meta.get("feed_count", 0))
            score += feed_count * WEIGHTS["feed_count"]
        except Exception:
            pass
    else:
        # Try to derive feed_count from stored metadata if present
        if meta and "sources" in meta:
            try:
                feed_count = len(meta.get("sources") or [])
                score += feed_count * WEIGHTS["feed_count"]
            except Exception:
                pass

    # post-processing and caps
    if score < 0:
        score = 0.0
    if score > MAX_SCORE:
        score = float(MAX_SCORE)

    return int(round(score))

# ---------- Utility: label from score ----------
def label_from_score(score: int) -> str:
    if score >= 75:
        return "malicious"
    if score >= 50:
        return "suspicious"
    if score >= 25:
        return "low"
    return "informational"

# ---------- DB integration: score single IOC ----------
def score_ioc_row(row: sqlite3.Row) -> Dict[str,Any]:
    """
    Given a DB row (from iocs table), attempt to read 'metadata' JSON which should contain previous enrichment info.
    Compute score and return a dict with details for DB update.
    """
    value = row["value"]
    meta_json = row.get("metadata") or "{}"
    try:
        meta = json.loads(meta_json)
    except Exception:
        meta = {}

    # enrichment payload expected under meta['enrichment'] if you stored it previously
    enrichment = meta.get("enrichment", {}) if isinstance(meta, dict) else {}

    # compute score using enrichment + meta
    computed = compute_score(enrichment, meta)
    label = label_from_score(computed)
    return {
        "value": value,
        "score": computed,
        "label": label,
        "score_updated_at": datetime.now(timezone.utc).isoformat(),
        "meta": meta
    }

def update_score_in_db(value: str, score: int, updated_at: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("UPDATE iocs SET score=?, score_updated_at=? WHERE value=?", (score, updated_at, value))
    conn.commit()
    conn.close()

# ---------- Batch scoring ----------
def score_all_iocs(limit: Optional[int] = None):
    ensure_score_columns()
    conn = get_conn()
    cur = conn.cursor()
    query = "SELECT * FROM iocs ORDER BY inserted_at DESC"
    if limit:
        query += f" LIMIT {int(limit)}"
    cur.execute(query)
    rows = cur.fetchall()
    total = 0
    print(f"[*] Scoring {len(rows)} IOCs...")
    for i, r in enumerate(rows):
        res = score_ioc_row(r)
        update_score_in_db(res["value"], res["score"], res["score_updated_at"])
        total += 1
        if (i + 1) % 1000 == 0:
            print(f"[*] Scored {i + 1}/{len(rows)} IOCs...")
    conn.close()
    print(f"[+] Scored {total} IOCs")

# ---------- Query top N ----------
def top_n(n: int = 50):
    ensure_score_columns()
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT value, ioc_type, score, score_updated_at, metadata FROM iocs ORDER BY score DESC, score_updated_at DESC LIMIT ?", (n,))
    rows = cur.fetchall()
    conn.close()
    return rows

# ---------- CLI ----------
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m app.core.scoring score_all | top <N> | score_one <IOC_VALUE>")
        sys.exit(1)
    cmd = sys.argv[1].lower()
    if cmd == "score_all":
        score_all_iocs()
    elif cmd == "top":
        n = 50
        if len(sys.argv) >= 3:
            try:
                n = int(sys.argv[2])
            except:
                pass
        rows = top_n(n)
        print(f"\n{'VALUE':<40} {'TYPE':<8} {'SCORE':<6} {'LABEL':<15} {'UPDATED':<25}")
        print("-" * 100)
        for r in rows:
            meta = {}
            try:
                meta = json.loads(r["metadata"] or "{}")
            except:
                pass
            label = label_from_score(r['score'])
            print(f"{r['value']:<40} {r['ioc_type']:<8} {r['score']:<6} {label:<15} {r['score_updated_at'] or 'N/A':<25}")
    elif cmd == "score_one" and len(sys.argv) >= 3:
        val = sys.argv[2]
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM iocs WHERE value=?", (val,))
        r = cur.fetchone()
        conn.close()
        if not r:
            print("IOC not found in DB.")
            sys.exit(2)
        res = score_ioc_row(r)
        update_score_in_db(res["value"], res["score"], res["score_updated_at"])
        print(f"Scored {res['value']}: {res['score']} label={res['label']}")
    else:
        print("Unknown command")
