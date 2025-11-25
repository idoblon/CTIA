"""
db_queries.py

Utility module with common database queries for the CTI system.
"""

import sqlite3
import json
from typing import List, Dict, Optional, Tuple
from datetime import datetime, timedelta
from app.config import DB_PATH


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ========== Query Functions ==========

def get_iocs_by_type(ioc_type: str, limit: int = 100) -> List[Dict]:
    """Get IOCs filtered by type."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM iocs WHERE ioc_type = ? ORDER BY inserted_at DESC LIMIT ?", 
               (ioc_type, limit))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_iocs_by_score_range(min_score: int, max_score: int = 100, limit: int = 100) -> List[Dict]:
    """Get IOCs within a score range."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""SELECT * FROM iocs 
                   WHERE score >= ? AND score <= ? 
                   ORDER BY score DESC, inserted_at DESC 
                   LIMIT ?""", 
               (min_score, max_score, limit))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recent_iocs(days: int = 7, limit: int = 100) -> List[Dict]:
    """Get IOCs added in the last N days."""
    conn = get_conn()
    cur = conn.cursor()
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    cur.execute("""SELECT * FROM iocs 
                   WHERE inserted_at >= ? 
                   ORDER BY inserted_at DESC 
                   LIMIT ?""", 
               (cutoff, limit))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_enriched_iocs(limit: int = 100) -> List[Dict]:
    """Get IOCs that have been enriched."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""SELECT * FROM iocs 
                   WHERE metadata IS NOT NULL 
                   AND metadata != '{}' 
                   AND metadata LIKE '%enrichment%'
                   ORDER BY inserted_at DESC 
                   LIMIT ?""", 
               (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_unenriched_iocs(limit: int = 100) -> List[Dict]:
    """Get IOCs that haven't been enriched yet."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""SELECT * FROM iocs 
                   WHERE metadata IS NULL 
                   OR metadata = '{}' 
                   OR metadata NOT LIKE '%enrichment%'
                   ORDER BY inserted_at DESC 
                   LIMIT ?""", 
               (limit,))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def search_iocs(search_term: str, limit: int = 100) -> List[Dict]:
    """Search IOCs by value (substring match)."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""SELECT * FROM iocs 
                   WHERE value LIKE ? 
                   ORDER BY score DESC, inserted_at DESC 
                   LIMIT ?""", 
               (f"%{search_term}%", limit))
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# ========== Statistics Functions ==========

def get_statistics() -> Dict:
    """Get comprehensive database statistics."""
    conn = get_conn()
    cur = conn.cursor()
    
    stats = {}
    
    # Total IOCs
    cur.execute("SELECT COUNT(*) as total FROM iocs")
    stats['total_iocs'] = cur.fetchone()['total']
    
    # IOCs by type
    cur.execute("SELECT ioc_type, COUNT(*) as count FROM iocs GROUP BY ioc_type")
    stats['by_type'] = {row['ioc_type']: row['count'] for row in cur.fetchall()}
    
    # Score distribution
    cur.execute("""SELECT 
                    SUM(CASE WHEN score >= 75 THEN 1 ELSE 0 END) as malicious,
                    SUM(CASE WHEN score >= 50 AND score < 75 THEN 1 ELSE 0 END) as suspicious,
                    SUM(CASE WHEN score >= 25 AND score < 50 THEN 1 ELSE 0 END) as low,
                    SUM(CASE WHEN score < 25 THEN 1 ELSE 0 END) as informational
                   FROM iocs""")
    row = cur.fetchone()
    stats['by_severity'] = {
        'malicious': row['malicious'] or 0,
        'suspicious': row['suspicious'] or 0,
        'low': row['low'] or 0,
        'informational': row['informational'] or 0
    }
    
    # Enrichment status
    cur.execute("""SELECT 
                    SUM(CASE WHEN metadata IS NOT NULL AND metadata != '{}' AND metadata LIKE '%enrichment%' THEN 1 ELSE 0 END) as enriched,
                    SUM(CASE WHEN metadata IS NULL OR metadata = '{}' OR metadata NOT LIKE '%enrichment%' THEN 1 ELSE 0 END) as unenriched
                   FROM iocs""")
    row = cur.fetchone()
    stats['enrichment'] = {
        'enriched': row['enriched'] or 0,
        'unenriched': row['unenriched'] or 0
    }
    
    # Sources
    cur.execute("SELECT source, COUNT(*) as count FROM iocs GROUP BY source")
    stats['by_source'] = {row['source']: row['count'] for row in cur.fetchall()}
    
    # Recent activity (last 7 days)
    cutoff = (datetime.now() - timedelta(days=7)).isoformat()
    cur.execute("SELECT COUNT(*) as count FROM iocs WHERE inserted_at >= ?", (cutoff,))
    stats['recent_7days'] = cur.fetchone()['count']
    
    conn.close()
    return stats


def print_statistics():
    """Print formatted statistics."""
    stats = get_statistics()
    
    print("\n" + "="*60)
    print("CTI DATABASE STATISTICS")
    print("="*60)
    
    print(f"\nTotal IOCs: {stats['total_iocs']:,}")
    
    print("\nBy Type:")
    for ioc_type, count in sorted(stats['by_type'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {ioc_type:<10}: {count:>10,}")
    
    print("\nBy Severity:")
    for severity, count in stats['by_severity'].items():
        print(f"  {severity:<15}: {count:>10,}")
    
    print("\nEnrichment Status:")
    for status, count in stats['enrichment'].items():
        print(f"  {status:<15}: {count:>10,}")
    
    print("\nBy Source:")
    for source, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {source:<20}: {count:>10,}")
    
    print(f"\nRecent Activity (7 days): {stats['recent_7days']:,}")
    print("="*60 + "\n")


# ========== CLI ==========

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m app.db.db_queries <command> [args]")
        print("\nCommands:")
        print("  stats                    - Show database statistics")
        print("  type <type> [limit]      - Get IOCs by type")
        print("  score <min> <max> [limit] - Get IOCs by score range")
        print("  recent [days] [limit]    - Get recent IOCs")
        print("  enriched [limit]         - Get enriched IOCs")
        print("  unenriched [limit]       - Get unenriched IOCs")
        print("  search <term> [limit]    - Search IOCs")
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    
    if cmd == "stats":
        print_statistics()
    
    elif cmd == "type" and len(sys.argv) >= 3:
        ioc_type = sys.argv[2]
        limit = int(sys.argv[3]) if len(sys.argv) >= 4 else 100
        iocs = get_iocs_by_type(ioc_type, limit)
        print(f"\nFound {len(iocs)} IOCs of type '{ioc_type}':")
        for ioc in iocs[:10]:  # Show first 10
            print(f"  {ioc['value'][:60]} (score: {ioc.get('score', 0)})")
    
    elif cmd == "score" and len(sys.argv) >= 4:
        min_score = int(sys.argv[2])
        max_score = int(sys.argv[3])
        limit = int(sys.argv[4]) if len(sys.argv) >= 5 else 100
        iocs = get_iocs_by_score_range(min_score, max_score, limit)
        print(f"\nFound {len(iocs)} IOCs with score {min_score}-{max_score}:")
        for ioc in iocs[:10]:
            print(f"  {ioc['value'][:60]} (score: {ioc.get('score', 0)})")
    
    elif cmd == "recent":
        days = int(sys.argv[2]) if len(sys.argv) >= 3 else 7
        limit = int(sys.argv[3]) if len(sys.argv) >= 4 else 100
        iocs = get_recent_iocs(days, limit)
        print(f"\nFound {len(iocs)} IOCs from last {days} days:")
        for ioc in iocs[:10]:
            print(f"  {ioc['value'][:60]} ({ioc['inserted_at']})")
    
    elif cmd == "enriched":
        limit = int(sys.argv[2]) if len(sys.argv) >= 3 else 100
        iocs = get_enriched_iocs(limit)
        print(f"\nFound {len(iocs)} enriched IOCs:")
        for ioc in iocs[:10]:
            print(f"  {ioc['value'][:60]} (score: {ioc.get('score', 0)})")
    
    elif cmd == "unenriched":
        limit = int(sys.argv[2]) if len(sys.argv) >= 3 else 100
        iocs = get_unenriched_iocs(limit)
        print(f"\nFound {len(iocs)} unenriched IOCs:")
        for ioc in iocs[:10]:
            print(f"  {ioc['value'][:60]}")
    
    elif cmd == "search" and len(sys.argv) >= 3:
        term = sys.argv[2]
        limit = int(sys.argv[3]) if len(sys.argv) >= 4 else 100
        iocs = search_iocs(term, limit)
        print(f"\nFound {len(iocs)} IOCs matching '{term}':")
        for ioc in iocs[:10]:
            print(f"  {ioc['value'][:60]} (score: {ioc.get('score', 0)})")
    
    else:
        print("Unknown command or missing arguments")
