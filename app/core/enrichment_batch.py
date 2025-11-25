"""
enrichment_batch.py

Batch enrichment processor for IOCs.
Processes IOCs from the database and enriches them with threat intelligence data.
"""

import sqlite3
import json
import time
from typing import Optional, List, Dict
from app.config import DB_PATH
from app.core.threat_enrichment import enrich_ioc_safe


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_unenriched_iocs(limit: Optional[int] = None, ioc_type: Optional[str] = None) -> List[sqlite3.Row]:
    """
    Get IOCs that haven't been enriched yet (no enrichment data in metadata).
    """
    conn = get_conn()
    cur = conn.cursor()
    
    query = "SELECT * FROM iocs WHERE metadata IS NULL OR metadata = '{}' OR metadata NOT LIKE '%enrichment%'"
    params = []
    
    if ioc_type:
        query += " AND ioc_type = ?"
        params.append(ioc_type)
    
    query += " ORDER BY inserted_at DESC"
    
    if limit:
        query += f" LIMIT {int(limit)}"
    
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def save_enrichment(ioc_value: str, enrichment_data: Dict):
    """
    Save enrichment data to the metadata column for an IOC.
    """
    conn = get_conn()
    cur = conn.cursor()
    
    # Get existing metadata
    cur.execute("SELECT metadata FROM iocs WHERE value = ?", (ioc_value,))
    row = cur.fetchone()
    
    if row:
        try:
            meta = json.loads(row["metadata"] or "{}")
        except:
            meta = {}
        
        # Add enrichment data
        meta["enrichment"] = enrichment_data
        meta["enriched_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        
        # Update database
        cur.execute("UPDATE iocs SET metadata = ? WHERE value = ?", 
                   (json.dumps(meta), ioc_value))
        conn.commit()
    
    conn.close()


def enrich_batch(limit: Optional[int] = 100, ioc_type: Optional[str] = None, delay: float = 1.5):
    """
    Enrich a batch of IOCs.
    
    Args:
        limit: Maximum number of IOCs to enrich
        ioc_type: Filter by IOC type (ip, domain, hash, url)
        delay: Delay between enrichments in seconds (for rate limiting)
    """
    print(f"[*] Fetching unenriched IOCs (limit={limit}, type={ioc_type})...")
    iocs = get_unenriched_iocs(limit=limit, ioc_type=ioc_type)
    
    if not iocs:
        print("[!] No unenriched IOCs found.")
        return
    
    print(f"[*] Found {len(iocs)} IOCs to enrich")
    print(f"[*] Rate limit delay: {delay}s between requests")
    
    enriched_count = 0
    error_count = 0
    
    for i, ioc in enumerate(iocs):
        ioc_value = ioc["value"]
        ioc_type_val = ioc["ioc_type"]
        
        print(f"[{i+1}/{len(iocs)}] Enriching {ioc_type_val}: {ioc_value[:50]}...")
        
        try:
            enrichment = enrich_ioc_safe(ioc_value, ioc_type_val)
            
            # Check if enrichment was successful
            if "error" in enrichment:
                print(f"    [!] Error: {enrichment['error']}")
                error_count += 1
            else:
                # Count successful enrichments
                sources = []
                if "vt" in enrichment and "vt_error" not in enrichment:
                    sources.append("virustotal")
                if "abuseip" in enrichment and "abuseip_error" not in enrichment:
                    sources.append("abuseipdb")
                if "otx" in enrichment and "otx_error" not in enrichment:
                    sources.append("otx")
                
                if sources:
                    print(f"    [+] Enriched from: {', '.join(sources)}")
                    enriched_count += 1
                else:
                    print(f"    [!] No enrichment data available")
                    error_count += 1
            
            # Save enrichment data
            save_enrichment(ioc_value, enrichment)
            
            # Rate limiting
            if i < len(iocs) - 1:  # Don't delay after last item
                time.sleep(delay)
                
        except Exception as e:
            print(f"    [!] Exception: {str(e)}")
            error_count += 1
            continue
    
    print(f"\n[+] Enrichment complete!")
    print(f"    Enriched: {enriched_count}")
    print(f"    Errors: {error_count}")
    print(f"    Total processed: {len(iocs)}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m app.core.enrichment_batch <limit> [ioc_type]")
        print("Example: python -m app.core.enrichment_batch 50 ip")
        print("Example: python -m app.core.enrichment_batch 100")
        sys.exit(1)
    
    limit = int(sys.argv[1])
    ioc_type = sys.argv[2] if len(sys.argv) >= 3 else None
    
    enrich_batch(limit=limit, ioc_type=ioc_type)
