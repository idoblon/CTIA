"""
db_maintenance.py

Database maintenance utilities for the CTI system.
"""

import sqlite3
import json
import csv
import os
from datetime import datetime, timedelta
from typing import Optional
from app.config import DB_PATH, BASE_DIR


def get_conn():
    return sqlite3.connect(DB_PATH)


# ========== Maintenance Functions ==========

def vacuum_database():
    """Vacuum the database to reclaim space and optimize performance."""
    print("[*] Vacuuming database...")
    conn = get_conn()
    conn.execute("VACUUM")
    conn.close()
    print("[+] Database vacuumed successfully")


def rebuild_indexes():
    """Rebuild database indexes for better performance."""
    print("[*] Rebuilding indexes...")
    conn = get_conn()
    cur = conn.cursor()
    
    # Drop existing indexes if they exist
    cur.execute("DROP INDEX IF EXISTS idx_ioc_type")
    cur.execute("DROP INDEX IF EXISTS idx_score")
    cur.execute("DROP INDEX IF EXISTS idx_inserted_at")
    cur.execute("DROP INDEX IF EXISTS idx_value")
    
    # Create indexes
    cur.execute("CREATE INDEX idx_ioc_type ON iocs(ioc_type)")
    cur.execute("CREATE INDEX idx_score ON iocs(score DESC)")
    cur.execute("CREATE INDEX idx_inserted_at ON iocs(inserted_at DESC)")
    cur.execute("CREATE INDEX idx_value ON iocs(value)")
    
    conn.commit()
    conn.close()
    print("[+] Indexes rebuilt successfully")


def get_db_size():
    """Get database file size in MB."""
    if os.path.exists(DB_PATH):
        size_bytes = os.path.getsize(DB_PATH)
        size_mb = size_bytes / (1024 * 1024)
        return size_mb
    return 0


def export_to_csv(output_file: str, limit: Optional[int] = None):
    """Export IOCs to CSV file."""
    print(f"[*] Exporting IOCs to {output_file}...")
    
    conn = get_conn()
    cur = conn.cursor()
    
    query = "SELECT id, ioc_type, value, source, first_seen, inserted_at, score, score_updated_at FROM iocs"
    if limit:
        query += f" LIMIT {limit}"
    
    cur.execute(query)
    rows = cur.fetchall()
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['id', 'ioc_type', 'value', 'source', 'first_seen', 'inserted_at', 'score', 'score_updated_at'])
        writer.writerows(rows)
    
    conn.close()
    print(f"[+] Exported {len(rows)} IOCs to {output_file}")


def export_to_json(output_file: str, limit: Optional[int] = None):
    """Export IOCs to JSON file."""
    print(f"[*] Exporting IOCs to {output_file}...")
    
    conn = get_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    query = "SELECT * FROM iocs"
    if limit:
        query += f" LIMIT {limit}"
    
    cur.execute(query)
    rows = cur.fetchall()
    
    data = []
    for row in rows:
        item = dict(row)
        # Parse metadata JSON
        if item.get('metadata'):
            try:
                item['metadata'] = json.loads(item['metadata'])
            except:
                pass
        data.append(item)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    conn.close()
    print(f"[+] Exported {len(data)} IOCs to {output_file}")


def cleanup_old_iocs(days: int = 90, dry_run: bool = True):
    """
    Remove IOCs older than specified days.
    
    Args:
        days: Remove IOCs older than this many days
        dry_run: If True, only show what would be deleted without actually deleting
    """
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()
    
    conn = get_conn()
    cur = conn.cursor()
    
    # Count IOCs to be deleted
    cur.execute("SELECT COUNT(*) as count FROM iocs WHERE inserted_at < ?", (cutoff,))
    count = cur.fetchone()[0]
    
    if dry_run:
        print(f"[*] DRY RUN: Would delete {count} IOCs older than {days} days (before {cutoff})")
    else:
        cur.execute("DELETE FROM iocs WHERE inserted_at < ?", (cutoff,))
        conn.commit()
        print(f"[+] Deleted {count} IOCs older than {days} days")
    
    conn.close()


def backup_database(backup_dir: Optional[str] = None):
    """Create a backup of the database."""
    if backup_dir is None:
        backup_dir = os.path.join(BASE_DIR, 'backups')
    
    os.makedirs(backup_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(backup_dir, f"cti_backup_{timestamp}.db")
    
    print(f"[*] Creating backup: {backup_file}...")
    
    # Copy database
    import shutil
    shutil.copy2(DB_PATH, backup_file)
    
    print(f"[+] Backup created successfully")
    print(f"    Size: {os.path.getsize(backup_file) / (1024*1024):.2f} MB")


def show_db_info():
    """Show database information."""
    conn = get_conn()
    cur = conn.cursor()
    
    print("\n" + "="*60)
    print("DATABASE INFORMATION")
    print("="*60)
    
    print(f"\nDatabase Path: {DB_PATH}")
    print(f"Database Size: {get_db_size():.2f} MB")
    
    # Table info
    cur.execute("PRAGMA table_info(iocs)")
    columns = cur.fetchall()
    print(f"\nTable: iocs")
    print(f"Columns: {len(columns)}")
    for col in columns:
        print(f"  - {col[1]} ({col[2]})")
    
    # Index info
    cur.execute("PRAGMA index_list(iocs)")
    indexes = cur.fetchall()
    print(f"\nIndexes: {len(indexes)}")
    for idx in indexes:
        print(f"  - {idx[1]}")
    
    # Row count
    cur.execute("SELECT COUNT(*) as count FROM iocs")
    count = cur.fetchone()[0]
    print(f"\nTotal IOCs: {count:,}")
    
    conn.close()
    print("="*60 + "\n")


# ========== CLI ==========

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python -m app.db.db_maintenance <command> [args]")
        print("\nCommands:")
        print("  info                     - Show database information")
        print("  vacuum                   - Vacuum database")
        print("  rebuild_indexes          - Rebuild indexes")
        print("  export_csv <file> [limit] - Export to CSV")
        print("  export_json <file> [limit] - Export to JSON")
        print("  cleanup <days> [--execute] - Remove old IOCs (dry run by default)")
        print("  backup [dir]             - Create database backup")
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    
    if cmd == "info":
        show_db_info()
    
    elif cmd == "vacuum":
        vacuum_database()
    
    elif cmd == "rebuild_indexes":
        rebuild_indexes()
    
    elif cmd == "export_csv" and len(sys.argv) >= 3:
        output_file = sys.argv[2]
        limit = int(sys.argv[3]) if len(sys.argv) >= 4 else None
        export_to_csv(output_file, limit)
    
    elif cmd == "export_json" and len(sys.argv) >= 3:
        output_file = sys.argv[2]
        limit = int(sys.argv[3]) if len(sys.argv) >= 4 else None
        export_to_json(output_file, limit)
    
    elif cmd == "cleanup" and len(sys.argv) >= 3:
        days = int(sys.argv[2])
        dry_run = "--execute" not in sys.argv
        cleanup_old_iocs(days, dry_run)
    
    elif cmd == "backup":
        backup_dir = sys.argv[2] if len(sys.argv) >= 3 else None
        backup_database(backup_dir)
    
    else:
        print("Unknown command or missing arguments")
