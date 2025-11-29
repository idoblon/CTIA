"""
automation/tasks.py

Automated tasks for CTIA system.
These tasks are scheduled by the scheduler to run periodically.
"""

import sys
import os
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.threat_feeds import fetch_all_feeds
from app.core.normalizer import normalize_all_feeds
from app.db.database import initialize_database, ingest_normalized
from app.core.enrichment_batch import enrich_batch
from app.core.scoring import score_all_iocs
from app.db.db_maintenance import vacuum_database, rebuild_indexes
from app.config import DB_PATH


def log_task_start(task_name):
    """Log task start with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'='*60}")
    print(f"[{timestamp}] Starting task: {task_name}")
    print(f"{'='*60}")


def log_task_end(task_name, success=True, error=None):
    """Log task completion with timestamp."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "✓ COMPLETED" if success else "✗ FAILED"
    print(f"[{timestamp}] Task {status}: {task_name}")
    if error:
        print(f"Error: {error}")
    print(f"{'='*60}\n")


def task_collect_feeds():
    """
    Automated task: Collect threat feeds, normalize, and ingest to database.
    Runs daily at scheduled time.
    """
    task_name = "Collect Threat Feeds"
    log_task_start(task_name)
    
    try:
        # Fetch feeds
        print("[*] Fetching threat feeds...")
        feed_count = fetch_all_feeds()
        
        # Normalize feeds
        print("[*] Normalizing IOCs...")
        normalize_all_feeds()
        
        # Initialize database (if needed)
        print("[*] Initializing database...")
        initialize_database()
        
        # Ingest normalized data
        print("[*] Ingesting to database...")
        ingest_normalized()
        
        log_task_end(task_name, success=True)
        return True
        
    except Exception as e:
        log_task_end(task_name, success=False, error=str(e))
        return False


def task_enrich_iocs(limit=50):
    """
    Automated task: Enrich unenriched IOCs.
    
    Args:
        limit: Number of IOCs to enrich per run (default: 50)
    """
    task_name = f"Enrich IOCs (limit={limit})"
    log_task_start(task_name)
    
    try:
        print(f"[*] Enriching up to {limit} IOCs...")
        
        # Enrich IPs
        print("\n[*] Enriching IPs...")
        enrich_batch(limit=limit//2, ioc_type='ip', delay=1.5)
        
        # Enrich domains
        print("\n[*] Enriching domains...")
        enrich_batch(limit=limit//2, ioc_type='domain', delay=1.5)
        
        log_task_end(task_name, success=True)
        return True
        
    except Exception as e:
        log_task_end(task_name, success=False, error=str(e))
        return False


def task_score_iocs():
    """
    Automated task: Score all IOCs in the database.
    """
    task_name = "Score IOCs"
    log_task_start(task_name)
    
    try:
        print("[*] Scoring all IOCs...")
        score_all_iocs()
        
        log_task_end(task_name, success=True)
        return True
        
    except Exception as e:
        log_task_end(task_name, success=False, error=str(e))
        return False


def task_database_maintenance():
    """
    Automated task: Perform database maintenance (vacuum and rebuild indexes).
    Runs weekly.
    """
    task_name = "Database Maintenance"
    log_task_start(task_name)
    
    try:
        print("[*] Rebuilding indexes...")
        rebuild_indexes()
        
        print("[*] Vacuuming database...")
        vacuum_database()
        
        log_task_end(task_name, success=True)
        return True
        
    except Exception as e:
        log_task_end(task_name, success=False, error=str(e))
        return False


def task_check_high_threats():
    """
    Automated task: Check for high-severity threats and send alerts.
    """
    task_name = "Check High Threats"
    log_task_start(task_name)
    
    try:
        from automation.alerting import check_and_alert
        
        print("[*] Checking for high-severity threats...")
        alert_count = check_and_alert()
        
        print(f"[*] Sent {alert_count} alerts")
        log_task_end(task_name, success=True)
        return True
        
    except Exception as e:
        log_task_end(task_name, success=False, error=str(e))
        return False


if __name__ == "__main__":
    """
    Test individual tasks.
    Usage: python automation/tasks.py <task_name>
    """
    if len(sys.argv) < 2:
        print("Usage: python automation/tasks.py <task_name>")
        print("Available tasks:")
        print("  - collect_feeds")
        print("  - enrich_iocs")
        print("  - score_iocs")
        print("  - database_maintenance")
        print("  - check_high_threats")
        sys.exit(1)
    
    task = sys.argv[1]
    
    if task == "collect_feeds":
        task_collect_feeds()
    elif task == "enrich_iocs":
        task_enrich_iocs(limit=10)  # Small limit for testing
    elif task == "score_iocs":
        task_score_iocs()
    elif task == "database_maintenance":
        task_database_maintenance()
    elif task == "check_high_threats":
        task_check_high_threats()
    else:
        print(f"Unknown task: {task}")
        sys.exit(1)
