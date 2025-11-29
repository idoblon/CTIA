"""
automation/scheduler.py

APScheduler-based task scheduler for CTIA automation.
Schedules periodic tasks for threat intelligence collection, enrichment, and scoring.
"""

import sys
import os
import signal
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from automation.tasks import (
    task_collect_feeds,
    task_enrich_iocs,
    task_score_iocs,
    task_database_maintenance,
    task_check_high_threats
)


# Global scheduler instance
scheduler = None


def start_scheduler():
    """
    Initialize and start the APScheduler.
    Configures all scheduled jobs.
    """
    global scheduler
    
    if scheduler is not None:
        print("[!] Scheduler is already running!")
        return scheduler
    
    print("[*] Initializing CTIA Automation Scheduler...")
    
    # Create scheduler
    scheduler = BackgroundScheduler(timezone='Asia/Kathmandu')
    
    # Job 1: Daily threat feed collection at 2:00 AM
    scheduler.add_job(
        task_collect_feeds,
        trigger=CronTrigger(hour=2, minute=0),
        id='collect_feeds',
        name='Daily Threat Feed Collection',
        replace_existing=True
    )
    print("[+] Scheduled: Daily threat feed collection at 2:00 AM")
    
    # Job 2: Daily enrichment at 3:00 AM (50 IOCs)
    scheduler.add_job(
        lambda: task_enrich_iocs(limit=50),
        trigger=CronTrigger(hour=3, minute=0),
        id='enrich_iocs',
        name='Daily IOC Enrichment',
        replace_existing=True
    )
    print("[+] Scheduled: Daily IOC enrichment at 3:00 AM")
    
    # Job 3: Daily scoring at 4:00 AM
    scheduler.add_job(
        task_score_iocs,
        trigger=CronTrigger(hour=4, minute=0),
        id='score_iocs',
        name='Daily IOC Scoring',
        replace_existing=True
    )
    print("[+] Scheduled: Daily IOC scoring at 4:00 AM")
    
    # Job 4: Weekly database maintenance on Sunday at 1:00 AM
    scheduler.add_job(
        task_database_maintenance,
        trigger=CronTrigger(day_of_week='sun', hour=1, minute=0),
        id='database_maintenance',
        name='Weekly Database Maintenance',
        replace_existing=True
    )
    print("[+] Scheduled: Weekly database maintenance on Sunday at 1:00 AM")
    
    # Job 5: Check for high threats every 6 hours
    scheduler.add_job(
        task_check_high_threats,
        trigger=CronTrigger(hour='*/6'),
        id='check_high_threats',
        name='High Threat Check (Every 6 Hours)',
        replace_existing=True
    )
    print("[+] Scheduled: High threat check every 6 hours")
    
    # Start the scheduler
    scheduler.start()
    print("\n[✓] Scheduler started successfully!")
    print(f"[*] Current time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return scheduler


def stop_scheduler():
    """
    Gracefully stop the scheduler.
    """
    global scheduler
    
    if scheduler is None:
        print("[!] Scheduler is not running!")
        return
    
    print("\n[*] Stopping scheduler...")
    scheduler.shutdown(wait=True)
    scheduler = None
    print("[✓] Scheduler stopped successfully!")


def list_jobs():
    """
    List all scheduled jobs.
    """
    global scheduler
    
    if scheduler is None:
        print("[!] Scheduler is not running!")
        return
    
    jobs = scheduler.get_jobs()
    
    if not jobs:
        print("[!] No jobs scheduled.")
        return
    
    print(f"\n{'='*80}")
    print(f"SCHEDULED JOBS ({len(jobs)} total)")
    print(f"{'='*80}")
    
    for job in jobs:
        print(f"\nJob ID: {job.id}")
        print(f"Name: {job.name}")
        print(f"Next Run: {job.next_run_time}")
        print(f"Trigger: {job.trigger}")
    
    print(f"\n{'='*80}\n")


def pause_job(job_id):
    """
    Pause a specific job.
    
    Args:
        job_id: ID of the job to pause
    """
    global scheduler
    
    if scheduler is None:
        print("[!] Scheduler is not running!")
        return
    
    try:
        scheduler.pause_job(job_id)
        print(f"[✓] Job '{job_id}' paused.")
    except Exception as e:
        print(f"[!] Failed to pause job '{job_id}': {e}")


def resume_job(job_id):
    """
    Resume a paused job.
    
    Args:
        job_id: ID of the job to resume
    """
    global scheduler
    
    if scheduler is None:
        print("[!] Scheduler is not running!")
        return
    
    try:
        scheduler.resume_job(job_id)
        print(f"[✓] Job '{job_id}' resumed.")
    except Exception as e:
        print(f"[!] Failed to resume job '{job_id}': {e}")


def signal_handler(signum, frame):
    """
    Handle shutdown signals (SIGINT, SIGTERM).
    """
    print("\n[*] Received shutdown signal...")
    stop_scheduler()
    sys.exit(0)


def run_scheduler():
    """
    Run the scheduler in the foreground.
    Blocks until interrupted.
    """
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start scheduler
    start_scheduler()
    
    # List scheduled jobs
    list_jobs()
    
    print("[*] Scheduler is running. Press Ctrl+C to stop.")
    print("[*] Waiting for scheduled tasks...\n")
    
    try:
        # Keep the main thread alive
        while True:
            import time
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        stop_scheduler()


if __name__ == "__main__":
    """
    Run the scheduler from command line.
    Usage: python automation/scheduler.py
    """
    print("""
╔════════════════════════════════════════════════════════════════╗
║         CTIA Automation Scheduler - Phase 8                    ║
║         Cyber Threat Intelligence Automation                   ║
╚════════════════════════════════════════════════════════════════╝
""")
    
    run_scheduler()
