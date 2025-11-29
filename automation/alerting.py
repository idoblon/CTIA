"""
automation/alerting.py

Alert system for high-severity threats.
Supports console alerts and email alerts (if configured).
"""

import sys
import os
import sqlite3
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import List, Dict

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.config import DB_PATH


def get_high_severity_iocs(threshold=75, limit=50):
    """
    Get high-severity IOCs from the database.
    
    Args:
        threshold: Minimum score to be considered high-severity (default: 75)
        limit: Maximum number of IOCs to return (default: 50)
    
    Returns:
        List of IOC dictionaries
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    query = """
        SELECT * FROM iocs 
        WHERE score >= ? 
        ORDER BY score DESC, score_updated_at DESC 
        LIMIT ?
    """
    
    cur.execute(query, (threshold, limit))
    rows = cur.fetchall()
    conn.close()
    
    # Convert to list of dicts
    iocs = []
    for row in rows:
        ioc = dict(row)
        # Parse metadata JSON
        if ioc.get('metadata'):
            try:
                ioc['metadata'] = json.loads(ioc['metadata'])
            except:
                ioc['metadata'] = {}
        iocs.append(ioc)
    
    return iocs


def format_alert_message(iocs: List[Dict]) -> str:
    """
    Format alert message for high-severity IOCs.
    
    Args:
        iocs: List of IOC dictionaries
    
    Returns:
        Formatted alert message
    """
    if not iocs:
        return "No high-severity threats detected."
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    message = f"""
{'='*70}
CTIA THREAT ALERT
{'='*70}
Timestamp: {timestamp}
High-Severity Threats Detected: {len(iocs)}
{'='*70}

"""
    
    for i, ioc in enumerate(iocs[:10], 1):  # Show top 10
        message += f"\n{i}. {ioc['ioc_type'].upper()}: {ioc['value'][:60]}\n"
        message += f"   Score: {ioc['score']}/100\n"
        message += f"   Source: {ioc.get('source', 'Unknown')}\n"
        
        # Add enrichment details if available
        metadata = ioc.get('metadata', {})
        enrichment = metadata.get('enrichment', {})
        
        if enrichment:
            details = []
            
            # VirusTotal
            if 'vt' in enrichment and 'malicious_count' in enrichment['vt']:
                details.append(f"VT: {enrichment['vt']['malicious_count']} detections")
            
            # AbuseIPDB
            if 'abuseip' in enrichment and 'abuse_score' in enrichment['abuseip']:
                details.append(f"AbuseIPDB: {enrichment['abuseip']['abuse_score']}/100")
            
            # OTX
            if 'otx' in enrichment and 'pulse_count' in enrichment['otx']:
                details.append(f"OTX: {enrichment['otx']['pulse_count']} pulses")
            
            if details:
                message += f"   Details: {', '.join(details)}\n"
        
        message += f"   Last Updated: {ioc.get('score_updated_at', 'Unknown')}\n"
    
    if len(iocs) > 10:
        message += f"\n... and {len(iocs) - 10} more high-severity threats.\n"
    
    message += f"\n{'='*70}\n"
    message += "Run 'python -m app.core.scoring top 50' for full details.\n"
    message += f"{'='*70}\n"
    
    return message


def send_console_alert(message: str):
    """
    Send alert to console.
    
    Args:
        message: Alert message to display
    """
    print("\n" + message)


def send_email_alert(subject: str, message: str):
    """
    Send email alert (if SMTP is configured).
    
    Args:
        subject: Email subject
        message: Email message body
    
    Returns:
        True if email sent successfully, False otherwise
    """
    try:
        # Import config here to avoid circular imports
        from app.config import (
            SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD,
            ALERT_EMAIL_FROM, ALERT_EMAIL_TO
        )
        
        # Check if SMTP is configured
        if not all([SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD, ALERT_EMAIL_TO]):
            print("[!] Email alerts not configured. Skipping email.")
            return False
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = ALERT_EMAIL_FROM or SMTP_USERNAME
        msg['To'] = ALERT_EMAIL_TO
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(message, 'plain'))
        
        # Send email
        print(f"[*] Sending email alert to {ALERT_EMAIL_TO}...")
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        
        print("[+] Email alert sent successfully!")
        return True
        
    except ImportError:
        print("[!] Email configuration not found in config.py")
        return False
    except Exception as e:
        print(f"[!] Failed to send email alert: {e}")
        return False


def check_and_alert(threshold=75, limit=50, send_email=True):
    """
    Check for high-severity threats and send alerts.
    
    Args:
        threshold: Minimum score for alerts (default: 75)
        limit: Maximum number of IOCs to check (default: 50)
        send_email: Whether to send email alerts (default: True)
    
    Returns:
        Number of alerts sent
    """
    print(f"[*] Checking for threats with score >= {threshold}...")
    
    # Get high-severity IOCs
    iocs = get_high_severity_iocs(threshold=threshold, limit=limit)
    
    if not iocs:
        print("[+] No high-severity threats detected.")
        return 0
    
    print(f"[!] Found {len(iocs)} high-severity threats!")
    
    # Format alert message
    message = format_alert_message(iocs)
    
    # Send console alert
    send_console_alert(message)
    
    # Send email alert if configured and requested
    alert_count = 1  # Console alert
    
    if send_email:
        subject = f"CTIA Alert: {len(iocs)} High-Severity Threats Detected"
        if send_email_alert(subject, message):
            alert_count += 1
    
    return alert_count


if __name__ == "__main__":
    """
    Test alerting system.
    Usage: python automation/alerting.py [threshold]
    """
    threshold = 75
    
    if len(sys.argv) >= 2:
        threshold = int(sys.argv[1])
    
    print(f"Testing alerting system with threshold={threshold}")
    check_and_alert(threshold=threshold, send_email=True)
