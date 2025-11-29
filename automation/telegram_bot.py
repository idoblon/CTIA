"""
automation/telegram_bot.py

Telegram Alert Bot for CTIA System
Sends threat intelligence alerts via Telegram.
"""

import sys
import os
import sqlite3
import json
from datetime import datetime
import requests

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.config import DB_PATH


def get_telegram_config():
    """
    Get Telegram configuration from environment variables.
    
    Required .env variables:
    - TELEGRAM_BOT_TOKEN: Bot token from @BotFather
    - TELEGRAM_CHAT_ID: Chat ID to send messages to
    
    Returns:
        tuple: (bot_token, chat_id) or (None, None) if not configured
    """
    bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    chat_id = os.getenv('TELEGRAM_CHAT_ID')
    
    if not bot_token or not chat_id:
        return None, None
    
    return bot_token, chat_id


def send_telegram_message(message, bot_token, chat_id, parse_mode='HTML'):
    """
    Send a message via Telegram Bot API.
    
    Args:
        message: Message text to send
        bot_token: Telegram bot token
        chat_id: Telegram chat ID
        parse_mode: Message parse mode (HTML or Markdown)
    
    Returns:
        bool: True if message sent successfully, False otherwise
    """
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    
    payload = {
        'chat_id': chat_id,
        'text': message,
        'parse_mode': parse_mode
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"[!] Failed to send Telegram message: {e}")
        return False


def get_high_severity_threats(threshold=75, limit=10):
    """
    Get high-severity threats from database.
    
    Args:
        threshold: Minimum score for high severity
        limit: Maximum number of threats to return
    
    Returns:
        list: List of threat dictionaries
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    cur.execute("""
        SELECT value, ioc_type, score, source, score_updated_at, metadata
        FROM iocs 
        WHERE score >= ? 
        ORDER BY score DESC, score_updated_at DESC 
        LIMIT ?
    """, (threshold, limit))
    
    threats = []
    for row in cur.fetchall():
        threat = dict(row)
        # Parse metadata
        if threat.get('metadata'):
            try:
                threat['metadata'] = json.loads(threat['metadata'])
            except:
                threat['metadata'] = {}
        threats.append(threat)
    
    conn.close()
    return threats


def format_telegram_alert(threats, threshold=75):
    """
    Format threat alert message for Telegram.
    
    Args:
        threats: List of threat dictionaries
        threshold: Threshold used for filtering
    
    Returns:
        str: Formatted HTML message
    """
    if not threats:
        return f"✅ <b>CTIA Alert</b>\n\nNo high-severity threats (score ≥ {threshold}) detected."
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    message = f"""🚨 <b>CTIA THREAT ALERT</b> 🚨

<b>Timestamp:</b> {timestamp}
<b>High-Severity Threats:</b> {len(threats)}
<b>Threshold:</b> Score ≥ {threshold}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
    
    for i, threat in enumerate(threats[:5], 1):  # Show top 5 in Telegram
        # Determine threat emoji
        if threat['score'] >= 90:
            emoji = "🔴"
        elif threat['score'] >= 75:
            emoji = "🟠"
        else:
            emoji = "🟡"
        
        # Truncate long values
        value = threat['value'][:50] + "..." if len(threat['value']) > 50 else threat['value']
        
        message += f"""
{emoji} <b>Threat #{i}</b>
<b>Type:</b> {threat['ioc_type'].upper()}
<b>Value:</b> <code>{value}</code>
<b>Score:</b> {threat['score']}/100
<b>Source:</b> {threat.get('source', 'Unknown')}
"""
        
        # Add enrichment details if available
        metadata = threat.get('metadata', {})
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
                message += f"<b>Intel:</b> {', '.join(details)}\n"
        
        message += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
    
    if len(threats) > 5:
        message += f"\n... and {len(threats) - 5} more threats.\n"
    
    message += f"""
<b>Action Required:</b> Review threats in CTIA dashboard
<b>Dashboard:</b> http://localhost:8501

<i>Automated alert from CTIA System</i>
"""
    
    return message


def send_threat_alert(threshold=75, limit=10):
    """
    Check for high-severity threats and send Telegram alert.
    
    Args:
        threshold: Minimum score for alerts
        limit: Maximum number of threats to include
    
    Returns:
        bool: True if alert sent successfully, False otherwise
    """
    print(f"[*] Checking for threats with score ≥ {threshold}...")
    
    # Get Telegram config
    bot_token, chat_id = get_telegram_config()
    
    if not bot_token or not chat_id:
        print("[!] Telegram not configured. Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in .env")
        return False
    
    # Get high-severity threats
    threats = get_high_severity_threats(threshold=threshold, limit=limit)
    
    if not threats:
        print("[+] No high-severity threats detected.")
        # Optionally send "all clear" message
        # message = format_telegram_alert([], threshold)
        # send_telegram_message(message, bot_token, chat_id)
        return True
    
    print(f"[!] Found {len(threats)} high-severity threats!")
    
    # Format and send alert
    message = format_telegram_alert(threats, threshold)
    
    success = send_telegram_message(message, bot_token, chat_id)
    
    if success:
        print(f"[+] Telegram alert sent successfully to chat {chat_id}")
    else:
        print(f"[!] Failed to send Telegram alert")
    
    return success


def send_daily_summary():
    """
    Send daily threat intelligence summary via Telegram.
    
    Returns:
        bool: True if summary sent successfully
    """
    print("[*] Generating daily threat summary...")
    
    bot_token, chat_id = get_telegram_config()
    
    if not bot_token or not chat_id:
        print("[!] Telegram not configured.")
        return False
    
    # Get statistics
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    # Total IOCs
    cur.execute("SELECT COUNT(*) as total FROM iocs")
    total = cur.fetchone()['total']
    
    # Threat levels
    cur.execute("""
        SELECT 
            SUM(CASE WHEN score >= 75 THEN 1 ELSE 0 END) as malicious,
            SUM(CASE WHEN score >= 50 AND score < 75 THEN 1 ELSE 0 END) as suspicious,
            SUM(CASE WHEN score >= 25 AND score < 50 THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN score < 25 THEN 1 ELSE 0 END) as info
        FROM iocs
    """)
    levels = cur.fetchone()
    
    conn.close()
    
    # Format message
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    message = f"""📊 <b>CTIA Daily Summary</b>

<b>Date:</b> {timestamp}

<b>Total IOCs:</b> {total:,}

<b>Threat Levels:</b>
🔴 Malicious (≥75): {levels['malicious']:,}
🟠 Suspicious (50-74): {levels['suspicious']:,}
🟡 Low (25-49): {levels['low']:,}
🟢 Informational (0-24): {levels['info']:,}

<b>Status:</b> System operational ✅

<i>Automated daily summary from CTIA</i>
"""
    
    success = send_telegram_message(message, bot_token, chat_id)
    
    if success:
        print("[+] Daily summary sent successfully")
    else:
        print("[!] Failed to send daily summary")
    
    return success


def test_telegram_bot():
    """
    Test Telegram bot configuration.
    
    Returns:
        bool: True if test successful
    """
    print("[*] Testing Telegram bot configuration...")
    
    bot_token, chat_id = get_telegram_config()
    
    if not bot_token or not chat_id:
        print("[!] Telegram not configured.")
        print("\nTo configure Telegram alerts:")
        print("1. Create a bot with @BotFather on Telegram")
        print("2. Get your chat ID (use @userinfobot)")
        print("3. Add to .env file:")
        print("   TELEGRAM_BOT_TOKEN=your_bot_token")
        print("   TELEGRAM_CHAT_ID=your_chat_id")
        return False
    
    test_message = f"""✅ <b>CTIA Telegram Bot Test</b>

<b>Timestamp:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Your Telegram bot is configured correctly!

<i>Test message from CTIA System</i>
"""
    
    success = send_telegram_message(test_message, bot_token, chat_id)
    
    if success:
        print(f"[+] Test message sent successfully to chat {chat_id}")
        print("[+] Telegram bot is working correctly!")
    else:
        print("[!] Failed to send test message")
        print("[!] Check your bot token and chat ID")
    
    return success


if __name__ == "__main__":
    """
    Telegram bot command-line interface.
    Usage: 
        python automation/telegram_bot.py test
        python automation/telegram_bot.py alert [threshold]
        python automation/telegram_bot.py summary
    """
    print("""
╔════════════════════════════════════════════════════════════════╗
║         CTIA Telegram Alert Bot - Phase 10                     ║
║         Cyber Threat Intelligence Automation                   ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python automation/telegram_bot.py test")
        print("  python automation/telegram_bot.py alert [threshold]")
        print("  python automation/telegram_bot.py summary")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    
    if command == "test":
        test_telegram_bot()
    
    elif command == "alert":
        threshold = int(sys.argv[2]) if len(sys.argv) > 2 else 75
        send_threat_alert(threshold=threshold)
    
    elif command == "summary":
        send_daily_summary()
    
    else:
        print(f"[!] Unknown command: {command}")
        sys.exit(1)
