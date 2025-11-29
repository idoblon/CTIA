# Phase 10 - Advanced Features Guide

## Overview

Phase 10 adds optional advanced features to enhance the CTIA system's capabilities:

1. **PDF Report Generation** - Professional threat intelligence reports
2. **Telegram Alert Bot** - Real-time alerts via Telegram
3. **Demonstration Video** - Complete system walkthrough

---

## 1. PDF Report Generation

### Setup

```bash
# Install reportlab
pip install reportlab
```

### Usage

```bash
# Generate default report (ctia_threat_report.pdf with top 20 threats)
python reports/pdf_generator.py

# Custom output path
python reports/pdf_generator.py my_report.pdf

# Custom output path and threat count
python reports/pdf_generator.py monthly_report.pdf 50
```

### Report Contents

- **Executive Summary**: Overview of threat landscape
- **Statistics Table**: Total IOCs, enrichment rate, threat levels
- **IOC Type Distribution**: Breakdown by IP, domain, URL, hash
- **Top Threats**: Ranked list with color-coded severity levels
  - 🔴 Red: Malicious (score ≥ 75)
  - 🟠 Orange: Suspicious (score 50-74)
  - 🟡 Yellow: Low (score 25-49)
  - 🟢 Green: Informational (score 0-24)

### Automated Report Generation

Add to scheduler for weekly reports:

```python
# In automation/tasks.py
def task_generate_weekly_report():
    """Generate weekly PDF report."""
    from reports.pdf_generator import generate_pdf_report
    timestamp = datetime.now().strftime("%Y%m%d")
    output_path = f"reports/weekly_report_{timestamp}.pdf"
    generate_pdf_report(output_path, top_count=50)
    print(f"[+] Weekly report generated: {output_path}")
```

Then add to scheduler:

```python
# In automation/scheduler.py
scheduler.add_job(
    task_generate_weekly_report,
    trigger=CronTrigger(day_of_week='sun', hour=23, minute=0),
    id='weekly_report',
    name='Weekly PDF Report Generation'
)
```

---

## 2. Telegram Alert Bot

### Setup

#### Step 1: Create Telegram Bot

1. Open Telegram and search for `@BotFather`
2. Send `/newbot` command
3. Follow instructions to create your bot
4. Copy the **bot token** (looks like: `123456789:ABCdefGHIjklMNOpqrsTUVwxyz`)

#### Step 2: Get Your Chat ID

1. Search for `@userinfobot` on Telegram
2. Start a conversation
3. Copy your **chat ID** (a number like: `123456789`)

#### Step 3: Configure Environment

Add to your `.env` file:

```env
# Telegram Bot Configuration
TELEGRAM_BOT_TOKEN=your_bot_token_here
TELEGRAM_CHAT_ID=your_chat_id_here
```

### Usage

#### Test Configuration

```bash
python automation/telegram_bot.py test
```

This sends a test message to verify your bot is configured correctly.

#### Send Threat Alert

```bash
# Alert for threats with score ≥ 75
python automation/telegram_bot.py alert

# Custom threshold
python automation/telegram_bot.py alert 80
```

#### Send Daily Summary

```bash
python automation/telegram_bot.py summary
```

### Alert Message Format

Telegram alerts include:
- 🚨 Threat count and timestamp
- Top 5 threats with details:
  - IOC type and value
  - Threat score
  - Source feed
  - Enrichment intel (VT, AbuseIPDB, OTX)
- Emoji indicators (🔴 🟠 🟡) based on severity
- Link to dashboard

### Integration with Automation

#### Option 1: Replace Console Alerts

Modify `automation/alerting.py`:

```python
def check_and_alert(threshold=75, limit=50, send_email=True, send_telegram=True):
    # ... existing code ...
    
    # Send Telegram alert
    if send_telegram:
        from automation.telegram_bot import send_threat_alert
        send_threat_alert(threshold=threshold, limit=limit)
```

#### Option 2: Add to Scheduler

In `automation/scheduler.py`:

```python
from automation.telegram_bot import send_daily_summary

# Add daily summary job
scheduler.add_job(
    send_daily_summary,
    trigger=CronTrigger(hour=9, minute=0),  # 9 AM daily
    id='telegram_summary',
    name='Daily Telegram Summary'
)
```

### Telegram Bot Features

- ✅ **Threat Alerts**: Real-time high-severity threat notifications
- ✅ **Daily Summaries**: Statistics and threat level breakdown
- ✅ **HTML Formatting**: Rich text with bold, code blocks, emojis
- ✅ **Enrichment Details**: VT, AbuseIPDB, OTX intelligence
- ✅ **Test Mode**: Verify configuration before deployment

---

## 3. Demonstration Video

### Recording Guide

Follow the comprehensive script in `DEMO_VIDEO_SCRIPT.md`:

1. **Preparation** (5 minutes)
   - Review script
   - Test all commands
   - Close unnecessary apps
   - Set up recording software

2. **Recording** (8-10 minutes)
   - Introduction and architecture
   - Database overview
   - Manual operations demo
   - Automation system
   - Alerting system
   - Web dashboard
   - Code walkthrough
   - Conclusion

3. **Post-Production** (10-15 minutes)
   - Edit video
   - Add title slide
   - Export as MP4

### Recommended Tools

**Recording:**
- OBS Studio (free, professional)
- Windows Game Bar (Win+G, built-in)
- ShareX (free, lightweight)

**Editing:**
- DaVinci Resolve (free, professional)
- OpenShot (free, simple)
- Windows Video Editor (built-in)

### Video Checklist

- [ ] Duration: 8-10 minutes
- [ ] Shows architecture overview
- [ ] Demonstrates automation scheduler
- [ ] Shows alerting system
- [ ] Demonstrates web dashboard
- [ ] Includes code walkthrough
- [ ] Clear audio (if voiceover)
- [ ] Exported as MP4
- [ ] File size < 500MB

---

## Testing Phase 10 Features

### 1. Test PDF Report Generation

```bash
# Ensure database has data
python -m app.db.db_queries stats

# Generate test report
python reports/pdf_generator.py test_report.pdf 10

# Open test_report.pdf to verify
```

### 2. Test Telegram Bot

```bash
# Test configuration
python automation/telegram_bot.py test

# If successful, test alert
python automation/telegram_bot.py alert 75

# Test daily summary
python automation/telegram_bot.py summary
```

### 3. Test Enhanced Dashboard

```bash
# Launch enhanced dashboard
streamlit run app/dashboard/dashboard_enhanced.py

# Test features:
# - Overview tab charts
# - IOC Explorer filtering
# - Top Threats display
# - Analytics statistics
# - CSV/JSON export
```

---

## Integration Examples

### Weekly Automated Reports

Create a new task in `automation/tasks.py`:

```python
def task_weekly_report():
    """Generate weekly PDF report and send via Telegram."""
    from reports.pdf_generator import generate_pdf_report
    from automation.telegram_bot import send_telegram_message, get_telegram_config
    
    # Generate PDF
    timestamp = datetime.now().strftime("%Y%m%d")
    pdf_path = f"reports/weekly_{timestamp}.pdf"
    generate_pdf_report(pdf_path, top_count=50)
    
    # Send notification via Telegram
    bot_token, chat_id = get_telegram_config()
    if bot_token and chat_id:
        message = f"📊 Weekly CTIA Report Generated\n\nReport: {pdf_path}\nTimestamp: {timestamp}"
        send_telegram_message(message, bot_token, chat_id)
```

### Enhanced Alerting

Combine email and Telegram alerts:

```python
def enhanced_alert_system(threshold=75):
    """Send alerts via multiple channels."""
    from automation.alerting import check_and_alert
    from automation.telegram_bot import send_threat_alert
    
    # Console and email alerts
    check_and_alert(threshold=threshold, send_email=True)
    
    # Telegram alerts
    send_threat_alert(threshold=threshold)
```

---

## Troubleshooting

### PDF Generation Issues

**Error: No module named 'reportlab'**
```bash
pip install reportlab
```

**Error: Database not found**
```bash
# Ensure database exists
python -m app.main run_all
```

### Telegram Bot Issues

**Error: Telegram not configured**
- Check `.env` file has `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID`
- Verify bot token is correct (from @BotFather)
- Verify chat ID is correct (from @userinfobot)

**Error: Failed to send message**
- Check internet connection
- Verify bot token is valid
- Ensure you've started a conversation with your bot
- Check chat ID is correct

**Bot doesn't respond**
- Make sure you've sent `/start` to your bot first
- Verify bot token is active
- Check bot hasn't been deleted in @BotFather

---

## Phase 10 Completion Checklist

### Core Deliverables
- [x] Architecture diagram (`ARCHITECTURE.md`)
- [x] Visual architecture (`VISUAL_ARCHITECTURE.md`)
- [x] Python scripts (all modules)
- [x] Database schema (`DB_SCHEMA.md`)
- [x] Documentation (`USER_GUIDE.md`, `README.md`)
- [x] Enhanced dashboard

### Advanced Features
- [x] PDF report generation
- [x] Telegram alert bot
- [ ] Demonstration video (script ready)

### Optional Features
- [ ] Excel report generation
- [ ] ML anomaly detection
- [ ] SIEM integration

---

## Next Steps

1. **Test all Phase 10 features**
   - Generate PDF report
   - Configure and test Telegram bot
   - Test enhanced dashboard

2. **Record demonstration video**
   - Follow `DEMO_VIDEO_SCRIPT.md`
   - Show all features including Phase 10 additions
   - Export as MP4

3. **Final review**
   - Verify all documentation is complete
   - Test all features one final time
   - Prepare for project submission

---

## Summary

Phase 10 adds professional reporting and real-time alerting capabilities to CTIA:

- **PDF Reports**: Professional threat intelligence documentation
- **Telegram Alerts**: Real-time threat notifications on your phone
- **Enhanced Dashboard**: Interactive visualizations with Plotly
- **Complete Documentation**: Ready for project submission

**Project Status**: 98% Complete  
**Remaining**: Record demonstration video
