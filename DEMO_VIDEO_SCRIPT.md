# CTIA Demonstration Video Script

**Duration**: 8-10 minutes  
**Recording Tool**: OBS Studio, Camtasia, or Windows Game Bar (Win+G)

---

## Pre-Recording Checklist

- [ ] Close unnecessary applications
- [ ] Clear terminal history: `cls` or `clear`
- [ ] Ensure database has data: Check `db/cti.db` exists
- [ ] Test all commands beforehand
- [ ] Prepare browser for dashboard
- [ ] Set up screen recording software
- [ ] Test audio (if doing voiceover)

---

## Video Structure

### 1. Introduction (30 seconds)

**Screen**: Show project folder in VS Code or File Explorer

**Script**:
> "Welcome to the Cyber Threat Intelligence Automation (CTIA) system demonstration. This project automates the collection, enrichment, scoring, and monitoring of threat intelligence from multiple sources. Let me walk you through the complete system."

**Show**:
- Project folder structure
- Quick overview of main directories: `app/`, `automation/`, `db/`

---

### 2. Architecture Overview (1 minute)

**Screen**: Open `VISUAL_ARCHITECTURE.md` or `ARCHITECTURE.md`

**Script**:
> "The CTIA system follows a multi-phase architecture. We collect threat feeds from sources like Feodo Tracker, URLhaus, and Malware Domains. These feeds are normalized, stored in a SQLite database, enriched using VirusTotal, AbuseIPDB, and AlienVault OTX APIs, and then scored based on threat severity."

**Show**:
- Scroll through architecture diagram
- Highlight key components:
  - Data Collection (Phase 3)
  - Normalization (Phase 4)
  - Enrichment (Phase 5)
  - Scoring (Phase 6)
  - Storage (Phase 7)
  - Automation (Phase 8)

---

### 3. Database Overview (1 minute)

**Screen**: Terminal

**Commands**:
```bash
# Activate virtual environment
.venv\Scripts\activate

# Show database statistics
python -m app.db.db_queries stats
```

**Script**:
> "Our database currently contains over 129,000 indicators of compromise. Let me show you the statistics."

**Show**:
- Total IOC count
- Breakdown by type (IPs, domains, URLs, hashes)
- Enrichment statistics
- Score distribution

---

### 4. Manual Operations Demo (2 minutes)

**Screen**: Terminal

#### 4a. Data Collection
**Commands**:
```bash
# Fetch fresh threat feeds
python -m app.main fetch

# Normalize the feeds
python -m app.main normalize

# Ingest to database
python -m app.main ingest
```

**Script**:
> "First, let's manually collect fresh threat intelligence. We fetch feeds, normalize them to extract IOCs, and ingest them into our database."

#### 4b. Enrichment
**Commands**:
```bash
# Enrich 10 IPs (for demo speed)
python -m app.core.enrichment_batch 10 ip
```

**Script**:
> "Next, we enrich IOCs by querying threat intelligence APIs. Watch as we enrich 10 IP addresses with data from AbuseIPDB and AlienVault OTX."

**Show**:
- Progress bar
- API responses
- Metadata being saved

#### 4c. Scoring
**Commands**:
```bash
# Score all IOCs
python -m app.core.scoring score_all

# Show top 20 threats
python -m app.core.scoring top 20
```

**Script**:
> "After enrichment, we calculate threat scores. Here are the top 20 most dangerous IOCs in our database."

**Show**:
- Scoring progress
- Top threats with scores
- Threat labels (Malicious, Suspicious, etc.)

---

### 5. Automation System Demo (2 minutes)

**Screen**: Terminal

**Commands**:
```bash
# Start the automation scheduler
python -m app.main scheduler
```

**Script**:
> "The real power of CTIA is automation. Our scheduler runs tasks automatically: daily feed collection at 2 AM, enrichment at 3 AM, scoring at 4 AM, and weekly database maintenance. It also checks for high-severity threats every 6 hours."

**Show**:
- Scheduler startup messages
- List of scheduled jobs with next run times
- Job details (cron triggers)

**Wait**: 10-15 seconds showing scheduler running

**Commands**:
```bash
# Press Ctrl+C to stop scheduler
# Then test individual tasks
python automation/tasks.py collect_feeds
```

**Script**:
> "We can also run individual tasks manually for testing. Let me demonstrate the feed collection task."

**Show**:
- Task execution with timestamps
- Success/failure messages

---

### 6. Alerting System Demo (1 minute)

**Screen**: Terminal

**Commands**:
```bash
# Test alerting system (threshold = 75)
python automation/alerting.py 75
```

**Script**:
> "The alerting system monitors for high-severity threats. When IOCs with scores above 75 are detected, alerts are sent to the console and optionally via email."

**Show**:
- Alert message with threat details
- IOC values, scores, and sources
- Enrichment details (VT detections, AbuseIPDB scores)

---

### 7. Web Dashboard Demo (2 minutes)

**Screen**: Browser

**Commands**:
```bash
# Launch Streamlit dashboard
streamlit run app/dashboard/dashboard.py
```

**Script**:
> "Finally, let's explore the web dashboard. This provides a user-friendly interface for viewing, filtering, and managing IOCs."

**Show**:
1. **Dashboard Overview**:
   - IOC table with filtering
   - Type distribution chart
   - Top threats table

2. **Filtering**:
   - Filter by IOC type (select "ip")
   - Adjust minimum score slider (set to 50)
   - Search for specific IOC

3. **IOC Details**:
   - Select an IOC from dropdown
   - Show enrichment metadata
   - Display score and source information

4. **Actions**:
   - Select an IOC
   - Choose "Enrich selected IOC" action
   - Show enrichment results

5. **Export**:
   - Demonstrate CSV export functionality

---

### 8. Code Walkthrough (1 minute)

**Screen**: VS Code

**Script**:
> "Let me briefly show you the code structure."

**Show**:
1. **Main Entry Point**: `app/main.py`
   - Show CLI commands
   - Highlight scheduler integration

2. **Automation Module**: `automation/scheduler.py`
   - Show scheduled jobs configuration
   - Highlight cron triggers

3. **Alerting**: `automation/alerting.py`
   - Show alert formatting
   - Email integration

4. **Dashboard**: `app/dashboard/dashboard.py`
   - Streamlit interface code

---

### 9. Conclusion (30 seconds)

**Screen**: Back to project overview or architecture diagram

**Script**:
> "To summarize, the CTIA system provides end-to-end threat intelligence automation: from data collection and normalization, through enrichment and scoring, to automated monitoring and alerting. The system runs 24/7, continuously updating threat intelligence and alerting on high-severity threats. Thank you for watching!"

**Show**:
- Final architecture diagram
- Project statistics summary

---

## Recording Tips

### Before Recording:
1. **Test everything** - Run all commands first
2. **Clean up** - Close unnecessary windows
3. **Prepare data** - Ensure database has enriched IOCs
4. **Set resolution** - 1920x1080 recommended
5. **Audio check** - Test microphone if doing voiceover

### During Recording:
1. **Speak clearly** - Explain what you're doing
2. **Go slow** - Give viewers time to read output
3. **Highlight important parts** - Use mouse to point
4. **Pause between sections** - Makes editing easier
5. **Show real results** - Don't fake data

### After Recording:
1. **Edit** - Remove mistakes, add transitions
2. **Add captions** - For key points
3. **Add intro/outro** - Title slide and credits
4. **Export** - MP4 format, H.264 codec
5. **Test playback** - Ensure audio/video sync

---

## Alternative: Shorter Version (5 minutes)

If time is limited, focus on:
1. Introduction (30s)
2. Architecture overview (30s)
3. Automation demo (2 min)
4. Dashboard demo (1.5 min)
5. Conclusion (30s)

---

## Tools Recommendation

### Free Options:
- **OBS Studio** (Best, free, professional)
- **Windows Game Bar** (Win+G, built-in, simple)
- **ShareX** (Free, lightweight)

### Paid Options:
- **Camtasia** (Professional, easy editing)
- **Bandicam** (Simple, good quality)

### Video Editing:
- **DaVinci Resolve** (Free, professional)
- **OpenShot** (Free, simple)
- **Windows Video Editor** (Built-in, basic)

---

## Checklist Before Submission

- [ ] Video is 5-10 minutes long
- [ ] Audio is clear (if voiceover)
- [ ] All major features demonstrated
- [ ] Shows automation scheduler running
- [ ] Shows alerting system
- [ ] Shows web dashboard
- [ ] Explains architecture
- [ ] Shows real data/results
- [ ] Exported in MP4 format
- [ ] File size reasonable (<500MB)
