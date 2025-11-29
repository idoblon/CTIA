# CTI System - User Guide

## Overview

The Cyber Threat Intelligence Automation (CTIA) system automatically collects, processes, enriches, and scores threat intelligence from multiple sources.

## Quick Start

### 1. Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Configure API keys in .env file
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_KEY=your_abuseipdb_api_key
OTX_KEY=your_otx_api_key  # Optional
```

### 2. Collect Threat Data

```bash
# Run full pipeline (fetch, normalize, ingest)
python -m app.main run_all

# Or run individual steps
python -m app.main fetch      # Fetch feeds
python -m app.main normalize  # Normalize IOCs
python -m app.main ingest     # Ingest to database
```

### 3. Enrich IOCs

```bash
# Enrich 50 IPs
python -m app.core.enrichment_batch 50 ip

# Enrich 100 domains
python -m app.core.enrichment_batch 100 domain

# Enrich 25 hashes
python -m app.core.enrichment_batch 25 hash
```

### 4. Score IOCs

```bash
# Score all IOCs
python -m app.core.scoring score_all

# View top 50 threats
python -m app.core.scoring top 50

# Score specific IOC
python -m app.core.scoring score_one 8.8.8.8
```

### 5. Launch Dashboard

```bash
streamlit run app/dashboard/dashboard.py
```

## Phase-by-Phase Guide

### Phase 3: Data Collection ✅

**Feeds Collected:**
- Feodo Tracker (IPs)
- URLhaus (URLs)
- Malware Domains (Domains)

**Commands:**
```bash
python -m app.main fetch
```

### Phase 4: IOC Parsing ✅

**Extracts:**
- IP addresses
- Domains
- URLs
- File hashes (MD5, SHA1, SHA256)

**Commands:**
```bash
python -m app.main normalize
```

### Phase 5: Enrichment ✅

**APIs Integrated:**
- VirusTotal (hashes, URLs)
- AbuseIPDB (IPs)
- AlienVault OTX (domains, IPs)

**Features:**
- Rate limiting (1s between calls)
- Error handling
- Batch processing

**Commands:**
```bash
# Enrich specific types
python -m app.core.enrichment_batch 50 ip
python -m app.core.enrichment_batch 50 domain
python -m app.core.enrichment_batch 50 hash

# Check enrichment status
python -m app.db.db_queries stats
```

### Phase 6: Scoring ✅

**Scoring Model:**
```
Score = (VT_positives × 8.0) 
      + (AbuseIPDB_score × 0.4)
      + (OTX_pulses × 3.0)
      + (Feed_count × 4.0)
```

**Labels:**
- **Malicious** (75-100): High threat
- **Suspicious** (50-74): Medium threat
- **Low** (25-49): Low threat
- **Informational** (0-24): Minimal threat

**Commands:**
```bash
# Score all IOCs
python -m app.core.scoring score_all

# View top threats
python -m app.core.scoring top 100

# Score specific IOC
python -m app.core.scoring score_one <ioc_value>
```

### Phase 7: Storage Layer ✅

**Database:** SQLite (`db/cti.db`)

**Query Utilities:**
```bash
# Statistics
python -m app.db.db_queries stats

# Get IOCs by type
python -m app.db.db_queries type ip 100

# Get IOCs by score range
python -m app.db.db_queries score 75 100

# Get recent IOCs
python -m app.db.db_queries recent 7

# Search IOCs
python -m app.db.db_queries search "malware"
```

**Maintenance:**
```bash
# Database info
python -m app.db.db_maintenance info

# Rebuild indexes
python -m app.db.db_maintenance rebuild_indexes

# Vacuum database
python -m app.db.db_maintenance vacuum

# Export data
python -m app.db.db_maintenance export_csv output.csv 1000
python -m app.db.db_maintenance export_json output.json 1000

# Backup
python -m app.db.db_maintenance backup

# Cleanup old IOCs (dry run)
python -m app.db.db_maintenance cleanup 90

# Cleanup old IOCs (execute)
python -m app.db.db_maintenance cleanup 90 --execute
```

## API Keys

### VirusTotal (Required for hash/URL enrichment)

1. Sign up at https://www.virustotal.com/
2. Get free API key (4 requests/minute)
3. Add to `.env`: `VT_API_KEY=your_key`

### AbuseIPDB (Required for IP enrichment)

1. Sign up at https://www.abuseipdb.com/
2. Get free API key (1000 requests/day)
3. Add to `.env`: `ABUSEIPDB_KEY=your_key`

### AlienVault OTX (Optional for domain/IP enrichment)

1. Sign up at https://otx.alienvault.com/
2. Get free API key
3. Add to `.env`: `OTX_KEY=your_key`

## Workflow Example

```bash
# 1. Collect fresh threat data
python -m app.main run_all

# 2. Rebuild indexes for performance
python -m app.db.db_maintenance rebuild_indexes

# 3. Enrich 100 IPs
python -m app.core.enrichment_batch 100 ip

# 4. Enrich 100 domains
python -m app.core.enrichment_batch 100 domain

# 5. Score all IOCs
python -m app.core.scoring score_all

# 6. View top threats
python -m app.core.scoring top 50

# 7. Launch dashboard
streamlit run app/dashboard/dashboard.py
```

## Troubleshooting

### API Rate Limits

If you hit rate limits:
- Increase delay in `enrichment_batch.py` (default: 1.5s)
- Process smaller batches
- Use free tier limits wisely

### Database Performance

If queries are slow:
```bash
python -m app.db.db_maintenance rebuild_indexes
python -m app.db.db_maintenance vacuum
```

### Missing Enrichment Data

Check API keys are configured:
```bash
python -c "from app.config import VT_API_KEY, ABUSEIPDB_KEY, OTX_KEY; print(f'VT: {bool(VT_API_KEY)}, Abuse: {bool(ABUSEIPDB_KEY)}, OTX: {bool(OTX_KEY)}')"
```

## Best Practices (Manual Mode)

1. **Daily Collection**: Run `python -m app.main run_all` daily (or use automation)
2. **Batch Enrichment**: Enrich in small batches (50-100) to respect rate limits
3. **Regular Scoring**: Score after enrichment
4. **Database Maintenance**: Vacuum and rebuild indexes weekly
5. **Backups**: Create backups before major operations
6. **Data Retention**: Clean up old IOCs monthly


## Phase 8: Automation ✅

**Automated Scheduling:**
- Daily threat feed collection
- Daily IOC enrichment
- Daily scoring
- Weekly database maintenance
- Periodic high-threat alerts

**Commands:**
```bash
# Start the automation scheduler
python -m app.main scheduler

# Test individual tasks
python automation/tasks.py collect_feeds
python automation/tasks.py enrich_iocs
python automation/tasks.py score_iocs
python automation/tasks.py database_maintenance
python automation/tasks.py check_high_threats

# Test alerting system
python automation/alerting.py 75
```

**Scheduled Jobs:**
1. **Daily Feed Collection** - 2:00 AM
2. **Daily Enrichment** - 3:00 AM (50 IOCs)
3. **Daily Scoring** - 4:00 AM
4. **Weekly DB Maintenance** - Sunday 1:00 AM
5. **High Threat Checks** - Every 6 hours

**Email Alerts (Optional):**

To enable email alerts, add to `.env`:
```bash
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
ALERT_EMAIL_FROM=ctia@yourdomain.com
ALERT_EMAIL_TO=admin@yourdomain.com
```

**Configuration:**

Edit `.env` to customize:
```bash
AUTOMATION_ENABLED=true
ENRICHMENT_BATCH_SIZE=50
ALERT_THRESHOLD=75
```

## Best Practices

1. **Automated Collection**: Run scheduler 24/7 for continuous monitoring
2. **Batch Enrichment**: Scheduler handles rate limiting automatically
3. **Regular Scoring**: Automated daily scoring keeps threat scores current
4. **Database Maintenance**: Weekly automated vacuum and index rebuild
5. **Backups**: Create backups before major operations
6. **Data Retention**: Clean up old IOCs monthly
7. **Monitor Alerts**: Check console/email for high-severity threats

## Next Steps (Phase 9+)

- **Phase 9**: Enhanced visualization dashboard
- **Phase 10**: Reports, ML anomaly detection, SIEM integration
