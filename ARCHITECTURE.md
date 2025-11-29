# CTI System Architecture

## System Overview

The Cyber Threat Intelligence Automation (CTIA) system is a Python-based platform that automatically collects, processes, enriches, and scores threat intelligence from multiple sources.

```
┌─────────────────────────────────────────────────────────────────┐
│                    CTI AUTOMATION SYSTEM                        │
└─────────────────────────────────────────────────────────────────┘

┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  Threat      │     │  Threat      │     │  Malware     │
│  Feeds       │────▶│  APIs        │────▶│  Databases   │
│              │     │              │     │              │
│ • Feodo      │     │ • VirusTotal │     │ • AbuseIPDB  │
│ • URLhaus    │     │ • AbuseIPDB  │     │ • OTX        │
│ • Malware    │     │ • OTX        │     │              │
│   Domains    │     │              │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
       │                     │                     │
       ▼                     ▼                     ▼
┌─────────────────────────────────────────────────────────┐
│              PHASE 3: DATA COLLECTION                   │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  threat_feeds.py                               │    │
│  │  • Fetch feeds from URLs                       │    │
│  │  • Save raw data to raw_feeds/                 │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│          PHASE 4: IOC PARSING & NORMALIZATION           │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  normalizer.py                                 │    │
│  │  • Extract IOCs (IP, domain, URL, hash)        │    │
│  │  • Validate formats with regex                 │    │
│  │  • Remove duplicates                           │    │
│  │  • Save to normalized_feeds/                   │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│              PHASE 7: STORAGE LAYER                     │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  database.py                                   │    │
│  │  • Initialize SQLite database                  │    │
│  │  • Ingest normalized IOCs                      │    │
│  │  • 129,251 IOCs stored                         │    │
│  └────────────────────────────────────────────────┘    │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  SQLite Database (cti.db)                      │    │
│  │  ┌──────────────────────────────────────────┐  │    │
│  │  │ iocs table                               │  │    │
│  │  │ • id, ioc_type, value                    │  │    │
│  │  │ • source, inserted_at                    │  │    │
│  │  │ • metadata (JSON)                        │  │    │
│  │  │ • score, score_updated_at                │  │    │
│  │  └──────────────────────────────────────────┘  │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│            PHASE 5: ENRICHMENT MODULE                   │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  threat_enrichment.py                          │    │
│  │  • Query VirusTotal API (hashes, URLs)         │    │
│  │  • Query AbuseIPDB API (IPs)                   │    │
│  │  • Query OTX API (domains, IPs)                │    │
│  │  • Rate limiting (1s between calls)            │    │
│  └────────────────────────────────────────────────┘    │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  enrichment_batch.py                           │    │
│  │  • Batch process IOCs                          │    │
│  │  • Save enrichment to metadata                 │    │
│  │  • Progress tracking                           │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│            PHASE 6: SCORING ENGINE                      │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  scoring.py                                    │    │
│  │  • Compute threat scores (0-100)               │    │
│  │  • Apply scoring weights:                      │    │
│  │    - VT positives × 8.0                        │    │
│  │    - AbuseIPDB score × 0.4                     │    │
│  │    - OTX pulses × 3.0                          │    │
│  │    - Feed count × 4.0                          │    │
│  │  • Assign labels:                              │    │
│  │    - Malicious (75-100)                        │    │
│  │    - Suspicious (50-74)                        │    │
│  │    - Low (25-49)                               │    │
│  │    - Informational (0-24)                      │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│          PHASE 7: QUERY & MAINTENANCE                   │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  db_queries.py                                 │    │
│  │  • Statistics and reporting                    │    │
│  │  • Filter by type, score, date                 │    │
│  │  • Search functionality                        │    │
│  └────────────────────────────────────────────────┘    │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  db_maintenance.py                             │    │
│  │  • Vacuum & rebuild indexes                    │    │
│  │  • Export (CSV, JSON)                          │    │
│  │  • Backup & cleanup                            │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│          PHASE 8: AUTOMATION (Scheduling)               │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  automation/scheduler.py (APScheduler)         │    │
│  │  • Background task scheduler                   │    │
│  │  • Cron-style job scheduling                   │    │
│  │  • Job management (pause/resume)               │    │
│  └────────────────────────────────────────────────┘    │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  automation/tasks.py                           │    │
│  │  • Daily feed collection (2:00 AM)             │    │
│  │  • Daily enrichment (3:00 AM)                  │    │
│  │  • Daily scoring (4:00 AM)                     │    │
│  │  • Weekly DB maintenance (Sunday 1:00 AM)      │    │
│  │  • High threat checks (every 6 hours)          │    │
│  └────────────────────────────────────────────────┘    │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  automation/alerting.py                        │    │
│  │  • Console alerts                              │    │
│  │  • Email alerts (optional)                     │    │
│  │  • High-severity threat detection              │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│          PHASE 9: VISUALIZATION (Dashboard)             │
│                                                          │
│  ┌────────────────────────────────────────────────┐    │
│  │  dashboard.py (Streamlit)                      │    │
│  │  • View IOCs with filters                      │    │
│  │  • Enrichment interface                        │    │
│  │  • Scoring interface                           │    │
│  │  • Export functionality                        │    │
│  │  • Statistics charts                           │    │
│  └────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## Data Flow

```
1. COLLECTION
   Threat Feeds → threat_feeds.py → raw_feeds/*.txt

2. NORMALIZATION  
   raw_feeds/*.txt → normalizer.py → normalized_feeds/*.json

3. INGESTION
   normalized_feeds/*.json → database.py → cti.db

4. ENRICHMENT
   cti.db → enrichment_batch.py → API calls → metadata (JSON)

5. SCORING
   metadata → scoring.py → threat scores → cti.db

6. AUTOMATION
   scheduler.py → scheduled tasks → automated collection/enrichment/scoring

7. ALERTING
   cti.db → alerting.py → console/email alerts

8. VISUALIZATION
   cti.db → dashboard.py → Web UI
```

## Component Details

### Core Modules (`app/core/`)

| Module | Purpose | Key Functions |
|--------|---------|---------------|
| `threat_feeds.py` | Fetch threat feeds | `fetch_all_feeds()` |
| `normalizer.py` | Extract and normalize IOCs | `normalize_all_feeds()` |
| `threat_enrichment.py` | Enrich IOCs via APIs | `enrich_ioc()` |
| `enrichment_batch.py` | Batch enrichment | `enrich_batch()` |
| `scoring.py` | Score threats | `score_all_iocs()`, `top_n()` |

### Database Modules (`app/db/`)

| Module | Purpose | Key Functions |
|--------|---------|---------------|
| `database.py` | DB initialization | `initialize_database()`, `ingest_normalized()` |
| `db_queries.py` | Query utilities | `get_statistics()`, `search_iocs()` |
| `db_maintenance.py` | Maintenance | `vacuum_database()`, `export_to_csv()` |

### Automation Modules (`automation/`)

| Module | Purpose | Key Functions |
|--------|---------|---------------|
| `scheduler.py` | APScheduler configuration | `start_scheduler()`, `stop_scheduler()`, `list_jobs()` |
| `tasks.py` | Scheduled automation tasks | `task_collect_feeds()`, `task_enrich_iocs()`, `task_score_iocs()` |
| `alerting.py` | Alert system | `check_and_alert()`, `send_email_alert()` |

### Dashboard (`app/dashboard/`)

| Module | Purpose |
|--------|---------|
| `dashboard.py` | Streamlit web interface for visualization |

## API Integration

### VirusTotal API
- **Purpose**: Hash and URL analysis
- **Rate Limit**: 4 requests/minute (free tier)
- **Endpoints**: `/files/{hash}`, `/urls/{url_id}`

### AbuseIPDB API
- **Purpose**: IP reputation scoring
- **Rate Limit**: 1000 requests/day (free tier)
- **Endpoint**: `/check?ipAddress={ip}`

### AlienVault OTX API
- **Purpose**: Threat intelligence pulses
- **Rate Limit**: Unlimited (free tier)
- **Endpoints**: `/indicators/domain/{domain}`, `/indicators/IPv4/{ip}`

## Database Schema

```sql
CREATE TABLE iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,           -- ip, domain, url, hash
    value TEXT NOT NULL UNIQUE,       -- IOC value
    source TEXT,                      -- Feed source
    first_seen TEXT,                  -- ISO 8601 timestamp
    inserted_at TEXT,                 -- ISO 8601 timestamp
    metadata TEXT,                    -- JSON: enrichment data
    score INTEGER DEFAULT 0,          -- Threat score (0-100)
    score_updated_at TEXT             -- ISO 8601 timestamp
);

-- Performance indexes
CREATE INDEX idx_ioc_type ON iocs(ioc_type);
CREATE INDEX idx_score ON iocs(score DESC);
CREATE INDEX idx_inserted_at ON iocs(inserted_at DESC);
CREATE INDEX idx_value ON iocs(value);
```

## Technology Stack

- **Language**: Python 3.12
- **Database**: SQLite 3
- **Web Framework**: Streamlit
- **Data Processing**: Pandas
- **HTTP Requests**: Requests library
- **Environment**: python-dotenv

## Security Considerations

1. **API Keys**: Stored in `.env` file (not in version control)
2. **Rate Limiting**: Implemented to respect API limits
3. **Error Handling**: Comprehensive try-catch blocks
4. **Data Validation**: Regex validation for IOCs
5. **SQL Injection**: Parameterized queries used throughout

## Performance Optimizations

1. **Database Indexes**: Fast queries on type, score, date
2. **Batch Processing**: Enrichment and scoring in batches
3. **Rate Limiting**: Prevents API throttling
4. **Vacuum**: Regular cleanup for optimal DB size
5. **JSON Metadata**: Flexible storage for enrichment data

## Deployment

### Local Development
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m app.main run_all
streamlit run app/dashboard/dashboard.py
```

### Production Considerations
- Use PostgreSQL instead of SQLite for scale
- Implement Redis for caching
- Add authentication to dashboard
- Set up automated backups
- Implement logging and monitoring
- Use Docker for deployment

## Future Enhancements (Phase 9-10)

- **Automation**: Cron jobs for daily collection
- **Alerting**: Email/Telegram notifications
- **ML**: Anomaly detection
- **SIEM**: Integration with Splunk/ELK
- **Reporting**: PDF/Excel reports
- **API**: REST API for external access
