# CTIA — Cyber Threat Intelligence Automation

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Phase 9 Complete](https://img.shields.io/badge/Status-Phase%209%20Complete-success.svg)](https://github.com)

A comprehensive, automated threat intelligence platform that collects, enriches, scores, and monitors cyber threats from multiple sources.

---

## 🎯 Project Overview

CTIA is a Python-based system that automates the entire threat intelligence lifecycle:

- **Automated Collection**: Fetches threat feeds from Feodo Tracker, URLhaus, and Malware Domains
- **IOC Normalization**: Extracts and validates IPs, domains, URLs, and file hashes
- **API Enrichment**: Enriches IOCs using VirusTotal, AbuseIPDB, and AlienVault OTX
- **Threat Scoring**: Calculates threat scores (0-100) based on multiple intelligence sources
```
CTIA/
├── app/
│   ├── core/                    # Core modules
│   │   ├── threat_feeds.py      # Feed collection
│   │   ├── normalizer.py        # IOC extraction
│   │   ├── threat_enrichment.py # API integration
│   │   ├── enrichment_batch.py  # Batch processing
│   │   └── scoring.py           # Threat scoring
│   ├── db/                      # Database layer
│   │   ├── database.py          # DB initialization
│   │   ├── db_queries.py        # Query utilities
│   │   └── db_maintenance.py    # Maintenance tools
│   ├── dashboard/               # Web interface
│   │   ├── dashboard.py         # Basic dashboard
│   │   └── dashboard_enhanced.py # Enhanced with Plotly
│   ├── utils/                   # Utilities
│   ├── config.py                # Configuration
│   └── main.py                  # CLI entry point
├── automation/                  # Phase 8: Automation
│   ├── scheduler.py             # APScheduler setup
│   ├── tasks.py                 # Scheduled tasks
│   └── alerting.py              # Alert system
├── db/                          # Database storage
│   └── cti.db                   # SQLite database
├── raw_feeds/                   # Raw threat feeds
├── normalized_feeds/            # Normalized IOC data
├── .env                         # API keys (not in repo)
├── requirements.txt             # Python dependencies
├── ARCHITECTURE.md              # System architecture
├── VISUAL_ARCHITECTURE.md       # Visual diagrams
├── DB_SCHEMA.md                 # Database schema
├── USER_GUIDE.md                # User documentation
└── DEMO_VIDEO_SCRIPT.md         # Video recording guide
```

---

## 🚀 Quick Start

### 1. Prerequisites

- Python 3.12 or higher
- Git (for cloning)
- API keys (optional but recommended):
  - [VirusTotal](https://www.virustotal.com/) - Free tier: 4 requests/minute
  - [AbuseIPDB](https://www.abuseipdb.com/) - Free tier: 1000 requests/day
  - [AlienVault OTX](https://otx.alienvault.com/) - Free tier: Unlimited

### 2. Installation

```bash
# Clone the repository
git clone <repository-url>
cd CTIA

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration

Create a `.env` file in the project root:

```env
# Required for enrichment
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_KEY=your_abuseipdb_api_key

# Optional
OTX_KEY=your_otx_api_key

# Optional: Email alerts
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
ALERT_EMAIL_FROM=ctia@yourdomain.com
ALERT_EMAIL_TO=admin@yourdomain.com
```

### 4. Initial Setup

```bash
# Run full pipeline (fetch, normalize, ingest)
python -m app.main run_all

# This will:
# 1. Fetch threat feeds
# 2. Normalize IOCs
# 3. Create database
# 4. Ingest IOCs
```

---

## 💻 Usage

### Manual Operations

```bash
# Fetch fresh threat feeds
python -m app.main fetch

# Normalize feeds
python -m app.main normalize

# Ingest to database
python -m app.main ingest

# Enrich IOCs (50 IPs)
python -m app.core.enrichment_batch 50 ip

# Score all IOCs
python -m app.core.scoring score_all

# View top 50 threats
python -m app.core.scoring top 50
```

### Automation (Phase 8)

```bash
# Start the automation scheduler
python -m app.main scheduler

# The scheduler will run:
# - Daily feed collection (2:00 AM)
# - Daily enrichment (3:00 AM)
# - Daily scoring (4:00 AM)
# - Weekly maintenance (Sunday 1:00 AM)
# - High threat checks (every 6 hours)

# Test individual tasks
python automation/tasks.py collect_feeds
python automation/tasks.py enrich_iocs
python automation/tasks.py score_iocs
python automation/tasks.py check_high_threats

# Test alerting
python automation/alerting.py 75
```

### Dashboard

```bash
# Launch basic dashboard
streamlit run app/dashboard/dashboard.py

# Launch enhanced dashboard (Phase 9)
streamlit run app/dashboard/dashboard_enhanced.py

# Access at: http://localhost:8501
```

### Database Queries

```bash
# View statistics
python -m app.db.db_queries stats

# Search IOCs
python -m app.db.db_queries search "malware"

# Get IOCs by type
python -m app.db.db_queries type ip 100

# Get recent IOCs (last 7 days)
python -m app.db.db_queries recent 7
```

### Maintenance

```bash
# Database info
python -m app.db.db_maintenance info

# Rebuild indexes
python -m app.db.db_maintenance rebuild_indexes

# Vacuum database
python -m app.db.db_maintenance vacuum

# Export to CSV
python -m app.db.db_maintenance export_csv output.csv 1000

# Backup database
python -m app.db.db_maintenance backup
```

---

## 📊 Threat Scoring

### Scoring Algorithm

```
Score = (VT_positives × 8.0) + (AbuseIPDB_score × 0.4) 
      + (OTX_pulses × 3.0) + (Feed_count × 4.0)
```

### Threat Labels

| Score Range | Label | Description |
|------------|-------|-------------|
| 75-100 | **Malicious** | High threat, immediate action required |
| 50-74 | **Suspicious** | Medium threat, investigation recommended |
| 25-49 | **Low** | Low threat, monitor |
| 0-24 | **Informational** | Minimal threat, informational only |

---

## 🎨 Dashboard Features

### Enhanced Dashboard (Phase 9)

- **Overview Tab**: IOC type distribution, threat level charts, score histograms
- **IOC Explorer**: Advanced filtering, search, detailed IOC information
- **Top Threats**: Ranked list of highest-scoring IOCs
- **Analytics**: Database statistics, enrichment rates, type breakdowns
- **Export**: CSV and JSON export with timestamps

### Interactive Visualizations

- Pie charts for IOC type distribution
- Bar charts for threat level distribution
- Histograms for score distribution
- Color-coded threat labels
- Real-time metrics

---

## 🔧 Technology Stack

- **Language**: Python 3.12
- **Database**: SQLite 3
- **Web Framework**: Streamlit
- **Visualization**: Plotly
- **Automation**: APScheduler
- **Data Processing**: Pandas
- **HTTP Requests**: Requests library
- **Environment**: python-dotenv

---

## 📈 Project Status

### Completed Phases

- ✅ **Phase 1-2**: Planning & Setup
- ✅ **Phase 3**: Data Collection
- ✅ **Phase 4**: IOC Parsing & Normalization
- ✅ **Phase 5**: Enrichment Module
- ✅ **Phase 6**: Scoring Engine
- ✅ **Phase 7**: Storage Layer
- ✅ **Phase 8**: Automation & Scheduling
- ✅ **Phase 9**: Enhanced Visualization

### Phase 10: Final Deliverables

- ✅ Architecture diagram (`ARCHITECTURE.md`)
- ✅ Visual architecture (`VISUAL_ARCHITECTURE.md`)
- ✅ Python scripts (all modules)
- ✅ Database schema (`DB_SCHEMA.md`)
- ✅ Documentation (`USER_GUIDE.md`)
- ✅ Enhanced dashboard
- ⏳ Demonstration video (script ready: `DEMO_VIDEO_SCRIPT.md`)

---

## 📹 Creating Demonstration Video

See `DEMO_VIDEO_SCRIPT.md` for a complete guide on recording your demonstration video.

**Quick Tips**:
1. Use OBS Studio or Windows Game Bar (Win+G)
2. Follow the script in `DEMO_VIDEO_SCRIPT.md`
3. Duration: 8-10 minutes
4. Show: Architecture, automation, dashboard, alerting
5. Export as MP4

---

## 🔒 Security Considerations

- API keys stored in `.env` (not in version control)
- Rate limiting to respect API limits
- Parameterized SQL queries to prevent injection
- Comprehensive error handling
- Input validation with regex

---

## 📚 Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture overview
- **[VISUAL_ARCHITECTURE.md](VISUAL_ARCHITECTURE.md)** - Visual diagrams (Mermaid)
- **[DB_SCHEMA.md](DB_SCHEMA.md)** - Database schema details
- **[USER_GUIDE.md](USER_GUIDE.md)** - Comprehensive user guide
- **[DEMO_VIDEO_SCRIPT.md](DEMO_VIDEO_SCRIPT.md)** - Video recording guide

---

## 🤝 Contributing

This is an academic project. For questions or suggestions, please contact the project maintainer.

---

## 📄 License

MIT License - See LICENSE file for details

---

## 👨‍💻 Author

**BCA 6th Semester Project**  
Cyber Threat Intelligence Automation System

---

## 🙏 Acknowledgments

- **Threat Feed Sources**: Feodo Tracker, URLhaus, Malware Domains
- **API Providers**: VirusTotal, AbuseIPDB, AlienVault OTX
- **Libraries**: Streamlit, Plotly, APScheduler, Pandas

---

**Status**: Phase 9 Complete ✅ | **Next**: Record Demonstration Video