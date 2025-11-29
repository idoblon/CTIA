# CTIA System - Visual Architecture Diagram

## System Architecture Overview

```mermaid
graph TB
    subgraph "External Sources"
        F1[Feodo Tracker<br/>Botnet IPs]
        F2[URLhaus<br/>Malicious URLs]
        F3[Malware Domains<br/>Bad Domains]
        A1[VirusTotal API<br/>Hash/URL Analysis]
        A2[AbuseIPDB API<br/>IP Reputation]
        A3[AlienVault OTX<br/>Threat Intel]
    end

    subgraph "Phase 3: Data Collection"
        TF[threat_feeds.py<br/>Fetch Feeds]
        RF[(raw_feeds/<br/>Raw Data)]
    end

    subgraph "Phase 4: Normalization"
        NM[normalizer.py<br/>Extract & Validate IOCs]
        NF[(normalized_feeds/<br/>JSON Files)]
    end

    subgraph "Phase 7: Storage Layer"
        DB[(SQLite Database<br/>cti.db<br/>129,251+ IOCs)]
        DBQ[db_queries.py<br/>Search & Stats]
        DBM[db_maintenance.py<br/>Vacuum & Export]
    end

    subgraph "Phase 5: Enrichment"
        TE[threat_enrichment.py<br/>API Integration]
        EB[enrichment_batch.py<br/>Batch Processing]
    end

    subgraph "Phase 6: Scoring"
        SC[scoring.py<br/>Threat Scoring<br/>0-100 Scale]
    end

    subgraph "Phase 8: Automation"
        SCHED[scheduler.py<br/>APScheduler]
        TASKS[tasks.py<br/>Automated Jobs]
        ALERT[alerting.py<br/>Threat Alerts]
    end

    subgraph "Phase 9: Visualization"
        DASH[dashboard.py<br/>Streamlit UI]
        CLI[main.py<br/>CLI Interface]
    end

    subgraph "Outputs"
        OUT1[Console Alerts]
        OUT2[Email Alerts]
        OUT3[CSV/JSON Export]
        OUT4[Web Dashboard]
    end

    F1 --> TF
    F2 --> TF
    F3 --> TF
    TF --> RF
    RF --> NM
    NM --> NF
    NF --> DB
    
    DB --> EB
    A1 --> TE
    A2 --> TE
    A3 --> TE
    TE --> EB
    EB --> DB
    
    DB --> SC
    SC --> DB
    
    SCHED --> TASKS
    TASKS --> TF
    TASKS --> EB
    TASKS --> SC
    TASKS --> DBM
    TASKS --> ALERT
    
    DB --> ALERT
    ALERT --> OUT1
    ALERT --> OUT2
    
    DB --> DBQ
    DB --> DBM
    DBM --> OUT3
    
    DB --> DASH
    DB --> CLI
    DASH --> OUT4
    
    style DB fill:#4a90e2,stroke:#2e5c8a,color:#fff
    style SCHED fill:#50c878,stroke:#2d7a4a,color:#fff
    style ALERT fill:#ff6b6b,stroke:#c92a2a,color:#fff
    style DASH fill:#9b59b6,stroke:#6c3483,color:#fff
```

## Data Flow Diagram

```mermaid
flowchart LR
    A[Threat Feeds] -->|Fetch| B[Raw Data]
    B -->|Normalize| C[Validated IOCs]
    C -->|Ingest| D[(Database)]
    D -->|Query| E[Enrichment APIs]
    E -->|Metadata| D
    D -->|Calculate| F[Threat Scores]
    F -->|Update| D
    D -->|Monitor| G{Score >= 75?}
    G -->|Yes| H[Send Alerts]
    G -->|No| I[Store Only]
    D -->|Display| J[Dashboard]
    D -->|Export| K[Reports]
    
    style D fill:#4a90e2,color:#fff
    style G fill:#ff6b6b,color:#fff
    style H fill:#ff6b6b,color:#fff
    style J fill:#9b59b6,color:#fff
```

## Automation Workflow

```mermaid
sequenceDiagram
    participant S as Scheduler
    participant T as Tasks
    participant C as Collection
    participant E as Enrichment
    participant SC as Scoring
    participant A as Alerting
    participant DB as Database

    Note over S: Daily at 2:00 AM
    S->>T: Trigger collect_feeds
    T->>C: Fetch & Normalize
    C->>DB: Ingest IOCs
    
    Note over S: Daily at 3:00 AM
    S->>T: Trigger enrich_iocs
    T->>E: Enrich 50 IOCs
    E->>DB: Update Metadata
    
    Note over S: Daily at 4:00 AM
    S->>T: Trigger score_iocs
    T->>SC: Calculate Scores
    SC->>DB: Update Scores
    
    Note over S: Every 6 Hours
    S->>T: Trigger check_threats
    T->>A: Check High Scores
    A->>DB: Query Score >= 75
    DB-->>A: High Threat IOCs
    A->>A: Send Console/Email Alerts
    
    Note over S: Weekly (Sunday 1:00 AM)
    S->>T: Trigger maintenance
    T->>DB: Vacuum & Rebuild Indexes
```

## Database Schema

```mermaid
erDiagram
    IOCS {
        INTEGER id PK
        TEXT ioc_type
        TEXT value UK
        TEXT source
        TEXT first_seen
        TEXT inserted_at
        TEXT metadata
        INTEGER score
        TEXT score_updated_at
    }
    
    IOCS ||--o{ INDEXES : "indexed by"
    
    INDEXES {
        TEXT idx_ioc_type
        TEXT idx_score
        TEXT idx_inserted_at
        TEXT idx_value
    }
```

## Component Interaction Map

```mermaid
graph LR
    subgraph "Core Modules"
        TF[threat_feeds]
        NM[normalizer]
        TE[threat_enrichment]
        EB[enrichment_batch]
        SC[scoring]
    end
    
    subgraph "Database Layer"
        DBD[database]
        DBQ[db_queries]
        DBM[db_maintenance]
    end
    
    subgraph "Automation"
        SCHED[scheduler]
        TASKS[tasks]
        ALERT[alerting]
    end
    
    subgraph "Interface"
        MAIN[main.py]
        DASH[dashboard]
    end
    
    TF --> NM
    NM --> DBD
    DBD --> EB
    TE --> EB
    EB --> DBD
    DBD --> SC
    SC --> DBD
    
    SCHED --> TASKS
    TASKS --> TF
    TASKS --> EB
    TASKS --> SC
    TASKS --> DBM
    TASKS --> ALERT
    
    DBQ --> DBD
    DBM --> DBD
    ALERT --> DBD
    
    MAIN --> TF
    MAIN --> NM
    MAIN --> DBD
    MAIN --> SCHED
    
    DASH --> DBQ
    DASH --> TE
    DASH --> SC
    
    style DBD fill:#4a90e2,color:#fff
    style SCHED fill:#50c878,color:#fff
    style ALERT fill:#ff6b6b,color:#fff
```

## Scoring Algorithm

```mermaid
graph TD
    A[IOC with Metadata] --> B{Has VT Data?}
    B -->|Yes| C[VT Positives × 8.0]
    B -->|No| D[0 points]
    
    A --> E{Has AbuseIPDB?}
    E -->|Yes| F[Abuse Score × 0.4]
    E -->|No| G[0 points]
    
    A --> H{Has OTX Data?}
    H -->|Yes| I[Pulse Count × 3.0]
    H -->|No| J[0 points]
    
    A --> K[Feed Count × 4.0]
    
    C --> L[Sum All Scores]
    D --> L
    F --> L
    G --> L
    I --> L
    J --> L
    K --> L
    
    L --> M{Score Range?}
    M -->|75-100| N[Malicious]
    M -->|50-74| O[Suspicious]
    M -->|25-49| P[Low]
    M -->|0-24| Q[Informational]
    
    style N fill:#ff6b6b,color:#fff
    style O fill:#ffa500,color:#fff
    style P fill:#ffeb3b,color:#000
    style Q fill:#4caf50,color:#fff
```

## Technology Stack

```mermaid
mindmap
    root((CTIA System))
        Language
            Python 3.12
        Database
            SQLite 3
            Indexes
            JSON Metadata
        Web Framework
            Streamlit
        Automation
            APScheduler
            Cron Triggers
        APIs
            VirusTotal
            AbuseIPDB
            AlienVault OTX
        Libraries
            Requests
            Pandas
            python-dotenv
        Security
            API Key Management
            Rate Limiting
            Parameterized Queries
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Development Environment"
        DEV[Local Machine<br/>Windows]
        VENV[Python Virtual Env<br/>.venv]
        ENV[.env File<br/>API Keys]
    end
    
    subgraph "Application Layer"
        APP[CTIA Application]
        SCHED[Background Scheduler]
        WEB[Streamlit Server<br/>Port 8501]
    end
    
    subgraph "Data Layer"
        DB[(SQLite DB<br/>db/cti.db)]
        RAW[(raw_feeds/)]
        NORM[(normalized_feeds/)]
    end
    
    subgraph "External Services"
        API1[VirusTotal]
        API2[AbuseIPDB]
        API3[OTX]
        SMTP[Email Server<br/>Optional]
    end
    
    DEV --> VENV
    VENV --> APP
    ENV --> APP
    
    APP --> SCHED
    APP --> WEB
    
    APP --> DB
    APP --> RAW
    APP --> NORM
    
    APP --> API1
    APP --> API2
    APP --> API3
    APP --> SMTP
    
    style DB fill:#4a90e2,color:#fff
    style SCHED fill:#50c878,color:#fff
    style WEB fill:#9b59b6,color:#fff
```

---

## Legend

- **Blue**: Database/Storage components
- **Green**: Automation/Scheduling components
- **Red**: Alerting/Warning components
- **Purple**: User Interface components
- **Gray**: External services/APIs

---

## Notes

1. All diagrams are created using Mermaid syntax for easy rendering
2. Can be viewed in GitHub, VS Code (with Mermaid extension), or online at mermaid.live
3. Diagrams show complete system architecture from data collection to alerting
4. Automation workflow demonstrates the scheduled task execution flow
