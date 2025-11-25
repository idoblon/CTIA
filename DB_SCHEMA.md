# CTI Database Schema

## Overview

The CTI (Cyber Threat Intelligence) system uses SQLite as its storage layer. The database stores Indicators of Compromise (IOCs) collected from various threat feeds, along with enrichment data and threat scores.

## Database Location

- **Path**: `db/cti.db`
- **Type**: SQLite 3
- **Size**: ~50-100 MB (depends on number of IOCs)

## Tables

### `iocs` Table

Main table storing all Indicators of Compromise.

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| `id` | INTEGER | Primary key | PRIMARY KEY, AUTOINCREMENT |
| `ioc_type` | TEXT | Type of IOC | NOT NULL |
| `value` | TEXT | The IOC value | NOT NULL, UNIQUE |
| `source` | TEXT | Source feed name | |
| `first_seen` | TEXT | First time seen (ISO 8601) | |
| `inserted_at` | TEXT | When inserted into DB (ISO 8601) | |
| `metadata` | TEXT | JSON metadata including enrichment | |
| `score` | INTEGER | Threat score (0-100) | DEFAULT 0 |
| `score_updated_at` | TEXT | When score was last updated | |

### IOC Types

- `ip` - IP addresses (IPv4)
- `domain` - Domain names
- `url` - URLs
- `hash` - File hashes (MD5, SHA1, SHA256)

### Metadata JSON Structure

The `metadata` column stores JSON data with the following structure:

```json
{
  "hash_algo": "sha256",
  "enrichment": {
    "vt": {
      "malicious_count": 45,
      "suspicious_count": 3,
      "undetected_count": 12,
      "harmless_count": 5
    },
    "abuseip": {
      "abuse_score": 85,
      "total_reports": 234,
      "is_whitelisted": false,
      "country_code": "CN",
      "usage_type": "Data Center"
    },
    "otx": {
      "pulse_count": 12,
      "pulses": [...]
    }
  },
  "enriched_at": "2025-11-25T16:45:00Z",
  "sources": ["feodotracker", "urlhaus_csv"]
}
```

## Indexes

For optimal query performance, the following indexes are created:

```sql
CREATE INDEX idx_ioc_type ON iocs(ioc_type);
CREATE INDEX idx_score ON iocs(score DESC);
CREATE INDEX idx_inserted_at ON iocs(inserted_at DESC);
CREATE INDEX idx_value ON iocs(value);
```

## Common Queries

### Get High-Severity IOCs

```sql
SELECT * FROM iocs 
WHERE score >= 75 
ORDER BY score DESC, inserted_at DESC 
LIMIT 100;
```

### Get IOCs by Type

```sql
SELECT * FROM iocs 
WHERE ioc_type = 'ip' 
ORDER BY score DESC 
LIMIT 100;
```

### Get Enriched IOCs

```sql
SELECT * FROM iocs 
WHERE metadata IS NOT NULL 
  AND metadata != '{}' 
  AND metadata LIKE '%enrichment%'
ORDER BY inserted_at DESC;
```

### Get Recent IOCs (Last 7 Days)

```sql
SELECT * FROM iocs 
WHERE inserted_at >= datetime('now', '-7 days')
ORDER BY inserted_at DESC;
```

### Statistics by Type

```sql
SELECT ioc_type, COUNT(*) as count 
FROM iocs 
GROUP BY ioc_type 
ORDER BY count DESC;
```

### Score Distribution

```sql
SELECT 
  CASE 
    WHEN score >= 75 THEN 'malicious'
    WHEN score >= 50 THEN 'suspicious'
    WHEN score >= 25 THEN 'low'
    ELSE 'informational'
  END as severity,
  COUNT(*) as count
FROM iocs
GROUP BY severity;
```

## Maintenance

### Vacuum Database

Reclaim unused space and optimize performance:

```bash
python -m app.db.db_maintenance vacuum
```

### Rebuild Indexes

Rebuild all indexes for better performance:

```bash
python -m app.db.db_maintenance rebuild_indexes
```

### Backup Database

Create a timestamped backup:

```bash
python -m app.db.db_maintenance backup
```

### Export Data

Export to CSV:
```bash
python -m app.db.db_maintenance export_csv output.csv 1000
```

Export to JSON:
```bash
python -m app.db.db_maintenance export_json output.json 1000
```

### Cleanup Old Data

Remove IOCs older than 90 days (dry run):
```bash
python -m app.db.db_maintenance cleanup 90
```

Execute cleanup:
```bash
python -m app.db.db_maintenance cleanup 90 --execute
```

## Performance Considerations

- **Indexes**: Ensure indexes are rebuilt periodically for optimal performance
- **Vacuum**: Run vacuum after large deletions to reclaim space
- **Batch Operations**: Use batch operations for enrichment and scoring
- **Query Limits**: Always use LIMIT clauses to prevent memory issues
- **Metadata Size**: Enrichment data can be large; consider cleanup policies

## Data Retention

Recommended retention policies:

- **Active IOCs**: Keep indefinitely
- **Low-score IOCs**: Keep for 90 days
- **Unenriched IOCs**: Keep for 30 days or enrich
- **Backups**: Keep weekly backups for 30 days
