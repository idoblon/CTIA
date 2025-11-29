# Reports Directory

This directory contains report generation modules for the CTIA system.

## Available Reports

### PDF Reports (`pdf_generator.py`)

Generate professional PDF reports with threat intelligence statistics and top threats.

**Usage:**
```bash
# Generate default report
python reports/pdf_generator.py

# Custom output path and threat count
python reports/pdf_generator.py my_report.pdf 50
```

**Features:**
- Executive summary
- Comprehensive statistics table
- IOC type distribution
- Top threats with color-coded severity
- Professional formatting with ReportLab

**Requirements:**
- `reportlab` library (install via `pip install reportlab`)

---

## Report Types

### 1. Threat Intelligence Report (PDF)
- **File**: `pdf_generator.py`
- **Format**: PDF
- **Content**: Statistics, IOC distribution, top threats
- **Use Case**: Executive reporting, compliance documentation

### 2. Future Report Types (Optional)
- Excel reports with charts
- HTML reports for web viewing
- JSON exports for API integration
- CSV exports for data analysis

---

## Integration with Automation

Reports can be integrated into the automation scheduler for periodic generation:

```python
# In automation/tasks.py
def task_generate_weekly_report():
    from reports.pdf_generator import generate_pdf_report
    timestamp = datetime.now().strftime("%Y%m%d")
    generate_pdf_report(f"reports/weekly_report_{timestamp}.pdf")
```

---

## Configuration

No additional configuration required. Reports use the same database (`db/cti.db`) as the rest of the CTIA system.
