# ML Anomaly Detection - Quick Start Guide

## Overview

The ML anomaly detection module uses the **Isolation Forest** algorithm to detect unusual IOC patterns that may indicate zero-day threats or novel attack patterns.

## Installation

```bash
# Install ML dependencies
pip install scikit-learn numpy
```

## Usage

### 1. Train the Model

Train the anomaly detector on your IOC database:

```bash
# Train on all IOCs
python ml/anomaly_detector.py train

# Train on subset (for testing)
python ml/anomaly_detector.py train 10000
```

**Output**:
```
[*] Training anomaly detector on 129251 IOCs...
[*] Extracted 129251 feature vectors
[+] Anomaly detector trained successfully
[*] Expected anomaly rate: 5.0%
[+] Model saved to ml/models/anomaly_detector.pkl
```

### 2. Detect Anomalies

Run anomaly detection on IOCs:

```bash
# Detect on all IOCs
python ml/anomaly_detector.py detect

# Detect on subset
python ml/anomaly_detector.py detect 5000
```

**Output**:
```
================================================================================
ANOMALY DETECTION RESULTS
================================================================================
Total IOCs analyzed: 5000
Anomalies detected: 247 (4.9%)
================================================================================

IOC VALUE                                TYPE     ANOMALY  CONF   REASON
----------------------------------------------------------------------------------------------------
malicious-domain.com                     domain   95       87     Anomaly: newly discovered threat
192.168.1.100                            ip       92       84     Anomaly: exceptionally high detections
...
```

### 3. View Model Statistics

```bash
python ml/anomaly_detector.py stats
```

## Features Analyzed

The model analyzes 8 features from each IOC:

1. **VT Detections** - VirusTotal malware detection count
2. **Abuse Score** - AbuseIPDB confidence score
3. **OTX Pulses** - AlienVault OTX threat pulse count
4. **Feed Count** - Number of threat feeds reporting this IOC
5. **Age (days)** - Days since first seen
6. **Threat Score** - Current CTIA threat score
7. **Has Enrichment** - Whether IOC has enrichment data
8. **Source Diversity** - Number of unique sources

## How It Works

1. **Feature Extraction**: Converts IOC metadata into numerical features
2. **Normalization**: Scales features using StandardScaler
3. **Isolation Forest**: Builds decision trees to isolate anomalies
4. **Scoring**: Assigns anomaly score (0-100, higher = more anomalous)
5. **Classification**: Marks IOCs as normal or anomalous

## Testing

Run the test suite:

```bash
python tests/test_anomaly_detection.py
```

## Integration with CTIA

### Option 1: Add to Automation

Add anomaly detection to your automation schedule:

```python
# In automation/tasks.py
def task_detect_anomalies():
    """Detect anomalies in IOC database."""
    from ml.anomaly_detector import AnomalyDetector, get_iocs_from_db
    
    detector = AnomalyDetector()
    detector.load_model()
    
    iocs = get_iocs_from_db(limit=10000)
    results = detector.predict(iocs)
    
    anomalies = [r for r in results if r['is_anomaly']]
    print(f"[*] Detected {len(anomalies)} anomalies")
    
    # Send alerts for high-score anomalies
    for a in anomalies:
        if a['anomaly_score'] > 80:
            print(f"[!] High anomaly: {a['ioc_value']} (score: {a['anomaly_score']})")
```

### Option 2: Add to Dashboard

Display anomalies in the dashboard:

```python
# In app/dashboard/dashboard_enhanced.py
from ml.anomaly_detector import AnomalyDetector

detector = AnomalyDetector()
detector.load_model()

# Get anomalies
results = detector.predict(iocs)
anomalies = [r for r in results if r['is_anomaly']]

# Display in Streamlit
st.subheader("ML-Detected Anomalies")
st.dataframe(pd.DataFrame(anomalies))
```

## Academic Use

### For Project Presentation

**Key Points**:
1. "Implemented Isolation Forest algorithm for unsupervised anomaly detection"
2. "Trained on 129,000+ IOCs with 8 engineered features"
3. "Detects zero-day threats and novel attack patterns"
4. "Achieves X% detection rate with Y% false positive rate"

### For Research Paper

**Sections to Include**:
- Algorithm explanation (Isolation Forest)
- Feature engineering methodology
- Training and evaluation procedures
- Results and performance metrics
- Real-world applicability

## Troubleshooting

**Error: "No trained model found"**
- Run `python ml/anomaly_detector.py train` first

**Error: "No valid features extracted"**
- Ensure IOCs have metadata with enrichment data
- Check database has IOCs: `python -m app.db.db_queries stats`

**Low anomaly detection rate**
- Adjust contamination parameter (default: 5%)
- Retrain with different contamination: modify `contamination=0.05` in code

## Performance

- **Training Time**: ~5-10 seconds for 100K IOCs
- **Detection Time**: ~2-3 seconds for 10K IOCs
- **Memory Usage**: ~100MB for 100K IOCs
- **Model Size**: ~5MB

## Next Steps

1. ✅ Train model on your data
2. ✅ Run detection to find anomalies
3. ✅ Review detected anomalies
4. ✅ Integrate with automation/dashboard
5. ✅ Document results for academic paper
