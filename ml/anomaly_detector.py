"""
ml/anomaly_detector.py

Anomaly detection for threat intelligence using Isolation Forest algorithm.
Detects zero-day threats and novel attack patterns.
"""

import sys
import os
import sqlite3
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import json

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.config import DB_PATH
from ml.feature_extractor import FeatureExtractor


class AnomalyDetector:
    """
    Detect anomalous IOCs using Isolation Forest algorithm.
    
    Anomalies indicate:
    - Potential zero-day threats
    - Novel attack patterns
    - Unusual behavioral signatures
    """
    
    def __init__(self, contamination=0.05, random_state=42):
        """
        Initialize anomaly detector.
        
        Args:
            contamination: Expected proportion of anomalies (default: 5%)
            random_state: Random seed for reproducibility
        """
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0,
            bootstrap=False,
            n_jobs=-1,  # Use all CPU cores
            verbose=0
        )
        self.scaler = StandardScaler()
        self.feature_extractor = FeatureExtractor()
        self.is_fitted = False
        self.contamination = contamination
    
    def fit(self, iocs):
        """
        Train the anomaly detector on IOC data.
        
        Args:
            iocs: List of IOC dictionaries from database
        
        Returns:
            Self (for method chaining)
        """
        print(f"[*] Training anomaly detector on {len(iocs)} IOCs...")
        
        # Extract features
        features, valid_iocs = self.feature_extractor.extract_batch(iocs)
        
        if len(features) == 0:
            raise ValueError("No valid features extracted from IOCs")
        
        print(f"[*] Extracted {len(features)} feature vectors")
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Train model
        self.model.fit(features_scaled)
        self.is_fitted = True
        
        print(f"[+] Anomaly detector trained successfully")
        print(f"[*] Expected anomaly rate: {self.contamination * 100:.1f}%")
        return self
    
    def predict(self, iocs):
        """
        Detect anomalies in IOC data.
        
        Args:
            iocs: List of IOC dictionaries
        
        Returns:
            List of anomaly results with scores and classifications
        """
        if not self.is_fitted:
            raise ValueError("Model not fitted. Call fit() first or load a trained model.")
        
        # Extract features
        features, valid_iocs = self.feature_extractor.extract_batch(iocs)
        
        if len(features) == 0:
            return []
        
        # Normalize features
        features_scaled = self.scaler.transform(features)
        
        # Predict anomalies (-1 for anomaly, 1 for normal)
        predictions = self.model.predict(features_scaled)
        
        # Get anomaly scores (lower = more anomalous)
        anomaly_scores = self.model.score_samples(features_scaled)
        
        # Prepare results
        results = []
        for ioc, pred, score in zip(valid_iocs, predictions, anomaly_scores):
            is_anomaly = (pred == -1)
            
            # Normalize score to 0-100 (higher = more anomalous)
            # Anomaly scores are typically in range [-0.5, 0.5]
            normalized_score = int((1 - (score + 0.5)) * 100)
            normalized_score = max(0, min(100, normalized_score))
            
            results.append({
                'ioc_value': ioc['value'],
                'ioc_type': ioc.get('ioc_type', 'unknown'),
                'is_anomaly': is_anomaly,
                'anomaly_score': normalized_score,
                'confidence': self._calculate_confidence(score),
                'original_score': ioc.get('score', 0),
                'reason': self._explain_anomaly(ioc, is_anomaly, score)
            })
        
        return results
    
    def _calculate_confidence(self, anomaly_score):
        """Calculate confidence level (0-100)."""
        # More extreme scores = higher confidence
        confidence = abs(anomaly_score) * 200
        return min(100, int(confidence))
    
    def _explain_anomaly(self, ioc, is_anomaly, score):
        """Generate human-readable explanation for anomaly."""
        if not is_anomaly:
            return "Normal threat pattern"
        
        # Analyze which features are unusual
        features = self.feature_extractor.extract_features(ioc)
        
        unusual_features = []
        
        # Check for unusual patterns
        if features[0] > 50:  # High VT detections
            unusual_features.append("exceptionally high malware detections")
        if features[1] > 90:  # High abuse score
            unusual_features.append("very high abuse confidence")
        if features[4] < 1:  # Very new
            unusual_features.append("newly discovered threat")
        if features[3] > 5:  # Many feeds
            unusual_features.append("reported by multiple sources")
        if features[5] > 80:  # High threat score
            unusual_features.append("high threat score")
        
        if unusual_features:
            return "Anomaly: " + ", ".join(unusual_features)
        else:
            return "Unusual threat pattern detected"
    
    def save_model(self, filepath='ml/models/anomaly_detector.pkl'):
        """Save trained model to disk."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_extractor': self.feature_extractor,
            'is_fitted': self.is_fitted,
            'contamination': self.contamination
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        print(f"[+] Model saved to {filepath}")
    
    def load_model(self, filepath='ml/models/anomaly_detector.pkl'):
        """Load trained model from disk."""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Model file not found: {filepath}")
        
        with open(filepath, 'rb') as f:
            model_data = pickle.load(f)
        
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_extractor = model_data['feature_extractor']
        self.is_fitted = model_data['is_fitted']
        self.contamination = model_data.get('contamination', 0.05)
        
        print(f"[+] Model loaded from {filepath}")


def get_iocs_from_db(limit=None):
    """Get IOCs from database."""
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database not found: {DB_PATH}")
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    query = "SELECT * FROM iocs"
    if limit:
        query += f" LIMIT {int(limit)}"
    
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    
    return [dict(row) for row in rows]


if __name__ == "__main__":
    """
    CLI for anomaly detection.
    
    Usage:
        python ml/anomaly_detector.py train [limit]
        python ml/anomaly_detector.py detect [limit]
        python ml/anomaly_detector.py stats
    """
    
    print("""
╔════════════════════════════════════════════════════════════════╗
║         CTIA Anomaly Detection - ML Module                     ║
║         Isolation Forest Algorithm                             ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python ml/anomaly_detector.py train [limit]")
        print("  python ml/anomaly_detector.py detect [limit]")
        print("  python ml/anomaly_detector.py stats")
        print("\nExamples:")
        print("  python ml/anomaly_detector.py train          # Train on all IOCs")
        print("  python ml/anomaly_detector.py train 10000    # Train on 10K IOCs")
        print("  python ml/anomaly_detector.py detect         # Detect on all IOCs")
        print("  python ml/anomaly_detector.py detect 5000    # Detect on 5K IOCs")
        sys.exit(1)
    
    command = sys.argv[1].lower()
    limit = int(sys.argv[2]) if len(sys.argv) > 2 else None
    
    if command == "train":
        # Train model
        print(f"[*] Loading IOCs from database (limit={limit or 'all'})...")
        try:
            iocs = get_iocs_from_db(limit=limit)
        except Exception as e:
            print(f"[!] Error loading IOCs: {e}")
            sys.exit(1)
        
        if len(iocs) < 100:
            print("[!] Warning: Training with fewer than 100 IOCs may not be effective")
            print(f"[!] Current IOC count: {len(iocs)}")
        
        detector = AnomalyDetector(contamination=0.05)
        
        try:
            detector.fit(iocs)
            detector.save_model()
            
            print(f"\n[+] Training complete!")
            print(f"[*] Model trained on {len(iocs)} IOCs")
            print(f"[*] Expected anomaly rate: 5%")
            print(f"[*] Model saved to: ml/models/anomaly_detector.pkl")
        except Exception as e:
            print(f"[!] Training failed: {e}")
            sys.exit(1)
        
    elif command == "detect":
        # Detect anomalies
        print(f"[*] Loading IOCs from database (limit={limit or 'all'})...")
        try:
            iocs = get_iocs_from_db(limit=limit)
        except Exception as e:
            print(f"[!] Error loading IOCs: {e}")
            sys.exit(1)
        
        print("[*] Loading trained model...")
        detector = AnomalyDetector()
        
        try:
            detector.load_model()
        except FileNotFoundError:
            print("[!] No trained model found. Run 'train' command first.")
            print("[!] Example: python ml/anomaly_detector.py train")
            sys.exit(1)
        
        print("[*] Detecting anomalies...")
        try:
            results = detector.predict(iocs)
        except Exception as e:
            print(f"[!] Detection failed: {e}")
            sys.exit(1)
        
        # Filter anomalies
        anomalies = [r for r in results if r['is_anomaly']]
        
        print(f"\n{'='*80}")
        print(f"ANOMALY DETECTION RESULTS")
        print(f"{'='*80}")
        print(f"Total IOCs analyzed: {len(results)}")
        print(f"Anomalies detected: {len(anomalies)} ({len(anomalies)/len(results)*100:.1f}%)")
        print(f"{'='*80}\n")
        
        if anomalies:
            # Sort by anomaly score
            anomalies.sort(key=lambda x: x['anomaly_score'], reverse=True)
            
            print(f"{'IOC VALUE':<40} {'TYPE':<8} {'ANOMALY':<8} {'CONF':<6} {'REASON'}")
            print("-" * 100)
            
            for a in anomalies[:20]:  # Show top 20
                ioc_val = a['ioc_value'][:37] + "..." if len(a['ioc_value']) > 40 else a['ioc_value']
                print(f"{ioc_val:<40} {a['ioc_type']:<8} {a['anomaly_score']:<8} {a['confidence']:<6} {a['reason']}")
            
            if len(anomalies) > 20:
                print(f"\n... and {len(anomalies) - 20} more anomalies")
        else:
            print("No anomalies detected.")
        
        print(f"\n[+] Detection complete!")
    
    elif command == "stats":
        # Show statistics
        print("[*] Loading model statistics...")
        detector = AnomalyDetector()
        
        try:
            detector.load_model()
            print(f"\n[+] Model Statistics:")
            print(f"  - Contamination rate: {detector.contamination * 100:.1f}%")
            print(f"  - Number of estimators: {detector.model.n_estimators}")
            print(f"  - Features: {', '.join(detector.feature_extractor.get_feature_names())}")
            print(f"  - Model fitted: {detector.is_fitted}")
        except FileNotFoundError:
            print("[!] No trained model found.")
            sys.exit(1)
    
    else:
        print(f"[!] Unknown command: {command}")
        print("[!] Valid commands: train, detect, stats")
        sys.exit(1)
