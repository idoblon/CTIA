"""
tests/test_anomaly_detection.py

Test suite for ML-based anomaly detection.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ml.anomaly_detector import AnomalyDetector, get_iocs_from_db
from ml.feature_extractor import FeatureExtractor
import numpy as np
import json


def test_feature_extraction():
    """Test feature extraction from IOC data."""
    print("\n[Test 1] Feature Extraction")
    print("-" * 60)
    
    extractor = FeatureExtractor()
    
    # Create sample IOC
    sample_ioc = {
        'value': '192.168.1.1',
        'ioc_type': 'ip',
        'score': 75,
        'first_seen': '2024-01-01T00:00:00',
        'metadata': json.dumps({
            'enrichment': {
                'vt': {'malicious_count': 10},
                'abuseip': {'abuse_score': 85}
            },
            'sources': ['feed1', 'feed2', 'feed3']
        })
    }
    
    features = extractor.extract_features(sample_ioc)
    
    assert features.shape == (8,), f"Expected 8 features, got {features.shape}"
    assert not np.any(np.isnan(features)), "Features contain NaN values"
    assert not np.any(np.isinf(features)), "Features contain Inf values"
    
    print(f"  ✓ Feature names: {extractor.get_feature_names()}")
    print(f"  ✓ Feature values: {features}")
    print(f"  ✓ Feature shape: {features.shape}")
    print("  ✓ Feature extraction test PASSED")


def test_batch_extraction():
    """Test batch feature extraction."""
    print("\n[Test 2] Batch Feature Extraction")
    print("-" * 60)
    
    extractor = FeatureExtractor()
    
    # Create sample IOCs
    sample_iocs = [
        {
            'value': f'192.168.1.{i}',
            'ioc_type': 'ip',
            'score': 50 + i,
            'first_seen': '2024-01-01T00:00:00',
            'metadata': json.dumps({
                'enrichment': {'vt': {'malicious_count': i}},
                'sources': [f'feed{j}' for j in range(i % 3 + 1)]
            })
        }
        for i in range(10)
    ]
    
    features, valid_iocs = extractor.extract_batch(sample_iocs)
    
    assert features.shape[0] == len(valid_iocs), "Mismatch between features and IOCs"
    assert features.shape[1] == 8, f"Expected 8 features per IOC, got {features.shape[1]}"
    
    print(f"  ✓ Extracted features for {len(valid_iocs)} IOCs")
    print(f"  ✓ Feature matrix shape: {features.shape}")
    print("  ✓ Batch extraction test PASSED")


def test_anomaly_detection():
    """Test anomaly detection with sample data."""
    print("\n[Test 3] Anomaly Detection")
    print("-" * 60)
    
    # Try to load real IOCs, fall back to sample data
    try:
        iocs = get_iocs_from_db(limit=1000)
        print(f"  ✓ Loaded {len(iocs)} IOCs from database")
    except:
        print("  ! Database not available, using sample data")
        iocs = [
            {
                'value': f'sample-{i}.com',
                'ioc_type': 'domain',
                'score': np.random.randint(0, 100),
                'first_seen': '2024-01-01T00:00:00',
                'metadata': json.dumps({
                    'enrichment': {
                        'vt': {'malicious_count': np.random.randint(0, 20)},
                        'abuseip': {'abuse_score': np.random.randint(0, 100)}
                    },
                    'sources': [f'feed{j}' for j in range(np.random.randint(1, 5))]
                })
            }
            for i in range(100)
        ]
    
    if len(iocs) < 50:
        print(f"  ! Warning: Only {len(iocs)} IOCs available, test may be limited")
        return
    
    # Train detector
    detector = AnomalyDetector(contamination=0.1)
    
    train_size = int(len(iocs) * 0.8)
    train_iocs = iocs[:train_size]
    test_iocs = iocs[train_size:]
    
    print(f"  ✓ Training on {len(train_iocs)} IOCs...")
    detector.fit(train_iocs)
    
    # Detect anomalies
    print(f"  ✓ Testing on {len(test_iocs)} IOCs...")
    results = detector.predict(test_iocs)
    
    anomalies = [r for r in results if r['is_anomaly']]
    
    assert len(results) > 0, "No results returned"
    assert all('is_anomaly' in r for r in results), "Missing 'is_anomaly' field"
    assert all('anomaly_score' in r for r in results), "Missing 'anomaly_score' field"
    
    print(f"  ✓ Analyzed {len(results)} IOCs")
    print(f"  ✓ Detected {len(anomalies)} anomalies ({len(anomalies)/len(results)*100:.1f}%)")
    print("  ✓ Anomaly detection test PASSED")


def test_model_persistence():
    """Test model save and load."""
    print("\n[Test 4] Model Persistence")
    print("-" * 60)
    
    # Create sample data
    sample_iocs = [
        {
            'value': f'test-{i}.com',
            'ioc_type': 'domain',
            'score': np.random.randint(0, 100),
            'first_seen': '2024-01-01T00:00:00',
            'metadata': json.dumps({
                'enrichment': {'vt': {'malicious_count': np.random.randint(0, 20)}},
                'sources': ['feed1']
            })
        }
        for i in range(100)
    ]
    
    # Train and save
    detector1 = AnomalyDetector()
    detector1.fit(sample_iocs)
    
    test_path = 'ml/models/test_model.pkl'
    detector1.save_model(test_path)
    
    assert os.path.exists(test_path), "Model file not created"
    print(f"  ✓ Model saved to {test_path}")
    
    # Load and test
    detector2 = AnomalyDetector()
    detector2.load_model(test_path)
    
    assert detector2.is_fitted, "Loaded model not fitted"
    print(f"  ✓ Model loaded successfully")
    
    # Test predictions
    results = detector2.predict(sample_iocs[:10])
    assert len(results) > 0, "No predictions from loaded model"
    
    print(f"  ✓ Generated {len(results)} predictions")
    print("  ✓ Model persistence test PASSED")
    
    # Cleanup
    if os.path.exists(test_path):
        os.remove(test_path)


def run_all_tests():
    """Run all tests."""
    print("""
╔════════════════════════════════════════════════════════════════╗
║         CTIA Anomaly Detection - Test Suite                    ║
╚════════════════════════════════════════════════════════════════╝
    """)
    
    tests = [
        test_feature_extraction,
        test_batch_extraction,
        test_anomaly_detection,
        test_model_persistence
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"\n  ✗ Test FAILED: {e}")
            failed += 1
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed} passed, {failed} failed")
    print(f"{'='*60}\n")
    
    if failed == 0:
        print("[+] All tests passed! ✓")
    else:
        print(f"[!] {failed} test(s) failed")
        sys.exit(1)


if __name__ == "__main__":
    run_all_tests()
