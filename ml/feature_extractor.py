"""
ml/feature_extractor.py

Extract numerical features from IOC data for machine learning.
Converts IOC metadata into feature vectors for anomaly detection.
"""

import json
from datetime import datetime
import numpy as np


class FeatureExtractor:
    """Extract numerical features from IOC data for ML algorithms."""
    
    def __init__(self):
        self.feature_names = [
            'vt_detections',
            'abuse_score',
            'otx_pulses',
            'feed_count',
            'age_days',
            'score',
            'has_enrichment',
            'source_diversity'
        ]
    
    def extract_features(self, ioc):
        """
        Extract feature vector from a single IOC.
        
        Args:
            ioc: Dictionary with IOC data from database
        
        Returns:
            numpy array of 8 features
        """
        # Parse metadata
        metadata = {}
        if ioc.get('metadata'):
            try:
                metadata = json.loads(ioc['metadata']) if isinstance(ioc['metadata'], str) else ioc['metadata']
            except:
                metadata = {}
        
        enrichment = metadata.get('enrichment', {})
        
        # Feature 1: VirusTotal detections
        vt_detections = 0
        if 'vt' in enrichment:
            vt_detections = enrichment['vt'].get('malicious_count', 0)
        
        # Feature 2: AbuseIPDB score
        abuse_score = 0
        if 'abuseip' in enrichment:
            abuse_score = enrichment['abuseip'].get('abuse_score', 0)
        
        # Feature 3: OTX pulses
        otx_pulses = 0
        if 'otx' in enrichment:
            otx_pulses = enrichment['otx'].get('pulse_count', 0)
        
        # Feature 4: Feed count (number of sources)
        feed_count = len(metadata.get('sources', []))
        if feed_count == 0:
            feed_count = 1  # At least one source reported it
        
        # Feature 5: Age in days
        age_days = 0
        if ioc.get('first_seen'):
            try:
                first_seen_str = ioc['first_seen']
                if isinstance(first_seen_str, str):
                    # Handle ISO format with or without timezone
                    first_seen_str = first_seen_str.replace('Z', '+00:00')
                    first_seen = datetime.fromisoformat(first_seen_str)
                    age_days = (datetime.now() - first_seen.replace(tzinfo=None)).days
            except:
                age_days = 0
        
        # Feature 6: Current threat score
        score = ioc.get('score', 0)
        
        # Feature 7: Has enrichment data (binary)
        has_enrichment = 1 if enrichment else 0
        
        # Feature 8: Source diversity (unique sources)
        source_diversity = len(set(metadata.get('sources', [])))
        if source_diversity == 0:
            source_diversity = 1
        
        features = np.array([
            float(vt_detections),
            float(abuse_score),
            float(otx_pulses),
            float(feed_count),
            float(age_days),
            float(score),
            float(has_enrichment),
            float(source_diversity)
        ], dtype=float)
        
        return features
    
    def extract_batch(self, iocs):
        """
        Extract features for multiple IOCs.
        
        Args:
            iocs: List of IOC dictionaries
        
        Returns:
            Tuple of (features_array, valid_iocs_list)
        """
        features_list = []
        valid_iocs = []
        
        for ioc in iocs:
            try:
                features = self.extract_features(ioc)
                # Check for NaN or Inf values
                if not np.any(np.isnan(features)) and not np.any(np.isinf(features)):
                    features_list.append(features)
                    valid_iocs.append(ioc)
            except Exception as e:
                # Skip IOCs that cause errors
                continue
        
        if len(features_list) == 0:
            return np.array([]), []
        
        return np.array(features_list), valid_iocs
    
    def get_feature_names(self):
        """Get list of feature names."""
        return self.feature_names.copy()


if __name__ == "__main__":
    # Test feature extraction
    print("Testing FeatureExtractor...")
    
    # Sample IOC
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
    
    extractor = FeatureExtractor()
    features = extractor.extract_features(sample_ioc)
    
    print(f"Feature names: {extractor.get_feature_names()}")
    print(f"Feature values: {features}")
    print(f"Feature shape: {features.shape}")
    print("✓ Feature extraction test passed!")
