import os
import requests
import time
from app.config import VT_API_KEY, ABUSEIPDB_KEY


HEADERS_VT = {'x-apikey': VT_API_KEY} if VT_API_KEY else {}
HEADERS_ABUSE = {'Key': ABUSEIPDB_KEY, 'Accept': 'application/json'} if ABUSEIPDB_KEY else {}

# Rate limiting: minimum seconds between API calls
RATE_LIMIT_DELAY = 1.0  # 1 second between calls
_last_api_call = {}


def _rate_limit(api_name: str):
    """Simple rate limiting to avoid hitting API limits"""
    global _last_api_call
    if api_name in _last_api_call:
        elapsed = time.time() - _last_api_call[api_name]
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
    _last_api_call[api_name] = time.time()


def enrich_ioc(ioc_value, ioc_type):
    """
    Enrich an IOC by querying external threat intelligence APIs.
    
    Args:
        ioc_value: The IOC value (IP, domain, hash, URL)
        ioc_type: Type of IOC ('ip', 'domain', 'hash', 'url')
    
    Returns:
        Dictionary with enrichment data from VirusTotal and AbuseIPDB
    """
    res = {}
    
    # VirusTotal - for hashes and URLs
    if ioc_type == 'hash' and VT_API_KEY:
        try:
            _rate_limit('vt')
            url = f'https://www.virustotal.com/api/v3/files/{ioc_value}'
            r = requests.get(url, headers=HEADERS_VT, timeout=30)
            if r.status_code == 200:
                data = r.json().get('data', {})
                stats = data.get('attributes', {}).get('last_analysis_stats', {})
                res['vt'] = {
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'undetected_count': stats.get('undetected', 0),
                    'harmless_count': stats.get('harmless', 0),
                    'raw': data
                }
            elif r.status_code == 404:
                res['vt'] = {'malicious_count': 0, 'note': 'Not found in VT database'}
            else:
                res['vt_error'] = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            res['vt_error'] = str(e)
    
    elif ioc_type == 'url' and VT_API_KEY:
        try:
            _rate_limit('vt')
            # For URLs, we need to submit and get the ID
            import base64
            url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
            url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            r = requests.get(url, headers=HEADERS_VT, timeout=30)
            if r.status_code == 200:
                data = r.json().get('data', {})
                stats = data.get('attributes', {}).get('last_analysis_stats', {})
                res['vt'] = {
                    'malicious_count': stats.get('malicious', 0),
                    'suspicious_count': stats.get('suspicious', 0),
                    'undetected_count': stats.get('undetected', 0),
                    'harmless_count': stats.get('harmless', 0)
                }
            elif r.status_code == 404:
                res['vt'] = {'malicious_count': 0, 'note': 'Not found in VT database'}
            else:
                res['vt_error'] = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            res['vt_error'] = str(e)
    
    # AbuseIPDB - for IPs
    if ioc_type == 'ip' and ABUSEIPDB_KEY:
        try:
            _rate_limit('abuseipdb')
            url = 'https://api.abuseipdb.com/api/v2/check'
            params = {'ipAddress': ioc_value, 'maxAgeInDays': 90}
            r = requests.get(url, headers=HEADERS_ABUSE, params=params, timeout=30)
            if r.status_code == 200:
                data = r.json().get('data', {})
                res['abuseip'] = {
                    'abuse_score': data.get('abuseConfidenceScore', 0),
                    'total_reports': data.get('totalReports', 0),
                    'is_whitelisted': data.get('isWhitelisted', False),
                    'country_code': data.get('countryCode', 'Unknown'),
                    'usage_type': data.get('usageType', 'Unknown'),
                    'raw': data
                }
            else:
                res['abuseip_error'] = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as e:
            res['abuseip_error'] = str(e)
    
    return res


def enrich_ioc_safe(ioc_value, ioc_type):
    """
    Safe wrapper for enrich_ioc that never raises exceptions.
    Returns enrichment data or error information.
    """
    try:
        return enrich_ioc(ioc_value, ioc_type)
    except Exception as e:
        return {'error': f'Enrichment failed: {str(e)}'}


if __name__ == '__main__':
    # Test enrichment
    import sys
    if len(sys.argv) >= 3:
        ioc_val = sys.argv[1]
        ioc_typ = sys.argv[2]
        print(f"Enriching {ioc_typ}: {ioc_val}")
        result = enrich_ioc(ioc_val, ioc_typ)
        import json
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python threat_enrichment.py <ioc_value> <ioc_type>")
        print("Example: python threat_enrichment.py 8.8.8.8 ip")