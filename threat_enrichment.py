# Phase 4 – Threat Enrichment & Correlation Layer

import requests
import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("77c4a791f3b4229c9591864e347d35ddfd36ca98619606a837dfecb26f698542")
ABUSEIPDB_KEY = os.getenv("899fe71bb687e75e5a8fd519d0cd4d9ede76852984e8003110a0b422697b93048c90ebaa95abd084")
# OTX_KEY = os.getenv("OTX_KEY")

# ---------------------------------------
# 1. VIRUSTOTAL LOOKUP
# ---------------------------------------
def vt_lookup_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        return {"error": "VT lookup failed"}

    data = r.json()
    positives = data["data"]["attributes"]["last_analysis_stats"]["malicious"]

    return {
        "source": "VirusTotal",
        "hash": file_hash,
        "malicious_count": positives
    }


# ---------------------------------------
# 2. AbuseIPDB lookup
# ---------------------------------------
def abuseip_lookup(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}

    r = requests.get(url, headers=headers, params=params)

    if r.status_code != 200:
        return {"error": "AbuseIPDB lookup failed"}

    data = r.json()["data"]

    return {
        "source": "AbuseIPDB",
        "ip": ip,
        "abuse_score": data["abuseConfidenceScore"]
    }


# ---------------------------------------
# 3. OTX lookup (optional)
# ---------------------------------------
def otx_lookup(domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
    headers = {"X-OTX-API-KEY": OTX_KEY}

    r = requests.get(url, headers=headers)

    if r.status_code != 200:
        return {"error": "OTX lookup failed"}

    data = r.json()

    return {
        "source": "OTX",
        "domain": domain,
        "pulse_count": len(data["pulse_info"]["pulses"])
    }


# ---------------------------------------------------
# 4. CORRELATION ENGINE
# ---------------------------------------------------
def correlate_with_database(ioc_value):
    conn = sqlite3.connect("threat_data.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM ioc_list WHERE indicator = ?", (ioc_value,))
    row = cursor.fetchone()

    conn.close()

    if row:
        return {
            "matched": True,
            "existing_tag": row[2],      # threat_type
            "severity": row[3]          # severity
        }
    else:
        return {
            "matched": False,
            "existing_tag": None,
            "severity": 0
        }


# ---------------------------------------------------
# 5. MASTER FUNCTION FOR THREAT ENRICHMENT
# ---------------------------------------------------
def enrich_ioc(ioc_value, ioc_type):
    result = {}

    # run external lookups
    if ioc_type == "hash":
        result["vt"] = vt_lookup_hash(ioc_value)

    if ioc_type == "ip":
        result["abuseip"] = abuseip_lookup(ioc_value)

    if ioc_type == "domain":
        result["otx"] = otx_lookup(ioc_value)

    # correlate with local DB
    result["correlation"] = correlate_with_database(ioc_value)

    return result


# ---------------------------------------------------
# 6. DEMO RUN
# ---------------------------------------------------
if __name__ == "__main__":
    sample_hash = "44d88612fea8a8f36de82e1278abb02f"  # Example: EICAR test hash

    enriched = enrich_ioc(sample_hash, "hash")
    print("=== THREAT ENRICHMENT OUTPUT ===")
    print(enriched)
