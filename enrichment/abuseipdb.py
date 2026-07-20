"""
AbuseIPDB enrichment lookup module.
"""

import os
import json
import re
import hashlib
import httpx
from dotenv import load_dotenv
from enrichment.cache import cache_response, get_cached_response

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

def query_ip(ip: str) -> dict:
    """
    Query AbuseIPDB for an IP address.
    Checks the local TTL cache (1 hour) first to prevent duplicate API hits.
    If ABUSEIPDB_API_KEY env variable is available, query the real API.
    Otherwise, load a deterministic mock response from mock_responses/.
    """
    cached_result = get_cached_response(ip)
    if cached_result is not None:
        return cached_result

    if ABUSEIPDB_API_KEY:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY
        }
        params = {
            "ipAddress": ip,
            "verbose": True
        }
        response = httpx.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json().get("data", {})
        result = {
            "abuse_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "last_reported_at": data.get("lastReportedAt")
        }
    else:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        mock_dir = os.path.join(base_dir, "mock_responses")
        
        if not os.path.exists(mock_dir):
            raise FileNotFoundError(f"Mock responses directory '{mock_dir}' not found.")
            
        mock_files = sorted([
            f for f in os.listdir(mock_dir)
            if f.startswith("abuseipdb_score_") and f.endswith(".json")
        ])
        
        if not mock_files:
            raise FileNotFoundError("No mock response files found in mock_responses.")
            
        selected_file = None
        
        # 1. Exact filename check (without extension) in ip string
        for f in mock_files:
            name_without_ext = f[:-5]
            if name_without_ext in ip:
                selected_file = f
                break
                
        # 2. Suffix check (like 100_2 or 0_2)
        if not selected_file:
            for suffix in ["100_1", "100_2", "0_1", "0_2"]:
                if suffix in ip:
                    for f in mock_files:
                        if suffix in f:
                            selected_file = f
                            break
                    if selected_file:
                        break
                        
        # 3. Numeric score check
        if not selected_file:
            numbers = re.findall(r'\d+', ip)
            for num in numbers:
                if num in ["15", "30", "50", "75", "85", "90"]:
                    for f in mock_files:
                        if f"_{num}.json" in f:
                            selected_file = f
                            break
                elif num == "100":
                    selected_file = "abuseipdb_score_100_1.json"
                elif num == "0":
                    selected_file = "abuseipdb_score_0_1.json"
                if selected_file:
                    break
                    
        # 4. Fallback to stable hash
        if not selected_file:
            hasher = hashlib.md5(ip.encode("utf-8"))
            hash_val = int(hasher.hexdigest(), 16)
            selected_file = mock_files[hash_val % len(mock_files)]
            
        file_path = os.path.join(mock_dir, selected_file)
        with open(file_path, "r", encoding="utf-8") as f:
            mock_data = json.load(f)
            
        result = {
            "abuse_score": mock_data.get("abuse_confidence_score"),
            "total_reports": mock_data.get("total_reports"),
            "country": mock_data.get("country_code"),
            "isp": mock_data.get("isp"),
            "last_reported_at": mock_data.get("last_reported")
        }

    cache_response(ip, result, ttl=3600)
    return result
