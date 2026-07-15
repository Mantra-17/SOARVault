"""
VirusTotal enrichment lookup module.
"""

import os
import json
import hashlib
import httpx
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

def _parse_vt_response(response_json: dict) -> dict:
    data = response_json.get("data", {})
    attributes = data.get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    
    malicious = stats.get("malicious", 0)
    harmless = stats.get("harmless", 0)
    suspicious = stats.get("suspicious", 0)
    
    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"
        
    return {
        "malicious_votes": malicious,
        "harmless_votes": harmless,
        "suspicious_votes": suspicious,
        "verdict": verdict
    }

def _get_mock_response(query: str) -> dict:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    mock_dir = os.path.join(base_dir, "mock_responses")
    
    if not os.path.exists(mock_dir):
        raise FileNotFoundError(f"Mock responses directory '{mock_dir}' not found.")
        
    mock_files = sorted([
        f for f in os.listdir(mock_dir)
        if f.startswith("virustotal_") and f.endswith(".json")
    ])
    
    if not mock_files:
        raise FileNotFoundError("No mock response files found in mock_responses.")
        
    selected_file = None
    
    # 1. Exact check if query contains the filename without extension (e.g. virustotal_clean_1 in query)
    for f in mock_files:
        name_without_ext = f[:-5]
        if name_without_ext in query:
            selected_file = f
            break
            
    # 2. Key phrase check (e.g. "clean_1", "malicious_2", etc.)
    if not selected_file:
        for f in mock_files:
            name_without_ext = f[:-5]
            key_part = name_without_ext.replace("virustotal_", "")
            if key_part in query:
                selected_file = f
                break
                
    # 3. Simple keyword check ("clean" -> clean_files, "malicious" -> malicious_files)
    if not selected_file:
        if "clean" in query:
            clean_files = [f for f in mock_files if "clean" in f]
            if clean_files:
                hasher = hashlib.md5(query.encode("utf-8"))
                hash_val = int(hasher.hexdigest(), 16)
                selected_file = clean_files[hash_val % len(clean_files)]
        elif "malicious" in query:
            malicious_files = [f for f in mock_files if "malicious" in f]
            if malicious_files:
                hasher = hashlib.md5(query.encode("utf-8"))
                hash_val = int(hasher.hexdigest(), 16)
                selected_file = malicious_files[hash_val % len(malicious_files)]
                
    # 4. Fallback to stable hash
    if not selected_file:
        hasher = hashlib.md5(query.encode("utf-8"))
        hash_val = int(hasher.hexdigest(), 16)
        selected_file = mock_files[hash_val % len(mock_files)]
        
    file_path = os.path.join(mock_dir, selected_file)
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)

def check_hash(file_hash: str) -> dict:
    """
    Query VirusTotal for a file hash reputation.
    If VIRUSTOTAL_API_KEY env variable is available, query the real API.
    Otherwise, load a deterministic mock response from mock_responses/.
    """
    if VIRUSTOTAL_API_KEY:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = httpx.get(url, headers=headers)
        response.raise_for_status()
        return _parse_vt_response(response.json())
    else:
        mock_data = _get_mock_response(file_hash)
        return _parse_vt_response(mock_data)

def check_domain(domain: str) -> dict:
    """
    Query VirusTotal for a domain reputation.
    If VIRUSTOTAL_API_KEY env variable is available, query the real API.
    Otherwise, load a deterministic mock response from mock_responses/.
    """
    if VIRUSTOTAL_API_KEY:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = httpx.get(url, headers=headers)
        response.raise_for_status()
        return _parse_vt_response(response.json())
    else:
        mock_data = _get_mock_response(domain)
        return _parse_vt_response(mock_data)
