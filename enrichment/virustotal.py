import os
import json
import httpx
from pathlib import Path

# Paths to mock response folder
MOCK_DIR = Path(__file__).parent / "mock_responses"

def check_ioc(ioc: str, ioc_type: str) -> dict:
    """
    Enriches an IOC (hash or IP) using VirusTotal.
    Uses real API key if available, otherwise maps the IOC to a mock JSON file.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    if api_key:
        try:
            endpoint_path = "files" if ioc_type == "hash" else "ip_addresses"
            url = f"https://www.virustotal.com/api/v3/{endpoint_path}/{ioc}"
            headers = {
                "x-apikey": api_key
            }
            with httpx.Client(timeout=10.0) as client:
                res = client.get(url, headers=headers)
                if res.status_code == 200:
                    attrs = res.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = malicious + harmless + undetected
                    
                    return {
                        "malicious_votes": malicious,
                        "harmless_votes": harmless,
                        "total_votes": total,
                        "meaningful_name": attrs.get("meaningful_name") or attrs.get("names", [None])[0],
                        "reputation": attrs.get("reputation", 0)
                    }
        except Exception as e:
            print(f"[*] VirusTotal API request failed, falling back to mock: {e}")

    # Mock fallback logic
    mock_filename = "virustotal_clean_1.json"
    
    # If the hash is the default malicious hash or includes common bad hash patterns
    is_malicious = False
    if ioc_type == "hash":
        if ioc == "d41d8cd98f00b204e9800998ecf8427e" or ioc.startswith("bad") or ioc.endswith("bad"):
            is_malicious = True
            mock_filename = "virustotal_malicious_1.json"
        else:
            # Hash to pick a clean mock file
            val = sum(ord(c) for c in ioc) % 3
            mock_filename = f"virustotal_clean_{val + 1}.json"
    else:
        # If it's an IP, make it malicious if it matches our demo bad IPs
        if ioc in ("185.220.101.7", "45.83.64.22", "203.0.113.55"):
            is_malicious = True
            mock_filename = "virustotal_malicious_2.json"
        else:
            mock_filename = "virustotal_clean_1.json"
            
    mock_file = MOCK_DIR / mock_filename
    
    if mock_file.exists():
        try:
            with open(mock_file, "r") as f:
                data = json.load(f)
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                total = malicious + harmless + undetected
                
                return {
                    "malicious_votes": malicious,
                    "harmless_votes": harmless,
                    "total_votes": total,
                    "meaningful_name": attrs.get("meaningful_name"),
                    "reputation": attrs.get("reputation", 0)
                }
        except Exception as e:
            print(f"[*] Error reading VirusTotal mock file {mock_filename}: {e}")
            
    # Default fallback values
    return {
        "malicious_votes": 68 if is_malicious else 0,
        "harmless_votes": 0 if is_malicious else 70,
        "total_votes": 72,
        "meaningful_name": "wannacry.exe" if is_malicious else "clean_utility.exe",
        "reputation": -100 if is_malicious else 50
    }
