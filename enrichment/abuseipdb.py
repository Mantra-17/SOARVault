import os
import json
import httpx
from pathlib import Path

# Paths to mock response folder
MOCK_DIR = Path(__file__).parent / "mock_responses"

def check_ip(ip: str) -> dict:
    """
    Enriches an IP address using AbuseIPDB.
    Uses real API key if available, otherwise maps the IP to a mock JSON file.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    
    if api_key:
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": api_key,
                "Accept": application/json
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": "90",
                "verbose": "true"
            }
            # Execute synchronous request
            with httpx.Client(timeout=10.0) as client:
                res = client.get(url, headers=headers, params=params)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    return {
                        "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "country_code": data.get("countryCode", "US"),
                        "isp": data.get("isp", "Unknown ISP"),
                        "domain": data.get("domain", ""),
                        "last_reported": data.get("lastReportedAt", "")
                    }
        except Exception as e:
            print(f"[*] AbuseIPDB API request failed, falling back to mock: {e}")

    # Private IP check
    parts = ip.split(".")
    if len(parts) == 4:
        # Simple private IP checks
        if parts[0] == "10" or (parts[0] == "192" and parts[1] == "168") or (parts[0] == "172" and 16 <= int(parts[1]) <= 31):
            return {
                "abuse_confidence_score": 0,
                "total_reports": 0,
                "country_code": "US",
                "isp": "Private Network",
                "domain": "local",
                "last_reported": None
            }
        
    # Mock fallback mapping based on the last octet
    try:
        last_octet = int(parts[-1])
    except ValueError:
        last_octet = 0
        
    last_digit = last_octet % 10
    
    # Map last digit to a specific mock file name
    mock_filename = "abuseipdb_score_0_1.json"
    if ip == "185.220.101.7":
        mock_filename = "abuseipdb_score_90.json"
    elif ip == "45.83.64.22":
        mock_filename = "abuseipdb_score_85.json"
    elif ip == "203.0.113.55":
        mock_filename = "abuseipdb_score_75.json"
    else:
        mapping = {
            0: "abuseipdb_score_0_1.json",
            1: "abuseipdb_score_0_2.json",
            2: "abuseipdb_score_15.json",
            3: "abuseipdb_score_30.json",
            4: "abuseipdb_score_50.json",
            5: "abuseipdb_score_75.json",
            6: "abuseipdb_score_85.json",
            7: "abuseipdb_score_90.json",
            8: "abuseipdb_score_100_1.json",
            9: "abuseipdb_score_100_2.json",
        }
        mock_filename = mapping.get(last_digit, "abuseipdb_score_0_1.json")
        
    mock_file = MOCK_DIR / mock_filename
    
    if mock_file.exists():
        try:
            with open(mock_file, "r") as f:
                data = json.load(f)
                return {
                    "abuse_confidence_score": data.get("abuse_confidence_score", 0),
                    "total_reports": data.get("total_reports", 0),
                    "country_code": data.get("country_code", "US"),
                    "isp": data.get("isp", "Mock ISP"),
                    "domain": data.get("domain", ""),
                    "last_reported": data.get("last_reported", "")
                }
        except Exception as e:
            print(f"[*] Error reading AbuseIPDB mock file {mock_filename}: {e}")
            
    # Default fallback
    return {
        "abuse_confidence_score": 10,
        "total_reports": 2,
        "country_code": "US",
        "isp": "Generic Mock ISP",
        "domain": "example.com",
        "last_reported": None
    }
