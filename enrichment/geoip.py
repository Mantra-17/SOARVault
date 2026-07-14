"""
IP Geolocation enrichment module using ip-api.com.
"""

import httpx

def get_geolocation(ip: str) -> dict:
    """
    Get geolocation details for an IP address using ip-api.com.
    Does not require an API key. Returns a dictionary with mapped fields.
    """
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = httpx.get(url, timeout=10.0)
        response.raise_for_status()
        data = response.json()
        
        if data.get("status") == "fail":
            return {
                "country": None,
                "country_code": None,
                "region": None,
                "city": None,
                "latitude": None,
                "longitude": None,
                "isp": None,
                "org": None,
                "asn": None,
                "timezone": None,
                "error": data.get("message", "unknown failure")
            }
            
        return {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "timezone": data.get("timezone")
        }
    except Exception as e:
        return {
            "country": None,
            "country_code": None,
            "region": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "isp": None,
            "org": None,
            "asn": None,
            "timezone": None,
            "error": str(e)
        }
