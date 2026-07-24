import httpx

def get_geoip(ip: str) -> dict:
    """
    Looks up geolocation and ASN information for an IP address.
    Tries a free ip-api.com lookup, falling back to mock definitions for demo IPs.
    """
    # Demo mappings
    demo_mappings = {
        "185.220.101.7": {
            "country_code": "RO",
            "country_name": "Romania",
            "city": "Bucharest",
            "asn": "AS9009 (M247 Europe SRL)",
            "isp": "M247 Europe SRL"
        },
        "45.83.64.22": {
            "country_code": "DE",
            "country_name": "Germany",
            "city": "Frankfurt",
            "asn": "AS24940 (Hetzner Online)",
            "isp": "Hetzner Online"
        },
        "203.0.113.55": {
            "country_code": "SG",
            "country_name": "Singapore",
            "city": "Singapore",
            "asn": "AS132203 (Tencent Cloud)",
            "isp": "Tencent Cloud"
        }
    }
    
    if ip in demo_mappings:
        return demo_mappings[ip]

    # Private IP check
    parts = ip.split(".")
    if len(parts) == 4:
        if parts[0] == "10" or (parts[0] == "192" and parts[1] == "168") or (parts[0] == "172" and 16 <= int(parts[1]) <= 31):
            return {
                "country_code": "US",
                "country_name": "United States",
                "city": "Local Network",
                "asn": "Local Private ASN",
                "isp": "Private Network"
            }

    # Attempt public API lookup
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,isp,as"
        with httpx.Client(timeout=2.0) as client:
            res = client.get(url)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    return {
                        "country_code": data.get("countryCode", "US"),
                        "country_name": data.get("country", "United States"),
                        "city": data.get("city", "Unknown City"),
                        "asn": data.get("as", "Unknown ASN"),
                        "isp": data.get("isp", "Unknown ISP")
                    }
    except Exception as e:
        print(f"[*] GeoIP API request failed, using generic fallback: {e}")

    # Generic fallback
    return {
        "country_code": "US",
        "country_name": "United States",
        "city": "Dallas",
        "asn": "AS15169 (Google LLC)",
        "isp": "Google LLC"
    }
