# Threat Intelligence API Rate Limits & Caching Architecture

This document details the rate limits of external threat intelligence APIs integrated into SOARVault and the caching strategies used to conserve quota.

## 1. AbuseIPDB

### Rate Limits
- **Free Tier Quotas**:
  - **Daily Limit**: 1,000 IP check queries per day.
  - **Check Endpoint**: `GET https://api.abuseipdb.com/api/v2/check`
  - **Subscribed / Paid Tier**: Higher limits (e.g. 10,000+ checks/day).

### Rate Limit Mitigation & Caching Strategy
- **Module**: [`enrichment/cache.py`](file:///c:/Users/Tirth%20Patel/OneDrive/Onedrive-Desktop/Infotact/SOARVault/enrichment/cache.py)
- **TTL (Time-To-Live)**: 3,600 seconds (1 hour).
- **Behavior**:
  - Before querying the AbuseIPDB API (or fallback mock data), `enrichment.abuseipdb.query_ip(ip)` checks the in-memory TTL cache.
  - If a valid cached response exists for `ip`, it returns the cached result immediately without issuing an HTTP network request.
  - Submitting identical IP lookups within the same hour consumes **only 1 API check credit**.
  - Cache entries automatically expire after 1 hour, ensuring threat intelligence remains fresh while respecting rate limits.

---

## 2. VirusTotal

### Rate Limits
- **Free Tier Quotas**:
  - **Daily Limit**: 500 requests per day.
  - **Rate Limit**: 4 requests per minute.
  - **Endpoints**: `/api/v3/files/{hash}`, `/api/v3/domains/{domain}`

---

## 3. GeoIP (ip-api.com)

### Rate Limits
- **Free Tier Quotas**:
  - **Rate Limit**: 45 requests per minute (HTTP).
  - **Endpoint**: `http://ip-api.com/json/{ip}`
