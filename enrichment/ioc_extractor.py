"""
enrichment/ioc_extractor.py
---------------------------
Extracts Indicators of Compromise (IoCs) from raw alert payloads.
"""

import re
from typing import Any, Dict, List, Optional
from ingestion.schema import IoC

# Regex patterns for IoC extraction
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}\b"
)
_RE_HASH_MD5    = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_HASH_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_RE_URL = re.compile(
    r"https?://[^\s\"'<>]+"
)

_INTERNAL_TLDS = {"local", "internal", "corp", "lan", "home", "localdomain"}

def _is_internal_domain(domain: str) -> bool:
    tld = domain.rsplit(".", 1)[-1].lower()
    return tld in _INTERNAL_TLDS

def extract_iocs(raw_alert: dict) -> List[IoC]:
    """
    Extract all IoCs from alert payload.
    Extract: all IPs (src + dst), file hashes (MD5/SHA256), domains, URLs
    
    Returns:
        List[IoC]: deduplicated list of IoC models.
    """
    seen = set()  # (type, value)
    results: List[IoC] = []

    def add(ioc_type: str, value: str, context: str) -> None:
        val_lower = value.lower().strip()
        key = (ioc_type, val_lower)
        if key not in seen:
            seen.add(key)
            results.append(IoC(type=ioc_type, value=value.strip(), context=context or None))

    def scan_text(text: str, context: str) -> None:
        # 1. URLs
        urls = _RE_URL.findall(text)
        for url in urls:
            add("url", url.rstrip(".,;:!?"), context)
        
        # Remove URLs before checking domains to avoid duplicate domain extraction
        text_no_urls = _RE_URL.sub("", text)
        
        # 2. Domains
        domains = _RE_DOMAIN.findall(text_no_urls)
        for dom in domains:
            if not _is_internal_domain(dom):
                add("domain", dom.lower(), context)

        # 3. IPs
        ips = _RE_IPV4.findall(text)
        for ip in ips:
            add("ip", ip, context)

        # 4. Hashes (MD5/SHA256)
        md5s = _RE_HASH_MD5.findall(text)
        for h in md5s:
            add("file_hash_md5", h.lower(), context)
            
        sha256s = _RE_HASH_SHA256.findall(text)
        for h in sha256s:
            add("file_hash_sha256", h.lower(), context)

    def recurse(val: Any, path: str = "") -> None:
        if isinstance(val, dict):
            for k, v in val.items():
                recurse(v, f"{path}.{k}" if path else k)
        elif isinstance(val, list):
            for i, item in enumerate(val):
                recurse(item, f"{path}[{i}]")
        elif isinstance(val, str):
            scan_text(val, path)

    recurse(raw_alert)
    return results
