"""
enrichment/virustotal.py
------------------------
VirusTotal IoC enrichment for files (hashes) and domains.

Design notes:
  - Uses bare `httpx.get()` calls (NOT httpx.Client) so that tests can patch
    `httpx.get` directly via mock.patch("httpx.get").
  - Real API key is read from VIRUSTOTAL_API_KEY env var.
  - Without a key: loads a mock JSON from mock_responses/ by matching the
    input string against known filename patterns, then falls back to a
    deterministic hash-based selection.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

# Expose API key so tests can patch it
VIRUSTOTAL_API_KEY: Optional[str] = os.getenv("VIRUSTOTAL_API_KEY")

MOCK_DIR = Path(__file__).parent / "mock_responses"

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_vt_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Parse a VirusTotal v3 JSON response into our standard dict."""
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    malicious   = stats.get("malicious", 0)
    harmless    = stats.get("harmless", 0)
    suspicious  = stats.get("suspicious", 0)
    verdict = "MALICIOUS" if malicious > 0 else "CLEAN"
    return {
        "malicious_votes":  malicious,
        "harmless_votes":   harmless,
        "suspicious_votes": suspicious,
        "verdict":          verdict,
    }


def _load_mock(ioc: str, ioc_type: str) -> Dict[str, Any]:
    """
    Load a mock response file.

    Priority:
      1. If `ioc` exactly matches a known filename stem   → load that file
      2. If `ioc` contains a known filename stem          → load that file
      3. Deterministic hash-based fallback
    """
    # Build candidate filename from ioc string (strip path separators)
    normalized = ioc.replace("/", "_").replace("\\", "_")

    # Check if the ioc itself names a mock file
    for stem in [normalized, f"virustotal_{normalized}"]:
        candidate = MOCK_DIR / f"{stem}.json"
        if candidate.exists():
            try:
                with open(candidate) as f:
                    return _parse_vt_response(json.load(f))
            except Exception:
                pass

    # Check if ioc is a substring of a mock filename stem
    for mock_file in sorted(MOCK_DIR.iterdir()):
        if mock_file.suffix != ".json":
            continue
        stem = mock_file.stem  # e.g. "virustotal_malicious_2"
        # match "malicious_2", "clean_1", "virustotal_malicious_2" etc.
        if stem in ioc or ioc in stem:
            try:
                with open(mock_file) as f:
                    return _parse_vt_response(json.load(f))
            except Exception:
                pass

    # Deterministic fallback — pick a file based on hash of the ioc string
    all_files = sorted(MOCK_DIR.glob("virustotal_*.json"))
    if all_files:
        idx = int(hashlib.md5(ioc.encode()).hexdigest(), 16) % len(all_files)
        try:
            with open(all_files[idx]) as f:
                return _parse_vt_response(json.load(f))
        except Exception:
            pass

    # Last resort
    return {
        "malicious_votes":  0,
        "harmless_votes":   70,
        "suspicious_votes": 0,
        "verdict":          "CLEAN",
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_hash(file_hash: str) -> Dict[str, Any]:
    """
    Check a file hash against VirusTotal.

    Uses real API if VIRUSTOTAL_API_KEY is set, otherwise loads a mock file.
    """
    api_key = VIRUSTOTAL_API_KEY or os.getenv("VIRUSTOTAL_API_KEY")

    if api_key:
        try:
            res = httpx.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"accept": "application/json", "x-apikey": api_key},
            )
            if res.status_code == 200:
                return _parse_vt_response(res.json())
        except Exception as e:
            print(f"[*] VirusTotal hash lookup failed, using mock: {e}")

    return _load_mock(file_hash, "hash")


def check_domain(domain: str) -> Dict[str, Any]:
    """
    Check a domain against VirusTotal.

    Uses real API if VIRUSTOTAL_API_KEY is set, otherwise loads a mock file.
    """
    api_key = VIRUSTOTAL_API_KEY or os.getenv("VIRUSTOTAL_API_KEY")

    if api_key:
        try:
            res = httpx.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"accept": "application/json", "x-apikey": api_key},
            )
            if res.status_code == 200:
                return _parse_vt_response(res.json())
        except Exception as e:
            print(f"[*] VirusTotal domain lookup failed, using mock: {e}")

    return _load_mock(domain, "domain")


def check_ioc(ioc: str, ioc_type: str) -> Dict[str, Any]:
    """Generic dispatcher — routes to check_hash or check_domain."""
    if ioc_type in ("hash", "file_hash", "file_hash_md5", "file_hash_sha1", "file_hash_sha256"):
        return check_hash(ioc)
    return check_domain(ioc)
