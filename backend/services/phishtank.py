"""
PhishTank API adapter.

P0 threat-intel source. Free, requires registration for API key.
Checks URLs against PhishTank's verified phishing database.
Hardened against secret leakage in error messages.
"""

from __future__ import annotations

import httpx

from backend.config import get_settings
from backend.models.evidence import ThreatIntelResult
from backend.utils.security_logging import safe_error_message

_PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"


async def check_phishtank(urls: list[str]) -> list[ThreatIntelResult]:
    """
    Query PhishTank for each URL. Returns one ThreatIntelResult per URL.
    Works with or without an API key (uses public checkurl with User-Agent).
    """
    settings = get_settings()
    results = []

    if not settings.phishtank_api_key:
        for url in urls:
            results.append(ThreatIntelResult(
                source="phishtank",
                match=None,
                lookup_url=url,
                error="API key not configured",
            ))
        return results

    async with httpx.AsyncClient(timeout=10.0) as client:
        for url in urls:
            try:
                data_payload: dict[str, str] = {
                    "url": url,
                    "format": "json",
                }
                if settings.phishtank_api_key and settings.phishtank_api_key != "public":
                    data_payload["app_key"] = settings.phishtank_api_key

                resp = await client.post(
                    _PHISHTANK_URL,
                    data=data_payload,
                    headers={"User-Agent": "phishtank/cyber-fraud-guardian"},
                )
                resp.raise_for_status()
                data = resp.json()

                result_data = data.get("results", {})
                in_database = result_data.get("in_database", False)
                is_valid = result_data.get("valid", False)
                phish_id = result_data.get("phish_id", "N/A")

                # If URL is in PhishTank's database, it is a known phishing threat
                if in_database:
                    if is_valid:
                        match = True
                        details = f"Verified phishing site on PhishTank (ID: {phish_id})"
                    else:
                        match = True
                        details = f"Reported phishing site listed in PhishTank (ID: {phish_id}, verification in progress)"
                else:
                    match = False
                    details = "Not in PhishTank database"

                results.append(ThreatIntelResult(
                    source="phishtank",
                    match=match,
                    lookup_url=url,
                    details=details,
                ))

            except httpx.TimeoutException:
                results.append(ThreatIntelResult(
                    source="phishtank",
                    match=None,
                    lookup_url=url,
                    error="Request timed out",
                ))
            except Exception as e:
                results.append(ThreatIntelResult(
                    source="phishtank",
                    match=None,
                    lookup_url=url,
                    error=safe_error_message(e),
                ))

    return results
