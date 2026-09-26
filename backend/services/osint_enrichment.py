"""
OSINT enrichment service for domain intelligence.

Collects WHOIS domain registration age and Certificate Transparency logs (crt.sh).
Includes an in-memory TTL cache to minimize external network lookups.
Fails safe on any exception or timeout, returning None or 'unavailable' status.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from threading import Lock
import time
from urllib.parse import urlparse

import requests
import whois

from backend.utils.security_logging import safe_error_message

logger = logging.getLogger(__name__)

# TTL Cache settings
_DEFAULT_TTL_SECONDS = 3600  # 1 hour
_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_LOCK = Lock()


def clear_osint_cache() -> None:
    """Clear in-memory OSINT cache (used in testing)."""
    with _CACHE_LOCK:
        _CACHE.clear()


def get_domain_age(domain: str) -> dict | None:
    """
    Perform WHOIS lookup to calculate domain age in days and identify registrar.
    Fails safe on timeouts, socket errors, or parsing failures.
    """
    try:
        w = whois.whois(domain)
        creation_date = getattr(w, "creation_date", None)
        if creation_date is None:
            return None

        # WHOIS creation_date may return a list of dates
        if isinstance(creation_date, list):
            creation_date = min((d for d in creation_date if d is not None), default=None)

        if not creation_date:
            return None

        now = datetime.now(timezone.utc)
        if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is not None:
            diff = now - creation_date
        else:
            diff = datetime.utcnow() - creation_date

        days_old = max(0, diff.days)
        registrar = getattr(w, "registrar", None)
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else None

        return {
            "days_old": days_old,
            "registrar": str(registrar).strip() if registrar else "an unknown registrar",
            "creation_date": creation_date.isoformat() if hasattr(creation_date, "isoformat") else str(creation_date),
        }
    except Exception as e:
        logger.debug("WHOIS lookup failed for %s: %s", domain, safe_error_message(e))
        return None


def get_cert_transparency(domain: str) -> dict | None:
    """
    Query crt.sh Certificate Transparency logs to find shared certificate domains.
    Fails safe on HTTP errors, timeouts, or JSON decode errors.
    """
    try:
        clean_domain = domain.lower().strip()
        url = f"https://crt.sh/?q=%.{clean_domain}&output=json"
        resp = requests.get(
            url,
            headers={"User-Agent": "cyber-fraud-guardian/0.1.0"},
            timeout=8.0,
        )
        if resp.status_code != 200:
            return None

        data = resp.json()
        if not isinstance(data, list):
            return None

        shared_domains: set[str] = set()
        for entry in data:
            name_val = entry.get("name_value", "")
            if not name_val:
                continue
            for line in name_val.split("\n"):
                clean_name = line.strip().lower()
                if clean_name.startswith("*."):
                    clean_name = clean_name[2:]
                # Check for distinct domains that share this certificate
                if clean_name and clean_name != clean_domain and "." in clean_name:
                    # Ignore standard subdomains of the target domain itself
                    if not clean_name.endswith(f".{clean_domain}"):
                        shared_domains.add(clean_name)

        return {
            "shared_cert_domains": sorted(list(shared_domains))[:10]
        }
    except Exception as e:
        logger.debug("crt.sh lookup failed for %s: %s", domain, safe_error_message(e))
        return None


def get_osint_enrichment(domain: str) -> dict:
    """
    Primary OSINT collection function.
    Queries WHOIS domain age and crt.sh certificate transparency with TTL caching.
    Guaranteed to return a structured dict and never raise an exception.
    """
    if not domain or not isinstance(domain, str):
        return {
            "status": "unavailable",
            "domain": str(domain) if domain else "",
            "domain_age": None,
            "cert_transparency": None,
        }

    clean_domain = domain.strip().lower()
    if "://" in clean_domain:
        parsed = urlparse(clean_domain)
        clean_domain = parsed.hostname or clean_domain
    clean_domain = clean_domain.split("/")[0].split(":")[0].strip()

    if not clean_domain or "." not in clean_domain:
        return {
            "status": "unavailable",
            "domain": clean_domain,
            "domain_age": None,
            "cert_transparency": None,
        }

    now = time.time()
    with _CACHE_LOCK:
        if clean_domain in _CACHE:
            cached_time, cached_val = _CACHE[clean_domain]
            if now - cached_time < _DEFAULT_TTL_SECONDS:
                return cached_val

    domain_age = get_domain_age(clean_domain)
    cert_transparency = get_cert_transparency(clean_domain)

    if domain_age is not None and cert_transparency is not None:
        status = "complete"
    elif domain_age is not None or cert_transparency is not None:
        status = "partial"
    else:
        status = "unavailable"

    result = {
        "status": status,
        "domain": clean_domain,
        "domain_age": domain_age,
        "cert_transparency": cert_transparency,
    }

    with _CACHE_LOCK:
        _CACHE[clean_domain] = (now, result)

    return result
