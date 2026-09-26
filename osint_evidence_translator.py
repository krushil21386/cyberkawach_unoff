"""
Translates raw osint_enrichment.py output into Evidence Contract items —
the same shape your rule engine / brand-impersonation / threat-intel
modules already produce, so the frontend's existing evidence list can
render these with zero new UI code.

Evidence item shape (matches the rest of the project):
{
    "module": "osint",
    "finding": "<human sentence>",
    "severity": "info" | "low" | "medium" | "high",
    "confidence": 0.0-1.0,
    "source": "whois" | "crt.sh",
}
"""

from __future__ import annotations

# Thresholds — tune these based on real testing, these are reasonable starting points
NEW_DOMAIN_HIGH_RISK_DAYS = 7
NEW_DOMAIN_MEDIUM_RISK_DAYS = 30


def translate_osint_evidence(osint_result: dict) -> list[dict]:
    """
    Takes the dict from get_osint_enrichment() and returns a list of
    Evidence Contract items ready to append to the same evidence array
    the frontend already renders.

    Returns an empty list if there's nothing worth showing the user —
    an old, unremarkable domain shouldn't clutter the evidence panel.
    """
    evidence: list[dict] = []

    if osint_result.get("status") == "unavailable":
        return evidence  # nothing to say — don't show a blank/error card

    evidence.extend(_domain_age_evidence(osint_result.get("domain_age")))
    evidence.extend(_cert_evidence(osint_result.get("cert_transparency")))

    return evidence


def _domain_age_evidence(domain_age: dict | None) -> list[dict]:
    if not domain_age or domain_age.get("days_old") is None:
        return []

    days = domain_age["days_old"]
    registrar = domain_age.get("registrar", "an unknown registrar")

    if days <= NEW_DOMAIN_HIGH_RISK_DAYS:
        return [{
            "module": "osint",
            "finding": (
                f"This website's domain was registered only {days} day"
                f"{'s' if days != 1 else ''} ago — right before you received "
                f"this message. Legitimate organizations don't set up new "
                f"websites days before contacting you."
            ),
            "severity": "high",
            "confidence": 0.85,
            "source": "whois",
        }]

    if days <= NEW_DOMAIN_MEDIUM_RISK_DAYS:
        return [{
            "module": "osint",
            "finding": (
                f"This website's domain is only {days} days old, registered "
                f"through {registrar}. New domains are more commonly used "
                f"for scams than established ones, though this alone isn't proof."
            ),
            "severity": "medium",
            "confidence": 0.6,
            "source": "whois",
        }]

    # Domain is old — this is reassuring context, not a red flag.
    return [{
        "module": "osint",
        "finding": f"This domain has existed for {days} days, which is not typical of a fresh scam site.",
        "severity": "info",
        "confidence": 0.5,
        "source": "whois",
    }]


def _cert_evidence(cert_info: dict | None) -> list[dict]:
    if not cert_info:
        return []

    related = cert_info.get("shared_cert_domains") or []
    if not related:
        return []

    preview = ", ".join(related[:3])
    more = f" and {len(related) - 3} more" if len(related) > 3 else ""

    return [{
        "module": "osint",
        "finding": (
            f"This website's security certificate is shared with other domains "
            f"({preview}{more}) — a pattern seen when scammers set up several "
            f"fake websites at once as part of the same campaign."
        ),
        "severity": "high",
        "confidence": 0.7,
        "source": "crt.sh",
    }]
