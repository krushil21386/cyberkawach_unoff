"""
Evidence fusion — combines all upstream signals into a single risk score.

FUS-01: Weighted fusion with provenance tracking.
Every contributing factor is recorded so the score is explainable.
"""

from __future__ import annotations

from backend.models.evidence import (
    EvidenceType,
    IncidentEvidence,
    RiskAssessment,
    RiskLevel,
)


# ─── Signal weights for fusion ───

_WEIGHTS = {
    EvidenceType.THREAT_INTEL_HIT: 0.35,
    EvidenceType.BRAND_MISMATCH: 0.28,
    EvidenceType.RULE_MATCH: 0.25,
    EvidenceType.URL_ANALYSIS: 0.20,
    EvidenceType.PATTERN_MATCH: 0.15,
    EvidenceType.LAYA_SIGNAL: 0.20,
    EvidenceType.IOC_EXTRACTED: 0.05,
    EvidenceType.THREAT_INTEL_MISS: 0.00,  # Zero-penalty: unindexed != safe
    EvidenceType.REDIRECT_CHAIN: 0.10,
    EvidenceType.DOMAIN_AGE: 0.12,
    EvidenceType.CAMPAIGN_LINK: 0.12,
}

# ─── Risk level thresholds ───

_THRESHOLDS = {
    RiskLevel.CRITICAL: 0.75,
    RiskLevel.HIGH: 0.55,
    RiskLevel.MEDIUM: 0.35,
    RiskLevel.LOW: 0.15,
}


def _score_to_level(score: float) -> RiskLevel:
    """Convert numeric score to risk level."""
    if score >= _THRESHOLDS[RiskLevel.CRITICAL]:
        return RiskLevel.CRITICAL
    elif score >= _THRESHOLDS[RiskLevel.HIGH]:
        return RiskLevel.HIGH
    elif score >= _THRESHOLDS[RiskLevel.MEDIUM]:
        return RiskLevel.MEDIUM
    elif score >= _THRESHOLDS[RiskLevel.LOW]:
        return RiskLevel.LOW
    else:
        return RiskLevel.UNKNOWN


def fuse_evidence(evidence: IncidentEvidence) -> IncidentEvidence:
    """
    Fuse all evidence items into a single risk score with provenance.
    Uses weighted summation clamped to [0, 1] with targeted floors for verified threat vectors.
    """
    if not evidence.evidence:
        evidence.risk = RiskAssessment(
            level=RiskLevel.UNKNOWN,
            score=0.0,
            calibrated=False,
            contributing_factors=["No evidence items to evaluate"],
        )
        return evidence

    total_score = 0.0
    contributing_factors = []

    # Group evidence by type and compute weighted contribution
    type_contributions: dict[str, float] = {}

    for item in evidence.evidence:
        weight = _WEIGHTS.get(item.type, 0.05)
        contribution = weight * item.confidence
        total_score += contribution

        type_key = item.type.value
        type_contributions[type_key] = type_contributions.get(type_key, 0.0) + contribution

        if contribution > 0.05:  # Only track significant contributors
            contributing_factors.append(
                f"{item.source}: {item.description[:80]} (+{contribution:.2f})"
            )

    # Clamp baseline score to [0, 1]
    final_score = max(0.0, min(1.0, total_score))

    # 1. Authoritative Threat Intelligence Floor
    ti_hits = [
        item for item in evidence.evidence
        if item.type == EvidenceType.THREAT_INTEL_HIT
    ]
    if ti_hits:
        max_ti_conf = max(item.confidence for item in ti_hits)
        ti_floor = 0.75 + (0.15 * max_ti_conf)  # e.g. 0.88 for 0.85 conf, 0.89 for 0.95 conf
        if final_score < ti_floor:
            final_score = ti_floor
            contributing_factors.append(
                f"Authoritative threat intelligence match ({ti_hits[0].source}) elevates risk to {final_score:.2f}"
            )

    # 2. Brand Impersonation Floor (Mimicking a major entity on non-official domain)
    brand_hits = [
        item for item in evidence.evidence
        if item.type == EvidenceType.BRAND_MISMATCH and item.confidence >= 0.70
    ]
    if brand_hits:
        max_brand_conf = max(item.confidence for item in brand_hits)
        brand_floor = 0.65 + (0.15 * max_brand_conf)  # 0.75 - 0.80 (HIGH/CRITICAL)
        if final_score < brand_floor:
            final_score = brand_floor
            contributing_factors.append(
                f"Brand impersonation on unofficial domain elevates risk to {final_score:.2f}"
            )

    # 3. Fraud Category Rule Match with Actionable Vectors Floor
    rule_hits = [
        item for item in evidence.evidence
        if item.type == EvidenceType.RULE_MATCH and item.confidence >= 0.50
    ]
    has_urgency_or_money = any(
        item.type in (EvidenceType.PATTERN_MATCH, EvidenceType.IOC_EXTRACTED, EvidenceType.URL_ANALYSIS)
        for item in evidence.evidence
    )

    if rule_hits and has_urgency_or_money:
        max_rule_conf = max(item.confidence for item in rule_hits)
        rule_floor = 0.58 + (0.17 * max_rule_conf)  # 0.66 - 0.75 (HIGH)
        if final_score < rule_floor:
            final_score = rule_floor
            contributing_factors.append(
                f"Fraud category match with urgency/financial/IOC signals elevates risk to {final_score:.2f}"
            )

    # 4. Zero-Day Phishing URL Heuristics Floor (Suspicious TLD + Path/Keyword/HTTP)
    url_items = [
        item for item in evidence.evidence
        if item.type == EvidenceType.URL_ANALYSIS
    ]
    if len(url_items) >= 2 or any('at_symbol' in item.description or 'ip_domain' in item.description for item in url_items):
        url_floor = 0.60 + min(0.15, 0.05 * (len(url_items) - 1))
        if final_score < url_floor:
            final_score = url_floor
            contributing_factors.append(
                f"Multiple deceptive URL signals establish phishing floor of {final_score:.2f}"
            )

    # 5. Multi-Module Synergy Boost
    active_threat_types = set(
        item.type for item in evidence.evidence
        if item.type in (EvidenceType.THREAT_INTEL_HIT, EvidenceType.BRAND_MISMATCH,
                         EvidenceType.RULE_MATCH, EvidenceType.URL_ANALYSIS,
                         EvidenceType.PATTERN_MATCH, EvidenceType.LAYA_SIGNAL)
        and item.confidence >= 0.35
    )
    if len(active_threat_types) >= 3:
        final_score = min(1.0, max(final_score, 0.65) + 0.10)
        contributing_factors.append(
            f"Multi-vector correlation ({len(active_threat_types)} threat modules concurring) — score boosted"
        )

    evidence.risk = RiskAssessment(
        level=_score_to_level(final_score),
        score=round(final_score, 3),
        calibrated=False,
        contributing_factors=contributing_factors,
    )

    return evidence
