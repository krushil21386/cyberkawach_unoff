"""
Tests for OSINT evidence translator.
Verifies conversion of raw OSINT metrics into Evidence Contract items.
"""

from backend.services.osint_evidence_translator import translate_osint_evidence


def test_new_domain_produces_high_severity_evidence():
    result = {
        "status": "complete",
        "domain_age": {"days_old": 4, "registrar": "Fake Registrar"},
        "cert_transparency": {"shared_cert_domains": []},
    }
    evidence = translate_osint_evidence(result)
    assert len(evidence) == 1
    assert evidence[0]["severity"] == "high"
    assert "4 day" in evidence[0]["finding"]


def test_old_domain_produces_info_not_alarm():
    result = {
        "status": "complete",
        "domain_age": {"days_old": 900, "registrar": "Old Registrar"},
        "cert_transparency": {"shared_cert_domains": []},
    }
    evidence = translate_osint_evidence(result)
    assert len(evidence) == 1
    assert evidence[0]["severity"] == "info"


def test_shared_cert_domains_flagged_as_campaign_signal():
    result = {
        "status": "complete",
        "domain_age": {"days_old": 900, "registrar": "Old Registrar"},
        "cert_transparency": {"shared_cert_domains": ["sbi-kyc-update.tk", "sbi-verify.xyz"]},
    }
    evidence = translate_osint_evidence(result)
    severities = [e["severity"] for e in evidence]
    assert "high" in severities
    assert any("sbi-kyc-update.tk" in e["finding"] for e in evidence)


def test_unavailable_status_returns_no_evidence():
    result = {"status": "unavailable", "domain_age": None, "cert_transparency": None}
    assert translate_osint_evidence(result) == []


def test_no_findings_when_nothing_notable():
    result = {
        "status": "complete",
        "domain_age": {"days_old": 900, "registrar": "R"},
        "cert_transparency": {"shared_cert_domains": []},
    }
    evidence = translate_osint_evidence(result)
    # Old domain still produces one reassuring info-level item, no cert flag
    assert len(evidence) == 1
    assert evidence[0]["module"] == "osint"
