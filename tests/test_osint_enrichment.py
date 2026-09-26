"""
Tests for OSINT enrichment module and API endpoint.
All external network calls (whois, requests/crt.sh) are strictly mocked.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app, _incidents
from backend.models.evidence import IncidentEvidence, URLSignal
from backend.services.osint_enrichment import (
    clear_osint_cache,
    get_cert_transparency,
    get_domain_age,
    get_osint_enrichment,
)
from backend.utils.rate_limiter import get_rate_limiter


@pytest.fixture(autouse=True)
def reset_cache_and_incidents():
    clear_osint_cache()
    get_rate_limiter().reset()
    yield
    clear_osint_cache()
    get_rate_limiter().reset()


def test_get_domain_age_success():
    mock_whois_record = MagicMock()
    mock_whois_record.creation_date = datetime.now(timezone.utc) - timedelta(days=10)
    mock_whois_record.registrar = "TestRegistrar Inc."

    with patch("backend.services.osint_enrichment.whois.whois", return_value=mock_whois_record):
        age_data = get_domain_age("scam-domain.xyz")

    assert age_data is not None
    assert age_data["days_old"] == 10
    assert age_data["registrar"] == "TestRegistrar Inc."
    assert "creation_date" in age_data


def test_get_domain_age_list_dates():
    earlier = datetime.now(timezone.utc) - timedelta(days=20)
    later = datetime.now(timezone.utc) - timedelta(days=5)
    mock_whois_record = MagicMock()
    mock_whois_record.creation_date = [later, earlier]
    mock_whois_record.registrar = ["Primary Registrar", "Secondary"]

    with patch("backend.services.osint_enrichment.whois.whois", return_value=mock_whois_record):
        age_data = get_domain_age("multi-date.com")

    assert age_data is not None
    assert age_data["days_old"] == 20
    assert age_data["registrar"] == "Primary Registrar"


def test_get_domain_age_fails_safe():
    with patch("backend.services.osint_enrichment.whois.whois", side_effect=Exception("WHOIS server down")):
        age_data = get_domain_age("nonexistent.xyz")

    assert age_data is None


def test_get_cert_transparency_success():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {"name_value": "target.com\nother-phish.xyz\n*.campaign-domain.top"},
        {"name_value": "target.com\nsub.target.com"},
    ]

    with patch("backend.services.osint_enrichment.requests.get", return_value=mock_resp):
        cert_data = get_cert_transparency("target.com")

    assert cert_data is not None
    shared = cert_data["shared_cert_domains"]
    assert "other-phish.xyz" in shared
    assert "campaign-domain.top" in shared
    # Standard subdomains of target.com must not be in shared_cert_domains
    assert "sub.target.com" not in shared


def test_get_cert_transparency_fails_safe_on_http_error():
    mock_resp = MagicMock()
    mock_resp.status_code = 502
    with patch("backend.services.osint_enrichment.requests.get", return_value=mock_resp):
        cert_data = get_cert_transparency("error-domain.com")

    assert cert_data is None


def test_get_cert_transparency_fails_safe_on_network_exception():
    with patch("backend.services.osint_enrichment.requests.get", side_effect=Exception("Connection reset")):
        cert_data = get_cert_transparency("exception-domain.com")

    assert cert_data is None


def test_get_osint_enrichment_caching():
    mock_whois_record = MagicMock()
    mock_whois_record.creation_date = datetime.now(timezone.utc) - timedelta(days=3)
    mock_whois_record.registrar = "FastRegistrar"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = []

    with patch("backend.services.osint_enrichment.whois.whois", return_value=mock_whois_record) as mock_whois_fn:
        with patch("backend.services.osint_enrichment.requests.get", return_value=mock_resp) as mock_requests_fn:
            res1 = get_osint_enrichment("cached-domain.com")
            res2 = get_osint_enrichment("cached-domain.com")

    assert res1 == res2
    assert res1["status"] in ("complete", "partial")
    # Verify cached call didn't invoke network lookups a second time
    assert mock_whois_fn.call_count == 1
    assert mock_requests_fn.call_count == 1


def test_get_osint_enrichment_status_unavailable():
    with patch("backend.services.osint_enrichment.get_domain_age", return_value=None):
        with patch("backend.services.osint_enrichment.get_cert_transparency", return_value=None):
            res = get_osint_enrichment("unavailable.test")

    assert res["status"] == "unavailable"
    assert res["domain_age"] is None
    assert res["cert_transparency"] is None


def test_osint_endpoint_success():
    client = TestClient(app)

    # Setup incident in store
    incident = IncidentEvidence(
        message="Please click http://test-scam.xyz/verify",
        urls=[URLSignal(url="http://test-scam.xyz/verify", domain="test-scam.xyz")],
    )
    _incidents[incident.incident_id] = incident

    mock_osint_result = {
        "status": "complete",
        "domain": "test-scam.xyz",
        "domain_age": {"days_old": 2, "registrar": "BadRegistrar"},
        "cert_transparency": {"shared_cert_domains": ["partner-scam.top"]},
    }

    with patch("backend.services.osint_enrichment.get_osint_enrichment", return_value=mock_osint_result):
        resp = client.post(f"/api/incidents/{incident.incident_id}/osint")

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "complete"
    assert "evidence" in data
    assert len(data["evidence"]) >= 1
    assert data["raw"]["domain"] == "test-scam.xyz"


def test_osint_endpoint_disabled_flag():
    client = TestClient(app)
    incident = IncidentEvidence(
        urls=[URLSignal(url="http://test-disabled.xyz", domain="test-disabled.xyz")]
    )
    _incidents[incident.incident_id] = incident

    from backend.config import Settings
    mock_settings = Settings(osint_enabled=False)
    with patch("backend.main.get_settings", return_value=mock_settings):
        resp = client.post(f"/api/incidents/{incident.incident_id}/osint")

    assert resp.status_code == 200
    assert resp.json()["status"] == "disabled"


def test_osint_endpoint_incident_not_found():
    client = TestClient(app)
    resp = client.post("/api/incidents/INC-2026-NONEXIST/osint")
    assert resp.status_code in (400, 404)
