"""
Unit and Integration Tests for Recommendations Engine.
Verifies deterministic remediation recommendations generation, step-by-step configuration snippets,
affected components, compliance mappings, and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.finding import UnifiedFinding
from app.models.rule_result import CryptoRuleResult
from app.services.recommendations_engine import RecommendationsEngineService


@pytest.fixture
def prepare_job_with_findings(db_session: Session) -> AnalysisJob:
    """Fixture creating an analysis job with findings for recommendations testing."""
    job = AnalysisJob(
        id="recommendations-test-job-1",
        pcap_file_id="pcap-dummy-rec-1",
        status="COMPLETED"
    )
    db_session.add(job)

    # Critical Deprecated SSLv3 finding
    f1 = UnifiedFinding(
        id="find-rec-1",
        job_id=job.id,
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        severity="CRITICAL",
        title="Deprecated SSL 3.0 Protocol Usage",
        reason="SSL 3.0 observed in stream 0",
        confidence=0.95,
        tcp_stream=0,
        rule_id="RULE-SSLV3-DEPRECATED",
        fingerprint=UnifiedFinding.generate_fingerprint(job.id, "CRYPTOGRAPHIC_WEAKNESS", "RULE-SSLV3-DEPRECATED", 0, "Deprecated SSL 3.0 Protocol Usage")
    )

    # Weak RSA Key finding
    f2 = UnifiedFinding(
        id="find-rec-2",
        job_id=job.id,
        finding_type="CERTIFICATE_FORENSIC",
        severity="HIGH",
        title="Weak 1024-bit RSA Public Key",
        reason="1024-bit RSA key observed",
        confidence=0.90,
        tcp_stream=0,
        rule_id="RULE-RSA-WEAK-KEY",
        fingerprint=UnifiedFinding.generate_fingerprint(job.id, "CERTIFICATE_FORENSIC", "RULE-RSA-WEAK-KEY", 0, "Weak 1024-bit RSA Public Key")
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    return job


def test_generate_job_recommendations(db_session: Session, prepare_job_with_findings: AnalysisJob):
    """Test generating deterministic remediation recommendations tied to security rules."""
    service = RecommendationsEngineService()
    summary = service.generate_job_recommendations(db_session, prepare_job_with_findings.id)

    assert summary.job_id == prepare_job_with_findings.id
    assert summary.total_recommendations == 2
    assert summary.critical_count == 1
    assert summary.high_count == 1

    rec_ssl = next(r for r in summary.recommendations if r.rule_id == "RULE-SSLV3-DEPRECATED")
    assert "Enforce TLS 1.2+" in rec_ssl.title
    assert "smtpd_tls_protocols" in rec_ssl.recommended_action
    assert "Postfix" in rec_ssl.affected_component
    assert len(rec_ssl.compliance_frameworks) > 0


def test_fallback_baseline_recommendation(db_session: Session):
    """Test generating baseline posture recommendation when no findings are detected."""
    job = AnalysisJob(id="job-clean-rec", pcap_file_id="pcap-clean", status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    service = RecommendationsEngineService()
    summary = service.generate_job_recommendations(db_session, job.id)

    assert summary.total_recommendations == 1
    assert summary.recommendations[0].rule_id == "RULE-BASELINE-POSTURE"
    assert "Enforce Mail Server Cryptographic Posture" in summary.recommendations[0].title


def test_api_recommendations_endpoints(client: TestClient, db_session: Session, prepare_job_with_findings: AnalysisJob):
    """Test REST API POST /recommendations/generate/{job_id} and GET /recommendations/job/{job_id}."""
    job_id = prepare_job_with_findings.id

    # Generate endpoint
    gen_resp = client.post(f"/api/v1/recommendations/generate/{job_id}")
    assert gen_resp.status_code == 200
    gen_data = gen_resp.json()

    assert gen_data["job_id"] == job_id
    assert gen_data["total_recommendations"] == 2

    # Get summary endpoint
    get_resp = client.get(f"/api/v1/recommendations/job/{job_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()

    assert get_data["job_id"] == job_id
    assert len(get_data["recommendations"]) == 2
