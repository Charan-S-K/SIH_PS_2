"""
Unit and Integration Tests for Prioritization Engine.
Verifies transparent evidence-backed Risk Priority Score calculation, customizable weights,
SHAP-equivalent feature attributions, ranking assignment, and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.finding import UnifiedFinding
from app.models.session import TcpSession
from app.schemas.prioritization import PrioritizationWeightsConfig
from app.services.prioritization_engine import PrioritizationEngineService


@pytest.fixture
def prepare_job_with_findings(db_session: Session) -> AnalysisJob:
    """Fixture creating an analysis job with TCP sessions and unified security findings."""
    job = AnalysisJob(
        id="prioritization-test-job-1",
        pcap_file_id="pcap-dummy-1",
        status="COMPLETED"
    )
    db_session.add(job)

    # Add TCP Session
    sess = TcpSession(
        id="sess-prio-1",
        job_id=job.id,
        tcp_stream=0,
        client_ip="203.0.113.5",  # Public IP
        server_ip="198.51.100.10", # Public IP
        client_port=54321,
        server_port=465,
        first_frame_number=1,
        last_frame_number=20
    )
    db_session.add(sess)

    # Add Critical Finding
    f1 = UnifiedFinding(
        id="find-crit-1",
        job_id=job.id,
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        severity="CRITICAL",
        title="Deprecated SSL 3.0 Protocol & Unencrypted Auth",
        reason="Critical cryptographic vulnerability detected",
        confidence=0.95,
        tcp_stream=0,
        rule_id="RULE-SSLV3-DEPRECATED",
        fingerprint=UnifiedFinding.generate_fingerprint(job.id, "CRYPTOGRAPHIC_WEAKNESS", "RULE-SSLV3-DEPRECATED", 0, "Deprecated SSL 3.0 Protocol & Unencrypted Auth")
    )
    # Add Low Finding
    f2 = UnifiedFinding(
        id="find-low-1",
        job_id=job.id,
        finding_type="CRYPTOGRAPHIC_INFO",
        severity="LOW",
        title="TLS 1.2 Cipher Suite Recommendation",
        reason="Minor cipher recommendation",
        confidence=0.70,
        tcp_stream=0,
        rule_id="RULE-CIPHER-REC",
        fingerprint=UnifiedFinding.generate_fingerprint(job.id, "CRYPTOGRAPHIC_INFO", "RULE-CIPHER-REC", 0, "TLS 1.2 Cipher Suite Recommendation")
    )
    db_session.add_all([f1, f2])
    db_session.commit()

    return job


def test_calculate_job_prioritization(db_session: Session, prepare_job_with_findings: AnalysisJob):
    """Test prioritization score calculation, ranking assignment, and factor attributions."""
    service = PrioritizationEngineService()
    summary = service.calculate_job_prioritization(db_session, prepare_job_with_findings.id)

    assert summary.job_id == prepare_job_with_findings.id
    assert summary.total_findings_evaluated == 2
    assert summary.rankings[0].rank == 1
    assert summary.rankings[0].finding_id == "find-crit-1"
    assert summary.rankings[0].priority_score > summary.rankings[1].priority_score
    assert summary.rankings[0].priority_level in ["CRITICAL_ACTION_REQUIRED", "HIGH_PRIORITY"]
    assert "feature_attributions_json" in summary.rankings[0].model_dump()


def test_custom_prioritization_weights(db_session: Session, prepare_job_with_findings: AnalysisJob):
    """Test custom prioritization weights altering risk score calculations."""
    service = PrioritizationEngineService()
    custom_cfg = PrioritizationWeightsConfig(
        weight_severity=0.60,
        weight_confidence=0.10,
        weight_exposure=0.10,
        weight_affected=0.10,
        weight_ml=0.10
    )
    summary = service.calculate_job_prioritization(db_session, prepare_job_with_findings.id, custom_cfg)

    assert summary.weights_config_json["weight_severity"] == 0.60
    assert summary.rankings[0].rank == 1
    assert summary.rankings[0].finding_id == "find-crit-1"


def test_api_prioritization_endpoints(client: TestClient, db_session: Session, prepare_job_with_findings: AnalysisJob):
    """Test REST API POST /prioritization/calculate/{job_id} and GET /prioritization/job/{job_id}."""
    job_id = prepare_job_with_findings.id

    # Calculate endpoint
    calc_resp = client.post(f"/api/v1/prioritization/calculate/{job_id}")
    assert calc_resp.status_code == 200
    calc_data = calc_resp.json()

    assert calc_data["job_id"] == job_id
    assert calc_data["total_findings_evaluated"] == 2
    assert len(calc_data["rankings"]) == 2
    assert calc_data["rankings"][0]["rank"] == 1

    # Get saved summary endpoint
    get_resp = client.get(f"/api/v1/prioritization/job/{job_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()

    assert get_data["job_id"] == job_id
    assert len(get_data["rankings"]) == 2
