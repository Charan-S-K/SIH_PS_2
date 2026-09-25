"""
Unit and Integration Tests for Stage 10: Unified Findings Model & Correlation Engine.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.pcap import PcapFile
from app.models.job import AnalysisJob
from app.models.session import TcpSession
from app.models.rule_result import CryptoRuleResult
from app.models.finding import UnifiedFinding
from app.services.findings_service import FindingsService


def test_generate_fingerprint():
    """Verify deterministic SHA-256 fingerprint generation."""
    fp1 = UnifiedFinding.generate_fingerprint(
        job_id="job-123",
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        rule_id="RULE-TLS-001",
        tcp_stream=0,
        title="Deprecated TLS Version: TLS 1.0"
    )
    fp2 = UnifiedFinding.generate_fingerprint(
        job_id="job-123",
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        rule_id="RULE-TLS-001",
        tcp_stream=0,
        title="Deprecated TLS Version: TLS 1.0"
    )
    assert len(fp1) == 64
    assert fp1 == fp2

    # Different title should produce different fingerprint
    fp3 = UnifiedFinding.generate_fingerprint(
        job_id="job-123",
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        rule_id="RULE-TLS-001",
        tcp_stream=0,
        title="Different Title"
    )
    assert fp1 != fp3


def test_map_category_to_type():
    """Verify category mapping to unified finding_type."""
    assert FindingsService.map_category_to_type("TLS_PROTOCOL") == "CRYPTOGRAPHIC_WEAKNESS"
    assert FindingsService.map_category_to_type("CIPHER_SUITE") == "CRYPTOGRAPHIC_WEAKNESS"
    assert FindingsService.map_category_to_type("CERTIFICATE") == "CERTIFICATE_FORENSIC"
    assert FindingsService.map_category_to_type("PROTOCOL_BEHAVIOR") == "PROTOCOL_SECURITY"
    assert FindingsService.map_category_to_type("STARTTLS") == "STARTTLS_INTEGRITY"
    assert FindingsService.map_category_to_type("EVIDENCE") == "EVIDENCE_GAP"
    assert FindingsService.map_category_to_type("UNKNOWN") == "GENERAL_SECURITY"


def test_consolidate_job_findings(db_session: Session):
    """Test consolidation and deduplication of findings for an analysis job."""
    pcap = PcapFile(
        original_filename="findings_test.pcap",
        stored_filename="findings_test.pcap",
        file_path="/tmp/findings_test.pcap",
        file_size_bytes=1024,
        sha256="1234567890abcdef",
        md5="1234567890abcdef",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(
        pcap_file_id=pcap.id,
        status="COMPLETED"
    )
    db_session.add(job)
    db_session.commit()

    session = TcpSession(
        job_id=job.id,
        tcp_stream=0,
        client_ip="192.168.1.50",
        server_ip="10.0.0.50",
        client_port=40000,
        server_port=25,
        protocol="SMTP",
        start_time=1.0,
        end_time=3.0,
        first_frame_number=1,
        last_frame_number=10
    )
    db_session.add(session)
    db_session.commit()

    # Create two rule results with identical parameters (to trigger deduplication)
    rule1 = CryptoRuleResult(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        rule_id="RULE-TLS-001",
        category="TLS_PROTOCOL",
        severity="HIGH",
        name="Deprecated TLS Version: TLS 1.0",
        reason="Server accepted TLS 1.0 handshake",
        confidence=1.0,
        confidence_label="HIGH",
        remediation="Upgrade server configuration to require TLS 1.2 or TLS 1.3"
    )
    rule2 = CryptoRuleResult(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        rule_id="RULE-TLS-001",
        category="TLS_PROTOCOL",
        severity="HIGH",
        name="Deprecated TLS Version: TLS 1.0",
        reason="Server accepted TLS 1.0 handshake",
        confidence=1.0,
        confidence_label="HIGH",
        remediation="Upgrade server configuration to require TLS 1.2 or TLS 1.3"
    )
    # Create a unique rule result
    rule3 = CryptoRuleResult(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        rule_id="RULE-CERT-001",
        category="CERTIFICATE",
        severity="CRITICAL",
        name="Expired X.509 Certificate",
        reason="Certificate validity end date expired",
        confidence=1.0,
        confidence_label="HIGH",
        remediation="Replace expired certificate"
    )
    db_session.add_all([rule1, rule2, rule3])
    db_session.commit()

    service = FindingsService()
    summary, findings = service.consolidate_job_findings(db_session, job.id, force_refresh=True)

    assert summary.total_findings == 3
    assert summary.unique_findings == 2
    assert summary.duplicate_findings == 1
    assert summary.high_count == 1
    assert summary.critical_count == 1

    # Check deduplication primary record
    primaries = [f for f in findings if not f.is_duplicate and f.rule_id == "RULE-TLS-001"]
    assert len(primaries) == 1
    assert primaries[0].occurrence_count == 2

    # Check duplicate record
    duplicates = [f for f in findings if f.is_duplicate and f.rule_id == "RULE-TLS-001"]
    assert len(duplicates) == 1
    assert duplicates[0].occurrence_count == 1


def test_findings_api_endpoints(client: TestClient, db_session: Session):
    """Integration test for Stage 10 REST API endpoints."""
    pcap = PcapFile(
        original_filename="api_findings_test.pcap",
        stored_filename="api_findings_test.pcap",
        file_path="/tmp/api_findings_test.pcap",
        file_size_bytes=512,
        sha256="fedcba0987654321",
        md5="fedcba0987654321",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(
        pcap_file_id=pcap.id,
        status="COMPLETED"
    )
    db_session.add(job)
    db_session.commit()

    # 1. Trigger consolidation API endpoint
    res_consolidate = client.post(f"/api/v1/jobs/{job.id}/consolidate-findings", json={"force_refresh": True})
    assert res_consolidate.status_code == 200
    data_cons = res_consolidate.json()
    assert data_cons["job_id"] == job.id
    assert "summary" in data_cons
    assert "findings" in data_cons

    # 2. Get unified findings list endpoint
    res_list = client.get(f"/api/v1/jobs/{job.id}/findings")
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert data_list["job_id"] == job.id

    # 3. Get findings summary endpoint
    res_summary = client.get(f"/api/v1/jobs/{job.id}/findings/summary")
    assert res_summary.status_code == 200
    data_summ = res_summary.json()
    assert data_summ["job_id"] == job.id
