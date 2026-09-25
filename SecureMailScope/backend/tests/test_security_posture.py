"""
Unit and Integration Tests for Stage 12: Security Posture Engine.
Verifies explainable score calculation, severity deductions with confidence weighting,
critical vulnerability score capping guardrails, per-server aggregation, and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.pcap import PcapFile
from app.models.job import AnalysisJob
from app.models.session import TcpSession
from app.models.finding import UnifiedFinding
from app.services.security_posture_engine import SecurityPostureEngine, SEVERITY_DEDUCTION_WEIGHTS


def test_grade_and_risk_mapping_boundaries():
    """Verify numeric score to grade/risk mapping thresholds and bounds."""
    engine = SecurityPostureEngine()

    # EXCELLENT (90-100)
    g, r = engine.calculate_grade_and_risk(100)
    assert (g, r) == ("EXCELLENT", "LOW")

    g, r = engine.calculate_grade_and_risk(90)
    assert (g, r) == ("EXCELLENT", "LOW")

    # GOOD (75-89)
    g, r = engine.calculate_grade_and_risk(89)
    assert (g, r) == ("GOOD", "LOW")

    g, r = engine.calculate_grade_and_risk(75)
    assert (g, r) == ("GOOD", "LOW")

    # FAIR (50-74)
    g, r = engine.calculate_grade_and_risk(74)
    assert (g, r) == ("FAIR", "MEDIUM")

    g, r = engine.calculate_grade_and_risk(50)
    assert (g, r) == ("FAIR", "MEDIUM")

    # POOR (25-49)
    g, r = engine.calculate_grade_and_risk(49)
    assert (g, r) == ("POOR", "HIGH")

    g, r = engine.calculate_grade_and_risk(25)
    assert (g, r) == ("POOR", "HIGH")

    # CRITICAL_RISK (0-24)
    g, r = engine.calculate_grade_and_risk(24)
    assert (g, r) == ("CRITICAL_RISK", "CRITICAL")

    g, r = engine.calculate_grade_and_risk(0)
    assert (g, r) == ("CRITICAL_RISK", "CRITICAL")


def test_critical_vulnerability_score_capping():
    """
    PROVE: Critical vulnerability guardrail.
    Verifies that a confirmed CRITICAL vulnerability caps score at CRITICAL_RISK,
    even if the raw mathematical score is higher.
    """
    engine = SecurityPostureEngine()

    # Raw score 85 with has_critical_finding=True -> grade capped to CRITICAL_RISK
    g, r = engine.calculate_grade_and_risk(85, has_critical_finding=True)
    assert g == "CRITICAL_RISK"
    assert r == "CRITICAL"


def test_calculate_job_posture_clean_job(db_session: Session):
    """Test security posture evaluation on a clean job with 0 findings."""
    pcap = PcapFile(
        original_filename="clean.pcap",
        stored_filename="clean.pcap",
        file_path="/tmp/clean.pcap",
        file_size_bytes=1024,
        sha256="clean123sha",
        md5="clean123md5",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(pcap_file_id=pcap.id, status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    engine = SecurityPostureEngine()
    dashboard = engine.calculate_job_posture(db_session, job.id, force_recalculate=True)

    assert dashboard.job_id == job.id
    assert dashboard.job_posture.overall_score == 100
    assert dashboard.job_posture.overall_grade == "EXCELLENT"
    assert dashboard.job_posture.risk_level == "LOW"
    assert dashboard.job_posture.total_deduction == 0.0
    assert dashboard.job_posture.findings_count == 0
    assert "No security posture flaws" in dashboard.job_posture.posture_summary


def test_calculate_job_posture_with_findings_and_duplicates(db_session: Session):
    """
    Test job security posture calculation with multiple findings,
    confidence weighting, and verification that duplicate findings are ignored.
    """
    pcap = PcapFile(
        original_filename="findings.pcap",
        stored_filename="findings.pcap",
        file_path="/tmp/findings.pcap",
        file_size_bytes=2048,
        sha256="find123sha",
        md5="find123md5",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(pcap_file_id=pcap.id, status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    session = TcpSession(
        job_id=job.id,
        tcp_stream=0,
        client_ip="192.168.1.50",
        server_ip="10.0.0.1",
        client_port=49000,
        server_port=25,
        protocol="SMTP",
        start_time=1.0,
        end_time=2.0,
        first_frame_number=1,
        last_frame_number=10
    )
    db_session.add(session)
    db_session.commit()

    # Unique Finding 1: HIGH severity (weight 20.0 * confidence 1.0 = deduction 20.0)
    f1 = UnifiedFinding(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        finding_type="PROTOCOL_VIOLATION",
        severity="HIGH",
        title="Plaintext Authentication",
        reason="AUTH PLAIN over unencrypted TCP",
        confidence=1.0,
        confidence_label="HIGH",
        rule_id="RULE-SMTP-001",
        fingerprint="fp_uniq_1",
        is_duplicate=False,
        occurrence_count=1
    )
    # Unique Finding 2: MEDIUM severity (weight 10.0 * confidence 0.5 = deduction 5.0)
    f2 = UnifiedFinding(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        severity="MEDIUM",
        title="Weak Cipher Suite",
        reason="3DES CBC cipher allowed",
        confidence=0.5,
        confidence_label="MEDIUM",
        rule_id="RULE-TLS-003",
        fingerprint="fp_uniq_2",
        is_duplicate=False,
        occurrence_count=1
    )
    # Duplicate Finding 3: Should be skipped in deduction total
    f3 = UnifiedFinding(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        finding_type="PROTOCOL_VIOLATION",
        severity="HIGH",
        title="Plaintext Authentication (Duplicate)",
        reason="AUTH PLAIN over unencrypted TCP duplicate",
        confidence=1.0,
        confidence_label="HIGH",
        rule_id="RULE-SMTP-001",
        fingerprint="fp_uniq_1",
        is_duplicate=True,
        occurrence_count=2
    )
    db_session.add_all([f1, f2, f3])
    db_session.commit()

    engine = SecurityPostureEngine()
    dashboard = engine.calculate_job_posture(db_session, job.id, force_recalculate=True)

    # Deduction total: 20.0 + 5.0 = 25.0 -> Score = 100 - 25 = 75 (GOOD, LOW risk)
    assert dashboard.job_posture.total_deduction == 25.0
    assert dashboard.job_posture.overall_score == 75
    assert dashboard.job_posture.overall_grade == "GOOD"
    assert dashboard.job_posture.findings_count == 2
    assert len(dashboard.job_posture.contributing_findings) == 2


def test_server_posture_aggregation(db_session: Session):
    """Test server-level posture calculation and stream grouping."""
    pcap = PcapFile(
        original_filename="servers.pcap",
        stored_filename="servers.pcap",
        file_path="/tmp/servers.pcap",
        file_size_bytes=2048,
        sha256="srv123sha",
        md5="srv123md5",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(pcap_file_id=pcap.id, status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    # Server A: 10.0.0.1 (2 streams)
    s1 = TcpSession(job_id=job.id, tcp_stream=0, server_ip="10.0.0.1", server_port=25, protocol="SMTP", first_frame_number=1, last_frame_number=5)
    s2 = TcpSession(job_id=job.id, tcp_stream=1, server_ip="10.0.0.1", server_port=465, protocol="SMTPS", first_frame_number=6, last_frame_number=10)
    # Server B: 10.0.0.2 (1 stream)
    s3 = TcpSession(job_id=job.id, tcp_stream=2, server_ip="10.0.0.2", server_port=993, protocol="IMAPS", first_frame_number=11, last_frame_number=15)
    db_session.add_all([s1, s2, s3])
    db_session.commit()

    # Finding on Server A (CRITICAL, deduction 35)
    f_srv_a = UnifiedFinding(
        job_id=job.id,
        tcp_session_id=s1.id,
        tcp_stream=0,
        finding_type="SECURITY_FLAW",
        severity="CRITICAL",
        title="Active STARTTLS Injection Vulnerability",
        reason="MitM response tampering",
        confidence=1.0,
        confidence_label="HIGH",
        rule_id="RULE-STARTTLS-001",
        fingerprint="fp_crit_srv_a",
        is_duplicate=False,
        occurrence_count=1
    )
    db_session.add(f_srv_a)
    db_session.commit()

    engine = SecurityPostureEngine()
    dashboard = engine.calculate_job_posture(db_session, job.id, force_recalculate=True)

    assert len(dashboard.server_postures) == 2
    server_map = {sp.server_ip: sp for sp in dashboard.server_postures}

    assert "10.0.0.1" in server_map
    assert "10.0.0.2" in server_map

    srv_a = server_map["10.0.0.1"]
    assert srv_a.stream_count == 2
    assert srv_a.critical_findings_count == 1
    assert srv_a.overall_grade == "CRITICAL_RISK"

    srv_b = server_map["10.0.0.2"]
    assert srv_b.stream_count == 1
    assert srv_b.overall_score == 100
    assert srv_b.overall_grade == "EXCELLENT"


def test_security_posture_api_endpoints(client: TestClient, db_session: Session):
    """Integration test for Stage 12 Security Posture REST API endpoints."""
    pcap = PcapFile(
        original_filename="api_posture.pcap",
        stored_filename="api_posture.pcap",
        file_path="/tmp/api_posture.pcap",
        file_size_bytes=1024,
        sha256="apipost123",
        md5="apipost123",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(pcap_file_id=pcap.id, status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    session = TcpSession(job_id=job.id, tcp_stream=0, server_ip="10.0.0.10", server_port=587, protocol="SMTP", first_frame_number=1, last_frame_number=10)
    db_session.add(session)
    db_session.commit()

    finding = UnifiedFinding(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        severity="MEDIUM",
        title="Deprecated TLS 1.0 Allowed",
        reason="Server supports TLS 1.0",
        confidence=1.0,
        confidence_label="HIGH",
        rule_id="RULE-TLS-001",
        fingerprint="fp_api_posture_1",
        is_duplicate=False,
        occurrence_count=1
    )
    db_session.add(finding)
    db_session.commit()

    # 1. POST /api/v1/jobs/{id}/calculate-posture
    res_calc = client.post(f"/api/v1/jobs/{job.id}/calculate-posture")
    assert res_calc.status_code == 200
    data_calc = res_calc.json()
    assert data_calc["job_id"] == job.id
    assert data_calc["job_posture"]["overall_score"] == 90  # 100 - 10 = 90
    assert data_calc["job_posture"]["overall_grade"] == "EXCELLENT"

    # 2. GET /api/v1/jobs/{id}/posture
    res_get = client.get(f"/api/v1/jobs/{job.id}/posture")
    assert res_get.status_code == 200
    data_get = res_get.json()
    assert data_get["job_id"] == job.id
    assert data_get["job_posture"]["overall_score"] == 90

    # 3. GET /api/v1/jobs/{id}/posture/servers
    res_servers = client.get(f"/api/v1/jobs/{job.id}/posture/servers")
    assert res_servers.status_code == 200
    data_servers = res_servers.json()
    assert len(data_servers) == 1
    assert data_servers[0]["server_ip"] == "10.0.0.10"
