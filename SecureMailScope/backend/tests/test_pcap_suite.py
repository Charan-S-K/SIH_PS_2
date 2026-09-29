"""
Unit and Integration Tests for Stage 24: Test PCAP Suite & Evaluation Service.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.database import get_db
from app.fixtures.test_pcap_suite import (
    CURATED_PCAP_SUITE,
    PcapSuiteScenario,
    generate_scenario_pcap_bytes,
)
from app.services.pcap_suite_runner import PcapSuiteRunnerService
from app.models.job import AnalysisJob
from app.models.protocol import ProtocolIdentification
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.finding import UnifiedFinding
from app.models.security_posture import SecurityPostureScore
from app.models.tls_anomaly import TlsAnomalyResult


client = TestClient(app)


def test_list_scenarios_service():
    scenarios = PcapSuiteRunnerService.list_scenarios()
    assert len(scenarios) == 8
    scenario_ids = [s.scenario_id for s in scenarios]
    assert "SECURE_TLS13_SMTP" in scenario_ids
    assert "WEAK_TLS10_IMAP" in scenario_ids
    assert "INCOMPLETE_EVIDENCE_TRUNCATED" in scenario_ids


def test_get_scenario_service():
    scenario = PcapSuiteRunnerService.get_scenario("WEAK_TLS10_IMAP")
    assert scenario is not None
    assert scenario.category == "WEAK_CRYPTO"
    assert "RULE_DEPRECATED_TLS_10" in scenario.expected_outcome.expected_rule_ids


def test_generate_scenario_pcap_bytes():
    pcap_bytes = generate_scenario_pcap_bytes("SECURE_TLS13_SMTP")
    assert len(pcap_bytes) > 24
    # Check PCAP magic number 0xa1b2c3d4 (little-endian: d4 c3 b2 a1)
    assert pcap_bytes[0:4] == b'\xd4\xc3\xb2\xa1'


from app.models.pcap import PcapFile


def test_evaluate_job_against_scenario_secure_tls13(db_session: Session):
    pcap = PcapFile(
        id="pcap_1",
        original_filename="test_secure.pcap",
        stored_filename="test_secure_stored.pcap",
        file_path="/tmp/test_secure.pcap",
        file_size_bytes=1024,
        sha256="dummyhash123",
        md5="dummymd5"
    )
    db_session.add(pcap)

    job = AnalysisJob(
        id="job_suite_secure_1",
        pcap_file_id="pcap_1",
        status="COMPLETED"
    )
    db_session.add(job)
    
    proto = ProtocolIdentification(
        id="proto_1",
        job_id="job_suite_secure_1",
        protocol="SMTP",
        server_port=587,
        confidence=1.0,
        packet_count=10
    )
    db_session.add(proto)
    
    tls = TlsHandshakeAnalysis(
        id="tls_1",
        job_id="job_suite_secure_1",
        tcp_stream=1,
        negotiated_version="TLS 1.3",
        negotiated_cipher_suite="TLS_AES_256_GCM_SHA384",
        sni="mail.example.com"
    )
    db_session.add(tls)
    
    posture = SecurityPostureScore(
        id="posture_1",
        job_id="job_suite_secure_1",
        overall_score=95,
        overall_grade="EXCELLENT",
        posture_summary="Secure SMTP TLS 1.3"
    )
    db_session.add(posture)
    db_session.commit()

    eval_result = PcapSuiteRunnerService.evaluate_job_against_scenario(
        db=db_session,
        job_id="job_suite_secure_1",
        scenario_id="SECURE_TLS13_SMTP"
    )

    assert eval_result["job_id"] == "job_suite_secure_1"
    assert eval_result["scenario_id"] == "SECURE_TLS13_SMTP"
    assert eval_result["match_score_percent"] == 100.0
    assert eval_result["passed"] is True
    assert len(eval_result["discrepancies"]) == 0


def test_api_list_fixtures(client):
    response = client.get("/api/v1/pcap-suite/fixtures")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 8
    assert data[0]["scenario_id"] == "SECURE_TLS13_SMTP"


def test_api_get_fixture_detail(client):
    response = client.get("/api/v1/pcap-suite/fixtures/EXPIRED_CERTIFICATE_POP3")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "POP3 Session with Expired X.509 Certificate"


def test_api_download_fixture(client):
    response = client.get("/api/v1/pcap-suite/fixtures/SECURE_TLS13_SMTP/download")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert len(response.content) > 24


def test_api_evaluate_job(client, db_session: Session):
    pcap = PcapFile(
        id="pcap_2",
        original_filename="test_weak.pcap",
        stored_filename="test_weak_stored.pcap",
        file_path="/tmp/test_weak.pcap",
        file_size_bytes=2048,
        sha256="dummyhash456",
        md5="dummymd5_2"
    )
    db_session.add(pcap)

    job = AnalysisJob(
        id="job_suite_weak_1",
        pcap_file_id="pcap_2",
        status="COMPLETED"
    )
    db_session.add(job)
    
    proto = ProtocolIdentification(
        id="proto_2",
        job_id="job_suite_weak_1",
        protocol="IMAP",
        server_port=993,
        confidence=1.0,
        packet_count=15
    )
    db_session.add(proto)
    
    tls = TlsHandshakeAnalysis(
        id="tls_2",
        job_id="job_suite_weak_1",
        tcp_stream=1,
        negotiated_version="TLS 1.0",
        negotiated_cipher_suite="TLS_RSA_WITH_AES_128_CBC_SHA",
        sni="imap.example.com"
    )
    db_session.add(tls)
    
    finding = UnifiedFinding(
        id="finding_1",
        job_id="job_suite_weak_1",
        rule_id="RULE_DEPRECATED_TLS_10",
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        title="Deprecated TLS 1.0",
        severity="HIGH",
        reason="Deprecated TLS 1.0 detected",
        fingerprint="dummyfingerprint123"
    )
    db_session.add(finding)
    
    posture = SecurityPostureScore(
        id="posture_2",
        job_id="job_suite_weak_1",
        overall_score=55,
        overall_grade="FAIR",
        posture_summary="Deprecated TLS 1.0 IMAP"
    )
    db_session.add(posture)
    db_session.commit()

    response = client.post("/api/v1/pcap-suite/evaluate/job_suite_weak_1?scenario_id=WEAK_TLS10_IMAP")
    assert response.status_code == 200
    data = response.json()
    assert data["scenario_id"] == "WEAK_TLS10_IMAP"
    assert data["passed"] is True
    assert data["match_score_percent"] >= 80.0
