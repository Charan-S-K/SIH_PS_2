"""
Unit and Integration Tests for Stage 11: Evidence Engine.
Verifies complete evidence chain construction, missing fact verification without fabrication,
and REST API endpoints.
"""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.pcap import PcapFile
from app.models.job import AnalysisJob
from app.models.packet import PacketMetadata
from app.models.session import TcpSession
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.certificate import X509CertificateAnalysis
from app.models.finding import UnifiedFinding
from app.services.evidence_engine import EvidenceEngine


def test_build_finding_evidence_chain_complete(db_session: Session):
    """Test full evidence chain assembly with complete TLS and certificate facts."""
    pcap = PcapFile(
        original_filename="evidence_test.pcap",
        stored_filename="evidence_test.pcap",
        file_path="/tmp/evidence_test.pcap",
        file_size_bytes=2048,
        sha256="abc123evidence",
        md5="abc123evidence",
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
        client_ip="192.168.1.100",
        server_ip="10.0.0.100",
        client_port=50000,
        server_port=465,
        protocol="SMTPS",
        start_time=1.0,
        end_time=3.0,
        first_frame_number=1,
        last_frame_number=20
    )
    db_session.add(session)
    db_session.commit()

    # Add packets
    pkt1 = PacketMetadata(
        job_id=job.id,
        frame_number=1,
        timestamp=1.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.100",
        src_port=50000,
        dst_port=465,
        tcp_stream=0,
        detected_protocol="TLS",
        frame_length=100,
        payload_preview="Client Hello"
    )
    pkt2 = PacketMetadata(
        job_id=job.id,
        frame_number=2,
        timestamp=1.1,
        src_ip="10.0.0.100",
        dst_ip="192.168.1.100",
        src_port=465,
        dst_port=50000,
        tcp_stream=0,
        detected_protocol="TLS",
        frame_length=1200,
        payload_preview="Server Hello, Certificate"
    )
    db_session.add_all([pkt1, pkt2])
    db_session.commit()

    # Add TLS Handshake & Certificate Analysis
    tls_hs = TlsHandshakeAnalysis(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        protocol="TLS",
        client_ip="192.168.1.100",
        server_ip="10.0.0.100",
        client_port=50000,
        server_port=465,
        negotiated_version="TLS 1.2",
        negotiated_cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        key_exchange_group="ECDHE",
        signature_scheme="RSA-SHA256"
    )
    now = datetime.now(timezone.utc)
    cert = X509CertificateAnalysis(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        chain_index=0,
        subject_dn="CN=mail.example.com",
        issuer_dn="CN=Example CA",
        serial_number="0102030405",
        fingerprint_sha256="abc123certsha256",
        fingerprint_sha1="abc123certsha1",
        raw_der_base64="Y2VydA==",
        not_before=now - timedelta(days=10),
        not_after=now + timedelta(days=365),
        validity_days=375,
        validity_status="VALID",
        is_self_signed=False,
        public_key_algorithm="RSA",
        key_size_bits=2048,
        signature_digest="SHA-256"
    )
    db_session.add_all([tls_hs, cert])
    db_session.commit()

    finding = UnifiedFinding(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        severity="MEDIUM",
        title="TLS 1.2 Handshake Posture",
        reason="Server uses TLS 1.2 cipher suite",
        confidence=1.0,
        confidence_label="HIGH",
        rule_id="RULE-TLS-002",
        fingerprint="fp123456789",
        is_duplicate=False,
        occurrence_count=1
    )
    db_session.add(finding)
    db_session.commit()

    engine = EvidenceEngine()
    chain = engine.build_finding_evidence_chain(db_session, finding.id)

    assert chain.finding_id == finding.id
    assert chain.evidence_status == "COMPLETE_EVIDENCE"
    assert chain.packet_range["first_frame"] == 1
    assert chain.packet_range["last_frame"] == 2
    assert len(chain.sample_packets) == 2
    assert len(chain.field_evidence) > 0
    assert len(chain.missing_evidence_reasons) == 0


def test_build_finding_evidence_chain_missing_evidence(db_session: Session):
    """
    PROVE: Test missing source evidence handling.
    Verifies that when evidence is missing, evidence_status becomes INSUFFICIENT_EVIDENCE / PARTIAL_EVIDENCE
    and explicitly lists missing reasons without inventing facts.
    """
    pcap = PcapFile(
        original_filename="missing_test.pcap",
        stored_filename="missing_test.pcap",
        file_path="/tmp/missing_test.pcap",
        file_size_bytes=512,
        sha256="missing123",
        md5="missing123",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(pcap_file_id=pcap.id, status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    # Plain unencrypted SMTP session with NO TLS or Certificate records
    finding = UnifiedFinding(
        job_id=job.id,
        tcp_stream=0,
        finding_type="EVIDENCE_GAP",
        severity="INFO",
        title="Insufficient TLS Evidence",
        reason="No TLS Handshake frames observed for stream",
        confidence=0.5,
        confidence_label="LOW",
        rule_id="RULE-EVIDENCE-001",
        fingerprint="fp_missing_999",
        is_duplicate=False,
        occurrence_count=1
    )
    db_session.add(finding)
    db_session.commit()

    engine = EvidenceEngine()
    chain = engine.build_finding_evidence_chain(db_session, finding.id)

    assert chain.finding_id == finding.id
    assert chain.evidence_status in ("INSUFFICIENT_EVIDENCE", "PARTIAL_EVIDENCE")
    assert len(chain.missing_evidence_reasons) > 0
    assert "No TLS Handshake record observed" in chain.missing_evidence_reasons[0]


def test_evidence_api_endpoints(client: TestClient, db_session: Session):
    """Integration test for Stage 11 Evidence Engine REST API endpoints."""
    pcap = PcapFile(
        original_filename="api_evidence_test.pcap",
        stored_filename="api_evidence_test.pcap",
        file_path="/tmp/api_evidence_test.pcap",
        file_size_bytes=512,
        sha256="api_ev_123",
        md5="api_ev_123",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(pcap_file_id=pcap.id, status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    finding = UnifiedFinding(
        job_id=job.id,
        tcp_stream=0,
        finding_type="CRYPTOGRAPHIC_WEAKNESS",
        severity="HIGH",
        title="Test Finding for API",
        reason="Test finding reason",
        confidence=1.0,
        confidence_label="HIGH",
        rule_id="RULE-TLS-001",
        fingerprint="fp_api_test_000",
        is_duplicate=False,
        occurrence_count=1
    )
    db_session.add(finding)
    db_session.commit()

    # 1. Fetch evidence chain endpoint
    res_chain = client.get(f"/api/v1/jobs/{job.id}/findings/{finding.id}/evidence")
    assert res_chain.status_code == 200
    data_chain = res_chain.json()
    assert data_chain["finding_id"] == finding.id
    assert "evidence_status" in data_chain

    # 2. Fetch job evidence summary endpoint
    res_summary = client.get(f"/api/v1/jobs/{job.id}/evidence-summary")
    assert res_summary.status_code == 200
    data_summary = res_summary.json()
    assert data_summary["job_id"] == job.id
    assert data_summary["total_findings"] >= 1
