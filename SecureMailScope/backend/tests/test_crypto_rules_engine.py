"""
Unit and Integration Tests for Stage 09: Cryptographic Rules Engine.
"""

from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.models.pcap import PcapFile
from app.models.job import AnalysisJob
from app.models.session import TcpSession
from app.models.email_analysis import EmailSessionAnalysis
from app.models.starttls import StarttlsAnalysis
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.certificate import X509CertificateAnalysis
from app.models.rule_result import CryptoRuleResult
from app.services.crypto_rules_engine import CryptographicRulesEngine, load_rules_definitions


def test_load_rules_definitions():
    """Verify loading default rule definitions."""
    rules = load_rules_definitions()
    assert len(rules) >= 15
    rule_ids = [r.id for r in rules]
    assert "RULE-TLS-001" in rule_ids
    assert "RULE-TLS-002" in rule_ids
    assert "RULE-CIPHER-001" in rule_ids
    assert "RULE-CERT-001" in rule_ids
    assert "RULE-AUTH-001" in rule_ids
    assert "RULE-STARTTLS-002" in rule_ids
    assert "RULE-EVIDENCE-001" in rule_ids


def test_evaluate_deprecated_tls_and_weak_cipher(db_session: Session):
    """Test rule evaluation for deprecated TLS 1.0 version and weak cipher suite."""
    pcap = PcapFile(
        original_filename="tls10_test.pcap",
        stored_filename="tls10_test.pcap",
        file_path="/tmp/tls10_test.pcap",
        file_size_bytes=2048,
        sha256="abc12345",
        md5="abc12345",
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
        client_ip="192.168.1.10",
        server_ip="10.0.0.1",
        client_port=50000,
        server_port=465,
        protocol="SMTPS",
        start_time=1.0,
        end_time=2.0,
        first_frame_number=1,
        last_frame_number=20
    )
    db_session.add(session)
    db_session.commit()

    # TLS 1.0 handshake with 3DES cipher
    handshake = TlsHandshakeAnalysis(
        job_id=job.id,
        tcp_session_id=session.id,
        tcp_stream=0,
        protocol="TLS",
        client_ip="192.168.1.10",
        server_ip="10.0.0.1",
        handshake_status="COMPLETED",
        negotiated_version="TLS 1.0",
        negotiated_cipher_suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        client_hello_version="TLS 1.0",
        server_hello_version="TLS 1.0"
    )
    db_session.add(handshake)
    db_session.commit()

    engine = CryptographicRulesEngine()
    summary, findings = engine.evaluate_job(db_session, job.id, force_reevaluate=True)

    assert summary.total_findings >= 2
    rule_ids = [f.rule_id for f in findings]
    assert "RULE-TLS-002" in rule_ids      # TLS 1.0 deprecated
    assert "RULE-CIPHER-001" in rule_ids    # 3DES insecure cipher

    # Check evidence structure
    tls_finding = next(f for f in findings if f.rule_id == "RULE-TLS-002")
    assert tls_finding.severity == "HIGH"
    assert tls_finding.evidence["negotiated_version"] == "TLS 1.0"
    assert tls_finding.tcp_stream == 0


def test_evaluate_expired_and_weak_certificates(db_session: Session):
    """Test rule evaluation for expired certificate, weak MD5 signature, and weak RSA 1024 key."""
    pcap = PcapFile(
        original_filename="cert_test.pcap",
        stored_filename="cert_test.pcap",
        file_path="/tmp/cert_test.pcap",
        file_size_bytes=2048,
        sha256="cert12345",
        md5="cert12345",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(pcap_file_id=pcap.id, status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    now = datetime.now(timezone.utc)
    cert = X509CertificateAnalysis(
        job_id=job.id,
        tcp_stream=1,
        subject_dn="CN=mail.weak.com",
        issuer_dn="CN=mail.weak.com",
        subject_cn="mail.weak.com",
        serial_number="123456",
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=35), # Expired 35 days ago
        validity_days=365,
        validity_status="EXPIRED",
        public_key_algorithm="RSA",
        key_size_bits=1024,                  # Weak key < 2048
        signature_algorithm="md5WithRSAEncryption",
        signature_digest="MD5",              # Weak signature algorithm
        is_self_signed=True,                 # Self-signed
        sans=[],
        fingerprint_sha256="abc123certfp",
        fingerprint_sha1="abc123sha1fp"
    )
    db_session.add(cert)
    db_session.commit()

    engine = CryptographicRulesEngine()
    summary, findings = engine.evaluate_job(db_session, job.id, force_reevaluate=True)

    rule_ids = [f.rule_id for f in findings]
    assert "RULE-CERT-001" in rule_ids  # Expired
    assert "RULE-CERT-003" in rule_ids  # Self-signed
    assert "RULE-CERT-004" in rule_ids  # MD5 signature
    assert "RULE-CERT-005" in rule_ids  # RSA 1024 weak key
    assert "RULE-CERT-007" in rule_ids  # SAN missing


def test_evaluate_cleartext_auth_and_starttls_stripping(db_session: Session):
    """Test rule evaluation for cleartext auth and STARTTLS stripping risk."""
    pcap = PcapFile(
        original_filename="smtp_stripping.pcap",
        stored_filename="smtp_stripping.pcap",
        file_path="/tmp/smtp_stripping.pcap",
        file_size_bytes=4096,
        sha256="smtp12345",
        md5="smtp12345",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(pcap_file_id=pcap.id, status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    email_sess = EmailSessionAnalysis(
        job_id=job.id,
        tcp_stream=2,
        protocol="SMTP",
        auth_attempted=True,
        auth_mechanisms=["PLAIN", "LOGIN"],
        security_warnings=["Observed cleartext password transmission"]
    )
    db_session.add(email_sess)

    stts = StarttlsAnalysis(
        job_id=job.id,
        tcp_stream=2,
        protocol="SMTP",
        advertised=True,
        accepted=False,
        upgrade_status="STRIPPING_DETECTED",
        cleartext_auth_observed=True
    )
    db_session.add(stts)
    db_session.commit()

    engine = CryptographicRulesEngine()
    summary, findings = engine.evaluate_job(db_session, job.id, force_reevaluate=True)

    rule_ids = [f.rule_id for f in findings]
    assert "RULE-AUTH-001" in rule_ids      # Cleartext credentials
    assert "RULE-AUTH-002" in rule_ids      # Insecure auth offered
    assert "RULE-STARTTLS-002" in rule_ids  # STARTTLS stripping risk
    assert summary.critical_count >= 2


def test_evaluate_missing_evidence(db_session: Session):
    """Test rule evaluation for unencrypted stream missing TLS facts."""
    pcap = PcapFile(
        original_filename="missing_tls.pcap",
        stored_filename="missing_tls.pcap",
        file_path="/tmp/missing_tls.pcap",
        file_size_bytes=1024,
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

    email_sess = EmailSessionAnalysis(
        job_id=job.id,
        tcp_stream=3,
        protocol="POP3",
        auth_attempted=False
    )
    db_session.add(email_sess)
    db_session.commit()

    engine = CryptographicRulesEngine()
    summary, findings = engine.evaluate_job(db_session, job.id, force_reevaluate=True)

    rule_ids = [f.rule_id for f in findings]
    assert "RULE-EVIDENCE-001" in rule_ids
    finding = next(f for f in findings if f.rule_id == "RULE-EVIDENCE-001")
    assert finding.severity == "INFO"
    assert finding.confidence_label == "MEDIUM"


def test_crypto_rules_api_endpoints(client: TestClient, db_session: Session):
    """Test REST API endpoints for cryptographic findings and rules definitions."""
    pcap = PcapFile(
        original_filename="api_rules_test.pcap",
        stored_filename="api_rules_test.pcap",
        file_path="/tmp/api_rules_test.pcap",
        file_size_bytes=1024,
        sha256="apirules123",
        md5="apirules123",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(pcap_file_id=pcap.id, status="COMPLETED")
    db_session.add(job)
    db_session.commit()

    # 1. GET /api/v1/rules
    resp = client.get("/api/v1/rules")
    assert resp.status_code == 200
    rules_data = resp.json()
    assert isinstance(rules_data, list)
    assert len(rules_data) >= 15

    # 2. POST /api/v1/jobs/{job_id}/evaluate-rules
    eval_resp = client.post(f"/api/v1/jobs/{job.id}/evaluate-rules", json={"force_reevaluate": True})
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()
    assert eval_data["job_id"] == job.id
    assert "summary" in eval_data
    assert "findings" in eval_data

    # 3. GET /api/v1/jobs/{job_id}/crypto-findings
    get_resp = client.get(f"/api/v1/jobs/{job.id}/crypto-findings")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["job_id"] == job.id
