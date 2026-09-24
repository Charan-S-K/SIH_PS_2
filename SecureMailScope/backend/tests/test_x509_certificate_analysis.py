import base64
import datetime
from datetime import timezone
import ipaddress
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, Raw, wrpcap

from app.database import Base
from app.models.pcap import PcapFile
from app.models.job import AnalysisJob
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.certificate import X509CertificateAnalysis
from app.services.x509_analyzer import X509Analyzer
from app.services.pcap_processor import PcapProcessor


# Helper generators for testing certificates
def generate_rsa_cert(
    cn: str = "mail.securemail.test",
    org: str = "SecureMail Forensic Labs",
    days_valid: int = 365,
    key_size: int = 2048,
    is_ca: bool = False,
    issuer_cert=None,
    issuer_key=None,
    sig_hash=hashes.SHA256(),
    expired: bool = False,
    not_yet_valid: bool = False,
) -> tuple:
    """Generate an RSA test certificate and return (cert, key, der_bytes)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    now = datetime.datetime.now(timezone.utc)

    if expired:
        not_before = now - datetime.timedelta(days=60)
        not_after = now - datetime.timedelta(days=1)
    elif not_yet_valid:
        not_before = now + datetime.timedelta(days=10)
        not_after = now + datetime.timedelta(days=365)
    else:
        not_before = now - datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=days_valid)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security Department"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    ])

    issuer_name = issuer_cert.subject if issuer_cert else subject
    signing_key = issuer_key if issuer_key else key

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(cn),
                x509.DNSName(f"smtp.{cn}"),
                x509.IPAddress(ipaddress.IPv4Address("192.168.1.50")),
                x509.RFC822Name(f"postmaster@{cn}"),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=is_ca,
                crl_sign=is_ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ]),
            critical=False,
        )
    )

    cert = builder.sign(signing_key, sig_hash)
    der = cert.public_bytes(serialization.Encoding.DER)
    return cert, key, der


def generate_ec_cert(cn: str = "ec.mail.test") -> tuple:
    """Generate an EC P-256 test certificate."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(timezone.utc)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Elliptic Labs"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1234567890)
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    return cert, key, der


# =============================================================================
# Unit Tests for X509Analyzer
# =============================================================================

def test_parse_valid_rsa_certificate():
    """Verify complete parsing of a valid RSA-2048 certificate with SANs and key usage."""
    cert, key, der = generate_rsa_cert(cn="mail.company.com", org="ACME Corp", days_valid=180)
    parsed = X509Analyzer.parse_certificate_der(der)

    assert parsed["parsing_status"] == "PARSED"
    assert parsed["error_message"] is None
    assert parsed["subject_cn"] == "mail.company.com"
    assert parsed["subject_org"] == "ACME Corp"
    assert parsed["subject_country"] == "US"
    assert "CN=mail.company.com" in parsed["subject_dn"]
    assert parsed["validity_status"] == "VALID"
    assert parsed["validity_days"] >= 179
    assert parsed["days_until_expiration"] > 0

    # Public key
    assert parsed["public_key_algorithm"] == "RSA"
    assert parsed["key_size_bits"] == 2048
    assert parsed["public_key_curve"] is None

    # Signature
    assert parsed["signature_digest"] == "SHA-256"

    # Self-signed
    assert parsed["is_self_signed"] is True
    assert parsed["is_ca"] is False

    # SANs
    assert len(parsed["sans"]) >= 3
    san_types = {s["type"] for s in parsed["sans"]}
    assert "DNS" in san_types
    assert "IP" in san_types
    assert "EMAIL" in san_types

    # Fingerprints
    assert len(parsed["fingerprint_sha256"]) == 64
    assert len(parsed["fingerprint_sha1"]) == 40
    assert len(parsed["raw_der_base64"]) > 0


def test_parse_expired_certificate():
    """Verify expired certificate detection (validity_status == EXPIRED)."""
    cert, key, der = generate_rsa_cert(cn="expired.mail.test", expired=True)
    parsed = X509Analyzer.parse_certificate_der(der)

    assert parsed["parsing_status"] == "PARSED"
    assert parsed["validity_status"] == "EXPIRED"
    assert parsed["days_until_expiration"] < 0


def test_parse_not_yet_valid_certificate():
    """Verify not-yet-valid certificate detection (validity_status == NOT_YET_VALID)."""
    cert, key, der = generate_rsa_cert(cn="future.mail.test", not_yet_valid=True)
    parsed = X509Analyzer.parse_certificate_der(der)

    assert parsed["parsing_status"] == "PARSED"
    assert parsed["validity_status"] == "NOT_YET_VALID"


def test_parse_elliptic_curve_certificate():
    """Verify Elliptic Curve P-256 (secp256r1) certificate parsing and self-signed verification."""
    cert, key, der = generate_ec_cert(cn="ec.mail.test")
    parsed = X509Analyzer.parse_certificate_der(der)

    assert parsed["parsing_status"] == "PARSED"
    assert parsed["public_key_algorithm"] == "EC"
    assert parsed["key_size_bits"] == 256
    assert parsed["public_key_curve"] == "secp256r1"
    assert parsed["is_self_signed"] is True
    assert parsed["signature_digest"] == "SHA-256"


def test_parse_weak_rsa_key():
    """Verify extraction of weak key (<2048)."""
    cert, key, der = generate_rsa_cert(cn="weak.mail.test", key_size=1024)
    parsed = X509Analyzer.parse_certificate_der(der)

    assert parsed["parsing_status"] == "PARSED"
    assert parsed["public_key_algorithm"] == "RSA"
    assert parsed["key_size_bits"] == 1024


def test_parse_corrupted_der_bytes():
    """Verify zero-crash handling of corrupted or truncated DER payload."""
    garbage = b"NOT_A_VALID_DER_CERTIFICATE_JUST_RANDOM_BYTES_12345"
    parsed = X509Analyzer.parse_certificate_der(garbage)

    assert parsed["parsing_status"] == "CORRUPTED"
    assert parsed["error_message"] is not None
    assert parsed["subject_dn"] == "CORRUPTED"
    assert parsed["validity_status"] == "CORRUPTED"

    # Empty bytes
    empty_parsed = X509Analyzer.parse_certificate_der(b"")
    assert empty_parsed["parsing_status"] == "CORRUPTED"


def test_certificate_chain_analysis_complete():
    """Verify multi-tier certificate chain analysis (Leaf -> Intermediate -> Root CA)."""
    # 1. Root CA
    root_cert, root_key, root_der = generate_rsa_cert(cn="Root CA", org="Trust Root", is_ca=True)
    # 2. Intermediate CA
    inter_cert, inter_key, inter_der = generate_rsa_cert(
        cn="Intermediate CA",
        org="Trust Intermediate",
        is_ca=True,
        issuer_cert=root_cert,
        issuer_key=root_key,
    )
    # 3. Leaf
    leaf_cert, leaf_key, leaf_der = generate_rsa_cert(
        cn="mail.example.com",
        org="Example Mailer",
        is_ca=False,
        issuer_cert=inter_cert,
        issuer_key=inter_key,
    )

    parsed_leaf = X509Analyzer.parse_certificate_der(leaf_der)
    parsed_inter = X509Analyzer.parse_certificate_der(inter_der)
    parsed_root = X509Analyzer.parse_certificate_der(root_der)

    chain = [parsed_leaf, parsed_inter, parsed_root]
    analyzed = X509Analyzer.analyze_certificate_chain(chain)

    assert len(analyzed) == 3
    assert analyzed[0]["chain_index"] == 0
    assert analyzed[0]["chain_length"] == 3
    assert analyzed[0]["chain_status"] == "COMPLETE_CHAIN"
    assert analyzed[0]["subject_cn"] == "mail.example.com"

    assert analyzed[1]["chain_index"] == 1
    assert analyzed[1]["chain_status"] == "COMPLETE_CHAIN"
    assert analyzed[1]["subject_cn"] == "Intermediate CA"

    assert analyzed[2]["chain_index"] == 2
    assert analyzed[2]["chain_status"] == "COMPLETE_CHAIN"
    assert analyzed[2]["subject_cn"] == "Root CA"
    assert analyzed[2]["is_self_signed"] is True


def test_certificate_chain_incomplete():
    """Verify single non-self-signed certificate marked INCOMPLETE_CHAIN."""
    root_cert, root_key, root_der = generate_rsa_cert(cn="External CA", is_ca=True)
    leaf_cert, leaf_key, leaf_der = generate_rsa_cert(
        cn="leaf.alone.test",
        is_ca=False,
        issuer_cert=root_cert,
        issuer_key=root_key,
    )
    parsed_leaf = X509Analyzer.parse_certificate_der(leaf_der)

    chain = [parsed_leaf]
    analyzed = X509Analyzer.analyze_certificate_chain(chain)

    assert len(analyzed) == 1
    assert analyzed[0]["chain_status"] == "INCOMPLETE_CHAIN"
    assert analyzed[0]["is_self_signed"] is False


# =============================================================================
# Integration & End-to-End API Tests
# =============================================================================

def test_pcap_processor_and_api_certificate_integration(client: TestClient, db_session, tmp_path):
    """
    End-to-end integration test:
    1. Construct synthetic PCAP with TLS handshake containing Certificate message.
    2. Ingest via PcapProcessor.
    3. Verify X.509 certificates extracted, linked, and persisted.
    4. Query GET /jobs/{id}/certificates and GET /jobs/{id}/certificates/{stream}.
    5. Trigger POST /jobs/{id}/analyze-certificates.
    """
    pcap_path = str(tmp_path / "tls_cert_flow.pcap")

    # Generate leaf certificate
    leaf_cert, leaf_key, leaf_der = generate_rsa_cert(cn="imap.testserver.org", org="Test Server Org")
    cert_b64 = base64.b64encode(leaf_der).decode("ascii")

    # Build TLS Certificate Handshake payload:
    # TLS Record Header: 0x16, 0x03, 0x03, Length
    # Handshake Header: 0x0b (Certificate), 3 bytes length
    # Certificate Chain: 3 bytes total length, then each: 3 bytes cert length + DER bytes
    cert_len = len(leaf_der)
    total_certs_len = cert_len + 3
    cert_chain_bytes = (
        total_certs_len.to_bytes(3, "big")
        + cert_len.to_bytes(3, "big")
        + leaf_der
    )
    hs_len = len(cert_chain_bytes)
    hs_bytes = b"\x0b" + hs_len.to_bytes(3, "big") + cert_chain_bytes
    record_bytes = b"\x16\x03\x03" + len(hs_bytes).to_bytes(2, "big") + hs_bytes

    # Build synthetic packet flow (ClientHello -> ServerHello + Certificate -> Finished)
    c_hello = (
        b"\x16\x03\x01\x00\x30"
        b"\x01\x00\x00\x2c\x03\x03"
        + b"\x00" * 32
        + b"\x00\x00\x02\x00\x9c\x01\x00\x00\x00"
    )
    s_hello = (
        b"\x16\x03\x03\x00\x26"
        b"\x02\x00\x00\x22\x03\x03"
        + b"\x01" * 32
        + b"\x00\x00\x9c\x00"
    )

    pkts = [
        # TCP Handshake
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")/IP(src="192.168.1.10", dst="192.168.1.100")/TCP(sport=50000, dport=993, flags="S", seq=100),
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")/IP(src="192.168.1.100", dst="192.168.1.10")/TCP(sport=993, dport=50000, flags="SA", seq=200, ack=101),
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")/IP(src="192.168.1.10", dst="192.168.1.100")/TCP(sport=50000, dport=993, flags="A", seq=101, ack=201),
        # ClientHello
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")/IP(src="192.168.1.10", dst="192.168.1.100")/TCP(sport=50000, dport=993, flags="PA", seq=101, ack=201)/Raw(load=c_hello),
        # ServerHello
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")/IP(src="192.168.1.100", dst="192.168.1.10")/TCP(sport=993, dport=50000, flags="A", seq=201, ack=101 + len(c_hello))/Raw(load=s_hello),
        # Certificate message
        Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55")/IP(src="192.168.1.100", dst="192.168.1.10")/TCP(sport=993, dport=50000, flags="PA", seq=201 + len(s_hello), ack=101 + len(c_hello))/Raw(load=record_bytes),
    ]
    wrpcap(pcap_path, pkts)

    # Create DB Job & PcapFile
    pcap_record = PcapFile(
        original_filename="tls_cert_flow.pcap",
        stored_filename="tls_cert_flow.pcap",
        file_path=pcap_path,
        file_size_bytes=1024,
        sha256="testsha256certflow",
        md5="testmd5certflow",
    )
    db_session.add(pcap_record)
    db_session.commit()
    db_session.refresh(pcap_record)

    job = AnalysisJob(pcap_file_id=pcap_record.id, status="PENDING")
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)

    # Process PCAP end-to-end
    processor = PcapProcessor(db_session)
    processor.process_job(job.id)

    db_session.refresh(job)
    assert job.status == "COMPLETED"

    # Verify X509CertificateAnalysis rows in database
    certs = db_session.query(X509CertificateAnalysis).filter(X509CertificateAnalysis.job_id == job.id).all()
    assert len(certs) >= 1
    leaf = certs[0]
    assert leaf.subject_cn == "imap.testserver.org"
    assert leaf.public_key_algorithm == "RSA"
    assert leaf.key_size_bits == 2048
    assert leaf.validity_status == "VALID"
    assert leaf.is_self_signed is True

    # 1. API: GET /api/v1/jobs/{job_id}/certificates
    resp = client.get(f"/api/v1/jobs/{job.id}/certificates")
    assert resp.status_code == 200
    data = resp.json()
    assert data["job_id"] == job.id
    assert data["total_certificates"] >= 1
    assert data["valid_certificates"] >= 1
    assert data["expired_certificates"] == 0
    assert data["self_signed_certificates"] >= 1
    assert len(data["certificates"]) >= 1

    cert_json = data["certificates"][0]
    assert cert_json["subject_cn"] == "imap.testserver.org"
    assert cert_json["public_key_algorithm"] == "RSA"
    assert cert_json["key_size_bits"] == 2048
    assert len(cert_json["sans"]) >= 1

    # 2. API: GET /api/v1/jobs/{job_id}/certificates/{stream}
    stream_id = leaf.tcp_stream
    stream_resp = client.get(f"/api/v1/jobs/{job.id}/certificates/{stream_id}")
    assert stream_resp.status_code == 200
    stream_data = stream_resp.json()
    assert len(stream_data) >= 1
    assert stream_data[0]["subject_cn"] == "imap.testserver.org"

    # 3. API: POST /api/v1/jobs/{job_id}/analyze-certificates
    refresh_resp = client.post(f"/api/v1/jobs/{job.id}/analyze-certificates")
    assert refresh_resp.status_code == 200
    refreshed_data = refresh_resp.json()
    assert refreshed_data["total_certificates"] >= 1

    # 4. Error handling
    not_found_resp = client.get("/api/v1/jobs/00000000-0000-0000-0000-000000000000/certificates")
    assert not_found_resp.status_code == 404


def test_session_with_no_certificates(client: TestClient, db_session):
    """Verify jobs with no observable certificates return empty list and zero metrics."""
    job = AnalysisJob(
        pcap_file_id="00000000-0000-0000-0000-000000000001",
        status="COMPLETED"
    )
    db_session.add(job)
    db_session.commit()
    db_session.refresh(job)
    # Add a handshake that observed no certificates
    hs = TlsHandshakeAnalysis(
        job_id=job.id,
        tcp_stream=0,
        handshake_status="CLIENT_HELLO_ONLY",
        raw_certificates_bytes=[],
    )
    db_session.add(hs)
    db_session.commit()

    # Run certificate analyzer
    certs = X509Analyzer.analyze_job_certificates(db_session, job.id)
    assert len(certs) == 0

    # Query API
    resp = client.get(f"/api/v1/jobs/{job.id}/certificates")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_certificates"] == 0
    assert data["valid_certificates"] == 0
    assert data["certificates"] == []
