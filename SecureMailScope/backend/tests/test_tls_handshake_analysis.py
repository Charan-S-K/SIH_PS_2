"""
Tests for Stage 07: TLS Handshake Analysis.
Verifies observable TLS Handshake reconstruction, negotiated version and
cipher suite extraction, extension dissection (SNI, ALPN, groups, sig algorithms),
TLS alert detection, direct vs STARTTLS categorization, and RESTful APIs.
"""

import os
import struct
import tempfile
from unittest import mock
import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, Raw, wrpcap

from app.models.job import AnalysisJob
from app.models.pcap import PcapFile
from app.models.session import TcpSession
from app.models.starttls import StarttlsAnalysis
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.services.pcap_processor import PcapProcessor
from app.services.tls_handshake_analyzer import TlsHandshakeAnalyzer


def create_eth_pkt(*layers):
    """Helper to create Ethernet wrapped packet avoiding macOS BPF permission issues."""
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    pkt = eth
    for l in layers:
        pkt = pkt / l
    return pkt


def make_tls_record(content_type: int, version: int, payload: bytes) -> bytes:
    """Build a standard 5-byte TLS record header followed by payload."""
    return struct.pack("!BHH", content_type, version, len(payload)) + payload


def make_handshake_msg(msg_type: int, payload: bytes) -> bytes:
    """Build a standard 4-byte Handshake header (type + 24-bit length) followed by payload."""
    hlen = len(payload)
    return struct.pack("!B", msg_type) + struct.pack("!I", hlen)[1:] + payload


def build_client_hello_payload(
    sni: str = "mail.example.org",
    ciphers: list = None,
    supported_versions: list = None,
    groups: list = None,
    sig_schemes: list = None,
    alpn: str = "smtp",
) -> bytes:
    """Helper to assemble a binary ClientHello payload."""
    ciphers = ciphers or [0x1302, 0x1301, 0xC030]
    supported_versions = supported_versions or [0x0304, 0x0303]
    groups = groups or [0x001D, 0x0017]
    sig_schemes = sig_schemes or [0x0804, 0x0403]

    exts = b""

    # 1. SNI
    if sni:
        host_bytes = sni.encode("utf-8")
        sni_data = struct.pack("!H", len(host_bytes) + 3) + b"\x00" + struct.pack("!H", len(host_bytes)) + host_bytes
        exts += struct.pack("!HH", 0x0000, len(sni_data)) + sni_data

    # 2. Supported Groups
    if groups:
        g_data = struct.pack("!H", len(groups) * 2) + b"".join(struct.pack("!H", g) for g in groups)
        exts += struct.pack("!HH", 0x000A, len(g_data)) + g_data

    # 3. Signature Algorithms
    if sig_schemes:
        sig_data = struct.pack("!H", len(sig_schemes) * 2) + b"".join(struct.pack("!H", s) for s in sig_schemes)
        exts += struct.pack("!HH", 0x000D, len(sig_data)) + sig_data

    # 4. ALPN
    if alpn:
        proto_b = alpn.encode("utf-8")
        alpn_data = struct.pack("!H", len(proto_b) + 1) + bytes([len(proto_b)]) + proto_b
        exts += struct.pack("!HH", 0x0010, len(alpn_data)) + alpn_data

    # 5. Supported Versions (TLS 1.3)
    if supported_versions:
        sv_data = bytes([len(supported_versions) * 2]) + b"".join(struct.pack("!H", v) for v in supported_versions)
        exts += struct.pack("!HH", 0x002B, len(sv_data)) + sv_data

    # 6. Key Share (x25519)
    ks_data = struct.pack("!H", 36) + struct.pack("!HH", 0x001D, 32) + (b"\x11" * 32)
    exts += struct.pack("!HH", 0x0033, len(ks_data)) + ks_data

    exts_block = struct.pack("!H", len(exts)) + exts

    # Handshake body: Version 0x0303, Random 32B, SessionID (len 0), Ciphers, Comp (len 1, 0x00), Exts
    ciphers_data = struct.pack("!H", len(ciphers) * 2) + b"".join(struct.pack("!H", c) for c in ciphers)
    ch_body = struct.pack("!H", 0x0303) + (b"\xaa" * 32) + b"\x00" + ciphers_data + b"\x01\x00" + exts_block
    return make_handshake_msg(1, ch_body)


def build_server_hello_payload(
    selected_cipher: int = 0x1302,
    selected_version: int = 0x0304,
    selected_group: int = 0x001D,
    alpn: str = "smtp",
) -> bytes:
    """Helper to assemble a binary ServerHello payload."""
    exts = b""

    # 1. Supported Versions extension (0x002b)
    if selected_version:
        sv_data = struct.pack("!H", selected_version)
        exts += struct.pack("!HH", 0x002B, len(sv_data)) + sv_data

    # 2. Key Share extension (0x0033)
    if selected_group:
        ks_data = struct.pack("!HH", selected_group, 32) + (b"\x22" * 32)
        exts += struct.pack("!HH", 0x0033, len(ks_data)) + ks_data

    # 3. ALPN extension (0x0010)
    if alpn:
        proto_b = alpn.encode("utf-8")
        alpn_data = struct.pack("!H", len(proto_b) + 1) + bytes([len(proto_b)]) + proto_b
        exts += struct.pack("!HH", 0x0010, len(alpn_data)) + alpn_data

    exts_block = struct.pack("!H", len(exts)) + exts

    # ServerHello body: Version 0x0303, Random 32B, SessionID (len 0), Selected Cipher, Comp (0x00), Exts
    sh_body = struct.pack("!H", 0x0303) + (b"\xbb" * 32) + b"\x00" + struct.pack("!H", selected_cipher) + b"\x00" + exts_block
    return make_handshake_msg(2, sh_body)


# ==========================================
# 1. Binary Dissection Unit Tests
# ==========================================

def test_tls_13_handshake_success():
    """Verify dissection of modern TLS 1.3 Handshake: ClientHello + ServerHello + ApplicationData."""
    ch_load = make_tls_record(0x16, 0x0301, build_client_hello_payload(sni="mail.example.org", ciphers=[0x1302]))
    sh_load = make_tls_record(0x16, 0x0303, build_server_hello_payload(selected_cipher=0x1302, selected_version=0x0304))
    app_load = make_tls_record(0x17, 0x0303, b"\x01\x02\x03\x04\x05")

    records = []
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(ch_load, 1, 1.0))
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(sh_load, 2, 1.1))
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(app_load, 3, 1.2))

    analyzer = TlsHandshakeAnalyzer(db=mock.MagicMock())
    analyzer._extract_stream_tls_records = mock.MagicMock(return_value=records)

    sess = mock.MagicMock(spec=TcpSession)
    sess.id = "sess-1"
    sess.tcp_stream = 0
    sess.protocol = "SMTPS"
    sess.client_ip = "10.0.0.1"
    sess.server_ip = "10.0.0.2"
    sess.client_port = 45000
    sess.server_port = 465

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-1"

    analyzer.db.query().filter().first.return_value = sess

    analysis = analyzer.analyze_stream_tls(job, 0, False)

    assert analysis.handshake_status == "COMPLETED"
    assert analysis.negotiated_version == "TLS 1.3"
    assert analysis.negotiated_version_raw == 0x0304
    assert analysis.negotiated_cipher_suite == "TLS_AES_256_GCM_SHA384"
    assert analysis.negotiated_cipher_id == 0x1302
    assert analysis.key_exchange_group == "x25519"
    assert analysis.sni == "mail.example.org"
    assert analysis.alpn_selected == "smtp"
    assert analysis.client_hello_frame == 1
    assert analysis.server_hello_frame == 2
    assert analysis.has_alert is False


def test_tls_12_handshake_with_certificate():
    """Verify dissection of TLS 1.2 Handshake with Certificate and ChangeCipherSpec."""
    # Build TLS 1.2 ClientHello
    ch_load = make_tls_record(0x16, 0x0303, build_client_hello_payload(sni="imap.example.com", ciphers=[0xC030], supported_versions=[0x0303]))

    # Build TLS 1.2 ServerHello (no supported_versions 0x0304 ext)
    sh_body = struct.pack("!H", 0x0303) + (b"\xbb" * 32) + b"\x00" + struct.pack("!H", 0xC030) + b"\x00" + struct.pack("!H", 0)
    sh_msg = make_handshake_msg(2, sh_body)
    sh_load = make_tls_record(0x16, 0x0303, sh_msg)

    # Build Certificate message (Type 11) with 1 fake cert DER
    dummy_cert = b"\x30\x82\x01\x0a" + b"\xff" * 20
    cert_entry = struct.pack("!I", len(dummy_cert))[1:] + dummy_cert
    certs_payload = struct.pack("!I", len(cert_entry))[1:] + cert_entry
    cert_msg = make_handshake_msg(11, certs_payload)
    cert_load = make_tls_record(0x16, 0x0303, cert_msg)

    # ChangeCipherSpec (ContentType 20)
    ccs_load = make_tls_record(0x14, 0x0303, b"\x01")

    records = []
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(ch_load, 1, 2.0))
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(sh_load, 2, 2.1))
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(cert_load, 3, 2.2))
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(ccs_load, 4, 2.3))

    analyzer = TlsHandshakeAnalyzer(db=mock.MagicMock())
    analyzer._extract_stream_tls_records = mock.MagicMock(return_value=records)

    sess = mock.MagicMock(spec=TcpSession)
    sess.id = "sess-2"
    sess.tcp_stream = 0
    sess.protocol = "IMAPS"
    sess.client_ip = "10.0.0.5"
    sess.server_ip = "10.0.0.10"
    sess.client_port = 50000
    sess.server_port = 993

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-2"
    analyzer.db.query().filter().first.return_value = sess

    analysis = analyzer.analyze_stream_tls(job, 0, False)

    assert analysis.handshake_status == "COMPLETED"
    assert analysis.negotiated_version == "TLS 1.2"
    assert analysis.negotiated_cipher_suite == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert analysis.certificate_frame == 3
    assert analysis.certificate_chain_length == 1
    assert len(analysis.raw_certificates_bytes) == 1


def test_legacy_tls_10_handshake():
    """Verify legacy TLS 1.0 (0x0301) negotiation extraction."""
    ch_load = make_tls_record(0x16, 0x0301, build_client_hello_payload(ciphers=[0x002F], supported_versions=[0x0301]))

    # ServerHello with raw version 0x0301 and cipher 0x002F
    sh_body = struct.pack("!H", 0x0301) + (b"\xbb" * 32) + b"\x00" + struct.pack("!H", 0x002F) + b"\x00" + struct.pack("!H", 0)
    sh_load = make_tls_record(0x16, 0x0301, make_handshake_msg(2, sh_body))

    records = []
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(ch_load, 1, 1.0))
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(sh_load, 2, 1.1))

    analyzer = TlsHandshakeAnalyzer(db=mock.MagicMock())
    analyzer._extract_stream_tls_records = mock.MagicMock(return_value=records)

    sess = mock.MagicMock(spec=TcpSession)
    sess.id = "sess-leg"
    sess.tcp_stream = 0
    sess.protocol = "POP3S"
    sess.server_port = 995
    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-leg"
    analyzer.db.query().filter().first.return_value = sess

    analysis = analyzer.analyze_stream_tls(job, 0, False)

    assert analysis.negotiated_version == "TLS 1.0"
    assert analysis.negotiated_version_raw == 0x0301
    assert analysis.negotiated_cipher_suite == "TLS_RSA_WITH_AES_128_CBC_SHA"
    assert analysis.handshake_status == "NEGOTIATED_INCOMPLETE"  # no Finished/AppData seen yet


def test_truncated_client_hello_only():
    """Verify incomplete handshake where only ClientHello was captured."""
    ch_load = make_tls_record(0x16, 0x0301, build_client_hello_payload())
    records = TlsHandshakeAnalyzer.dissect_tls_payload(ch_load, 1, 1.0)

    analyzer = TlsHandshakeAnalyzer(db=mock.MagicMock())
    analyzer._extract_stream_tls_records = mock.MagicMock(return_value=records)

    sess = mock.MagicMock(spec=TcpSession)
    sess.id = "sess-ch-only"
    sess.tcp_stream = 0
    sess.protocol = "SMTPS"
    sess.server_port = 465
    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-ch-only"
    analyzer.db.query().filter().first.return_value = sess

    analysis = analyzer.analyze_stream_tls(job, 0, False)

    assert analysis.handshake_status == "CLIENT_HELLO_ONLY"
    assert analysis.client_hello_frame == 1
    assert analysis.server_hello_frame is None
    # Adhere strictly to "never guess"
    assert analysis.negotiated_version == "UNKNOWN"
    assert analysis.negotiated_cipher_suite == "UNKNOWN"


def test_tls_alert_handshake_failure():
    """Verify handshake aborted by TLS Alert (fatal handshake_failure 40)."""
    ch_load = make_tls_record(0x16, 0x0301, build_client_hello_payload())
    # Alert: ContentType 0x15, Level 2 (Fatal), Description 40 (handshake_failure)
    alert_load = make_tls_record(0x15, 0x0303, struct.pack("!BB", 2, 40))

    records = []
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(ch_load, 1, 1.0))
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(alert_load, 2, 1.1))

    analyzer = TlsHandshakeAnalyzer(db=mock.MagicMock())
    analyzer._extract_stream_tls_records = mock.MagicMock(return_value=records)

    sess = mock.MagicMock(spec=TcpSession)
    sess.id = "sess-alert"
    sess.tcp_stream = 0
    sess.protocol = "SMTPS"
    sess.server_port = 465
    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-alert"
    analyzer.db.query().filter().first.return_value = sess

    analysis = analyzer.analyze_stream_tls(job, 0, False)

    assert analysis.handshake_status == "ALERT_TERMINATED"
    assert analysis.has_alert is True
    assert analysis.alert_level == "FATAL"
    assert "handshake_failure" in analysis.alert_description
    assert analysis.alert_frame == 2


def test_starttls_upgrade_to_tls_handshake():
    """Verify session after STARTTLS negotiation is properly analyzed as is_starttls=True."""
    ch_load = make_tls_record(0x16, 0x0301, build_client_hello_payload(alpn="smtp"))
    sh_load = make_tls_record(0x16, 0x0303, build_server_hello_payload(selected_cipher=0x1302, selected_version=0x0304))
    app_load = make_tls_record(0x17, 0x0303, b"encrypted-app-data")

    records = []
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(ch_load, 5, 2.0))
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(sh_load, 6, 2.1))
    records.extend(TlsHandshakeAnalyzer.dissect_tls_payload(app_load, 7, 2.2))

    analyzer = TlsHandshakeAnalyzer(db=mock.MagicMock())
    analyzer._extract_stream_tls_records = mock.MagicMock(return_value=records)

    sess = mock.MagicMock(spec=TcpSession)
    sess.id = "sess-st"
    sess.tcp_stream = 0
    sess.protocol = "SMTP"
    sess.server_port = 587
    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-st"
    analyzer.db.query().filter().first.return_value = sess

    analysis = analyzer.analyze_stream_tls(job, 0, True)

    assert analysis.is_starttls is True
    assert analysis.protocol == "SMTP"
    assert analysis.handshake_status == "COMPLETED"
    assert analysis.negotiated_version == "TLS 1.3"


def test_direct_tls_ports():
    """Verify direct implicit TLS ports (465, 993, 995) are mapped to SMTPS, IMAPS, POP3S."""
    analyzer = TlsHandshakeAnalyzer(db=mock.MagicMock())
    analyzer._extract_stream_tls_records = mock.MagicMock(return_value=[])

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-ports"

    for port, expected_proto in [(465, "SMTPS"), (993, "IMAPS"), (995, "POP3S")]:
        sess = mock.MagicMock(spec=TcpSession)
        sess.id = f"sess-{port}"
        sess.tcp_stream = 0
        sess.protocol = "UNKNOWN"
        sess.server_port = port
        analyzer.db.query().filter().first.return_value = sess

        analysis = analyzer.analyze_stream_tls(job, 0, False)
        assert analysis.is_starttls is False
        assert analysis.protocol == expected_proto


def test_dissect_extensions():
    """Verify detailed extension parsing (SNI, ALPN, Supported Groups, Signature Schemes)."""
    ch_msg = build_client_hello_payload(
        sni="secure.mail.corp",
        ciphers=[0x1302, 0xC030],
        supported_versions=[0x0304, 0x0303],
        groups=[0x001D, 0x0017],  # x25519, secp256r1
        sig_schemes=[0x0804, 0x0403],  # rsa_pss_rsae_sha256, ecdsa_secp256r1_sha256
        alpn="imap",
    )
    rec = make_tls_record(0x16, 0x0301, ch_msg)
    dissected = TlsHandshakeAnalyzer.dissect_tls_payload(rec, 10, 5.0)

    ch = dissected[0]["handshake_messages"][0]
    assert ch["sni"] == "secure.mail.corp"
    assert "x25519" in ch["supported_groups"]
    assert "secp256r1" in ch["supported_groups"]
    assert "rsa_pss_rsae_sha256" in ch["signature_algorithms"]
    assert "imap" in ch["alpn_protocols"]
    assert "TLS 1.3" in ch["supported_versions"]


# ==========================================
# 2. Pipeline Integration Test
# ==========================================

def test_pcap_processor_tls_integration(db_session):
    """End-to-end integration: PCAP -> PcapProcessor -> Protocol -> Reconstruct -> Email -> STARTTLS -> TLS Handshake."""
    ch_load = make_tls_record(0x16, 0x0301, build_client_hello_payload(sni="mail.pipeline.org"))
    sh_load = make_tls_record(0x16, 0x0303, build_server_hello_payload(selected_cipher=0x1302, selected_version=0x0304))
    app_load = make_tls_record(0x17, 0x0303, b"pipeline-app-data")

    pkts = [
        create_eth_pkt(IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=42000, dport=465, flags="S", seq=10, ack=0)),
        create_eth_pkt(IP(src="192.168.1.1", dst="192.168.1.50")/TCP(sport=465, dport=42000, flags="SA", seq=50, ack=11)),
        create_eth_pkt(IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=42000, dport=465, flags="PA", seq=11, ack=51)/Raw(load=ch_load)),
        create_eth_pkt(IP(src="192.168.1.1", dst="192.168.1.50")/TCP(sport=465, dport=42000, flags="PA", seq=51, ack=11 + len(ch_load))/Raw(load=sh_load)),
        create_eth_pkt(IP(src="192.168.1.50", dst="192.168.1.1")/TCP(sport=42000, dport=465, flags="PA", seq=11 + len(ch_load), ack=51 + len(sh_load))/Raw(load=app_load)),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        temp_path = f.name

    try:
        pcap_file = PcapFile(
            original_filename="tls_pipeline.pcap",
            stored_filename="tls_pipeline_stored.pcap",
            file_path=temp_path,
            file_size_bytes=os.path.getsize(temp_path),
            sha256="test_sha_tls_pipeline",
            md5="test_md5_tls_pipeline",
            file_format="pcap",
        )
        db_session.add(pcap_file)
        db_session.commit()

        job = AnalysisJob(pcap_file_id=pcap_file.id, status="QUEUED")
        db_session.add(job)
        db_session.commit()

        processor = PcapProcessor(db_session)
        res = processor.process_job(job.id)
        assert res["status"] == "COMPLETED"

        handshake_records = (
            db_session.query(TlsHandshakeAnalysis)
            .filter(TlsHandshakeAnalysis.job_id == job.id)
            .all()
        )
        assert len(handshake_records) == 1
        hs = handshake_records[0]
        assert hs.protocol == "SMTPS"
        assert hs.handshake_status == "COMPLETED"
        assert hs.negotiated_version == "TLS 1.3"
        assert hs.negotiated_cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert hs.sni == "mail.pipeline.org"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ==========================================
# 3. RESTful API Endpoints Tests
# ==========================================

def test_api_tls_handshakes_endpoints(client: TestClient, db_session):
    """Test GET /api/v1/jobs/{job_id}/tls-handshakes, GET /tls-handshakes/{stream}, and POST /analyze-tls-handshakes."""
    ch_load = make_tls_record(0x16, 0x0301, build_client_hello_payload(sni="api.tls.net"))
    sh_load = make_tls_record(0x16, 0x0303, build_server_hello_payload(selected_cipher=0x1302, selected_version=0x0304))
    app_load = make_tls_record(0x17, 0x0303, b"app-data")

    pkts = [
        create_eth_pkt(IP(src="10.4.4.5", dst="10.4.4.10")/TCP(sport=48000, dport=993, flags="S", seq=100, ack=0)),
        create_eth_pkt(IP(src="10.4.4.10", dst="10.4.4.5")/TCP(sport=993, dport=48000, flags="SA", seq=200, ack=101)),
        create_eth_pkt(IP(src="10.4.4.5", dst="10.4.4.10")/TCP(sport=48000, dport=993, flags="PA", seq=101, ack=201)/Raw(load=ch_load)),
        create_eth_pkt(IP(src="10.4.4.10", dst="10.4.4.5")/TCP(sport=993, dport=48000, flags="PA", seq=201, ack=101 + len(ch_load))/Raw(load=sh_load)),
        create_eth_pkt(IP(src="10.4.4.5", dst="10.4.4.10")/TCP(sport=48000, dport=993, flags="PA", seq=101 + len(ch_load), ack=201 + len(sh_load))/Raw(load=app_load)),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        temp_path = f.name

    try:
        pcap_file = PcapFile(
            original_filename="api_tls.pcap",
            stored_filename="api_tls_stored.pcap",
            file_path=temp_path,
            file_size_bytes=os.path.getsize(temp_path),
            sha256="test_api_tls_sha",
            md5="test_api_tls_md5",
            file_format="pcap",
        )
        db_session.add(pcap_file)
        db_session.commit()

        job = AnalysisJob(pcap_file_id=pcap_file.id, status="QUEUED")
        db_session.add(job)
        db_session.commit()

        processor = PcapProcessor(db_session)
        processor.process_job(job.id)

        # 1. GET /api/v1/jobs/{job_id}/tls-handshakes
        res = client.get(f"/api/v1/jobs/{job.id}/tls-handshakes")
        assert res.status_code == 200
        data = res.json()
        assert data["job_id"] == job.id
        assert data["total_handshakes"] == 1
        assert data["completed_count"] == 1
        assert data["tls13_count"] == 1
        assert data["analyses"][0]["negotiated_version"] == "TLS 1.3"
        assert data["analyses"][0]["sni"] == "api.tls.net"

        # 2. GET /api/v1/jobs/{job_id}/tls-handshakes/{tcp_stream}
        stream_res = client.get(f"/api/v1/jobs/{job.id}/tls-handshakes/0")
        assert stream_res.status_code == 200
        stream_data = stream_res.json()
        assert stream_data["tcp_stream"] == 0
        assert stream_data["negotiated_cipher_suite"] == "TLS_AES_256_GCM_SHA384"
        assert stream_data["handshake_status"] == "COMPLETED"

        # 3. 404 on invalid stream
        not_found_res = client.get(f"/api/v1/jobs/{job.id}/tls-handshakes/999")
        assert not_found_res.status_code == 404

        # 4. 404 on invalid job
        fake_res = client.get("/api/v1/jobs/fake-id/tls-handshakes")
        assert fake_res.status_code == 404

        # 5. POST /api/v1/jobs/{job_id}/analyze-tls-handshakes
        refresh_res = client.post(f"/api/v1/jobs/{job.id}/analyze-tls-handshakes")
        assert refresh_res.status_code == 200
        refresh_data = refresh_res.json()
        assert refresh_data["total_handshakes"] == 1
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
