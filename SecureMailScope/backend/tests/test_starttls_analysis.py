"""
Tests for Stage 06: STARTTLS Analysis.
Verifies opportunistic TLS (STARTTLS / STLS) negotiation inspection,
downgrade and stripping risk detection, suspicious cleartext authentication,
direct TLS classification, and RESTful API endpoints.
"""

import os
import tempfile
from unittest import mock
import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, Raw, wrpcap

from app.models.job import AnalysisJob
from app.models.packet import PacketMetadata
from app.models.pcap import PcapFile
from app.models.session import TcpSession
from app.models.starttls import StarttlsAnalysis
from app.services.pcap_processor import PcapProcessor
from app.services.starttls_analyzer import StarttlsAnalyzer


def create_eth_pkt(*layers):
    """Helper to create Ethernet wrapped packet avoiding macOS BPF permission issues."""
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    pkt = eth
    for l in layers:
        pkt = pkt / l
    return pkt


# ==========================================
# 1. SMTP STARTTLS Unit Tests
# ==========================================

def test_smtp_starttls_success():
    """Verify successful SMTP STARTTLS upgrade: advertised -> requested -> 220 -> TLS record."""
    db_mock = mock.MagicMock()
    # Mock TLS record query
    tls_pkt = mock.MagicMock()
    tls_pkt.detected_protocol = "TLS"
    tls_pkt.frame_number = 6
    db_mock.query().filter().order_by().all.return_value = [tls_pkt]

    analyzer = StarttlsAnalyzer(db=db_mock)
    turns = [
        {"direction": "s2c", "text_preview": "220 mail.example.com ESMTP Postfix\r\n", "start_frame": 1},
        {"direction": "c2s", "text_preview": "EHLO client.example.com\r\n", "start_frame": 2},
        {"direction": "s2c", "text_preview": "250-mail.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n", "start_frame": 3},
        {"direction": "c2s", "text_preview": "STARTTLS\r\n", "start_frame": 4},
        {"direction": "s2c", "text_preview": "220 2.0.0 Ready to start TLS\r\n", "start_frame": 5},
    ]

    sess = mock.MagicMock(spec=TcpSession)
    sess.job_id = "job-smtp-1"
    sess.id = "sess-smtp-1"
    sess.tcp_stream = 0
    sess.protocol = "SMTP"
    sess.client_ip = "192.168.1.50"
    sess.server_ip = "192.168.1.1"
    sess.client_port = 45000
    sess.server_port = 25
    sess.conversation_flow = turns
    sess.first_frame_number = 1

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-smtp-1"
    job.pcap_file = None

    analysis = analyzer.analyze_stream_starttls(job, sess, "SMTP")

    assert analysis.advertised is True
    assert analysis.advertised_frame == 3
    assert analysis.requested is True
    assert analysis.requested_frame == 4
    assert analysis.accepted is True
    assert analysis.response_frame == 5
    assert analysis.response_code == "220"
    assert analysis.upgrade_status == "UPGRADED_SUCCESS"
    assert analysis.tls_record_detected is True
    assert analysis.tls_start_frame == 6
    assert any(f["code"] == "STARTTLS_SUCCESSFULLY_NEGOTIATED" for f in analysis.findings)


def test_smtp_starttls_rejected():
    """Verify server rejection of STARTTLS (e.g. 454 TLS not available)."""
    db_mock = mock.MagicMock()
    analyzer = StarttlsAnalyzer(db=db_mock)
    turns = [
        {"direction": "s2c", "text_preview": "220 mail.example.com ESMTP\r\n", "start_frame": 1},
        {"direction": "c2s", "text_preview": "EHLO client.example.com\r\n", "start_frame": 2},
        {"direction": "s2c", "text_preview": "250-mail.example.com\r\n250-STARTTLS\r\n250 DSN\r\n", "start_frame": 3},
        {"direction": "c2s", "text_preview": "STARTTLS\r\n", "start_frame": 4},
        {"direction": "s2c", "text_preview": "454 4.7.0 TLS not available due to temporary reason\r\n", "start_frame": 5},
    ]

    sess = mock.MagicMock(spec=TcpSession)
    sess.job_id = "job-smtp-2"
    sess.id = "sess-smtp-2"
    sess.tcp_stream = 0
    sess.protocol = "SMTP"
    sess.client_ip = "192.168.1.50"
    sess.server_ip = "192.168.1.1"
    sess.client_port = 45000
    sess.server_port = 25
    sess.conversation_flow = turns
    sess.first_frame_number = 1

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-smtp-2"
    job.pcap_file = None

    analysis = analyzer.analyze_stream_starttls(job, sess, "SMTP")

    assert analysis.advertised is True
    assert analysis.requested is True
    assert analysis.accepted is False
    assert analysis.response_code == "454"
    assert analysis.upgrade_status == "UPGRADE_REJECTED"
    assert any(f["code"] == "STARTTLS_NEGOTIATION_FAILED" and f["severity"] == "HIGH" for f in analysis.findings)


def test_smtp_starttls_downgrade_ignored():
    """Verify non-upgrade / downgrade risk when server advertises STARTTLS but client ignores it."""
    db_mock = mock.MagicMock()
    analyzer = StarttlsAnalyzer(db=db_mock)
    turns = [
        {"direction": "s2c", "text_preview": "220 mail.example.com ESMTP\r\n", "start_frame": 1},
        {"direction": "c2s", "text_preview": "EHLO client.example.com\r\n", "start_frame": 2},
        {"direction": "s2c", "text_preview": "250-mail.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n", "start_frame": 3},
        {"direction": "c2s", "text_preview": "MAIL FROM:<alice@example.com>\r\n", "start_frame": 4},
        {"direction": "s2c", "text_preview": "250 2.1.0 Ok\r\n", "start_frame": 5},
    ]

    sess = mock.MagicMock(spec=TcpSession)
    sess.job_id = "job-smtp-3"
    sess.id = "sess-smtp-3"
    sess.tcp_stream = 0
    sess.protocol = "SMTP"
    sess.client_ip = "192.168.1.50"
    sess.server_ip = "192.168.1.1"
    sess.client_port = 45000
    sess.server_port = 25
    sess.conversation_flow = turns
    sess.first_frame_number = 1

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-smtp-3"
    job.pcap_file = None

    analysis = analyzer.analyze_stream_starttls(job, sess, "SMTP")

    assert analysis.advertised is True
    assert analysis.requested is False
    assert analysis.upgrade_status == "NOT_REQUESTED_IGNORED"
    assert any(f["code"] == "STARTTLS_DOWNGRADE_OR_STRIPPING_RISK" and f["severity"] == "HIGH" for f in analysis.findings)


def test_cleartext_auth_after_starttls_offered():
    """Verify critical alert when client sends unencrypted credentials after STARTTLS was offered."""
    db_mock = mock.MagicMock()
    analyzer = StarttlsAnalyzer(db=db_mock)
    turns = [
        {"direction": "s2c", "text_preview": "220 mail.example.com ESMTP\r\n", "start_frame": 1},
        {"direction": "c2s", "text_preview": "EHLO client.example.com\r\n", "start_frame": 2},
        {"direction": "s2c", "text_preview": "250-mail.example.com\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 OK\r\n", "start_frame": 3},
        {"direction": "c2s", "text_preview": "AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ=\r\n", "start_frame": 4},
        {"direction": "s2c", "text_preview": "235 2.7.0 Authentication successful\r\n", "start_frame": 5},
    ]

    sess = mock.MagicMock(spec=TcpSession)
    sess.job_id = "job-smtp-4"
    sess.id = "sess-smtp-4"
    sess.tcp_stream = 0
    sess.protocol = "SMTP"
    sess.client_ip = "192.168.1.50"
    sess.server_ip = "192.168.1.1"
    sess.client_port = 45000
    sess.server_port = 587
    sess.conversation_flow = turns
    sess.first_frame_number = 1

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-smtp-4"
    job.pcap_file = None

    analysis = analyzer.analyze_stream_starttls(job, sess, "SMTP")

    assert analysis.advertised is True
    assert analysis.requested is False
    assert analysis.cleartext_auth_observed is True
    assert analysis.cleartext_auth_frame == 4
    assert "AUTH PLAIN" in analysis.cleartext_auth_command
    assert analysis.upgrade_status == "CLEARTEXT_AUTH_AFTER_ADVERTISED"
    assert any(f["code"] == "SUSPICIOUS_CLEARTEXT_AUTH_AFTER_STARTTLS_OFFERED" and f["severity"] == "CRITICAL" for f in analysis.findings)


# ==========================================
# 2. IMAP & POP3 STARTTLS / STLS Tests
# ==========================================

def test_imap_starttls_negotiation_and_cleartext_login():
    """Verify IMAP STARTTLS advertisement, request, and cleartext LOGIN detection."""
    db_mock = mock.MagicMock()
    analyzer = StarttlsAnalyzer(db=db_mock)

    # 1. IMAP STARTTLS advertised and accepted
    turns_ok = [
        {"direction": "s2c", "text_preview": "* OK [CAPABILITY IMAP4rev1 STARTTLS] IMAP4 server ready\r\n", "start_frame": 1},
        {"direction": "c2s", "text_preview": "a001 STARTTLS\r\n", "start_frame": 2},
        {"direction": "s2c", "text_preview": "a001 OK Begin TLS negotiation now\r\n", "start_frame": 3},
    ]
    sess_ok = mock.MagicMock(spec=TcpSession)
    sess_ok.job_id = "job-imap-1"
    sess_ok.id = "sess-imap-1"
    sess_ok.tcp_stream = 0
    sess_ok.protocol = "IMAP"
    sess_ok.server_port = 143
    sess_ok.conversation_flow = turns_ok
    sess_ok.first_frame_number = 1

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-imap-1"
    job.pcap_file = None

    # Without TLS record following: UPGRADE_ACCEPTED
    db_mock.query().filter().order_by().all.return_value = []
    analysis_ok = analyzer.analyze_stream_starttls(job, sess_ok, "IMAP")
    assert analysis_ok.advertised is True
    assert analysis_ok.requested is True
    assert analysis_ok.accepted is True
    assert analysis_ok.response_code == "OK"
    assert analysis_ok.upgrade_status == "UPGRADE_ACCEPTED"

    # 2. IMAP cleartext LOGIN after advertised
    turns_clear = [
        {"direction": "s2c", "text_preview": "* OK [CAPABILITY IMAP4rev1 STARTTLS] IMAP4 server ready\r\n", "start_frame": 1},
        {"direction": "c2s", "text_preview": "a001 LOGIN alice secretpass\r\n", "start_frame": 2},
        {"direction": "s2c", "text_preview": "a001 OK Logged in\r\n", "start_frame": 3},
    ]
    sess_clear = mock.MagicMock(spec=TcpSession)
    sess_clear.job_id = "job-imap-2"
    sess_clear.id = "sess-imap-2"
    sess_clear.tcp_stream = 1
    sess_clear.protocol = "IMAP"
    sess_clear.server_port = 143
    sess_clear.conversation_flow = turns_clear
    sess_clear.first_frame_number = 1

    analysis_clear = analyzer.analyze_stream_starttls(job, sess_clear, "IMAP")
    assert analysis_clear.cleartext_auth_observed is True
    assert analysis_clear.upgrade_status == "CLEARTEXT_AUTH_AFTER_ADVERTISED"
    assert any(f["severity"] == "CRITICAL" for f in analysis_clear.findings)


def test_pop3_stls_negotiation_and_cleartext_pass():
    """Verify POP3 STLS capability detection, request, and cleartext PASS detection."""
    db_mock = mock.MagicMock()
    analyzer = StarttlsAnalyzer(db=db_mock)

    # POP3 STLS accepted
    turns_stls = [
        {"direction": "s2c", "text_preview": "+OK POP3 server ready\r\n", "start_frame": 1},
        {"direction": "c2s", "text_preview": "CAPA\r\n", "start_frame": 2},
        {"direction": "s2c", "text_preview": "+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n", "start_frame": 3},
        {"direction": "c2s", "text_preview": "STLS\r\n", "start_frame": 4},
        {"direction": "s2c", "text_preview": "+OK Begin TLS negotiation\r\n", "start_frame": 5},
    ]
    sess_stls = mock.MagicMock(spec=TcpSession)
    sess_stls.job_id = "job-pop-1"
    sess_stls.id = "sess-pop-1"
    sess_stls.tcp_stream = 0
    sess_stls.protocol = "POP3"
    sess_stls.server_port = 110
    sess_stls.conversation_flow = turns_stls
    sess_stls.first_frame_number = 1

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-pop-1"
    job.pcap_file = None
    db_mock.query().filter().order_by().all.return_value = []

    analysis = analyzer.analyze_stream_starttls(job, sess_stls, "POP3")
    assert analysis.advertised is True
    assert analysis.requested is True
    assert analysis.accepted is True
    assert analysis.response_code == "+OK"

    # POP3 cleartext PASS after STLS offered
    turns_pass = [
        {"direction": "s2c", "text_preview": "+OK POP3 server ready\r\n", "start_frame": 1},
        {"direction": "c2s", "text_preview": "CAPA\r\n", "start_frame": 2},
        {"direction": "s2c", "text_preview": "+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n", "start_frame": 3},
        {"direction": "c2s", "text_preview": "USER bob\r\n", "start_frame": 4},
        {"direction": "s2c", "text_preview": "+OK User accepted\r\n", "start_frame": 5},
        {"direction": "c2s", "text_preview": "PASS secret123\r\n", "start_frame": 6},
        {"direction": "s2c", "text_preview": "+OK Mailbox open\r\n", "start_frame": 7},
    ]
    sess_pass = mock.MagicMock(spec=TcpSession)
    sess_pass.job_id = "job-pop-2"
    sess_pass.id = "sess-pop-2"
    sess_pass.tcp_stream = 1
    sess_pass.protocol = "POP3"
    sess_pass.server_port = 110
    sess_pass.conversation_flow = turns_pass
    sess_pass.first_frame_number = 1

    analysis_pass = analyzer.analyze_stream_starttls(job, sess_pass, "POP3")
    assert analysis_pass.cleartext_auth_observed is True
    assert analysis_pass.cleartext_auth_command == "PASS"
    assert analysis_pass.upgrade_status == "CLEARTEXT_AUTH_AFTER_ADVERTISED"
    assert any(f["severity"] == "CRITICAL" for f in analysis_pass.findings)


# ==========================================
# 3. Direct TLS & Unadvertised Tests
# ==========================================

def test_direct_tls_ports():
    """Verify dedicated implicit TLS ports (465, 993, 995) are marked DIRECT_TLS."""
    analyzer = StarttlsAnalyzer(db=mock.MagicMock())
    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-direct-tls"
    job.pcap_file = None

    for port, proto in [(465, "SMTP"), (993, "IMAP"), (995, "POP3")]:
        sess = mock.MagicMock(spec=TcpSession)
        sess.job_id = "job-direct-tls"
        sess.id = f"sess-{port}"
        sess.tcp_stream = 0
        sess.protocol = proto
        sess.server_port = port
        sess.first_frame_number = 1
        sess.conversation_flow = []

        res = analyzer.analyze_stream_starttls(job, sess, proto)
        assert res.upgrade_status == "DIRECT_TLS"
        assert res.tls_record_detected is True
        assert any(f["code"] == "DIRECT_TLS_PORT" for f in res.findings)


def test_starttls_not_advertised():
    """Verify non-STARTTLS session is marked NOT_ADVERTISED."""
    analyzer = StarttlsAnalyzer(db=mock.MagicMock())
    turns = [
        {"direction": "s2c", "text_preview": "220 mail.example.com ESMTP\r\n", "start_frame": 1},
        {"direction": "c2s", "text_preview": "EHLO client.example.com\r\n", "start_frame": 2},
        {"direction": "s2c", "text_preview": "250-mail.example.com\r\n250 8BITMIME\r\n", "start_frame": 3},
        {"direction": "c2s", "text_preview": "QUIT\r\n", "start_frame": 4},
        {"direction": "s2c", "text_preview": "221 Bye\r\n", "start_frame": 5},
    ]
    sess = mock.MagicMock(spec=TcpSession)
    sess.job_id = "job-not-adv"
    sess.id = "sess-not-adv"
    sess.tcp_stream = 0
    sess.protocol = "SMTP"
    sess.server_port = 25
    sess.conversation_flow = turns
    sess.first_frame_number = 1

    job = mock.MagicMock(spec=AnalysisJob)
    job.id = "job-not-adv"
    job.pcap_file = None

    res = analyzer.analyze_stream_starttls(job, sess, "SMTP")
    assert res.advertised is False
    assert res.upgrade_status == "NOT_ADVERTISED"
    assert any(f["code"] == "STARTTLS_NOT_ADVERTISED" for f in res.findings)


# ==========================================
# 4. Pipeline Integration Test
# ==========================================

def test_pcap_processor_starttls_integration(db_session):
    """End-to-end integration: PCAP -> PcapProcessor -> Protocol -> TCP Reconstruct -> Email Analysis -> STARTTLS Analysis."""
    # Synthetic SMTP STARTTLS capture
    # Handshake + 220 + EHLO + 250 STARTTLS + STARTTLS + 220 + TLS Client Hello record (0x16 0x03)
    tls_client_hello = b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00"

    pkts = [
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.25")/TCP(sport=40000, dport=25, flags="S", seq=100, ack=0)),
        create_eth_pkt(IP(src="192.168.1.25", dst="192.168.1.10")/TCP(sport=25, dport=40000, flags="SA", seq=200, ack=101)),
        create_eth_pkt(IP(src="192.168.1.25", dst="192.168.1.10")/TCP(sport=25, dport=40000, flags="PA", seq=201, ack=101)/Raw(load=b"220 mail.integration.org ESMTP\r\n")),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.25")/TCP(sport=40000, dport=25, flags="PA", seq=101, ack=232)/Raw(load=b"EHLO test.client\r\n")),
        create_eth_pkt(IP(src="192.168.1.25", dst="192.168.1.10")/TCP(sport=25, dport=40000, flags="PA", seq=232, ack=119)/Raw(load=b"250-mail.integration.org\r\n250-STARTTLS\r\n250 OK\r\n")),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.25")/TCP(sport=40000, dport=25, flags="PA", seq=119, ack=280)/Raw(load=b"STARTTLS\r\n")),
        create_eth_pkt(IP(src="192.168.1.25", dst="192.168.1.10")/TCP(sport=25, dport=40000, flags="PA", seq=280, ack=129)/Raw(load=b"220 2.0.0 Ready to start TLS\r\n")),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.25")/TCP(sport=40000, dport=25, flags="PA", seq=129, ack=310)/Raw(load=tls_client_hello)),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        temp_path = f.name

    try:
        pcap_file = PcapFile(
            original_filename="smtp_starttls_int.pcap",
            stored_filename="smtp_starttls_stored.pcap",
            file_path=temp_path,
            file_size_bytes=os.path.getsize(temp_path),
            sha256="test_sha_starttls_int",
            md5="test_md5_starttls_int",
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

        starttls_records = (
            db_session.query(StarttlsAnalysis)
            .filter(StarttlsAnalysis.job_id == job.id)
            .all()
        )
        assert len(starttls_records) == 1
        st = starttls_records[0]
        assert st.protocol == "SMTP"
        assert st.advertised is True
        assert st.requested is True
        assert st.accepted is True
        assert st.upgrade_status == "UPGRADED_SUCCESS"
        assert st.tls_record_detected is True
        assert st.tls_start_frame is not None
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ==========================================
# 5. RESTful API Endpoints Tests
# ==========================================

def test_api_starttls_endpoints(client: TestClient, db_session):
    """Test GET /api/v1/jobs/{job_id}/starttls, GET /starttls/{stream}, and POST /analyze-starttls."""
    pkts = [
        create_eth_pkt(IP(src="10.3.3.5", dst="10.3.3.10")/TCP(sport=38000, dport=25, flags="S", seq=50, ack=0)),
        create_eth_pkt(IP(src="10.3.3.10", dst="10.3.3.5")/TCP(sport=25, dport=38000, flags="SA", seq=80, ack=51)),
        create_eth_pkt(IP(src="10.3.3.10", dst="10.3.3.5")/TCP(sport=25, dport=38000, flags="PA", seq=81, ack=51)/Raw(load=b"220 mail.api.org ESMTP\r\n")),
        create_eth_pkt(IP(src="10.3.3.5", dst="10.3.3.10")/TCP(sport=38000, dport=25, flags="PA", seq=51, ack=105)/Raw(load=b"EHLO client.api\r\n")),
        create_eth_pkt(IP(src="10.3.3.10", dst="10.3.3.5")/TCP(sport=25, dport=38000, flags="PA", seq=105, ack=68)/Raw(load=b"250-mail.api.org\r\n250-STARTTLS\r\n250 OK\r\n")),
        create_eth_pkt(IP(src="10.3.3.5", dst="10.3.3.10")/TCP(sport=38000, dport=25, flags="PA", seq=68, ack=150)/Raw(load=b"MAIL FROM:<attacker@api.org>\r\n")),
        create_eth_pkt(IP(src="10.3.3.10", dst="10.3.3.5")/TCP(sport=25, dport=38000, flags="PA", seq=150, ack=99)/Raw(load=b"250 OK\r\n")),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        temp_path = f.name

    try:
        pcap_file = PcapFile(
            original_filename="starttls_api.pcap",
            stored_filename="starttls_api_stored.pcap",
            file_path=temp_path,
            file_size_bytes=os.path.getsize(temp_path),
            sha256="test_starttls_api_sha",
            md5="test_starttls_api_md5",
            file_format="pcap",
        )
        db_session.add(pcap_file)
        db_session.commit()

        job = AnalysisJob(pcap_file_id=pcap_file.id, status="QUEUED")
        db_session.add(job)
        db_session.commit()

        processor = PcapProcessor(db_session)
        processor.process_job(job.id)

        # 1. GET /api/v1/jobs/{job_id}/starttls
        res = client.get(f"/api/v1/jobs/{job.id}/starttls")
        assert res.status_code == 200
        data = res.json()
        assert data["job_id"] == job.id
        assert data["total_streams"] == 1
        assert data["downgrade_risk_count"] == 1
        assert data["analyses"][0]["upgrade_status"] == "NOT_REQUESTED_IGNORED"

        # 2. GET /api/v1/jobs/{job_id}/starttls/{tcp_stream}
        stream_res = client.get(f"/api/v1/jobs/{job.id}/starttls/0")
        assert stream_res.status_code == 200
        stream_data = stream_res.json()
        assert stream_data["tcp_stream"] == 0
        assert stream_data["advertised"] is True
        assert stream_data["requested"] is False
        assert len(stream_data["findings"]) >= 1

        # 3. 404 on non-existent stream
        not_found_res = client.get(f"/api/v1/jobs/{job.id}/starttls/999")
        assert not_found_res.status_code == 404

        # 4. 404 on non-existent job
        fake_res = client.get("/api/v1/jobs/non-existent-uuid/starttls")
        assert fake_res.status_code == 404

        # 5. POST /api/v1/jobs/{job_id}/analyze-starttls
        refresh_res = client.post(f"/api/v1/jobs/{job.id}/analyze-starttls")
        assert refresh_res.status_code == 200
        refresh_data = refresh_res.json()
        assert refresh_data["total_streams"] == 1
        assert refresh_data["downgrade_risk_count"] == 1
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
