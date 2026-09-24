"""
Tests for Stage 05: Email Protocol Analysis.
Verifies deep session analysis for SMTP, IMAP, and POP3 protocols,
including command/response tracking, capability extraction,
STARTTLS/STLS detection, authentication parsing with credential redaction,
security warnings, and RESTful APIs.
"""

import base64
import os
import tempfile
from unittest import mock
import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Raw, wrpcap, Ether

from app.models.job import AnalysisJob
from app.models.pcap import PcapFile
from app.models.session import TcpSession
from app.models.email_analysis import EmailSessionAnalysis
from app.services.email_protocol_analyzer import EmailProtocolAnalyzer, redact_auth_argument
from app.services.pcap_processor import PcapProcessor


def create_eth_pkt(*layers):
    """Helper to create Ethernet wrapped packet avoiding macOS BPF permission issues."""
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    pkt = eth
    for l in layers:
        pkt = pkt / l
    return pkt


# ==========================================
# 1. Pure Unit Tests for Redaction & Sanitization
# ==========================================

def test_redact_auth_argument_plain():
    """Verify PLAIN auth base64 credentials are redacted while username is extracted."""
    # Format: \0user\0pass
    raw_plain = "\x00alice@example.com\x00SuperSecret123"
    b64_plain = base64.b64encode(raw_plain.encode()).decode()
    sanitized, user = redact_auth_argument("AUTH", f"PLAIN {b64_plain}")

    assert "SuperSecret123" not in sanitized
    assert "[REDACTED_CREDENTIALS]" in sanitized
    assert user == "alice@example.com"


def test_redact_auth_argument_imap_login():
    """Verify IMAP LOGIN username is preserved and password is redacted."""
    sanitized, user = redact_auth_argument("LOGIN", "bob@example.com MyPassword456")
    assert "MyPassword456" not in sanitized
    assert "[REDACTED_PASSWORD]" in sanitized
    assert user == "bob@example.com"


def test_redact_auth_argument_pop3_pass():
    """Verify POP3 PASS password is completely redacted."""
    sanitized, user = redact_auth_argument("PASS", "PasswordSecret789")
    assert sanitized == "[REDACTED_PASSWORD]"
    assert user is None


# ==========================================
# 2. SMTP State Machine & Capability Tests
# ==========================================

def test_smtp_analysis_full_transaction():
    """Verify complete SMTP session analysis: 220 banner, EHLO capabilities, STARTTLS, MAIL/RCPT."""
    analyzer = EmailProtocolAnalyzer(db=mock.MagicMock())
    turns = [
        {"direction": "s2c", "text_preview": "220 mail.example.org ESMTP Postfix\r\n", "start_frame": 1, "start_time": 1.0},
        {"direction": "c2s", "text_preview": "EHLO client.example.org\r\n", "start_frame": 2, "start_time": 1.1},
        {"direction": "s2c", "text_preview": "250-mail.example.org\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n", "start_frame": 3, "start_time": 1.2},
        {"direction": "c2s", "text_preview": "STARTTLS\r\n", "start_frame": 4, "start_time": 1.3},
        {"direction": "s2c", "text_preview": "220 2.0.0 Ready to start TLS\r\n", "start_frame": 5, "start_time": 1.4},
        {"direction": "c2s", "text_preview": "QUIT\r\n", "start_frame": 6, "start_time": 1.5},
        {"direction": "s2c", "text_preview": "221 2.0.0 Bye\r\n", "start_frame": 7, "start_time": 1.6},
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
    sess.last_frame_number = 7

    res = analyzer._analyze_smtp_session(sess)

    assert res.protocol == "SMTP"
    assert "220 mail.example.org" in res.server_banner
    assert "EHLO client.example.org" in res.client_greeting
    assert res.starttls_advertised is True
    assert res.starttls_requested is True
    assert res.starttls_accepted is True
    assert "PLAIN" in res.auth_mechanisms
    assert "LOGIN" in res.auth_mechanisms
    assert "8BITMIME" in res.capabilities
    assert res.commands_count == 3  # EHLO, STARTTLS, QUIT
    assert len(res.events) >= 6


def test_smtp_cleartext_auth_warning():
    """Verify security warnings when SMTP client performs AUTH without STARTTLS."""
    analyzer = EmailProtocolAnalyzer(db=mock.MagicMock())
    turns = [
        {"direction": "s2c", "text_preview": "220 mail.insecure.corp ESMTP\r\n", "start_frame": 1, "start_time": 1.0},
        {"direction": "c2s", "text_preview": "EHLO client.insecure.corp\r\n", "start_frame": 2, "start_time": 1.1},
        {"direction": "s2c", "text_preview": "250-mail.insecure.corp\r\n250 AUTH PLAIN\r\n", "start_frame": 3, "start_time": 1.2},
        {"direction": "c2s", "text_preview": "AUTH PLAIN AHVzZXIAcGFzcw==\r\n", "start_frame": 4, "start_time": 1.3},
        {"direction": "s2c", "text_preview": "535 5.7.8 Authentication credentials invalid\r\n", "start_frame": 5, "start_time": 1.4},
    ]

    sess = mock.MagicMock(spec=TcpSession)
    sess.job_id = "job-smtp-2"
    sess.id = "sess-smtp-2"
    sess.tcp_stream = 0
    sess.protocol = "SMTP"
    sess.client_ip = "10.0.0.1"
    sess.server_ip = "10.0.0.2"
    sess.client_port = 50000
    sess.server_port = 25
    sess.conversation_flow = turns
    sess.first_frame_number = 1
    sess.last_frame_number = 5

    res = analyzer._analyze_smtp_session(sess)

    assert res.starttls_advertised is False
    assert res.auth_attempted is True
    assert res.auth_successful is False
    assert "user" in res.auth_usernames
    assert any("STARTTLS_NOT_ADVERTISED" in w for w in res.security_warnings)
    assert any("CLEARTEXT_AUTH" in w for w in res.security_warnings)
    assert any("AUTH_FAILURE" in w for w in res.security_warnings)


# ==========================================
# 3. IMAP State Machine & Capability Tests
# ==========================================

def test_imap_analysis_session():
    """Verify IMAP session analysis: greeting, CAPABILITY, STARTTLS, LOGIN, SELECT."""
    analyzer = EmailProtocolAnalyzer(db=mock.MagicMock())
    turns = [
        {"direction": "s2c", "text_preview": "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] Server ready\r\n", "start_frame": 1, "start_time": 1.0},
        {"direction": "c2s", "text_preview": "A001 CAPABILITY\r\n", "start_frame": 2, "start_time": 1.1},
        {"direction": "s2c", "text_preview": "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN\r\nA001 OK CAPABILITY completed\r\n", "start_frame": 3, "start_time": 1.2},
        {"direction": "c2s", "text_preview": "A002 STARTTLS\r\n", "start_frame": 4, "start_time": 1.3},
        {"direction": "s2c", "text_preview": "A002 OK Begin TLS negotiation now\r\n", "start_frame": 5, "start_time": 1.4},
        {"direction": "c2s", "text_preview": "A003 LOGOUT\r\n", "start_frame": 6, "start_time": 1.5},
        {"direction": "s2c", "text_preview": "* BYE Logging out\r\nA003 OK LOGOUT completed\r\n", "start_frame": 7, "start_time": 1.6},
    ]

    sess = mock.MagicMock(spec=TcpSession)
    sess.job_id = "job-imap-1"
    sess.id = "sess-imap-1"
    sess.tcp_stream = 1
    sess.protocol = "IMAP"
    sess.client_ip = "192.168.1.10"
    sess.server_ip = "192.168.1.25"
    sess.client_port = 48000
    sess.server_port = 143
    sess.conversation_flow = turns
    sess.first_frame_number = 1
    sess.last_frame_number = 7

    res = analyzer._analyze_imap_session(sess)

    assert res.protocol == "IMAP"
    assert "* OK" in res.server_banner
    assert res.starttls_advertised is True
    assert res.starttls_requested is True
    assert res.starttls_accepted is True
    assert "PLAIN" in res.auth_mechanisms
    assert res.commands_count == 3


# ==========================================
# 4. POP3 State Machine & Capability Tests
# ==========================================

def test_pop3_analysis_session():
    """Verify POP3 session analysis: +OK banner, CAPA, STLS, USER/PASS."""
    analyzer = EmailProtocolAnalyzer(db=mock.MagicMock())
    turns = [
        {"direction": "s2c", "text_preview": "+OK POP3 server ready <1234@pop.test>\r\n", "start_frame": 1, "start_time": 1.0},
        {"direction": "c2s", "text_preview": "CAPA\r\n", "start_frame": 2, "start_time": 1.1},
        {"direction": "s2c", "text_preview": "+OK Capability list follows\r\nSTLS\r\nUSER\r\nSASL PLAIN\r\n.\r\n", "start_frame": 3, "start_time": 1.2},
        {"direction": "c2s", "text_preview": "STLS\r\n", "start_frame": 4, "start_time": 1.3},
        {"direction": "s2c", "text_preview": "+OK Begin TLS negotiation\r\n", "start_frame": 5, "start_time": 1.4},
        {"direction": "c2s", "text_preview": "USER carol@test.com\r\n", "start_frame": 6, "start_time": 1.5},
        {"direction": "s2c", "text_preview": "+OK User accepted\r\n", "start_frame": 7, "start_time": 1.6},
        {"direction": "c2s", "text_preview": "PASS MySecretPassword\r\n", "start_frame": 8, "start_time": 1.7},
        {"direction": "s2c", "text_preview": "+OK Mailbox open\r\n", "start_frame": 9, "start_time": 1.8},
        {"direction": "c2s", "text_preview": "QUIT\r\n", "start_frame": 10, "start_time": 1.9},
        {"direction": "s2c", "text_preview": "+OK Bye\r\n", "start_frame": 11, "start_time": 2.0},
    ]

    sess = mock.MagicMock(spec=TcpSession)
    sess.job_id = "job-pop-1"
    sess.id = "sess-pop-1"
    sess.tcp_stream = 0
    sess.protocol = "POP3"
    sess.client_ip = "10.10.10.5"
    sess.server_ip = "10.10.10.1"
    sess.client_port = 38000
    sess.server_port = 110
    sess.conversation_flow = turns
    sess.first_frame_number = 1
    sess.last_frame_number = 11

    res = analyzer._analyze_pop3_session(sess)

    assert res.protocol == "POP3"
    assert "+OK POP3" in res.server_banner
    assert res.starttls_advertised is True
    assert res.starttls_requested is True
    assert res.starttls_accepted is True
    assert "STLS" in res.capabilities
    assert "carol@test.com" in res.auth_usernames
    assert res.auth_successful is True
    assert res.commands_count == 5


# ==========================================
# 5. Integration Tests with Database and PCAP
# ==========================================

def test_pcap_processing_populates_email_sessions(client: TestClient, db_session):
    """Verify that processing a PCAP capture automatically performs Email Protocol Analysis."""
    pkts = [
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=44444, dport=25, flags="S", seq=100, ack=0)),
        create_eth_pkt(IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=25, dport=44444, flags="SA", seq=200, ack=101)),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=44444, dport=25, flags="A", seq=101, ack=201)),
        create_eth_pkt(IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=25, dport=44444, flags="PA", seq=201, ack=101)/Raw(load=b"220 mail.integration.org ESMTP\r\n")),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=44444, dport=25, flags="PA", seq=101, ack=233)/Raw(load=b"EHLO client.org\r\n")),
        create_eth_pkt(IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=25, dport=44444, flags="PA", seq=233, ack=118)/Raw(load=b"250-mail.integration.org\r\n250 STARTTLS\r\n")),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=44444, dport=25, flags="PA", seq=118, ack=278)/Raw(load=b"QUIT\r\n")),
        create_eth_pkt(IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=25, dport=44444, flags="PA", seq=278, ack=124)/Raw(load=b"221 Bye\r\n")),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        temp_path = f.name

    try:
        pcap_file = PcapFile(
            original_filename="smtp_analysis.pcap",
            stored_filename="smtp_analysis_stored.pcap",
            file_path=temp_path,
            file_size_bytes=os.path.getsize(temp_path),
            sha256="test_smtp_sha256",
            md5="test_smtp_md5",
            file_format="pcap",
        )
        db_session.add(pcap_file)
        db_session.commit()

        job = AnalysisJob(pcap_file_id=pcap_file.id, status="QUEUED")
        db_session.add(job)
        db_session.commit()

        processor = PcapProcessor(db_session)
        result = processor.process_job(job.id)
        assert result["status"] == "COMPLETED"

        # Verify EmailSessionAnalysis was automatically created
        email_sessions = db_session.query(EmailSessionAnalysis).filter(EmailSessionAnalysis.job_id == job.id).all()
        assert len(email_sessions) == 1
        es = email_sessions[0]
        assert es.protocol == "SMTP"
        assert es.starttls_advertised is True
        assert es.commands_count >= 2
        assert "220 mail.integration.org" in es.server_banner
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ==========================================
# 6. RESTful API Endpoints Tests
# ==========================================

def test_api_email_sessions_endpoints(client: TestClient, db_session):
    """Test GET /api/v1/jobs/{job_id}/email-sessions, GET /email-sessions/{stream}, and POST /analyze-email-protocols."""
    pkts = [
        create_eth_pkt(IP(src="10.2.2.5", dst="10.2.2.10")/TCP(sport=35000, dport=110, flags="S", seq=50, ack=0)),
        create_eth_pkt(IP(src="10.2.2.10", dst="10.2.2.5")/TCP(sport=110, dport=35000, flags="SA", seq=80, ack=51)),
        create_eth_pkt(IP(src="10.2.2.10", dst="10.2.2.5")/TCP(sport=110, dport=35000, flags="PA", seq=81, ack=51)/Raw(load=b"+OK POP3 ready\r\n")),
        create_eth_pkt(IP(src="10.2.2.5", dst="10.2.2.10")/TCP(sport=35000, dport=110, flags="PA", seq=51, ack=98)/Raw(load=b"QUIT\r\n")),
        create_eth_pkt(IP(src="10.2.2.10", dst="10.2.2.5")/TCP(sport=110, dport=35000, flags="PA", seq=98, ack=57)/Raw(load=b"+OK Bye\r\n")),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        temp_path = f.name

    try:
        pcap_file = PcapFile(
            original_filename="pop3_api.pcap",
            stored_filename="pop3_api_stored.pcap",
            file_path=temp_path,
            file_size_bytes=os.path.getsize(temp_path),
            sha256="test_pop3_api_sha",
            md5="test_pop3_api_md5",
            file_format="pcap",
        )
        db_session.add(pcap_file)
        db_session.commit()

        job = AnalysisJob(pcap_file_id=pcap_file.id, status="QUEUED")
        db_session.add(job)
        db_session.commit()

        processor = PcapProcessor(db_session)
        processor.process_job(job.id)

        # 1. GET /api/v1/jobs/{job_id}/email-sessions
        res = client.get(f"/api/v1/jobs/{job.id}/email-sessions")
        assert res.status_code == 200
        data = res.json()
        assert data["job_id"] == job.id
        assert data["total_email_sessions"] == 1
        assert data["sessions"][0]["protocol"] == "POP3"

        # 2. GET /api/v1/jobs/{job_id}/email-sessions/{tcp_stream}
        stream_res = client.get(f"/api/v1/jobs/{job.id}/email-sessions/0")
        assert stream_res.status_code == 200
        stream_data = stream_res.json()
        assert stream_data["tcp_stream"] == 0
        assert stream_data["server_banner"] == "+OK POP3 ready"
        assert len(stream_data["events"]) >= 2

        # 3. 404 on invalid stream
        not_found_res = client.get(f"/api/v1/jobs/{job.id}/email-sessions/999")
        assert not_found_res.status_code == 404

        # 4. 404 on invalid job
        fake_res = client.get("/api/v1/jobs/non-existent-uuid/email-sessions")
        assert fake_res.status_code == 404

        # 5. POST /api/v1/jobs/{job_id}/analyze-email-protocols
        refresh_res = client.post(f"/api/v1/jobs/{job.id}/analyze-email-protocols")
        assert refresh_res.status_code == 200
        refresh_data = refresh_res.json()
        assert refresh_data["total_email_sessions"] == 1
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
