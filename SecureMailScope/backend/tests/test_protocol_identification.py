"""
Tests for Stage 03: Protocol Identification.
Verifies identification of SMTP, IMAP, and POP3 using behavioral signatures,
conversational flow, and TLS inspection—not ports alone.
Includes positive tests (standard & non-standard ports, direct TLS),
negative tests (HTTP/SSH on standard & email ports, DNS),
unknown/insufficient evidence tests (empty TCP handshake, random binary),
and API endpoints.
"""

import io
import os
import tempfile
from unittest import mock
import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, UDP, Raw, wrpcap, Ether

from app.services.protocol_identifier import ProtocolIdentifier, StreamPacketRecord, parse_tls_client_hello


def create_eth_pkt(*layers):
    """Helper to create Ethernet wrapped packet avoiding macOS BPF permission issues."""
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    pkt = eth
    for l in layers:
        pkt = pkt / l
    return pkt


# ==========================================
# 1. Pure Unit Tests for ProtocolIdentifier
# ==========================================

def test_identify_smtp_standard_port():
    """Verify SMTP identified with high confidence on standard port 25 via 220 banner + EHLO."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    packets = [
        StreamPacketRecord(1, 100.0, "10.0.0.1", "10.0.0.2", 40001, 25, "S", b""),
        StreamPacketRecord(2, 100.1, "10.0.0.2", "10.0.0.1", 25, 40001, "SA", b""),
        StreamPacketRecord(3, 100.2, "10.0.0.2", "10.0.0.1", 25, 40001, "PA", b"220 mail.example.org ESMTP Postfix\r\n"),
        StreamPacketRecord(4, 100.3, "10.0.0.1", "10.0.0.2", 40001, 25, "PA", b"EHLO client.example.org\r\n"),
        StreamPacketRecord(5, 100.4, "10.0.0.2", "10.0.0.1", 25, 40001, "PA", b"250-mail.example.org\r\n250 STARTTLS\r\n"),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "SMTP"
    assert res["confidence"] == 1.0
    assert res["confidence_level"] == "HIGH"
    assert res["is_mail_protocol"] is True
    assert res["classification_method"] == "SIGNATURE_AND_BEHAVIOR"
    assert res["evidence"]["port_analysis"]["matches_detected_protocol"] is True
    assert any("220" in s for s in res["evidence"]["matched_signatures"])
    assert any("EHLO" in s for s in res["evidence"]["matched_signatures"])
    assert len(res["evidence"]["anomalies"]) == 0


def test_identify_smtp_non_standard_port():
    """Verify SMTP identified on non-standard port 2525 strictly from payload signatures."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    packets = [
        StreamPacketRecord(1, 100.0, "10.0.0.1", "10.0.0.2", 55555, 2525, "S", b""),
        StreamPacketRecord(2, 100.1, "10.0.0.2", "10.0.0.1", 2525, 55555, "SA", b""),
        StreamPacketRecord(3, 100.2, "10.0.0.2", "10.0.0.1", 2525, 55555, "PA", b"220 custom-relay.corp ESMTP\r\n"),
        StreamPacketRecord(4, 100.3, "10.0.0.1", "10.0.0.2", 55555, 2525, "PA", b"EHLO internal.corp\r\n"),
    ]
    res = identifier.classify_tcp_stream(1, packets)

    assert res["protocol"] == "SMTP"
    assert res["confidence"] >= 0.95
    assert res["confidence_level"] == "HIGH"
    assert res["is_mail_protocol"] is True
    assert res["server_port"] == 2525


def test_identify_imap_standard_port():
    """Verify IMAP identified on port 143 via * OK greeting + tagged command."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    packets = [
        StreamPacketRecord(1, 10.0, "192.168.1.5", "192.168.1.10", 41234, 143, "S", b""),
        StreamPacketRecord(2, 10.1, "192.168.1.10", "192.168.1.5", 143, 41234, "PA", b"* OK [CAPABILITY IMAP4rev1] Server Ready\r\n"),
        StreamPacketRecord(3, 10.2, "192.168.1.5", "192.168.1.10", 41234, 143, "PA", b"a001 CAPABILITY\r\n"),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "IMAP"
    assert res["confidence"] == 1.0
    assert res["confidence_level"] == "HIGH"
    assert res["is_mail_protocol"] is True
    assert res["evidence"]["port_analysis"]["matches_detected_protocol"] is True


def test_identify_imap_non_standard_port():
    """Verify IMAP identified on non-standard port 1143."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    packets = [
        StreamPacketRecord(1, 10.0, "192.168.1.5", "192.168.1.10", 41234, 1143, "S", b""),
        StreamPacketRecord(2, 10.1, "192.168.1.10", "192.168.1.5", 1143, 41234, "PA", b"* OK Dovecot ready.\r\n"),
        StreamPacketRecord(3, 10.2, "192.168.1.5", "192.168.1.10", 41234, 1143, "PA", b"A01 LOGIN alice secret\r\n"),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "IMAP"
    assert res["confidence"] >= 0.95
    assert res["is_mail_protocol"] is True
    assert res["evidence"]["port_analysis"]["matches_detected_protocol"] is False
    assert "non-standard" in res["evidence"]["port_analysis"]["notes"].lower()


def test_identify_pop3_standard_port():
    """Verify POP3 identified on port 110 via +OK greeting + USER command."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    packets = [
        StreamPacketRecord(1, 20.0, "192.168.2.5", "192.168.2.10", 38000, 110, "S", b""),
        StreamPacketRecord(2, 20.1, "192.168.2.10", "192.168.2.5", 110, 38000, "PA", b"+OK POP3 server ready <xyz@mail>\r\n"),
        StreamPacketRecord(3, 20.2, "192.168.2.5", "192.168.2.10", 38000, 110, "PA", b"USER bob\r\n"),
        StreamPacketRecord(4, 20.3, "192.168.2.10", "192.168.2.5", 110, 38000, "PA", b"+OK password required\r\n"),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "POP3"
    assert res["confidence"] == 1.0
    assert res["confidence_level"] == "HIGH"
    assert res["is_mail_protocol"] is True
    assert res["evidence"]["port_analysis"]["matches_detected_protocol"] is True


def test_identify_pop3_non_standard_port():
    """Verify POP3 identified on non-standard port 8110."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    packets = [
        StreamPacketRecord(1, 20.0, "192.168.2.5", "192.168.2.10", 38000, 8110, "S", b""),
        StreamPacketRecord(2, 20.1, "192.168.2.10", "192.168.2.5", 8110, 38000, "PA", b"+OK POP3 ready\r\n"),
        StreamPacketRecord(3, 20.2, "192.168.2.5", "192.168.2.10", 38000, 8110, "PA", b"CAPA\r\n"),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "POP3"
    assert res["confidence"] >= 0.95
    assert res["is_mail_protocol"] is True


def test_identify_tls_smtps_and_sni_parsing():
    """Verify TLS SMTPS detection on port 465 with SNI extraction."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())

    # Build synthetic TLS Client Hello with SNI "smtp.example.org"
    sni_bytes = b"smtp.example.org"
    # Extension 0x0000: server_name
    ext_sni = b"\x00\x00" + int(len(sni_bytes) + 5).to_bytes(2, "big") + \
              int(len(sni_bytes) + 3).to_bytes(2, "big") + b"\x00" + \
              int(len(sni_bytes)).to_bytes(2, "big") + sni_bytes
    exts = int(len(ext_sni)).to_bytes(2, "big") + ext_sni

    client_hello = (
        b"\x01" + b"\x00\x00\x40" + b"\x03\x03" + b"\x00" * 32 +
        b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + exts
    )
    tls_record = b"\x16\x03\x01" + int(len(client_hello)).to_bytes(2, "big") + client_hello

    packets = [
        StreamPacketRecord(1, 1.0, "10.0.0.1", "10.0.0.2", 49152, 465, "S", b""),
        StreamPacketRecord(2, 1.1, "10.0.0.1", "10.0.0.2", 49152, 465, "PA", tls_record),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "SMTPS"
    assert res["confidence"] >= 0.90
    assert res["confidence_level"] == "HIGH"
    assert res["is_mail_protocol"] is True
    assert res["classification_method"] == "TLS_INSPECTION"


def test_identify_negative_http_on_standard_port():
    """Negative test: HTTP traffic on port 80 must NOT be classified as email."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    http_payload = b"GET /api/v1/health HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
    packets = [
        StreamPacketRecord(1, 1.0, "10.0.0.1", "10.0.0.2", 50000, 80, "S", b""),
        StreamPacketRecord(2, 1.1, "10.0.0.1", "10.0.0.2", 50000, 80, "PA", http_payload),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "HTTP"
    assert res["is_mail_protocol"] is False
    assert res["confidence"] >= 0.95
    assert len(res["evidence"]["anomalies"]) == 0


def test_identify_negative_http_on_port_25_anomaly():
    """Negative test: HTTP traffic on SMTP port 25 must be detected as HTTP with anomaly flag."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    http_payload = b"POST /upload HTTP/1.1\r\nHost: badactor.org\r\n\r\n"
    packets = [
        StreamPacketRecord(1, 1.0, "10.0.0.1", "10.0.0.2", 50000, 25, "S", b""),
        StreamPacketRecord(2, 1.1, "10.0.0.1", "10.0.0.2", 50000, 25, "PA", http_payload),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "HTTP"
    assert res["is_mail_protocol"] is False
    assert res["confidence"] >= 0.95
    assert any("SUSPICIOUS_PORT_MISMATCH" in a for a in res["evidence"]["anomalies"])


def test_identify_negative_ssh():
    """Negative test: SSH traffic must be identified as SSH with zero email false positive."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    ssh_banner = b"SSH-2.0-OpenSSH_9.3\r\n"
    packets = [
        StreamPacketRecord(1, 1.0, "10.0.0.1", "10.0.0.2", 50000, 22, "S", b""),
        StreamPacketRecord(2, 1.1, "10.0.0.2", "10.0.0.1", 22, 50000, "PA", ssh_banner),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "SSH"
    assert res["is_mail_protocol"] is False
    assert res["confidence"] == 1.0


def test_identify_unknown_tcp_handshake_only():
    """
    Unknown test: TCP stream with ONLY handshake (SYN/ACK) and 0 payload bytes
    must be classified as UNKNOWN with confidence 0.0, despite contacting port 25.
    """
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    packets = [
        StreamPacketRecord(1, 1.0, "10.0.0.1", "10.0.0.2", 45000, 25, "S", b""),
        StreamPacketRecord(2, 1.1, "10.0.0.2", "10.0.0.1", 25, 45000, "SA", b""),
        StreamPacketRecord(3, 1.2, "10.0.0.1", "10.0.0.2", 45000, 25, "A", b""),
        StreamPacketRecord(4, 1.3, "10.0.0.1", "10.0.0.2", 45000, 25, "FA", b""),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "UNKNOWN"
    assert res["confidence"] == 0.0
    assert res["confidence_level"] == "UNKNOWN"
    assert res["classification_method"] == "INSUFFICIENT_EVIDENCE"
    assert res["is_mail_protocol"] is False
    assert "zero application payload" in res["evidence"]["insufficient_evidence_reason"].lower()


def test_identify_unknown_random_binary():
    """Unknown test: Arbitrary non-email binary payload on arbitrary port returns UNKNOWN."""
    identifier = ProtocolIdentifier(db=mock.MagicMock())
    packets = [
        StreamPacketRecord(1, 1.0, "10.0.0.1", "10.0.0.2", 45000, 9999, "S", b""),
        StreamPacketRecord(2, 1.1, "10.0.0.1", "10.0.0.2", 45000, 9999, "PA", b"\xfe\xed\xfa\xce\xaa\xbb\xcc\xdd"),
    ]
    res = identifier.classify_tcp_stream(0, packets)

    assert res["protocol"] == "UNKNOWN"
    assert res["confidence"] == 0.0
    assert res["confidence_level"] == "UNKNOWN"
    assert res["is_mail_protocol"] is False


# ==========================================
# 2. End-to-End API and Integration Tests
# ==========================================

def test_api_protocol_identification_workflow(client: TestClient, tmp_path):
    """End-to-end integration test: Upload multi-stream PCAP, process, and query protocol APIs."""
    pcap_path = os.path.join(tmp_path, "multi_protocol.pcap")

    packets = [
        # Stream 0: Clean SMTP
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.25"), TCP(sport=30000, dport=25, flags="S", seq=100)),
        create_eth_pkt(IP(src="192.168.1.25", dst="192.168.1.10"), TCP(sport=25, dport=30000, flags="SA", seq=500, ack=101)),
        create_eth_pkt(IP(src="192.168.1.25", dst="192.168.1.10"), TCP(sport=25, dport=30000, flags="PA", seq=501, ack=101), Raw(load=b"220 smtp.corp ESMTP\r\n")),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.25"), TCP(sport=30000, dport=25, flags="PA", seq=101, ack=521), Raw(load=b"EHLO client.corp\r\n")),

        # Stream 1: Clean IMAP on non-standard port 1143
        create_eth_pkt(IP(src="192.168.1.11", dst="192.168.1.143"), TCP(sport=40000, dport=1143, flags="S", seq=200)),
        create_eth_pkt(IP(src="192.168.1.143", dst="192.168.1.11"), TCP(sport=1143, dport=40000, flags="PA", seq=600, ack=201), Raw(load=b"* OK IMAP4rev1 Ready\r\n")),
        create_eth_pkt(IP(src="192.168.1.11", dst="192.168.1.143"), TCP(sport=40000, dport=1143, flags="PA", seq=201, ack=621), Raw(load=b"A1 CAPABILITY\r\n")),

        # Stream 2: Empty TCP handshake on port 25 (Zero application data)
        create_eth_pkt(IP(src="192.168.1.12", dst="192.168.1.25"), TCP(sport=50000, dport=25, flags="S", seq=300)),
        create_eth_pkt(IP(src="192.168.1.25", dst="192.168.1.12"), TCP(sport=25, dport=50000, flags="SA", seq=700, ack=301)),
        create_eth_pkt(IP(src="192.168.1.12", dst="192.168.1.25"), TCP(sport=50000, dport=25, flags="FA", seq=301, ack=701)),

        # Flow 3: UDP DNS
        create_eth_pkt(IP(src="192.168.1.10", dst="8.8.8.8"), UDP(sport=53000, dport=53), Raw(load=b"DNS Query")),
    ]
    wrpcap(pcap_path, packets)

    with open(pcap_path, "rb") as f:
        content = f.read()

    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        # 1. Upload PCAP
        upload_res = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("multi_protocol.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        assert upload_res.status_code == 201
        job_id = upload_res.json()["job_id"]

        # 2. Process capture
        process_res = client.post(f"/api/v1/jobs/{job_id}/process")
        assert process_res.status_code == 200

        # 3. Query all protocols for job
        proto_res = client.get(f"/api/v1/jobs/{job_id}/protocols")
        assert proto_res.status_code == 200
        data = proto_res.json()

        assert data["job_id"] == job_id
        assert data["total_streams"] >= 3
        assert data["mail_streams"] >= 2

        protocols_found = {p["protocol"]: p for p in data["protocols"]}
        assert "SMTP" in protocols_found
        assert "IMAP" in protocols_found
        assert "UNKNOWN" in protocols_found

        smtp_rec = protocols_found["SMTP"]
        assert smtp_rec["confidence"] == 1.0
        assert smtp_rec["is_mail_protocol"] is True
        assert len(smtp_rec["evidence"]["evidence_frames"]) >= 2

        imap_rec = protocols_found["IMAP"]
        assert imap_rec["confidence"] >= 0.95
        assert imap_rec["is_mail_protocol"] is True

        unknown_rec = protocols_found["UNKNOWN"]
        assert unknown_rec["confidence"] == 0.0
        assert unknown_rec["classification_method"] == "INSUFFICIENT_EVIDENCE"

        # 4. Query specific stream endpoint
        stream_id = smtp_rec["tcp_stream"]
        stream_res = client.get(f"/api/v1/jobs/{job_id}/protocols/{stream_id}")
        assert stream_res.status_code == 200
        stream_data = stream_res.json()
        assert stream_data["protocol"] == "SMTP"
        assert stream_data["tcp_stream"] == stream_id

        # 5. Test 404 on invalid stream ID
        bad_stream_res = client.get(f"/api/v1/jobs/{job_id}/protocols/99999")
        assert bad_stream_res.status_code == 404

        # 6. Test manual re-trigger endpoint
        retrigger_res = client.post(f"/api/v1/jobs/{job_id}/identify-protocols")
        assert retrigger_res.status_code == 200
        retrigger_data = retrigger_res.json()
        assert retrigger_data["total_streams"] == data["total_streams"]


def test_api_protocol_endpoints_not_found(client: TestClient):
    """Verify 404 responses for non-existent job UUIDs across protocol endpoints."""
    fake_job = "00000000-0000-0000-0000-000000000000"

    res1 = client.get(f"/api/v1/jobs/{fake_job}/protocols")
    assert res1.status_code == 404

    res2 = client.get(f"/api/v1/jobs/{fake_job}/protocols/0")
    assert res2.status_code == 404

    res3 = client.post(f"/api/v1/jobs/{fake_job}/identify-protocols")
    assert res3.status_code == 404

