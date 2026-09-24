"""
Tests for Stage 02: PCAP Processing, frame metadata extraction, protocol detection, and corruption handling.
"""

import io
import os
import tempfile
from unittest import mock
import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, IPv6, TCP, UDP, Raw, wrpcap, Ether

from app.models.job import AnalysisJob
from app.models.pcap import PcapFile
from app.models.packet import PacketMetadata
from app.services.pcap_processor import PcapProcessor, get_tcp_flags_string, detect_layer7_protocol


def create_sample_email_pcap_file(filepath: str):
    """Generate a realistic PCAP with SMTP handshake, commands, TLS packet, UDP DNS, and IPv6."""
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    packets = []

    # Stream 0: SMTP Conversation (192.168.1.100 -> 192.168.1.25, Port 25)
    # 1. TCP SYN
    p1 = eth/IP(src="192.168.1.100", dst="192.168.1.25")/TCP(sport=45120, dport=25, flags="S", seq=1000)
    # 2. TCP SYN-ACK
    p2 = eth/IP(src="192.168.1.25", dst="192.168.1.100")/TCP(sport=25, dport=45120, flags="SA", seq=5000, ack=1001)
    # 3. TCP ACK
    p3 = eth/IP(src="192.168.1.100", dst="192.168.1.25")/TCP(sport=45120, dport=25, flags="A", seq=1001, ack=5001)
    # 4. Server 220 Greeting
    p4 = eth/IP(src="192.168.1.25", dst="192.168.1.100")/TCP(sport=25, dport=45120, flags="PA", seq=5001, ack=1001)/Raw(load=b"220 mail.example.com ESMTP\r\n")
    # 5. Client EHLO
    p5 = eth/IP(src="192.168.1.100", dst="192.168.1.25")/TCP(sport=45120, dport=25, flags="PA", seq=1001, ack=5028)/Raw(load=b"EHLO client.example.com\r\n")

    # Stream 1: Separate IMAP Conversation (192.168.1.101 -> 192.168.1.143, Port 143)
    p6 = eth/IP(src="192.168.1.101", dst="192.168.1.143")/TCP(sport=51234, dport=143, flags="PA", seq=2000, ack=3000)/Raw(load=b"* OK IMAP4rev1 Server Ready\r\n")

    # TLS Handshake Client Hello Packet
    tls_payload = b"\x16\x03\x01\x00\x10" + b"\x01\x00\x00\x0c" + b"\x03\x03" + b"\x00" * 8
    p7 = eth/IP(src="192.168.1.100", dst="192.168.1.25")/TCP(sport=45120, dport=25, flags="PA", seq=1025, ack=5028)/Raw(load=tls_payload)

    # UDP DNS Packet
    p8 = eth/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=54321, dport=53)/Raw(load=b"DNS Query")

    # IPv6 Packet
    p9 = eth/IPv6(src="2001:db8::1", dst="2001:db8::2")/TCP(sport=60000, dport=993, flags="S", seq=999)

    packets.extend([p1, p2, p3, p4, p5, p6, p7, p8, p9])
    wrpcap(filepath, packets)


def test_helper_tcp_flags_formatting():
    """Verify formatting of TCP flags."""
    assert "SYN" in get_tcp_flags_string("S")
    assert "ACK" in get_tcp_flags_string("A")
    assert "FIN" in get_tcp_flags_string("FA")
    assert get_tcp_flags_string("") == "NONE"


def test_helper_protocol_detection():
    """Verify Layer 7 protocol heuristics."""
    # SMTP
    assert detect_layer7_protocol("TCP", 45000, 25, b"EHLO mail.com") == "SMTP"
    assert detect_layer7_protocol("TCP", 25, 45000, b"220 greeting") == "SMTP"
    # IMAP
    assert detect_layer7_protocol("TCP", 143, 50000, b"* OK IMAP") == "IMAP"
    # POP3
    assert detect_layer7_protocol("TCP", 110, 50000, b"+OK POP3 server") == "POP3"
    # TLS Handshake
    assert detect_layer7_protocol("TCP", 50000, 465, b"\x16\x03\x03\x00\x20") == "TLS (Handshake)"
    # DNS
    assert detect_layer7_protocol("UDP", 53000, 53, b"query") == "DNS"
    # Generic TCP
    assert detect_layer7_protocol("TCP", 8080, 9090, b"random_binary") == "TCP"


def test_process_valid_pcap_job(client: TestClient, tmp_path):
    """Test full processing workflow on uploaded PCAP."""
    pcap_path = os.path.join(tmp_path, "synthetic_email.pcap")
    create_sample_email_pcap_file(pcap_path)

    with open(pcap_path, "rb") as f:
        content = f.read()

    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        # 1. Upload PCAP
        upload_res = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("synthetic_email.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        assert upload_res.status_code == 201
        job_id = upload_res.json()["job_id"]

        # 2. Process capture
        process_res = client.post(f"/api/v1/jobs/{job_id}/process")
        assert process_res.status_code == 200
        job_data = process_res.json()
        assert job_data["status"] == "COMPLETED"
        assert job_data["progress_percent"] == 100
        assert "Packet metadata extracted successfully" in job_data["stage_message"]

        # 3. Query packets
        packets_res = client.get(f"/api/v1/jobs/{job_id}/packets?limit=20")
        assert packets_res.status_code == 200
        pkt_data = packets_res.json()
        assert pkt_data["total"] == 9
        assert len(pkt_data["packets"]) == 9

        # Check frame 1
        f1 = pkt_data["packets"][0]
        assert f1["frame_number"] == 1
        assert f1["src_ip"] == "192.168.1.100"
        assert f1["dst_ip"] == "192.168.1.25"
        assert f1["transport_protocol"] == "TCP"
        assert f1["src_port"] == 45120
        assert f1["dst_port"] == 25
        assert "SYN" in f1["tcp_flags"]

        # Check IPv6 packet (frame 9)
        f9 = pkt_data["packets"][8]
        assert f9["frame_number"] == 9
        assert f9["ip_version"] == 6
        assert "2001:db8" in f9["src_ip"]

        # 4. Query summary
        summary_res = client.get(f"/api/v1/jobs/{job_id}/summary")
        assert summary_res.status_code == 200
        summary_data = summary_res.json()
        assert summary_data["total_packets"] == 9
        assert summary_data["tcp_packets"] == 8
        assert summary_data["udp_packets"] == 1
        assert "SMTP" in summary_data["detected_protocols"]
        assert "IMAP" in summary_data["detected_protocols"]
        assert "DNS" in summary_data["detected_protocols"]
        assert summary_data["distinct_conversations"] >= 2


def test_packet_filtering_endpoints(client: TestClient, tmp_path):
    """Test filtering packet metadata by protocol, port, and TCP stream."""
    pcap_path = os.path.join(tmp_path, "synthetic_filter.pcap")
    create_sample_email_pcap_file(pcap_path)

    with open(pcap_path, "rb") as f:
        content = f.read()

    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        upload_res = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("filter.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        job_id = upload_res.json()["job_id"]
        client.post(f"/api/v1/jobs/{job_id}/process")

        # Filter by protocol = SMTP
        smtp_res = client.get(f"/api/v1/jobs/{job_id}/packets?protocol=SMTP")
        assert smtp_res.status_code == 200
        for pkt in smtp_res.json()["packets"]:
            assert "SMTP" in pkt["detected_protocol"]

        # Filter by port = 53 (DNS)
        port_res = client.get(f"/api/v1/jobs/{job_id}/packets?port=53")
        assert port_res.status_code == 200
        assert port_res.json()["total"] == 1
        assert port_res.json()["packets"][0]["dst_port"] == 53

        # Filter by TCP stream = 0
        stream_res = client.get(f"/api/v1/jobs/{job_id}/packets?tcp_stream=0")
        assert stream_res.status_code == 200
        for pkt in stream_res.json()["packets"]:
            assert pkt["tcp_stream"] == 0


def test_process_corrupted_pcap(client: TestClient, tmp_path):
    """Test corrupted capture handling produces graceful FAILED state without crashing."""
    corrupt_file_path = os.path.join(tmp_path, "corrupt.pcap")
    # Valid 24-byte PCAP header followed by corrupted invalid packet header
    with open(corrupt_file_path, "wb") as f:
        f.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
        f.write(b"\xff\xff\x00\x00")  # Truncated invalid packet header

    with open(corrupt_file_path, "rb") as f:
        content = f.read()

    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        upload_res = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("corrupt.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        assert upload_res.status_code == 201
        job_id = upload_res.json()["job_id"]

        process_res = client.post(f"/api/v1/jobs/{job_id}/process")
        assert process_res.status_code == 200
        data = process_res.json()
        assert data["status"] == "FAILED"
        assert "Corrupt" in data["error_message"] or "parsing error" in data["error_message"] or "valid packet" in data["error_message"]


def test_process_missing_file_on_disk(client: TestClient, tmp_path):
    """Test graceful failure when underlying capture file was removed from disk."""
    pcap_path = os.path.join(tmp_path, "missing_test.pcap")
    create_sample_email_pcap_file(pcap_path)

    with open(pcap_path, "rb") as f:
        content = f.read()

    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        upload_res = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("missing_test.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        job_id = upload_res.json()["job_id"]

        # Delete the stored file from disk
        for fname in os.listdir(tmp_path):
            if fname.endswith(".pcap"):
                os.remove(os.path.join(tmp_path, fname))

        process_res = client.post(f"/api/v1/jobs/{job_id}/process")
        assert process_res.status_code == 200
        assert process_res.json()["status"] == "FAILED"
        assert "not found on disk" in process_res.json()["error_message"]


def test_endpoints_not_found(client: TestClient):
    """Test 404 responses for non-existent job queries."""
    assert client.post("/api/v1/jobs/unknown-uuid/process").status_code == 404
    assert client.get("/api/v1/jobs/unknown-uuid/packets").status_code == 404
    assert client.get("/api/v1/jobs/unknown-uuid/summary").status_code == 404
