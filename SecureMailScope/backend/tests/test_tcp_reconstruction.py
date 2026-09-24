"""
Tests for Stage 04: TCP Session Reconstruction.
Verifies bidirectional TCP reassembly, out-of-order handling,
retransmission/duplicate filtering, sequence gap detection,
session lifecycle state tracking, conversation turns generation,
and RESTful session endpoints.
"""

import io
import os
import tempfile
from unittest import mock
import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, Raw, wrpcap, Ether

from app.models.job import AnalysisJob
from app.models.pcap import PcapFile
from app.models.session import TcpSession
from app.services.pcap_processor import PcapProcessor
from app.services.tcp_reconstructor import TcpReconstructor, RawTcpSegment, safe_text_preview


def create_eth_pkt(*layers):
    """Helper to create Ethernet wrapped packet avoiding macOS BPF permission issues."""
    eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
    pkt = eth
    for l in layers:
        pkt = pkt / l
    return pkt


# ==========================================
# 1. Pure Unit Tests for TcpReconstructor
# ==========================================

def test_safe_text_preview():
    """Verify safe_text_preview sanitizes binary bytes and truncates properly."""
    assert safe_text_preview(b"") == ""
    assert safe_text_preview(b"Hello\r\nWorld") == "Hello\r\nWorld"
    # Non-printable replaced by '.'
    assert safe_text_preview(bytes([0x00, 0x01, 0x41, 0x42])) == "..AB"
    # Truncation
    long_data = b"A" * 300
    res = safe_text_preview(long_data, max_len=50)
    assert len(res) > 50
    assert "more bytes" in res


def test_in_order_reassembly():
    """Verify segments arriving in order are reassembled cleanly without retransmissions or gaps."""
    reconstructor = TcpReconstructor(db=mock.MagicMock())
    # Client sends two segments in order
    segments = [
        RawTcpSegment(1, 100.0, "10.0.0.1", "10.0.0.2", 40000, 25, 1000, 1, "PA", b"EHLO example.com\r\n"),
        RawTcpSegment(2, 100.1, "10.0.0.1", "10.0.0.2", 40000, 25, 1018, 1, "PA", b"MAIL FROM:<alice@example.com>\r\n"),
    ]
    data, retrans, ooo, gaps = reconstructor._reassemble_direction(segments)

    assert data == b"EHLO example.com\r\nMAIL FROM:<alice@example.com>\r\n"
    assert len(retrans) == 0
    assert len(ooo) == 0
    assert len(gaps) == 0


def test_out_of_order_reassembly():
    """Verify segments arriving out of order (Segment 2 arrives before Segment 1) are sorted and reassembled."""
    reconstructor = TcpReconstructor(db=mock.MagicMock())
    # Segment 2 (seq=1010, len=10) arrives BEFORE Segment 1 (seq=1000, len=10)
    seg1 = RawTcpSegment(2, 100.2, "10.0.0.1", "10.0.0.2", 40000, 25, 1000, 1, "PA", b"0123456789")
    seg2 = RawTcpSegment(1, 100.1, "10.0.0.1", "10.0.0.2", 40000, 25, 1010, 1, "PA", b"ABCDEFGHIJ")

    arrival_order = [seg2, seg1]
    data, retrans, ooo, gaps = reconstructor._reassemble_direction(arrival_order)

    # Reassembled data should be ordered by seq (seg1 + seg2)
    assert data == b"0123456789ABCDEFGHIJ"
    assert len(ooo) == 1
    assert ooo[0]["frame_number"] == 2
    assert ooo[0]["seq"] == 1000
    assert len(retrans) == 0
    assert len(gaps) == 0


def test_retransmission_and_duplicate_deduplication():
    """Verify exact retransmissions and duplicate segments are detected and not duplicated in payload."""
    reconstructor = TcpReconstructor(db=mock.MagicMock())
    # Segment 1 sent, then exact retransmission of Segment 1
    seg1 = RawTcpSegment(1, 100.0, "10.0.0.1", "10.0.0.2", 40000, 25, 1000, 1, "PA", b"HELLO")
    seg1_dupe = RawTcpSegment(2, 100.2, "10.0.0.1", "10.0.0.2", 40000, 25, 1000, 1, "PA", b"HELLO")
    seg2 = RawTcpSegment(3, 100.4, "10.0.0.1", "10.0.0.2", 40000, 25, 1005, 1, "PA", b" WORLD")

    data, retrans, ooo, gaps = reconstructor._reassemble_direction([seg1, seg1_dupe, seg2])

    assert data == b"HELLO WORLD"
    assert len(retrans) == 1
    assert retrans[0]["type"] == "DUPLICATE_OR_SUBSET"
    assert retrans[0]["frame_number"] == 2
    assert len(gaps) == 0


def test_partial_overlap_handling():
    """Verify partial overlap trimming: segment 1 has bytes [0..10], segment 2 has bytes [5..15]."""
    reconstructor = TcpReconstructor(db=mock.MagicMock())
    # Segment 1: seq=1000, len=10 (bytes "0123456789")
    seg1 = RawTcpSegment(1, 100.0, "10.0.0.1", "10.0.0.2", 40000, 25, 1000, 1, "PA", b"0123456789")
    # Segment 2: seq=1005, len=10 (bytes "56789ABCDE") -> overlap of 5 bytes
    seg2 = RawTcpSegment(2, 100.1, "10.0.0.1", "10.0.0.2", 40000, 25, 1005, 1, "PA", b"56789ABCDE")

    data, retrans, ooo, gaps = reconstructor._reassemble_direction([seg1, seg2])

    assert data == b"0123456789ABCDE"
    assert len(retrans) == 1
    assert retrans[0]["type"] == "PARTIAL_OVERLAP"
    assert retrans[0]["overlap_bytes"] == 5
    assert retrans[0]["new_bytes"] == 5


def test_sequence_gap_detection():
    """Verify sequence gaps (packet loss) are detected and recorded with byte offset."""
    reconstructor = TcpReconstructor(db=mock.MagicMock())
    # Segment 1: seq=1000, len=10 -> expected next is 1010
    seg1 = RawTcpSegment(1, 100.0, "10.0.0.1", "10.0.0.2", 40000, 25, 1000, 1, "PA", b"0123456789")
    # Missing 20 bytes (seq 1010 to 1030)
    # Segment 2: seq=1030, len=5
    seg2 = RawTcpSegment(2, 100.2, "10.0.0.1", "10.0.0.2", 40000, 25, 1030, 1, "PA", b"XYZ12")

    data, retrans, ooo, gaps = reconstructor._reassemble_direction([seg1, seg2])

    assert data == b"0123456789XYZ12"
    assert len(gaps) == 1
    assert gaps[0]["missing_start_seq"] == 1010
    assert gaps[0]["missing_end_seq"] == 1030
    assert gaps[0]["missing_bytes"] == 20
    assert gaps[0]["resuming_frame"] == 2


def test_session_lifecycle_states():
    """Verify proper classification of ESTABLISHED, CLOSED_FIN, RESET, and INCOMPLETE."""
    reconstructor = TcpReconstructor(db=mock.MagicMock())

    # Case 1: Full handshake + bidirectional FIN -> CLOSED_FIN
    closed_segments = [
        RawTcpSegment(1, 10.0, "10.0.0.1", "10.0.0.2", 50000, 25, 100, 0, "S", b""),
        RawTcpSegment(2, 10.1, "10.0.0.2", "10.0.0.1", 25, 50000, 200, 101, "SA", b""),
        RawTcpSegment(3, 10.2, "10.0.0.1", "10.0.0.2", 50000, 25, 101, 201, "A", b""),
        RawTcpSegment(4, 10.3, "10.0.0.1", "10.0.0.2", 50000, 25, 101, 201, "FA", b""),
        RawTcpSegment(5, 10.4, "10.0.0.2", "10.0.0.1", 25, 50000, 201, 102, "FA", b""),
        RawTcpSegment(6, 10.5, "10.0.0.1", "10.0.0.2", 50000, 25, 102, 202, "A", b""),
    ]
    sess1 = reconstructor.reconstruct_stream("job-1", 0, closed_segments, "SMTP")
    assert sess1.session_state == "CLOSED_FIN"
    assert sess1.syn_frame_number == 1
    assert sess1.syn_ack_frame_number == 2
    assert len(sess1.fin_frame_numbers) == 2

    # Case 2: RST segment present -> RESET
    reset_segments = [
        RawTcpSegment(1, 10.0, "10.0.0.1", "10.0.0.2", 50000, 25, 100, 0, "S", b""),
        RawTcpSegment(2, 10.1, "10.0.0.2", "10.0.0.1", 25, 50000, 200, 101, "SA", b""),
        RawTcpSegment(3, 10.2, "10.0.0.1", "10.0.0.2", 50000, 25, 101, 201, "R", b""),
    ]
    sess2 = reconstructor.reconstruct_stream("job-1", 1, reset_segments, "SMTP")
    assert sess2.session_state == "RESET"
    assert len(sess2.rst_frame_numbers) == 1

    # Case 3: Handshake without close -> ESTABLISHED
    estab_segments = [
        RawTcpSegment(1, 10.0, "10.0.0.1", "10.0.0.2", 50000, 25, 100, 0, "S", b""),
        RawTcpSegment(2, 10.1, "10.0.0.2", "10.0.0.1", 25, 50000, 200, 101, "SA", b""),
        RawTcpSegment(3, 10.2, "10.0.0.1", "10.0.0.2", 50000, 25, 101, 201, "A", b""),
        RawTcpSegment(4, 10.3, "10.0.0.1", "10.0.0.2", 50000, 25, 101, 201, "PA", b"EHLO test\r\n"),
    ]
    sess3 = reconstructor.reconstruct_stream("job-1", 2, estab_segments, "SMTP")
    assert sess3.session_state == "ESTABLISHED"

    # Case 4: No handshake -> INCOMPLETE
    incomp_segments = [
        RawTcpSegment(1, 10.0, "10.0.0.1", "10.0.0.2", 50000, 25, 101, 201, "PA", b"EHLO test\r\n"),
    ]
    sess4 = reconstructor.reconstruct_stream("job-1", 3, incomp_segments, "SMTP")
    assert sess4.session_state == "INCOMPLETE"


def test_conversation_flow_turns():
    """Verify conversational flow groups contiguous packets into unified turns."""
    reconstructor = TcpReconstructor(db=mock.MagicMock())
    segments = [
        # Server banner
        RawTcpSegment(1, 100.0, "10.0.0.2", "10.0.0.1", 25, 50000, 1, 1, "PA", b"220 mail.corp\r\n"),
        # Client sends 2 consecutive packets (should be merged into 1 c2s turn)
        RawTcpSegment(2, 100.1, "10.0.0.1", "10.0.0.2", 50000, 25, 1, 15, "PA", b"EHLO "),
        RawTcpSegment(3, 100.2, "10.0.0.1", "10.0.0.2", 50000, 25, 6, 15, "PA", b"test.corp\r\n"),
        # Server responds
        RawTcpSegment(4, 100.3, "10.0.0.2", "10.0.0.1", 25, 50000, 15, 17, "PA", b"250 OK\r\n"),
    ]

    turns = reconstructor._build_conversation_flow(segments, client_port=50000)

    assert len(turns) == 3
    assert turns[0]["direction"] == "s2c"
    assert "220 mail.corp" in turns[0]["text_preview"]

    assert turns[1]["direction"] == "c2s"
    assert turns[1]["start_frame"] == 2
    assert turns[1]["end_frame"] == 3
    assert turns[1]["byte_length"] == 16
    assert "EHLO test.corp" in turns[1]["text_preview"]

    assert turns[2]["direction"] == "s2c"
    assert "250 OK" in turns[2]["text_preview"]


# ==========================================
# 2. Integration Tests with Database and PCAP
# ==========================================

def test_pcap_processing_populates_tcp_sessions(client: TestClient, db_session):
    """Verify that processing a PCAP capture automatically reconstructs and persists TcpSessions."""
    pkts = [
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=44444, dport=25, flags="S", seq=100, ack=0)),
        create_eth_pkt(IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=25, dport=44444, flags="SA", seq=200, ack=101)),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=44444, dport=25, flags="A", seq=101, ack=201)),
        create_eth_pkt(IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=25, dport=44444, flags="PA", seq=201, ack=101)/Raw(load=b"220 mail.test ESMTP\r\n")),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=44444, dport=25, flags="PA", seq=101, ack=222)/Raw(load=b"EHLO client.test\r\n")),
        create_eth_pkt(IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=25, dport=44444, flags="PA", seq=222, ack=119)/Raw(load=b"250-mail.test\r\n250 STARTTLS\r\n")),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=44444, dport=25, flags="FA", seq=119, ack=250)),
        create_eth_pkt(IP(src="192.168.1.20", dst="192.168.1.10")/TCP(sport=25, dport=44444, flags="FA", seq=250, ack=120)),
        create_eth_pkt(IP(src="192.168.1.10", dst="192.168.1.20")/TCP(sport=44444, dport=25, flags="A", seq=120, ack=251)),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        temp_path = f.name

    try:
        pcap_file = PcapFile(
            original_filename="smtp_session.pcap",
            stored_filename="smtp_session_stored.pcap",
            file_path=temp_path,
            file_size_bytes=os.path.getsize(temp_path),
            sha256="test_sha256",
            md5="test_md5",
            file_format="pcap",
        )
        db_session.add(pcap_file)
        db_session.commit()

        job = AnalysisJob(
            pcap_file_id=pcap_file.id,
            status="QUEUED",
        )
        db_session.add(job)
        db_session.commit()

        # Process the PCAP
        processor = PcapProcessor(db_session)
        result = processor.process_job(job.id)

        assert result["status"] == "COMPLETED"

        # Verify TcpSession record was created
        sessions = db_session.query(TcpSession).filter(TcpSession.job_id == job.id).all()
        assert len(sessions) == 1
        s = sessions[0]
        assert s.tcp_stream == 0
        assert s.protocol == "SMTP"
        assert s.session_state == "CLOSED_FIN"
        assert s.client_ip == "192.168.1.10"
        assert s.server_ip == "192.168.1.20"
        assert s.client_port == 44444
        assert s.server_port == 25
        assert s.packet_count == 9
        assert "220 mail.test" in s.s2c_payload_preview
        assert "EHLO client.test" in s.c2s_payload_preview
        assert len(s.conversation_flow) >= 3
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


# ==========================================
# 3. API Endpoints Tests
# ==========================================

def test_api_list_sessions_and_detail(client: TestClient, db_session):
    """Test GET /api/v1/jobs/{job_id}/sessions and GET /api/v1/jobs/{job_id}/sessions/{tcp_stream}."""
    pkts = [
        create_eth_pkt(IP(src="10.1.1.5", dst="10.1.1.10")/TCP(sport=35000, dport=110, flags="S", seq=50, ack=0)),
        create_eth_pkt(IP(src="10.1.1.10", dst="10.1.1.5")/TCP(sport=110, dport=35000, flags="SA", seq=80, ack=51)),
        create_eth_pkt(IP(src="10.1.1.10", dst="10.1.1.5")/TCP(sport=110, dport=35000, flags="PA", seq=81, ack=51)/Raw(load=b"+OK POP3 server ready\r\n")),
    ]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        wrpcap(f.name, pkts)
        temp_path = f.name

    try:
        pcap_file = PcapFile(
            original_filename="pop3_session.pcap",
            stored_filename="pop3_session_stored.pcap",
            file_path=temp_path,
            file_size_bytes=os.path.getsize(temp_path),
            sha256="hash_pop3",
            md5="md5_pop3",
            file_format="pcap",
        )
        db_session.add(pcap_file)
        db_session.commit()

        job = AnalysisJob(pcap_file_id=pcap_file.id, status="QUEUED")
        db_session.add(job)
        db_session.commit()

        # Process PCAP
        processor = PcapProcessor(db_session)
        processor.process_job(job.id)

        # 1. Test GET /api/v1/jobs/{job_id}/sessions
        res = client.get(f"/api/v1/jobs/{job.id}/sessions")
        assert res.status_code == 200
        data = res.json()
        assert data["job_id"] == job.id
        assert data["total_sessions"] == 1
        assert len(data["sessions"]) == 1
        assert data["sessions"][0]["tcp_stream"] == 0
        assert data["sessions"][0]["protocol"] == "POP3"

        # 2. Test GET /api/v1/jobs/{job_id}/sessions/{tcp_stream}
        stream_res = client.get(f"/api/v1/jobs/{job.id}/sessions/0")
        assert stream_res.status_code == 200
        stream_data = stream_res.json()
        assert stream_data["tcp_stream"] == 0
        assert stream_data["client_port"] == 35000
        assert stream_data["server_port"] == 110
        assert "+OK POP3" in stream_data["s2c_payload_preview"]

        # 3. Test 404 for non-existent stream
        not_found_res = client.get(f"/api/v1/jobs/{job.id}/sessions/999")
        assert not_found_res.status_code == 404

        # 4. Test 404 for non-existent job
        fake_res = client.get("/api/v1/jobs/non-existent-uuid/sessions")
        assert fake_res.status_code == 404

        # 5. Test POST /api/v1/jobs/{job_id}/reconstruct-sessions
        reconstruct_res = client.post(f"/api/v1/jobs/{job.id}/reconstruct-sessions")
        assert reconstruct_res.status_code == 200
        reconstruct_data = reconstruct_res.json()
        assert reconstruct_data["total_sessions"] == 1
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)
