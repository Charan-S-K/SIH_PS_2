"""
PCAP and PCAPNG forensic processing engine.
Extracts frame-by-frame metadata, IP/transport details, TCP stream indices, and packet summaries.
Supports Scapy and TShark/PyShark processing with robust error handling for corrupted captures.
"""

import json
import logging
import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from scapy.all import IP, IPv6, TCP, UDP, ICMP, PcapReader, Raw
from scapy.error import Scapy_Exception
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.job import AnalysisJob
from app.models.packet import PacketMetadata

logger = logging.getLogger(__name__)
settings = get_settings()


def get_tcp_flags_string(flags) -> str:
    """Format TCP flag bitmask or FlagValue into readable comma-separated string."""
    flag_names = []
    flag_str = str(flags)
    mapping = {
        "F": "FIN",
        "S": "SYN",
        "R": "RST",
        "P": "PSH",
        "A": "ACK",
        "U": "URG",
        "E": "ECE",
        "C": "CWR",
    }
    for char in flag_str:
        if char in mapping:
            flag_names.append(mapping[char])
    return ",".join(flag_names) if flag_names else "NONE"


def detect_layer7_protocol(transport: str, sport: int, dport: int, payload: bytes) -> str:
    """
    Deterministic protocol identification heuristic for observable packet metadata.
    Does not guess or invent facts; uses observable signatures and port indicators.
    """
    if transport != "TCP":
        if transport == "UDP" and (sport == 53 or dport == 53):
            return "DNS"
        return transport

    ports = {sport, dport}

    # TLS Record Header signature: Content Type 0x14-0x18 + Legacy Version 0x0301-0x0303
    if len(payload) >= 5 and payload[0] in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03:
        if payload[0] == 0x16:
            return "TLS (Handshake)"
        elif payload[0] == 0x17:
            return "TLS (Application Data)"
        return "TLS"

    # Plaintext Email Protocol Command/Greeting signatures
    if payload:
        prefix = payload[:16]
        # SMTP Signatures
        if prefix.startswith((b"220 ", b"EHLO", b"HELO", b"MAIL FROM:", b"RCPT TO:", b"STARTTLS", b"QUIT")):
            return "SMTP"
        # IMAP Signatures
        if prefix.startswith((b"* OK", b"* CAPABILITY", b"a001 ", b"A001 ", b". CAPABILITY", b"TAG ")):
            return "IMAP"
        # POP3 Signatures
        if prefix.startswith((b"+OK", b"-ERR", b"USER ", b"PASS ", b"STLS", b"CAPA")):
            return "POP3"

    # Well-known email port indicators when payload is generic/empty
    if ports.intersection({25, 465, 587}):
        return "SMTP"
    if ports.intersection({143, 993}):
        return "IMAP"
    if ports.intersection({110, 995}):
        return "POP3"

    return "TCP"


def generate_safe_payload_preview(payload: bytes, max_len: int = 32) -> str:
    """Generate safe, sanitized hex/ascii preview without leaking full email bodies."""
    if not payload:
        return ""
    sample = payload[:max_len]
    hex_str = sample.hex()
    ascii_repr = "".join(chr(b) if 32 <= b <= 126 else "." for b in sample)
    return f"{ascii_repr[:16]} ({hex_str[:24]}...)"


class PcapProcessor:
    """Forensic capture processing service."""

    def __init__(self, db: Session):
        self.db = db
        self.tshark_available = bool(
            settings.TSHARK_PATH and os.path.exists(settings.TSHARK_PATH)
        ) or bool(shutil.which("tshark"))

    def process_job(self, job_id: str) -> Dict[str, Any]:
        """
        Process the PCAP file associated with the given AnalysisJob ID.
        Extracts packet metadata, records TCP streams, and persists to database.
        """
        job = self.db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job '{job_id}' not found")

        pcap_file = job.pcap_file
        if not pcap_file or not os.path.exists(pcap_file.file_path):
            job.status = "FAILED"
            job.error_message = f"Capture file not found on disk at {pcap_file.file_path if pcap_file else 'None'}"
            self.db.commit()
            return {"status": "FAILED", "error": job.error_message}

        # Transition job state to PROCESSING
        job.status = "PROCESSING"
        job.progress_percent = 10
        job.stage_message = "Parsing packet capture headers and frames"
        self.db.commit()

        # Clear any existing packets for idempotency if re-processing
        self.db.query(PacketMetadata).filter(PacketMetadata.job_id == job_id).delete()
        self.db.commit()

        try:
            return self._process_with_scapy(job, pcap_file.file_path)
        except Exception as exc:
            logger.error("Capture processing failed for job %s: %s", job_id, exc, exc_info=True)
            job.status = "FAILED"
            job.error_message = f"Forensic parsing error: {exc.__class__.__name__}: {str(exc)}"
            job.stage_message = "Processing failed"
            self.db.commit()
            return {"status": "FAILED", "error": job.error_message}

    def _process_with_scapy(self, job: AnalysisJob, file_path: str) -> Dict[str, Any]:
        """Process packet capture using Scapy engine with conversation stream tracking."""
        frame_number = 0
        total_packets = 0
        tcp_packets = 0
        udp_packets = 0
        other_packets = 0
        start_time: Optional[float] = None
        end_time: Optional[float] = None
        detected_protocols: Set[str] = set()

        # TCP stream tracking map: sorted (ip, port) 4-tuple -> stream_index
        tcp_streams: Dict[Tuple, int] = {}
        next_stream_id = 0

        packet_batch: List[PacketMetadata] = []
        batch_size = settings.DEFAULT_PACKET_BATCH_SIZE

        try:
            with PcapReader(file_path) as pcap_reader:
                for packet in pcap_reader:
                    frame_number += 1
                    total_packets += 1

                    # Extract timestamps
                    pkt_time = float(packet.time) if hasattr(packet, "time") else 0.0
                    if start_time is None or pkt_time < start_time:
                        start_time = pkt_time
                    if end_time is None or pkt_time > end_time:
                        end_time = pkt_time

                    pkt_len = len(packet)
                    ip_ver = 4
                    src_ip = None
                    dst_ip = None

                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        ip_ver = 4
                    elif IPv6 in packet:
                        src_ip = packet[IPv6].src
                        dst_ip = packet[IPv6].dst
                        ip_ver = 6

                    transport = "OTHER"
                    src_port = None
                    dst_port = None
                    tcp_seq = None
                    tcp_ack = None
                    tcp_flags_str = None
                    tcp_stream_id = None
                    payload_bytes = b""

                    if TCP in packet:
                        transport = "TCP"
                        tcp_packets += 1
                        tcp_layer = packet[TCP]
                        src_port = int(tcp_layer.sport)
                        dst_port = int(tcp_layer.dport)
                        tcp_seq = int(tcp_layer.seq)
                        tcp_ack = int(tcp_layer.ack)
                        tcp_flags_str = get_tcp_flags_string(tcp_layer.flags)

                        # Compute TCP stream index
                        if src_ip and dst_ip:
                            endpoint_a = (src_ip, src_port)
                            endpoint_b = (dst_ip, dst_port)
                            stream_key = tuple(sorted([endpoint_a, endpoint_b]))
                            if stream_key not in tcp_streams:
                                tcp_streams[stream_key] = next_stream_id
                                next_stream_id += 1
                            tcp_stream_id = tcp_streams[stream_key]

                        if Raw in packet:
                            payload_bytes = bytes(packet[Raw].load)

                    elif UDP in packet:
                        transport = "UDP"
                        udp_packets += 1
                        udp_layer = packet[UDP]
                        src_port = int(udp_layer.sport)
                        dst_port = int(udp_layer.dport)
                        if Raw in packet:
                            payload_bytes = bytes(packet[Raw].load)

                    elif ICMP in packet:
                        transport = "ICMP"
                        other_packets += 1
                    else:
                        other_packets += 1

                    detected_proto = detect_layer7_protocol(
                        transport,
                        src_port or 0,
                        dst_port or 0,
                        payload_bytes
                    )
                    detected_protocols.add(detected_proto)

                    payload_size = len(payload_bytes)
                    payload_preview = generate_safe_payload_preview(payload_bytes)

                    metadata_record = PacketMetadata(
                        id=str(uuid.uuid4()),
                        job_id=job.id,
                        frame_number=frame_number,
                        timestamp=pkt_time,
                        frame_length=pkt_len,
                        ip_version=ip_ver,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        transport_protocol=transport,
                        src_port=src_port,
                        dst_port=dst_port,
                        detected_protocol=detected_proto,
                        tcp_stream=tcp_stream_id,
                        tcp_seq=tcp_seq,
                        tcp_ack=tcp_ack,
                        tcp_flags=tcp_flags_str,
                        payload_size=payload_size,
                        payload_preview=payload_preview
                    )
                    packet_batch.append(metadata_record)

                    # Bulk persist batch
                    if len(packet_batch) >= batch_size:
                        self.db.bulk_save_objects(packet_batch)
                        self.db.commit()
                        packet_batch.clear()

        except (Scapy_Exception, EOFError, ValueError) as parse_err:
            if total_packets == 0:
                raise ValueError(f"Corrupt or unreadable PCAP capture: {parse_err}") from parse_err
            logger.warning("Truncated or partial PCAP encountered at frame %d: %s", frame_number, parse_err)
            job.stage_message = f"Warning: Corrupted capture tail. Extracted {total_packets} valid frames."

        # If zero packets were read, capture is corrupt or empty
        if total_packets == 0:
            job.status = "FAILED"
            job.error_message = "Corrupt capture: 0 valid packet frames could be parsed"
            job.stage_message = "Processing failed: zero readable frames"
            self.db.commit()
            return {"status": "FAILED", "error": job.error_message}

        # Flush remaining packets
        if packet_batch:
            self.db.bulk_save_objects(packet_batch)
            self.db.commit()
            packet_batch.clear()

        # Stage 03: Run Protocol Identification across extracted streams
        try:
            from app.services.protocol_identifier import ProtocolIdentifier
            proto_identifier = ProtocolIdentifier(self.db)
            proto_results = proto_identifier.identify_protocols_for_job(job.id)
            if proto_results:
                detected_protocols = set(p.protocol for p in proto_results)
        except Exception as proto_err:
            logger.warning("Protocol identification encountered a non-fatal issue for job %s: %s", job.id, proto_err)

        # Stage 04: Reconstruct TCP Sessions and conversational streams
        try:
            from app.services.tcp_reconstructor import TcpReconstructor
            reconstructor = TcpReconstructor(self.db)
            reconstructor.reconstruct_job_sessions(job.id)
        except Exception as sess_err:
            logger.warning("TCP Session reconstruction encountered a non-fatal issue for job %s: %s", job.id, sess_err)

        # Stage 05: Analyze Email Protocols (SMTP, IMAP, POP3) state machines & events
        try:
            from app.services.email_protocol_analyzer import EmailProtocolAnalyzer
            email_analyzer = EmailProtocolAnalyzer(self.db)
            email_analyzer.analyze_job_sessions(job.id)
        except Exception as email_err:
            logger.warning("Email protocol analysis encountered a non-fatal issue for job %s: %s", job.id, email_err)

        # Stage 06: Analyze Opportunistic TLS (STARTTLS / STLS) & Downgrade Risk
        try:
            from app.services.starttls_analyzer import StarttlsAnalyzer
            starttls_analyzer = StarttlsAnalyzer(self.db)
            starttls_analyzer.analyze_job_starttls(job.id)
        except Exception as starttls_err:
            logger.warning("STARTTLS analysis encountered a non-fatal issue for job %s: %s", job.id, starttls_err)

        # Stage 07: Reconstruct and analyze observable TLS Handshakes
        try:
            from app.services.tls_handshake_analyzer import TlsHandshakeAnalyzer
            tls_analyzer = TlsHandshakeAnalyzer(self.db)
            tls_analyzer.analyze_job_tls_handshakes(job.id)
        except Exception as tls_err:
            logger.warning("TLS handshake analysis encountered a non-fatal issue for job %s: %s", job.id, tls_err)


        # Update AnalysisJob with statistics and mark COMPLETED
        duration = 0.0


        if start_time is not None and end_time is not None:
            duration = max(0.0, round(end_time - start_time, 4))

        job.status = "COMPLETED"
        job.progress_percent = 100
        if not job.stage_message.startswith("Warning"):
            job.stage_message = f"Packet metadata extracted successfully ({total_packets} frames processed)"
        job.completed_at = datetime.now(timezone.utc)
        job.total_packets = total_packets
        job.tcp_packets = tcp_packets
        job.udp_packets = udp_packets
        job.other_packets = other_packets
        job.duration_seconds = duration
        job.capture_start_time = start_time
        job.capture_end_time = end_time
        job.detected_protocols = json.dumps(sorted(list(detected_protocols)))

        self.db.commit()
        self.db.refresh(job)

        return {
            "status": "COMPLETED",
            "total_packets": total_packets,
            "tcp_packets": tcp_packets,
            "udp_packets": udp_packets,
            "duration_seconds": duration,
            "detected_protocols": sorted(list(detected_protocols)),
            "distinct_conversations": len(tcp_streams)
        }
