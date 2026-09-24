"""
TCP Session Reconstruction Service for SecureMailScope.
Reconstructs bidirectional TCP conversations using sequence/ACK numbers,
detects and handles retransmissions, out-of-order deliveries, and packet loss gaps,
generates conversational flow turns, and records full forensic session metadata.
"""

import json
import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple

from scapy.all import IP, IPv6, TCP, PcapReader, Raw
from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.protocol import ProtocolIdentification
from app.models.session import TcpSession

logger = logging.getLogger(__name__)


def safe_text_preview(data: bytes, max_len: int = 256) -> str:
    """Format bytes as safe, readable text with sanitized non-printable characters."""
    if not data:
        return ""
    sample = data[:max_len]
    chars = []
    for b in sample:
        if b in (10, 13, 9):  # \n, \r, \t
            chars.append(chr(b))
        elif 32 <= b <= 126:
            chars.append(chr(b))
        else:
            chars.append(".")
    preview = "".join(chars)
    if len(data) > max_len:
        preview += f" ... [{len(data) - max_len} more bytes]"
    return preview


class RawTcpSegment:
    """In-memory representation of a single captured TCP segment."""
    def __init__(
        self,
        frame_number: int,
        timestamp: float,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        seq: int,
        ack: int,
        flags: str,
        payload: bytes,
    ):
        self.frame_number = frame_number
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.payload = payload


class TcpReconstructor:
    """Forensic TCP session reassembly and conversation tracking engine."""

    def __init__(self, db: Session):
        self.db = db

    def reconstruct_job_sessions(self, job_id: str) -> List[TcpSession]:
        """
        Reconstruct all TCP conversation sessions for an AnalysisJob from its PCAP file.
        Idempotent: removes previously reconstructed sessions for this job.
        """
        job = self.db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job '{job_id}' not found")

        pcap_file = job.pcap_file
        if not pcap_file or not os.path.exists(pcap_file.file_path):
            raise ValueError(f"PCAP file for job '{job_id}' not found on disk")

        # Clean existing sessions for idempotency
        self.db.query(TcpSession).filter(TcpSession.job_id == job_id).delete()
        self.db.commit()

        # Load protocol classifications map (tcp_stream -> protocol name)
        proto_map: Dict[int, str] = {}
        for p in self.db.query(ProtocolIdentification).filter(
            ProtocolIdentification.job_id == job_id,
            ProtocolIdentification.tcp_stream.isnot(None),
        ).all():
            proto_map[p.tcp_stream] = p.protocol

        # Read PCAP and extract TCP streams
        streams_data = self._read_tcp_streams(pcap_file.file_path)

        reconstructed_sessions: List[TcpSession] = []
        for stream_id, segments in sorted(streams_data.items(), key=lambda x: x[0]):
            protocol = proto_map.get(stream_id, "UNKNOWN")
            session = self.reconstruct_stream(job_id, stream_id, segments, protocol)
            self.db.add(session)
            reconstructed_sessions.append(session)

        self.db.commit()
        logger.info(
            "TCP Session reconstruction completed for job %s: %d sessions reconstructed",
            job_id, len(reconstructed_sessions)
        )
        return reconstructed_sessions

    def reconstruct_stream(
        self,
        job_id: str,
        stream_id: int,
        segments: List[RawTcpSegment],
        protocol: str = "UNKNOWN",
    ) -> TcpSession:
        """
        Reconstruct a single bidirectional TCP stream using sequence information,
        handling reordering, retransmission, and gaps.
        """
        if not segments:
            raise ValueError(f"No segments provided for stream {stream_id}")

        first_frame = segments[0].frame_number
        last_frame = segments[-1].frame_number
        start_time = segments[0].timestamp
        end_time = segments[-1].timestamp
        duration = max(0.0, round(end_time - start_time, 4))

        # 1. Determine Client vs Server endpoints
        client_ip, server_ip, client_port, server_port = self._determine_endpoints(segments)

        # 2. Lifecycle & Handshake Analysis
        syn_frame: Optional[int] = None
        syn_ack_frame: Optional[int] = None
        fin_frames: List[int] = []
        rst_frames: List[int] = []
        has_c2s_fin = False
        has_s2c_fin = False

        for seg in segments:
            flags = seg.flags
            if "S" in flags and "A" not in flags:
                if syn_frame is None:
                    syn_frame = seg.frame_number
            elif "S" in flags and "A" in flags:
                if syn_ack_frame is None:
                    syn_ack_frame = seg.frame_number
            if "F" in flags:
                fin_frames.append(seg.frame_number)
                if seg.src_port == client_port:
                    has_c2s_fin = True
                else:
                    has_s2c_fin = True
            if "R" in flags:
                rst_frames.append(seg.frame_number)

        # Determine session state
        if rst_frames:
            session_state = "RESET"
        elif has_c2s_fin and has_s2c_fin:
            session_state = "CLOSED_FIN"
        elif has_c2s_fin or has_s2c_fin:
            session_state = "CLOSED_HALF"
        elif syn_frame is not None and syn_ack_frame is not None:
            session_state = "ESTABLISHED"
        else:
            session_state = "INCOMPLETE"

        # 3. Separate segments by direction
        c2s_segments: List[RawTcpSegment] = []
        s2c_segments: List[RawTcpSegment] = []

        for seg in segments:
            if seg.src_port == client_port:
                c2s_segments.append(seg)
            else:
                s2c_segments.append(seg)

        # 4. Reassemble unidirectional streams with sequence ordering & deduplication
        c2s_bytes, c2s_retrans, c2s_ooo, c2s_gaps = self._reassemble_direction(c2s_segments)
        s2c_bytes, s2c_retrans, s2c_ooo, s2c_gaps = self._reassemble_direction(s2c_segments)

        total_retransmissions = len(c2s_retrans) + len(s2c_retrans)
        total_ooo = len(c2s_ooo) + len(s2c_ooo)
        total_gaps = len(c2s_gaps) + len(s2c_gaps)

        # 5. Build chronological conversational turns (Follow Stream flow)
        conversation_flow = self._build_conversation_flow(segments, client_port)

        reconstruction_metadata = {
            "retransmissions": c2s_retrans + s2c_retrans,
            "out_of_order_segments": c2s_ooo + s2c_ooo,
            "gaps": c2s_gaps + s2c_gaps,
            "syn_observed": syn_frame is not None,
            "syn_ack_observed": syn_ack_frame is not None,
            "fin_observed": len(fin_frames) > 0,
            "rst_observed": len(rst_frames) > 0,
        }

        return TcpSession(
            job_id=job_id,
            tcp_stream=stream_id,
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=client_port,
            server_port=server_port,
            protocol=protocol,
            session_state=session_state,
            start_time=start_time,
            end_time=end_time,
            duration_seconds=duration,
            first_frame_number=first_frame,
            last_frame_number=last_frame,
            packet_count=len(segments),
            c2s_packet_count=len(c2s_segments),
            s2c_packet_count=len(s2c_segments),
            c2s_bytes=len(c2s_bytes),
            s2c_bytes=len(s2c_bytes),
            total_payload_bytes=len(c2s_bytes) + len(s2c_bytes),
            retransmissions_count=total_retransmissions,
            out_of_order_count=total_ooo,
            gaps_count=total_gaps,
            syn_frame_number=syn_frame,
            syn_ack_frame_number=syn_ack_frame,
            fin_frame_numbers=fin_frames if fin_frames else None,
            rst_frame_numbers=rst_frames if rst_frames else None,
            c2s_payload_preview=safe_text_preview(c2s_bytes),
            s2c_payload_preview=safe_text_preview(s2c_bytes),
            conversation_flow=conversation_flow,
            reconstruction_metadata=reconstruction_metadata,
        )

    def _reassemble_direction(
        self, segments: List[RawTcpSegment]
    ) -> Tuple[bytes, List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Reassemble byte stream for one direction.
        Detects out-of-order arrivals, eliminates retransmissions and overlaps,
        records sequence gaps, and returns reassembled bytes.
        """
        payload_segments = [s for s in segments if s.payload]
        if not payload_segments:
            return b"", [], [], []

        retransmissions: List[Dict[str, Any]] = []
        out_of_order: List[Dict[str, Any]] = []
        gaps: List[Dict[str, Any]] = []

        # 1. Detect Out-of-Order arrival (by capture arrival order)
        max_seq_seen = -1
        for s in payload_segments:
            if max_seq_seen != -1 and s.seq < max_seq_seen:
                out_of_order.append({
                    "frame_number": s.frame_number,
                    "seq": s.seq,
                    "highest_seq_previously_seen": max_seq_seen,
                    "length": len(s.payload),
                })
            else:
                max_seq_seen = s.seq

        # 2. Sort segments by sequence number, breaking ties with frame number
        sorted_segments = sorted(payload_segments, key=lambda s: (s.seq, s.frame_number))

        # 3. Assemble bytes, handle duplicates, overlaps, and gaps
        assembled = bytearray()
        current_seq: Optional[int] = None

        for s in sorted_segments:
            p_len = len(s.payload)
            if p_len == 0:
                continue

            if current_seq is None:
                current_seq = s.seq
                assembled.extend(s.payload)
                current_seq += p_len
                continue

            # Case A: Exact duplicate or fully covered subset (Retransmission)
            if s.seq + p_len <= current_seq:
                retransmissions.append({
                    "frame_number": s.frame_number,
                    "seq": s.seq,
                    "length": p_len,
                    "type": "DUPLICATE_OR_SUBSET",
                })
                continue

            # Case B: Partial overlap (Prefix is redundant, suffix is new data)
            if s.seq < current_seq < s.seq + p_len:
                overlap = current_seq - s.seq
                new_data = s.payload[overlap:]
                assembled.extend(new_data)
                retransmissions.append({
                    "frame_number": s.frame_number,
                    "seq": s.seq,
                    "overlap_bytes": overlap,
                    "new_bytes": len(new_data),
                    "type": "PARTIAL_OVERLAP",
                })
                current_seq = s.seq + p_len
                continue

            # Case C: Gap detected (Missing segment between current_seq and s.seq)
            if s.seq > current_seq:
                missing_bytes = s.seq - current_seq
                gaps.append({
                    "missing_start_seq": current_seq,
                    "missing_end_seq": s.seq,
                    "missing_bytes": missing_bytes,
                    "resuming_frame": s.frame_number,
                })
                assembled.extend(s.payload)
                current_seq = s.seq + p_len
                continue

            # Case D: In-order contiguous segment
            assembled.extend(s.payload)
            current_seq += p_len

        return bytes(assembled), retransmissions, out_of_order, gaps

    def _build_conversation_flow(
        self, segments: List[RawTcpSegment], client_port: Optional[int]
    ) -> List[Dict[str, Any]]:
        """
        Merge chronological segments into discrete conversational turns (Follow Stream).
        Combines contiguous packets sent by the same party into unified turns.
        """
        turns: List[Dict[str, Any]] = []
        current_turn: Optional[Dict[str, Any]] = None

        for s in segments:
            if not s.payload:
                continue

            direction = "c2s" if s.src_port == client_port else "s2c"

            if current_turn is not None and current_turn["direction"] == direction:
                # Extend current conversational turn
                current_turn["end_frame"] = s.frame_number
                current_turn["end_time"] = s.timestamp
                current_turn["byte_length"] += len(s.payload)
                current_turn["_raw_bytes"] += s.payload
            else:
                # Flush existing turn
                if current_turn is not None:
                    current_turn["text_preview"] = safe_text_preview(current_turn.pop("_raw_bytes"))
                    turns.append(current_turn)

                # Start new turn
                current_turn = {
                    "direction": direction,
                    "start_frame": s.frame_number,
                    "end_frame": s.frame_number,
                    "start_time": s.timestamp,
                    "end_time": s.timestamp,
                    "byte_length": len(s.payload),
                    "_raw_bytes": bytearray(s.payload),
                }

        if current_turn is not None:
            current_turn["text_preview"] = safe_text_preview(current_turn.pop("_raw_bytes"))
            turns.append(current_turn)

        return turns

    def _determine_endpoints(
        self, segments: List[RawTcpSegment]
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        """Determine client vs server IPs and ports from stream segments."""
        # 1. Pure SYN packet without ACK
        for s in segments:
            if "S" in s.flags and "A" not in s.flags:
                return s.src_ip, s.dst_ip, s.src_port, s.dst_port

        # 2. Known standard ports in destination
        well_known_server_ports = {25, 465, 587, 2525, 110, 995, 143, 993, 80, 443, 22, 53, 8080}
        for s in segments:
            if s.dst_port in well_known_server_ports:
                return s.src_ip, s.dst_ip, s.src_port, s.dst_port
            if s.src_port in well_known_server_ports:
                return s.dst_ip, s.src_ip, s.dst_port, s.src_port

        # 3. Fallback: first segment sender is client
        first = segments[0]
        return first.src_ip, first.dst_ip, first.src_port, first.dst_port

    def _read_tcp_streams(self, pcap_path: str) -> Dict[int, List[RawTcpSegment]]:
        """Read all TCP packets in PCAP and group into sorted streams."""
        tcp_streams_map: Dict[Tuple, int] = {}
        next_stream_id = 0
        streams_data: Dict[int, List[RawTcpSegment]] = {}

        frame_num = 0
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                frame_num += 1
                if TCP not in pkt:
                    continue

                pkt_time = float(pkt.time) if hasattr(pkt, "time") else 0.0
                src_ip, dst_ip = None, None
                if IP in pkt:
                    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
                elif IPv6 in pkt:
                    src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

                tcp_layer = pkt[TCP]
                sport, dport = int(tcp_layer.sport), int(tcp_layer.dport)
                seq = int(tcp_layer.seq)
                ack = int(tcp_layer.ack)
                flags_str = str(tcp_layer.flags)
                payload = bytes(pkt[Raw].load) if Raw in pkt else b""

                if src_ip and dst_ip:
                    key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
                    if key not in tcp_streams_map:
                        tcp_streams_map[key] = next_stream_id
                        next_stream_id += 1
                    stream_id = tcp_streams_map[key]
                else:
                    stream_id = 0

                seg = RawTcpSegment(
                    frame_number=frame_num,
                    timestamp=pkt_time,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=sport,
                    dst_port=dport,
                    seq=seq,
                    ack=ack,
                    flags=flags_str,
                    payload=payload,
                )
                streams_data.setdefault(stream_id, []).append(seg)

        return streams_data
