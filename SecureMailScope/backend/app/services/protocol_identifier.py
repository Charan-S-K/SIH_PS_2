"""
Protocol Identification Engine for SecureMailScope.
Identifies SMTP, IMAP, and POP3 email protocols using deep protocol behavior,
conversational flow, and payload signatures—never relying on ports alone.
Supports TLS handshake inspection (SNI/ALPN), TShark corroboration, and
defensive handling of non-mail protocols, anomalies, and insufficient evidence.
"""

import json
import logging
import os
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from scapy.all import IP, IPv6, TCP, UDP, PcapReader, Raw
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.job import AnalysisJob
from app.models.packet import PacketMetadata
from app.models.protocol import ProtocolIdentification

logger = logging.getLogger(__name__)
settings = get_settings()

# Standard well-known email ports
SMTP_STANDARD_PORTS = {25, 465, 587, 2525}
IMAP_STANDARD_PORTS = {143, 993}
POP3_STANDARD_PORTS = {110, 995}

# Regex Signatures for Application Protocols
SMTP_BANNER_REGEX = re.compile(r"^220[- ]([^\r\n]*)", re.IGNORECASE)
SMTP_CMD_REGEX = re.compile(
    r"^(EHLO|HELO|MAIL FROM:|RCPT TO:|DATA|STARTTLS|RSET|QUIT|AUTH|VRFY|EXPN|NOOP|HELP|BDAT)\b([^\r\n]*)",
    re.IGNORECASE,
)
SMTP_RESP_REGEX = re.compile(
    r"^(250[- ]|354\b|221\b|500\b|501\b|502\b|503\b|530\b|535\b|421\b|451\b)([^\r\n]*)",
    re.IGNORECASE,
)

IMAP_GREETING_REGEX = re.compile(r"^\* (OK|PREAUTH|BYE)\b([^\r\n]*)", re.IGNORECASE)
IMAP_CMD_REGEX = re.compile(
    r"^[A-Za-z0-9_.-]+ (CAPABILITY|LOGIN|AUTHENTICATE|STARTTLS|SELECT|EXAMINE|CREATE|DELETE|RENAME|"
    r"SUBSCRIBE|UNSUBSCRIBE|LIST|LSUB|STATUS|APPEND|CHECK|CLOSE|EXPUNGE|SEARCH|FETCH|STORE|COPY|"
    r"UID|NOOP|LOGOUT|ID|ENABLE|NAMESPACE)\b([^\r\n]*)",
    re.IGNORECASE,
)
IMAP_RESP_UNTAGGED_REGEX = re.compile(
    r"^\* (CAPABILITY|LIST|FLAGS|OK|BAD|NO|SEARCH|STATUS|BYE)\b([^\r\n]*)",
    re.IGNORECASE,
)
IMAP_RESP_TAGGED_REGEX = re.compile(r"^[A-Za-z0-9_.-]+ (OK|NO|BAD)\b([^\r\n]*)", re.IGNORECASE)

POP3_GREETING_REGEX = re.compile(r"^\+OK\b([^\r\n]*)", re.IGNORECASE)
POP3_CMD_REGEX = re.compile(
    r"^(USER |PASS |STAT\b|LIST\b|RETR |DELE |NOOP\b|RSET\b|QUIT\b|TOP |UIDL\b|CAPA\b|STLS\b|AUTH |APOP )([^\r\n]*)",
    re.IGNORECASE,
)
POP3_RESP_REGEX = re.compile(r"^(\+OK|-ERR)\b([^\r\n]*)", re.IGNORECASE)

HTTP_REQ_REGEX = re.compile(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT) \S+ HTTP/[12]", re.IGNORECASE)
HTTP_RESP_REGEX = re.compile(r"^HTTP/[12]\.[0-9] [1-5][0-9]{2}", re.IGNORECASE)
SSH_BANNER_REGEX = re.compile(r"^SSH-[12]\.[0-9]")


def parse_tls_client_hello(payload: bytes) -> Dict[str, Any]:
    """
    Safely extract SNI and ALPN extensions from a TLS Client Hello record.
    Returns a dict with sni and alpn_protocols if parsed.
    """
    result: Dict[str, Any] = {"is_tls": False, "sni": None, "alpn": []}
    if not payload or len(payload) < 9:
        return result

    # TLS Record Header: Content Type 0x16 (Handshake), Version 0x0301-0x0304
    if payload[0] != 0x16 or payload[1] != 0x03:
        return result

    result["is_tls"] = True
    record_len = int.from_bytes(payload[3:5], "big")
    if len(payload) < 5 + min(record_len, 4):
        return result

    # Handshake type 0x01 = Client Hello
    if payload[5] != 0x01:
        return result

    try:
        offset = 6  # After handshake type
        handshake_len = int.from_bytes(payload[offset:offset + 3], "big")
        offset += 3
        offset += 2  # Client version
        offset += 32  # Client random

        if offset >= len(payload):
            return result

        # Session ID
        session_id_len = payload[offset]
        offset += 1 + session_id_len

        # Cipher Suites
        if offset + 2 > len(payload):
            return result
        cipher_suites_len = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2 + cipher_suites_len

        # Compression methods
        if offset >= len(payload):
            return result
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
        if offset + 2 > len(payload):
            return result
        ext_total_len = int.from_bytes(payload[offset:offset + 2], "big")
        offset += 2

        ext_end = min(offset + ext_total_len, len(payload))
        while offset + 4 <= ext_end:
            ext_type = int.from_bytes(payload[offset:offset + 2], "big")
            ext_len = int.from_bytes(payload[offset + 2:offset + 4], "big")
            offset += 4

            if offset + ext_len > ext_end:
                break

            ext_data = payload[offset:offset + ext_len]
            # Extension 0x0000 = Server Name Indication (SNI)
            if ext_type == 0:
                if len(ext_data) >= 5:
                    name_type = ext_data[2]
                    name_len = int.from_bytes(ext_data[3:5], "big")
                    if name_type == 0 and len(ext_data) >= 5 + name_len:
                        result["sni"] = ext_data[5:5 + name_len].decode("utf-8", errors="ignore")

            # Extension 0x0010 = ALPN
            elif ext_type == 16:
                if len(ext_data) >= 2:
                    alpn_list_len = int.from_bytes(ext_data[0:2], "big")
                    alpn_off = 2
                    while alpn_off < min(len(ext_data), 2 + alpn_list_len):
                        proto_len = ext_data[alpn_off]
                        alpn_off += 1
                        if alpn_off + proto_len <= len(ext_data):
                            proto_str = ext_data[alpn_off:alpn_off + proto_len].decode("utf-8", errors="ignore")
                            result["alpn"].append(proto_str)
                            alpn_off += proto_len
                        else:
                            break

            offset += ext_len

    except Exception as exc:
        logger.debug("Non-fatal TLS extension parsing exception: %s", exc)

    return result


class StreamPacketRecord:
    """Lightweight representation of a frame in a stream."""
    def __init__(
        self,
        frame_number: int,
        timestamp: float,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        src_port: Optional[int],
        dst_port: Optional[int],
        flags: Optional[str],
        payload: bytes,
    ):
        self.frame_number = frame_number
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.flags = flags or ""
        self.payload = payload


class ProtocolIdentifier:
    """Forensic protocol classification service."""

    def __init__(self, db: Session):
        self.db = db
        self.tshark_available = bool(
            settings.TSHARK_PATH and os.path.exists(settings.TSHARK_PATH)
        ) or bool(shutil.which("tshark"))

    def identify_protocols_for_job(self, job_id: str) -> List[ProtocolIdentification]:
        """
        Perform passive protocol identification across all streams of an AnalysisJob.
        Extracts evidence, determines confidence, detects anomalies, and persists results.
        """
        job = self.db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job '{job_id}' not found")

        pcap_file = job.pcap_file
        if not pcap_file or not os.path.exists(pcap_file.file_path):
            raise ValueError(f"PCAP file for job '{job_id}' not found on disk")

        # 1. Read PCAP and aggregate frames by stream
        streams_data, udp_flows = self._extract_streams_from_pcap(pcap_file.file_path)

        # 2. Corroborate with TShark if available
        tshark_protocols = self._get_tshark_dissections(pcap_file.file_path) if self.tshark_available else {}

        # 3. Clean previous protocol identifications for idempotency
        self.db.query(ProtocolIdentification).filter(ProtocolIdentification.job_id == job_id).delete()
        self.db.commit()

        results: List[ProtocolIdentification] = []
        protocol_counts: Dict[str, int] = {}

        # 4. Classify each TCP stream
        for stream_id, packets in streams_data.items():
            tshark_proto = tshark_protocols.get(stream_id)
            classification = self.classify_tcp_stream(stream_id, packets, tshark_proto)
            record = ProtocolIdentification(
                job_id=job_id,
                tcp_stream=stream_id,
                protocol=classification["protocol"],
                confidence=classification["confidence"],
                confidence_level=classification["confidence_level"],
                classification_method=classification["classification_method"],
                is_mail_protocol=classification["is_mail_protocol"],
                client_ip=classification["client_ip"],
                server_ip=classification["server_ip"],
                client_port=classification["client_port"],
                server_port=classification["server_port"],
                summary=classification["summary"],
                evidence=classification["evidence"],
                packet_count=len(packets),
                total_bytes=sum(len(p.payload) for p in packets),
            )
            self.db.add(record)
            results.append(record)

            proto_name = classification["protocol"]
            protocol_counts[proto_name] = protocol_counts.get(proto_name, 0) + 1

            # Update PacketMetadata.detected_protocol for all frames in this stream
            self.db.query(PacketMetadata).filter(
                PacketMetadata.job_id == job_id,
                PacketMetadata.tcp_stream == stream_id,
            ).update({"detected_protocol": proto_name}, synchronize_session=False)

        # 5. Classify UDP flows (e.g. DNS)
        for (src_ip, dst_ip, sport, dport), packets in udp_flows.items():
            classification = self._classify_udp_flow(src_ip, dst_ip, sport, dport, packets)
            record = ProtocolIdentification(
                job_id=job_id,
                tcp_stream=None,
                protocol=classification["protocol"],
                confidence=classification["confidence"],
                confidence_level=classification["confidence_level"],
                classification_method=classification["classification_method"],
                is_mail_protocol=False,
                client_ip=src_ip,
                server_ip=dst_ip,
                client_port=sport,
                server_port=dport,
                summary=classification["summary"],
                evidence=classification["evidence"],
                packet_count=len(packets),
                total_bytes=sum(len(p.payload) for p in packets),
            )
            self.db.add(record)
            results.append(record)

            proto_name = classification["protocol"]
            protocol_counts[proto_name] = protocol_counts.get(proto_name, 0) + 1

        # 6. Update AnalysisJob detected_protocols overview
        job.detected_protocols = json.dumps(list(protocol_counts.keys()))
        self.db.commit()

        logger.info(
            "Protocol identification completed for job %s: %d streams classified (%s)",
            job_id, len(results), protocol_counts
        )
        return results

    def classify_tcp_stream(
        self,
        stream_id: int,
        packets: List[StreamPacketRecord],
        tshark_proto: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Classify a single TCP stream using forensic signatures, conversational flow,
        and TLS metadata. Port is used strictly as corroborating evidence, never as sole proof.
        """
        if not packets:
            return self._unknown_stream_result(stream_id, "No packets in stream.")

        # Determine Client vs Server endpoints
        client_ip, server_ip, client_port, server_port = self._determine_endpoints(packets)

        total_app_bytes = sum(len(p.payload) for p in packets)
        evidence_frames: List[Dict[str, Any]] = []
        matched_signatures: List[str] = []
        anomalies: List[str] = []

        # 1. Zero application payload check
        if total_app_bytes == 0:
            notes = (
                f"Stream contains only TCP control/handshake frames ({len(packets)} frames) "
                f"with 0 application payload bytes. Standard port {server_port} observed, "
                f"but port alone is insufficient for protocol identification."
            )
            return {
                "protocol": "UNKNOWN",
                "confidence": 0.0,
                "confidence_level": "UNKNOWN",
                "classification_method": "INSUFFICIENT_EVIDENCE",
                "is_mail_protocol": False,
                "client_ip": client_ip,
                "server_ip": server_ip,
                "client_port": client_port,
                "server_port": server_port,
                "summary": "TCP handshake/control frames only with zero application payload; insufficient evidence.",
                "evidence": {
                    "matched_signatures": [],
                    "evidence_frames": [],
                    "port_analysis": {
                        "server_port": server_port,
                        "standard_port_for": self._get_standard_service_for_port(server_port),
                        "matches_detected_protocol": False,
                        "notes": notes,
                    },
                    "insufficient_evidence_reason": "Zero application payload bytes observed in capture stream.",
                    "anomalies": [],
                    "tshark_protocol": tshark_proto,
                }
            }

        # 2. Check for Non-Email Protocols (Negative Tests)
        # Check for HTTP
        for pkt in packets:
            if pkt.payload:
                text_preview = pkt.payload[:64].decode("latin-1", errors="ignore")
                if HTTP_REQ_REGEX.match(text_preview) or HTTP_RESP_REGEX.match(text_preview):
                    direction = "client_to_server" if pkt.src_port == client_port else "server_to_client"
                    matched_signatures.append(f"HTTP header in frame {pkt.frame_number}")
                    evidence_frames.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": "HTTP Signature",
                        "matched_text": text_preview.split("\r\n")[0],
                    })
                    # Port anomaly check: HTTP on standard mail port
                    if server_port in (SMTP_STANDARD_PORTS | IMAP_STANDARD_PORTS | POP3_STANDARD_PORTS):
                        anomalies.append(
                            f"SUSPICIOUS_PORT_MISMATCH: HTTP protocol traffic detected on standard email port {server_port}"
                        )
                    return {
                        "protocol": "HTTP",
                        "confidence": 0.98,
                        "confidence_level": "HIGH",
                        "classification_method": "SIGNATURE_AND_BEHAVIOR",
                        "is_mail_protocol": False,
                        "client_ip": client_ip,
                        "server_ip": server_ip,
                        "client_port": client_port,
                        "server_port": server_port,
                        "summary": f"Identified HTTP traffic (Confidence: 98%){' with port anomaly' if anomalies else ''}.",
                        "evidence": {
                            "matched_signatures": matched_signatures,
                            "evidence_frames": evidence_frames,
                            "port_analysis": {
                                "server_port": server_port,
                                "standard_port_for": self._get_standard_service_for_port(server_port),
                                "matches_detected_protocol": server_port in {80, 8080, 8000},
                                "notes": "HTTP request/response structure matched.",
                            },
                            "insufficient_evidence_reason": None,
                            "anomalies": anomalies,
                            "tshark_protocol": tshark_proto,
                        }
                    }

        # Check for SSH
        for pkt in packets:
            if pkt.payload:
                text_preview = pkt.payload[:32].decode("latin-1", errors="ignore")
                if SSH_BANNER_REGEX.match(text_preview):
                    direction = "client_to_server" if pkt.src_port == client_port else "server_to_client"
                    matched_signatures.append(f"SSH Identification string in frame {pkt.frame_number}")
                    evidence_frames.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": "SSH Banner",
                        "matched_text": text_preview.strip(),
                    })
                    if server_port in (SMTP_STANDARD_PORTS | IMAP_STANDARD_PORTS | POP3_STANDARD_PORTS):
                        anomalies.append(
                            f"SUSPICIOUS_PORT_MISMATCH: SSH protocol traffic detected on standard email port {server_port}"
                        )
                    return {
                        "protocol": "SSH",
                        "confidence": 1.0,
                        "confidence_level": "HIGH",
                        "classification_method": "SIGNATURE_AND_BEHAVIOR",
                        "is_mail_protocol": False,
                        "client_ip": client_ip,
                        "server_ip": server_ip,
                        "client_port": client_port,
                        "server_port": server_port,
                        "summary": f"Identified SSH protocol (Confidence: 100%){' with port anomaly' if anomalies else ''}.",
                        "evidence": {
                            "matched_signatures": matched_signatures,
                            "evidence_frames": evidence_frames,
                            "port_analysis": {
                                "server_port": server_port,
                                "standard_port_for": self._get_standard_service_for_port(server_port),
                                "matches_detected_protocol": server_port == 22,
                                "notes": "SSH identification string matched.",
                            },
                            "insufficient_evidence_reason": None,
                            "anomalies": anomalies,
                            "tshark_protocol": tshark_proto,
                        }
                    }

        # 3. Check for Email Protocol Behavioral Signatures (SMTP, IMAP, POP3)
        smtp_score = 0
        imap_score = 0
        pop3_score = 0

        smtp_evidence: List[Dict[str, Any]] = []
        imap_evidence: List[Dict[str, Any]] = []
        pop3_evidence: List[Dict[str, Any]] = []

        for pkt in packets:
            if not pkt.payload:
                continue

            direction = "client_to_server" if pkt.src_port == client_port else "server_to_client"
            text_lines = pkt.payload.decode("latin-1", errors="ignore").splitlines()

            for line in text_lines[:5]:  # Inspect first few lines per packet
                line_str = line.strip()
                if not line_str:
                    continue

                # --- SMTP Checks ---
                banner_match = SMTP_BANNER_REGEX.match(line_str)
                if banner_match:
                    smtp_score += 40
                    smtp_evidence.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": "SMTP 220 Server Greeting Banner",
                        "matched_text": line_str[:64],
                    })
                cmd_match = SMTP_CMD_REGEX.match(line_str)
                if cmd_match:
                    smtp_score += 40
                    smtp_evidence.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": f"SMTP Client Command {cmd_match.group(1).upper()}",
                        "matched_text": line_str[:64],
                    })
                resp_match = SMTP_RESP_REGEX.match(line_str)
                if resp_match and not banner_match:
                    smtp_score += 20
                    smtp_evidence.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": f"SMTP Response {resp_match.group(1).strip()}",
                        "matched_text": line_str[:64],
                    })

                # --- IMAP Checks ---
                imap_greet = IMAP_GREETING_REGEX.match(line_str)
                if imap_greet:
                    imap_score += 40
                    imap_evidence.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": f"IMAP Server Greeting (* {imap_greet.group(1)})",
                        "matched_text": line_str[:64],
                    })
                imap_cmd = IMAP_CMD_REGEX.match(line_str)
                if imap_cmd:
                    imap_score += 40
                    imap_evidence.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": f"IMAP Tagged Command ({imap_cmd.group(1).upper()})",
                        "matched_text": line_str[:64],
                    })
                if (IMAP_RESP_UNTAGGED_REGEX.match(line_str) or IMAP_RESP_TAGGED_REGEX.match(line_str)) and not imap_greet and not imap_cmd:
                    imap_score += 20
                    imap_evidence.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": "IMAP Server Response",
                        "matched_text": line_str[:64],
                    })

                # --- POP3 Checks ---
                pop_greet = POP3_GREETING_REGEX.match(line_str)
                if pop_greet:
                    pop3_score += 40
                    pop3_evidence.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": "POP3 +OK Server Greeting",
                        "matched_text": line_str[:64],
                    })
                pop_cmd = POP3_CMD_REGEX.match(line_str)
                if pop_cmd:
                    pop3_score += 40
                    pop3_evidence.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": f"POP3 Client Command ({pop_cmd.group(1).strip().upper()})",
                        "matched_text": line_str[:64],
                    })
                pop_resp = POP3_RESP_REGEX.match(line_str)
                if pop_resp and not pop_greet:
                    pop3_score += 15
                    pop3_evidence.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": direction,
                        "signature_matched": "POP3 Server Response",
                        "matched_text": line_str[:64],
                    })


        # Evaluate highest scoring email protocol
        max_score = max(smtp_score, imap_score, pop3_score)
        if max_score >= 35:
            if max_score == smtp_score:
                protocol = "SMTP"
                ev_list = smtp_evidence
                is_standard = server_port in SMTP_STANDARD_PORTS
            elif max_score == imap_score:
                protocol = "IMAP"
                ev_list = imap_evidence
                is_standard = server_port in IMAP_STANDARD_PORTS
            else:
                protocol = "POP3"
                ev_list = pop3_evidence
                is_standard = server_port in POP3_STANDARD_PORTS

            # Calculate confidence score
            if max_score >= 60:
                confidence = 1.0
                conf_level = "HIGH"
            elif max_score >= 40:
                confidence = 0.95
                conf_level = "HIGH"
            else:
                confidence = 0.85
                conf_level = "HIGH" if is_standard else "MEDIUM"

            port_notes = (
                f"Standard {protocol} port confirmed ({server_port})."
                if is_standard
                else f"{protocol} behavioral signatures matched on non-standard port {server_port}."
            )

            summary = (
                f"Conclusively identified {protocol} (Confidence: {int(confidence * 100)}%) "
                f"via {len(ev_list)} forensic signatures; {port_notes}"
            )

            return {
                "protocol": protocol,
                "confidence": confidence,
                "confidence_level": conf_level,
                "classification_method": "SIGNATURE_AND_BEHAVIOR",
                "is_mail_protocol": True,
                "client_ip": client_ip,
                "server_ip": server_ip,
                "client_port": client_port,
                "server_port": server_port,
                "summary": summary,
                "evidence": {
                    "matched_signatures": [e["signature_matched"] for e in ev_list],
                    "evidence_frames": ev_list,
                    "port_analysis": {
                        "server_port": server_port,
                        "standard_port_for": self._get_standard_service_for_port(server_port),
                        "matches_detected_protocol": is_standard,
                        "notes": port_notes,
                    },
                    "insufficient_evidence_reason": None,
                    "anomalies": [],
                    "tshark_protocol": tshark_proto,
                }
            }

        # 4. Check for TLS Handshake (Implicit Email Protocols or General TLS)
        tls_info = {"is_tls": False, "sni": None, "alpn": []}
        for pkt in packets:
            if pkt.payload and pkt.src_port == client_port:
                tls_info = parse_tls_client_hello(pkt.payload)
                if tls_info["is_tls"]:
                    evidence_frames.append({
                        "frame_number": pkt.frame_number,
                        "timestamp": pkt.timestamp,
                        "direction": "client_to_server",
                        "signature_matched": "TLS Client Hello",
                        "matched_text": f"TLS Client Hello (SNI={tls_info['sni']}, ALPN={tls_info['alpn']})",
                    })
                    break

        if tls_info["is_tls"]:
            sni = (tls_info["sni"] or "").lower()
            alpn = [a.lower() for a in tls_info["alpn"]]

            # Check if implicit email protocol on standard implicit TLS port or indicated by SNI/ALPN
            if server_port == 465 or "smtp" in alpn or "smtps" in alpn or "smtp." in sni:
                protocol = "SMTPS"
                is_mail = True
                confidence = 0.95 if (sni or alpn) else 0.90
                conf_level = "HIGH"
                summary = f"Identified SMTPS (Implicit TLS) on port {server_port} (Confidence: {int(confidence*100)}%)."
            elif server_port == 993 or "imap" in alpn or "imaps" in alpn or "imap." in sni:
                protocol = "IMAPS"
                is_mail = True
                confidence = 0.95 if (sni or alpn) else 0.90
                conf_level = "HIGH"
                summary = f"Identified IMAPS (Implicit TLS) on port {server_port} (Confidence: {int(confidence*100)}%)."
            elif server_port == 995 or "pop3" in alpn or "pop3s" in alpn or "pop." in sni:
                protocol = "POP3S"
                is_mail = True
                confidence = 0.95 if (sni or alpn) else 0.90
                conf_level = "HIGH"
                summary = f"Identified POP3S (Implicit TLS) on port {server_port} (Confidence: {int(confidence*100)}%)."
            else:
                protocol = "TLS"
                is_mail = False
                confidence = 0.90
                conf_level = "HIGH"
                summary = f"Identified generic TLS session on port {server_port} (Confidence: 90%)."

            return {
                "protocol": protocol,
                "confidence": confidence,
                "confidence_level": conf_level,
                "classification_method": "TLS_INSPECTION",
                "is_mail_protocol": is_mail,
                "client_ip": client_ip,
                "server_ip": server_ip,
                "client_port": client_port,
                "server_port": server_port,
                "summary": summary,
                "evidence": {
                    "matched_signatures": ["TLS Record Header", "TLS Client Hello"],
                    "evidence_frames": evidence_frames,
                    "port_analysis": {
                        "server_port": server_port,
                        "standard_port_for": self._get_standard_service_for_port(server_port),
                        "matches_detected_protocol": is_mail,
                        "notes": f"Observed TLS handshake on port {server_port} with SNI='{tls_info['sni']}' and ALPN={tls_info['alpn']}.",
                    },
                    "insufficient_evidence_reason": None if is_mail else "Encrypted TLS session; application layer protocol cannot be determined without ALPN/SNI.",
                    "anomalies": [],
                    "tshark_protocol": tshark_proto,
                }
            }

        # 5. Unknown / Ambiguous Payload (Unable to determine protocol)
        return {
            "protocol": "UNKNOWN",
            "confidence": 0.0,
            "confidence_level": "UNKNOWN",
            "classification_method": "UNKNOWN",
            "is_mail_protocol": False,
            "client_ip": client_ip,
            "server_ip": server_ip,
            "client_port": client_port,
            "server_port": server_port,
            "summary": (
                f"No recognizable application protocol signatures found in {len(packets)} frames "
                f"({total_app_bytes} payload bytes) on port {server_port}."
            ),
            "evidence": {
                "matched_signatures": [],
                "evidence_frames": [],
                "port_analysis": {
                    "server_port": server_port,
                    "standard_port_for": self._get_standard_service_for_port(server_port),
                    "matches_detected_protocol": False,
                    "notes": f"Port {server_port} was contacted, but payload did not match any email or known protocol signatures.",
                },
                "insufficient_evidence_reason": "Payload does not match any recognized application protocol signatures.",
                "anomalies": [],
                "tshark_protocol": tshark_proto,
            }
        }

    def _classify_udp_flow(
        self,
        src_ip: Optional[str],
        dst_ip: Optional[str],
        sport: Optional[int],
        dport: Optional[int],
        packets: List[StreamPacketRecord],
    ) -> Dict[str, Any]:
        """Classify UDP flows such as DNS."""
        server_port = dport if dport == 53 else (sport or dport)
        is_dns = (sport == 53 or dport == 53)
        return {
            "protocol": "DNS" if is_dns else "UDP",
            "confidence": 0.95 if is_dns else 0.50,
            "confidence_level": "HIGH" if is_dns else "MEDIUM",
            "classification_method": "PORT_FALLBACK" if is_dns else "UNKNOWN",
            "summary": "DNS query/response flow" if is_dns else "Generic UDP datagram flow",
            "evidence": {
                "matched_signatures": ["UDP Port 53"] if is_dns else [],
                "evidence_frames": [
                    {"frame_number": p.frame_number, "timestamp": p.timestamp, "direction": "unknown", "signature_matched": "DNS"}
                    for p in packets[:3]
                ] if is_dns else [],
                "port_analysis": {
                    "server_port": server_port,
                    "standard_port_for": "DNS" if is_dns else None,
                    "matches_detected_protocol": is_dns,
                    "notes": "Standard DNS UDP port" if is_dns else "Non-DNS UDP traffic",
                },
                "insufficient_evidence_reason": None if is_dns else "Generic UDP flow without specific protocol header match.",
                "anomalies": [],
                "tshark_protocol": "DNS" if is_dns else None,
            }
        }

    def _determine_endpoints(
        self, packets: List[StreamPacketRecord]
    ) -> Tuple[Optional[str], Optional[str], Optional[int], Optional[int]]:
        """
        Determine (client_ip, server_ip, client_port, server_port).
        Uses SYN packet source as client, or known service ports, or first packet.
        """
        # Look for SYN packet without ACK (pure client connection initiator)
        for pkt in packets:
            if "SYN" in pkt.flags and "ACK" not in pkt.flags:
                return pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port

        # Look for well-known server ports in destination
        well_known_ports = SMTP_STANDARD_PORTS | IMAP_STANDARD_PORTS | POP3_STANDARD_PORTS | {80, 443, 22, 53, 8080}
        for pkt in packets:
            if pkt.dst_port in well_known_ports:
                return pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port
            if pkt.src_port in well_known_ports:
                return pkt.dst_ip, pkt.src_ip, pkt.dst_port, pkt.src_port

        # Fallback: first packet defines client -> server
        first = packets[0]
        return first.src_ip, first.dst_ip, first.src_port, first.dst_port

    def _get_standard_service_for_port(self, port: Optional[int]) -> Optional[str]:
        """Map port number to its canonical standard IANA email/network service."""
        if port is None:
            return None
        if port == 25:
            return "SMTP (MTA Relay)"
        elif port == 587:
            return "SMTP (Mail Submission)"
        elif port == 465:
            return "SMTPS (Implicit TLS)"
        elif port == 2525:
            return "SMTP (Alternative Submission)"
        elif port == 143:
            return "IMAP4"
        elif port == 993:
            return "IMAPS (Implicit TLS)"
        elif port == 110:
            return "POP3"
        elif port == 995:
            return "POP3S (Implicit TLS)"
        elif port in {80, 8080}:
            return "HTTP"
        elif port in {443, 8443}:
            return "HTTPS"
        elif port == 22:
            return "SSH"
        elif port == 53:
            return "DNS"
        return None

    def _extract_streams_from_pcap(
        self, pcap_path: str
    ) -> Tuple[Dict[int, List[StreamPacketRecord]], Dict[Tuple, List[StreamPacketRecord]]]:
        """Read PCAP with Scapy, aggregating packets into TCP streams and UDP flows."""
        tcp_streams: Dict[Tuple, int] = {}
        next_stream_id = 0
        streams_data: Dict[int, List[StreamPacketRecord]] = {}
        udp_flows: Dict[Tuple, List[StreamPacketRecord]] = {}

        frame_num = 0
        with PcapReader(pcap_path) as reader:
            for pkt in reader:
                frame_num += 1
                pkt_time = float(pkt.time) if hasattr(pkt, "time") else 0.0

                src_ip, dst_ip = None, None
                if IP in pkt:
                    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
                elif IPv6 in pkt:
                    src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst

                if TCP in pkt:
                    tcp_layer = pkt[TCP]
                    sport, dport = int(tcp_layer.sport), int(tcp_layer.dport)
                    flags_str = str(tcp_layer.flags)
                    payload = bytes(pkt[Raw].load) if Raw in pkt else b""

                    if src_ip and dst_ip:
                        key = tuple(sorted([(src_ip, sport), (dst_ip, dport)]))
                        if key not in tcp_streams:
                            tcp_streams[key] = next_stream_id
                            next_stream_id += 1
                        s_id = tcp_streams[key]
                    else:
                        s_id = 0

                    rec = StreamPacketRecord(
                        frame_number=frame_num,
                        timestamp=pkt_time,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=sport,
                        dst_port=dport,
                        flags=flags_str,
                        payload=payload,
                    )
                    streams_data.setdefault(s_id, []).append(rec)

                elif UDP in pkt:
                    udp_layer = pkt[UDP]
                    sport, dport = int(udp_layer.sport), int(udp_layer.dport)
                    payload = bytes(pkt[Raw].load) if Raw in pkt else b""
                    flow_key = (src_ip, dst_ip, sport, dport)
                    rec = StreamPacketRecord(
                        frame_number=frame_num,
                        timestamp=pkt_time,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=sport,
                        dst_port=dport,
                        flags="",
                        payload=payload,
                    )
                    udp_flows.setdefault(flow_key, []).append(rec)

        return streams_data, udp_flows

    def _get_tshark_dissections(self, pcap_path: str) -> Dict[int, str]:
        """Run tshark to extract protocol column by TCP stream if binary is available."""
        stream_protos: Dict[int, str] = {}
        tshark_cmd = settings.TSHARK_PATH or "tshark"
        try:
            cmd = [
                tshark_cmd,
                "-r", pcap_path,
                "-Y", "tcp",
                "-T", "fields",
                "-e", "tcp.stream",
                "-e", "_ws.col.Protocol",
            ]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    parts = line.strip().split("\t")
                    if len(parts) >= 2 and parts[0].isdigit():
                        st_id = int(parts[0])
                        proto = parts[1].strip()
                        if proto and proto not in {"TCP"}:
                            stream_protos[st_id] = proto
        except Exception as exc:
            logger.debug("TShark dissection lookup failed (falling back to pure python engine): %s", exc)
        return stream_protos

    def _unknown_stream_result(self, stream_id: int, reason: str) -> Dict[str, Any]:
        """Fallback for empty or unparseable stream."""
        return {
            "protocol": "UNKNOWN",
            "confidence": 0.0,
            "confidence_level": "UNKNOWN",
            "classification_method": "INSUFFICIENT_EVIDENCE",
            "is_mail_protocol": False,
            "client_ip": None,
            "server_ip": None,
            "client_port": None,
            "server_port": None,
            "summary": f"Stream {stream_id}: {reason}",
            "evidence": {
                "matched_signatures": [],
                "evidence_frames": [],
                "port_analysis": None,
                "insufficient_evidence_reason": reason,
                "anomalies": [],
                "tshark_protocol": None,
            }
        }
