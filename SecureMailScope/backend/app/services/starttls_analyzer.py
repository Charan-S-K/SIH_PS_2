"""
STARTTLS Analysis Service for SecureMailScope.
Detects STARTTLS/STLS advertisement, request, upgrade negotiation,
rejection/failure, non-upgrade downgrade risks, and suspicious cleartext
authentication after TLS was offered by the server.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from scapy.all import PcapReader, Raw, TCP
from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.packet import PacketMetadata
from app.models.session import TcpSession
from app.models.starttls import StarttlsAnalysis

logger = logging.getLogger(__name__)


class StarttlsAnalyzer:
    """Forensic opportunistic TLS (STARTTLS/STLS) inspection engine."""

    def __init__(self, db: Session):
        self.db = db

    def analyze_job_starttls(self, job_id: str) -> List[StarttlsAnalysis]:
        """
        Analyze all email streams in an AnalysisJob for STARTTLS/STLS security posture.
        Idempotent: removes previously recorded analyses for this job.
        """
        job = self.db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job '{job_id}' not found")

        # Delete existing starttls records for idempotency
        self.db.query(StarttlsAnalysis).filter(StarttlsAnalysis.job_id == job_id).delete()
        self.db.commit()

        tcp_sessions = (
            self.db.query(TcpSession)
            .filter(TcpSession.job_id == job_id)
            .order_by(TcpSession.tcp_stream.asc())
            .all()
        )

        analyzed_records: List[StarttlsAnalysis] = []
        for sess in tcp_sessions:
            proto = (sess.protocol or "UNKNOWN").upper()
            # Identify if this stream is an email protocol or candidate
            server_port = sess.server_port or 0
            if proto not in ("SMTP", "IMAP", "POP3"):
                if server_port in (25, 465, 587, 2525):
                    proto = "SMTP"
                elif server_port in (143, 993):
                    proto = "IMAP"
                elif server_port in (110, 995):
                    proto = "POP3"
                else:
                    continue

            record = self.analyze_stream_starttls(job, sess, proto)
            if record:
                self.db.add(record)
                analyzed_records.append(record)

        self.db.commit()
        logger.info(
            "STARTTLS analysis completed for job %s: %d streams analyzed",
            job_id, len(analyzed_records)
        )
        return analyzed_records

    def analyze_stream_starttls(
        self, job: AnalysisJob, sess: TcpSession, proto: str
    ) -> Optional[StarttlsAnalysis]:
        """Analyze STARTTLS negotiation lifecycle for a single TCP stream."""
        server_port = sess.server_port or 0

        # Case 0: Implicit Direct TLS (SMTPS, IMAPS, POP3S)
        if server_port in (465, 993, 995):
            return self._handle_direct_tls(sess, proto)

        # Inspect conversation turns
        turns = sess.conversation_flow or []
        findings: List[Dict[str, Any]] = []

        advertised = False
        advertised_frame: Optional[int] = None
        advertised_command: Optional[str] = None

        requested = False
        requested_frame: Optional[int] = None
        requested_command: Optional[str] = None

        accepted = False
        response_frame: Optional[int] = None
        response_code: Optional[str] = None
        response_text: Optional[str] = None

        cleartext_auth_observed = False
        cleartext_auth_frame: Optional[int] = None
        cleartext_auth_command: Optional[str] = None

        in_ehlo_response = False
        in_capa_response = False

        for turn in turns:
            direction = turn.get("direction", "c2s")
            preview = turn.get("text_preview", "")
            frame = turn.get("start_frame")
            lines = [l.strip() for l in preview.splitlines() if l.strip()]

            for line in lines:
                if direction == "s2c":
                    # Server responses
                    if proto == "SMTP":
                        match_code = re.match(r"^(\d{3})([\s\-])(.*)$", line)
                        if match_code:
                            code, sep, rest = match_code.groups()
                            is_cont = (sep == "-")
                            if code == "250" and in_ehlo_response:
                                if "STARTTLS" in rest.upper():
                                    advertised = True
                                    advertised_frame = frame
                                    advertised_command = line
                                if not is_cont:
                                    in_ehlo_response = False
                            elif code == "220" and requested:
                                accepted = True
                                response_frame = frame
                                response_code = code
                                response_text = line
                            elif code in ("454", "554") and requested:
                                accepted = False
                                response_frame = frame
                                response_code = code
                                response_text = line

                    elif proto == "IMAP":
                        if "STARTTLS" in line.upper() and ("* OK" in line or "* CAPABILITY" in line):
                            advertised = True
                            advertised_frame = frame
                            advertised_command = line
                        elif requested:
                            parts = line.split(" ", 2)
                            status = parts[1].upper() if len(parts) > 1 else ""
                            if status == "OK":
                                accepted = True
                                response_frame = frame
                                response_code = "OK"
                                response_text = line
                            elif status in ("NO", "BAD"):
                                accepted = False
                                response_frame = frame
                                response_code = status
                                response_text = line

                    elif proto == "POP3":
                        if in_capa_response:
                            if line == ".":
                                in_capa_response = False
                            elif "STLS" in line.upper():
                                advertised = True
                                advertised_frame = frame
                                advertised_command = line
                        elif requested:
                            if line.startswith("+OK"):
                                accepted = True
                                response_frame = frame
                                response_code = "+OK"
                                response_text = line
                            elif line.startswith("-ERR"):
                                accepted = False
                                response_frame = frame
                                response_code = "-ERR"
                                response_text = line

                else:
                    # Client commands (c2s)
                    parts = line.split(" ", 1)
                    cmd = parts[0].upper()
                    arg = parts[1] if len(parts) > 1 else ""

                    if proto == "SMTP":
                        if cmd == "EHLO":
                            in_ehlo_response = True
                        elif cmd == "STARTTLS":
                            requested = True
                            requested_frame = frame
                            requested_command = line
                        elif cmd == "AUTH" and not (accepted and response_frame and frame > response_frame):
                            cleartext_auth_observed = True
                            cleartext_auth_frame = frame
                            cleartext_auth_command = f"AUTH {arg.split()[0]}" if arg else "AUTH"

                    elif proto == "IMAP":
                        # IMAP: <tag> <cmd>
                        imap_parts = line.split(" ", 2)
                        imap_cmd = imap_parts[1].upper() if len(imap_parts) > 1 else ""
                        if imap_cmd == "STARTTLS":
                            requested = True
                            requested_frame = frame
                            requested_command = line
                        elif imap_cmd in ("LOGIN", "AUTHENTICATE") and not (accepted and response_frame and frame > response_frame):
                            cleartext_auth_observed = True
                            cleartext_auth_frame = frame
                            cleartext_auth_command = imap_cmd

                    elif proto == "POP3":
                        if cmd == "CAPA":
                            in_capa_response = True
                        elif cmd == "STLS":
                            requested = True
                            requested_frame = frame
                            requested_command = line
                        elif cmd in ("USER", "PASS") and not (accepted and response_frame and frame > response_frame):
                            cleartext_auth_observed = True
                            cleartext_auth_frame = frame
                            cleartext_auth_command = cmd

        # Check for subsequent TLS Record Layer packets
        tls_record_detected = False
        tls_start_frame: Optional[int] = None

        if accepted and response_frame:
            tls_record_detected, tls_start_frame = self._detect_tls_record_transition(
                job, sess.tcp_stream, response_frame
            )

        # Classify Upgrade Status & Synthesize Findings
        if cleartext_auth_observed and advertised and not (accepted and tls_record_detected):
            upgrade_status = "CLEARTEXT_AUTH_AFTER_ADVERTISED"
            findings.append({
                "code": "SUSPICIOUS_CLEARTEXT_AUTH_AFTER_STARTTLS_OFFERED",
                "severity": "CRITICAL",
                "message": f"Client transmitted unencrypted {cleartext_auth_command} credentials despite STARTTLS/STLS being advertised by the server",
                "evidence_frame": cleartext_auth_frame,
            })
        elif requested and accepted and tls_record_detected:
            upgrade_status = "UPGRADED_SUCCESS"
            findings.append({
                "code": "STARTTLS_SUCCESSFULLY_NEGOTIATED",
                "severity": "INFO",
                "message": "Session successfully upgraded to TLS encrypted communication",
                "evidence_frame": response_frame,
            })
        elif requested and accepted and not tls_record_detected:
            upgrade_status = "UPGRADE_ACCEPTED"
            findings.append({
                "code": "STARTTLS_ACCEPTED_AWAITING_HANDSHAKE",
                "severity": "LOW",
                "message": "Server accepted STARTTLS; subsequent TLS records incomplete or truncated in capture",
                "evidence_frame": response_frame,
            })
        elif requested and not accepted:
            upgrade_status = "UPGRADE_REJECTED"
            findings.append({
                "code": "STARTTLS_NEGOTIATION_FAILED",
                "severity": "HIGH",
                "message": f"Server rejected STARTTLS request with response: {response_text or response_code}",
                "evidence_frame": response_frame,
            })
        elif advertised and not requested:
            upgrade_status = "NOT_REQUESTED_IGNORED"
            findings.append({
                "code": "STARTTLS_DOWNGRADE_OR_STRIPPING_RISK",
                "severity": "HIGH",
                "message": "Server advertised STARTTLS capability but client proceeded with unencrypted cleartext mail transfer (possible downgrade or stripping)",
                "evidence_frame": advertised_frame,
            })
        else:
            upgrade_status = "NOT_ADVERTISED"
            findings.append({
                "code": "STARTTLS_NOT_ADVERTISED",
                "severity": "MEDIUM",
                "message": f"Server does not advertise opportunistic TLS ({'STARTTLS' if proto in ('SMTP', 'IMAP') else 'STLS'}) capability",
                "evidence_frame": sess.first_frame_number,
            })

        return StarttlsAnalysis(
            job_id=sess.job_id,
            tcp_session_id=sess.id,
            tcp_stream=sess.tcp_stream,
            protocol=proto,
            client_ip=sess.client_ip,
            server_ip=sess.server_ip,
            client_port=sess.client_port,
            server_port=sess.server_port,
            advertised=advertised,
            advertised_frame=advertised_frame,
            advertised_command=advertised_command,
            requested=requested,
            requested_frame=requested_frame,
            requested_command=requested_command,
            accepted=accepted,
            response_frame=response_frame,
            response_code=response_code,
            response_text=response_text,
            upgrade_status=upgrade_status,
            tls_record_detected=tls_record_detected,
            tls_start_frame=tls_start_frame,
            cleartext_auth_observed=cleartext_auth_observed,
            cleartext_auth_frame=cleartext_auth_frame,
            cleartext_auth_command=cleartext_auth_command,
            findings=findings,
        )

    def _handle_direct_tls(self, sess: TcpSession, proto: str) -> StarttlsAnalysis:
        """Handle sessions connecting directly to implicit TLS mail ports (465, 993, 995)."""
        findings = [{
            "code": "DIRECT_TLS_PORT",
            "severity": "INFO",
            "message": f"Session connects to dedicated implicit TLS port {sess.server_port} ({proto}); opportunistic STARTTLS not applicable",
            "evidence_frame": sess.first_frame_number,
        }]
        return StarttlsAnalysis(
            job_id=sess.job_id,
            tcp_session_id=sess.id,
            tcp_stream=sess.tcp_stream,
            protocol=proto,
            client_ip=sess.client_ip,
            server_ip=sess.server_ip,
            client_port=sess.client_port,
            server_port=sess.server_port,
            advertised=False,
            requested=False,
            accepted=False,
            upgrade_status="DIRECT_TLS",
            tls_record_detected=True,
            tls_start_frame=sess.first_frame_number,
            cleartext_auth_observed=False,
            findings=findings,
        )

    def _detect_tls_record_transition(
        self, job: AnalysisJob, stream_id: int, response_frame: int
    ) -> Tuple[bool, Optional[int]]:
        """
        Check if packets following affirmative STARTTLS response transition to TLS record layer (0x16 Handshake).
        """
        # Query PacketMetadata for this stream where frame > response_frame
        packets = (
            self.db.query(PacketMetadata)
            .filter(
                PacketMetadata.job_id == job.id,
                PacketMetadata.tcp_stream == stream_id,
                PacketMetadata.frame_number > response_frame,
            )
            .order_by(PacketMetadata.frame_number.asc())
            .all()
        )

        for p in packets:
            if p.detected_protocol == "TLS":
                return True, p.frame_number

        # Fallback inspection of raw capture file if available
        pcap_file = job.pcap_file
        if pcap_file and pcap_file.file_path:
            try:
                frame_idx = 0
                with PcapReader(pcap_file.file_path) as reader:
                    for pkt in reader:
                        frame_idx += 1
                        if frame_idx <= response_frame:
                            continue
                        if TCP in pkt and Raw in pkt:
                            load = bytes(pkt[Raw].load)
                            # TLS record header: ContentType 0x16 (Handshake) + Version 0x03 [0x00-0x04]
                            if len(load) >= 5 and load[0] == 0x16 and load[1] == 0x03:
                                return True, frame_idx
            except Exception as e:
                logger.debug("Raw PCAP TLS transition check error: %s", e)

        return False, None
