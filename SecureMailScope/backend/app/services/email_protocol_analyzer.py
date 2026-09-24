"""
Email Protocol Analyzer Service for SecureMailScope.
Performs deep conversational state machine analysis for SMTP, IMAP, and POP3 sessions,
extracting commands, greetings, capabilities, STARTTLS/STLS negotiations, authentication
exchanges, and security anomalies without premature TLS evaluation.
"""

import base64
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.session import TcpSession
from app.models.email_analysis import EmailSessionAnalysis

logger = logging.getLogger(__name__)


def redact_auth_argument(cmd: str, arg: str) -> Tuple[str, Optional[str]]:
    """
    Sanitize sensitive authentication credentials from arguments.
    Returns (sanitized_argument, extracted_username_if_any).
    """
    cmd_upper = cmd.upper()
    extracted_user = None

    if cmd_upper == "AUTH":
        parts = arg.split(" ", 1)
        mech = parts[0].upper()
        if len(parts) > 1:
            raw_b64 = parts[1].strip()
            # Attempt safe base64 decode for PLAIN
            if mech == "PLAIN":
                try:
                    decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
                    # PLAIN format: [authzid]\0authcid\0passwd
                    fields = decoded.split("\x00")
                    if len(fields) >= 2:
                        extracted_user = fields[1] or fields[0]
                except Exception:
                    pass
            elif mech == "LOGIN":
                try:
                    decoded = base64.b64decode(raw_b64).decode("utf-8", errors="ignore")
                    extracted_user = decoded.strip()
                except Exception:
                    pass
            return f"{mech} [REDACTED_CREDENTIALS]", extracted_user
        return mech, None

    if cmd_upper == "PASS":
        return "[REDACTED_PASSWORD]", None

    if cmd_upper == "USER":
        user = arg.strip()
        return user, user

    if cmd_upper == "LOGIN":
        # IMAP LOGIN <username> <password>
        tokens = arg.split(" ", 1)
        if len(tokens) >= 1:
            extracted_user = tokens[0].strip("\"'")
            return f"{tokens[0]} [REDACTED_PASSWORD]", extracted_user
        return "[REDACTED_CREDENTIALS]", None

    return arg, None


class EmailProtocolAnalyzer:
    """Forensic email protocol session analysis and event state machine."""

    def __init__(self, db: Session):
        self.db = db

    def analyze_job_sessions(self, job_id: str) -> List[EmailSessionAnalysis]:
        """
        Analyze all email conversation sessions for an AnalysisJob.
        Idempotent: removes previous analyses for this job.
        """
        job = self.db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job '{job_id}' not found")

        # Delete existing analyses for this job
        self.db.query(EmailSessionAnalysis).filter(EmailSessionAnalysis.job_id == job_id).delete()
        self.db.commit()

        tcp_sessions = (
            self.db.query(TcpSession)
            .filter(TcpSession.job_id == job_id)
            .order_by(TcpSession.tcp_stream.asc())
            .all()
        )

        analyzed_records: List[EmailSessionAnalysis] = []
        for sess in tcp_sessions:
            proto = (sess.protocol or "UNKNOWN").upper()
            if proto not in ("SMTP", "IMAP", "POP3"):
                # Also check port hints if protocol is UNKNOWN but server port matches email
                if proto == "UNKNOWN" and sess.server_port in (25, 465, 587, 2525):
                    proto = "SMTP"
                elif proto == "UNKNOWN" and sess.server_port in (143, 993):
                    proto = "IMAP"
                elif proto == "UNKNOWN" and sess.server_port in (110, 995):
                    proto = "POP3"
                else:
                    continue

            record = self.analyze_session(sess, proto)
            if record:
                self.db.add(record)
                analyzed_records.append(record)

        self.db.commit()
        logger.info(
            "Email Protocol Analysis completed for job %s: %d email sessions analyzed",
            job_id, len(analyzed_records)
        )
        return analyzed_records

    def analyze_session(self, sess: TcpSession, proto: str) -> Optional[EmailSessionAnalysis]:
        """Route to appropriate protocol state machine analyzer."""
        if proto == "SMTP":
            return self._analyze_smtp_session(sess)
        elif proto == "IMAP":
            return self._analyze_imap_session(sess)
        elif proto == "POP3":
            return self._analyze_pop3_session(sess)
        return None

    # ==========================================
    # SMTP State Machine & Event Parsing
    # ==========================================

    def _analyze_smtp_session(self, sess: TcpSession) -> EmailSessionAnalysis:
        turns = sess.conversation_flow or []
        events: List[Dict[str, Any]] = []
        warnings: List[str] = []
        capabilities: List[str] = []
        auth_mechanisms: List[str] = []
        auth_usernames: Set[str] = set()

        server_banner: Optional[str] = None
        client_greeting: Optional[str] = None
        session_state = "INIT"
        starttls_advertised = False
        starttls_requested = False
        starttls_accepted = False
        auth_attempted = False
        auth_successful: Optional[bool] = None
        commands_count = 0
        tls_established = False

        in_ehlo_response = False

        for turn in turns:
            direction = turn.get("direction", "c2s")
            preview = turn.get("text_preview", "")
            frame = turn.get("start_frame")
            t_time = turn.get("start_time")
            lines = [l.strip() for l in preview.splitlines() if l.strip()]

            for line in lines:
                if direction == "s2c":
                    # Server responses
                    match_code = re.match(r"^(\d{3})([\s\-])(.*)$", line)
                    if not match_code:
                        continue
                    code, sep, rest = match_code.groups()
                    is_cont = (sep == "-")

                    if code == "220" and server_banner is None and not tls_established:
                        server_banner = line
                        session_state = "CONNECTED"
                        events.append({
                            "direction": "s2c",
                            "event_type": "BANNER",
                            "response_code": code,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif code == "220" and starttls_requested:
                        starttls_accepted = True
                        tls_established = True
                        session_state = "STARTTLS_NEGOTIATED"
                        events.append({
                            "direction": "s2c",
                            "event_type": "STARTTLS_NEGOTIATION",
                            "response_code": code,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif code == "250" and in_ehlo_response:
                        cap_item = rest.strip()
                        if cap_item and cap_item not in capabilities:
                            capabilities.append(cap_item)
                        # Check STARTTLS capability
                        if "STARTTLS" in cap_item.upper():
                            starttls_advertised = True
                        # Check AUTH capability (e.g. "AUTH PLAIN LOGIN")
                        if cap_item.upper().startswith("AUTH"):
                            mechs = cap_item.split()[1:]
                            for m in mechs:
                                m_clean = m.strip().upper()
                                if m_clean and m_clean not in auth_mechanisms:
                                    auth_mechanisms.append(m_clean)

                        events.append({
                            "direction": "s2c",
                            "event_type": "CAPABILITY_LIST",
                            "response_code": code,
                            "argument": cap_item,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                        if not is_cont:
                            in_ehlo_response = False
                            session_state = "GREETED"
                    elif code == "235":
                        auth_successful = True
                        session_state = "AUTHENTICATED"
                        events.append({
                            "direction": "s2c",
                            "event_type": "AUTH_EXCHANGE",
                            "response_code": code,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif code == "535":
                        auth_successful = False
                        warnings.append("AUTH_FAILURE: Server rejected client authentication credentials")
                        events.append({
                            "direction": "s2c",
                            "event_type": "AUTH_EXCHANGE",
                            "response_code": code,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    else:
                        events.append({
                            "direction": "s2c",
                            "event_type": "RESPONSE",
                            "response_code": code,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                        if not is_cont:
                            in_ehlo_response = False

                else:
                    # Client commands (c2s)
                    commands_count += 1
                    parts = line.split(" ", 1)
                    cmd = parts[0].upper()
                    arg = parts[1] if len(parts) > 1 else ""

                    if cmd in ("EHLO", "HELO"):
                        client_greeting = line
                        in_ehlo_response = (cmd == "EHLO")
                        events.append({
                            "direction": "c2s",
                            "event_type": "COMMAND",
                            "command": cmd,
                            "argument": arg,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "STARTTLS":
                        starttls_requested = True
                        events.append({
                            "direction": "c2s",
                            "event_type": "STARTTLS_NEGOTIATION",
                            "command": "STARTTLS",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "AUTH":
                        auth_attempted = True
                        sanitized_arg, extracted_user = redact_auth_argument(cmd, arg)
                        if extracted_user:
                            auth_usernames.add(extracted_user)
                        if not tls_established:
                            warnings.append("CLEARTEXT_AUTH_ATTEMPTED: Client initiated AUTH before establishing TLS encryption")
                        events.append({
                            "direction": "c2s",
                            "event_type": "AUTH_EXCHANGE",
                            "command": "AUTH",
                            "argument": sanitized_arg,
                            "raw_text": f"AUTH {sanitized_arg}",
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd in ("MAIL", "RCPT"):
                        # Handle "MAIL FROM:" and "RCPT TO:"
                        full_cmd = line.split(":", 1)[0].upper() if ":" in line else cmd
                        full_arg = line.split(":", 1)[1] if ":" in line else arg
                        session_state = "TRANSACTION"
                        events.append({
                            "direction": "c2s",
                            "event_type": "COMMAND",
                            "command": full_cmd,
                            "argument": full_arg.strip(),
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "DATA":
                        session_state = "TRANSACTION"
                        events.append({
                            "direction": "c2s",
                            "event_type": "COMMAND",
                            "command": "DATA",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "QUIT":
                        session_state = "TERMINATED"
                        events.append({
                            "direction": "c2s",
                            "event_type": "CLOSING",
                            "command": "QUIT",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    else:
                        events.append({
                            "direction": "c2s",
                            "event_type": "COMMAND",
                            "command": cmd,
                            "argument": arg,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })

        # Forensic posture checks
        if capabilities and not starttls_advertised and not tls_established:
            warnings.append("STARTTLS_NOT_ADVERTISED: Server does not advertise STARTTLS encryption capability in EHLO")
        if auth_mechanisms and not tls_established:
            warnings.append("CLEARTEXT_AUTH_OFFERED: Server offers AUTH mechanisms over unencrypted session")

        return EmailSessionAnalysis(
            job_id=sess.job_id,
            tcp_session_id=sess.id,
            tcp_stream=sess.tcp_stream,
            protocol="SMTP",
            client_ip=sess.client_ip,
            server_ip=sess.server_ip,
            client_port=sess.client_port,
            server_port=sess.server_port,
            server_banner=server_banner,
            client_greeting=client_greeting,
            session_state=session_state,
            capabilities=capabilities if capabilities else None,
            starttls_advertised=starttls_advertised,
            starttls_requested=starttls_requested,
            starttls_accepted=starttls_accepted,
            auth_mechanisms=auth_mechanisms if auth_mechanisms else None,
            auth_attempted=auth_attempted,
            auth_successful=auth_successful,
            auth_usernames=sorted(list(auth_usernames)) if auth_usernames else None,
            commands_count=commands_count,
            events=events,
            security_warnings=list(dict.fromkeys(warnings)),  # unique preserve order
            first_frame_number=sess.first_frame_number,
            last_frame_number=sess.last_frame_number,
        )

    # ==========================================
    # IMAP State Machine & Event Parsing
    # ==========================================

    def _analyze_imap_session(self, sess: TcpSession) -> EmailSessionAnalysis:
        turns = sess.conversation_flow or []
        events: List[Dict[str, Any]] = []
        warnings: List[str] = []
        capabilities: List[str] = []
        auth_mechanisms: List[str] = []
        auth_usernames: Set[str] = set()

        server_banner: Optional[str] = None
        session_state = "NOT_AUTHENTICATED"
        starttls_advertised = False
        starttls_requested = False
        starttls_accepted = False
        auth_attempted = False
        auth_successful: Optional[bool] = None
        commands_count = 0
        tls_established = False

        for turn in turns:
            direction = turn.get("direction", "c2s")
            preview = turn.get("text_preview", "")
            frame = turn.get("start_frame")
            t_time = turn.get("start_time")
            lines = [l.strip() for l in preview.splitlines() if l.strip()]

            for line in lines:
                if direction == "s2c":
                    if line.startswith("* OK"):
                        if server_banner is None:
                            server_banner = line
                        events.append({
                            "direction": "s2c",
                            "event_type": "BANNER",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                        # Extract inline capabilities [CAPABILITY ...]
                        cap_match = re.search(r"\[CAPABILITY\s+([^\]]+)\]", line, re.IGNORECASE)
                        if cap_match:
                            for c in cap_match.group(1).split():
                                c_clean = c.strip().upper()
                                if c_clean and c_clean not in capabilities:
                                    capabilities.append(c_clean)
                    elif line.startswith("* CAPABILITY"):
                        for c in line.split()[2:]:
                            c_clean = c.strip().upper()
                            if c_clean and c_clean not in capabilities:
                                capabilities.append(c_clean)
                        events.append({
                            "direction": "s2c",
                            "event_type": "CAPABILITY_LIST",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    else:
                        # Tagged responses (e.g. A01 OK ..., A01 NO ..., A01 BAD ...)
                        parts = line.split(" ", 2)
                        tag = parts[0]
                        status = parts[1].upper() if len(parts) > 1 else ""
                        msg = parts[2] if len(parts) > 2 else ""

                        if starttls_requested and status == "OK":
                            starttls_accepted = True
                            tls_established = True
                            session_state = "STARTTLS_NEGOTIATED"
                            events.append({
                                "direction": "s2c",
                                "event_type": "STARTTLS_NEGOTIATION",
                                "response_code": status,
                                "raw_text": line,
                                "frame_number": frame,
                                "timestamp": t_time,
                            })
                        elif auth_attempted and status == "OK" and auth_successful is None:
                            auth_successful = True
                            session_state = "AUTHENTICATED"
                            events.append({
                                "direction": "s2c",
                                "event_type": "AUTH_EXCHANGE",
                                "response_code": status,
                                "raw_text": line,
                                "frame_number": frame,
                                "timestamp": t_time,
                            })
                        elif auth_attempted and status in ("NO", "BAD") and auth_successful is None:
                            auth_successful = False
                            warnings.append(f"AUTH_FAILURE: IMAP server returned {status} for authentication attempt")
                            events.append({
                                "direction": "s2c",
                                "event_type": "AUTH_EXCHANGE",
                                "response_code": status,
                                "raw_text": line,
                                "frame_number": frame,
                                "timestamp": t_time,
                            })
                        else:
                            events.append({
                                "direction": "s2c",
                                "event_type": "RESPONSE",
                                "response_code": status,
                                "raw_text": line,
                                "frame_number": frame,
                                "timestamp": t_time,
                            })

                else:
                    # Client command (c2s): <tag> <command> [arguments]
                    commands_count += 1
                    parts = line.split(" ", 2)
                    tag = parts[0]
                    cmd = parts[1].upper() if len(parts) > 1 else ""
                    arg = parts[2] if len(parts) > 2 else ""

                    if cmd == "CAPABILITY":
                        events.append({
                            "direction": "c2s",
                            "event_type": "COMMAND",
                            "command": "CAPABILITY",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "STARTTLS":
                        starttls_requested = True
                        events.append({
                            "direction": "c2s",
                            "event_type": "STARTTLS_NEGOTIATION",
                            "command": "STARTTLS",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd in ("LOGIN", "AUTHENTICATE"):
                        auth_attempted = True
                        sanitized_arg, extracted_user = redact_auth_argument(cmd, arg)
                        if extracted_user:
                            auth_usernames.add(extracted_user)
                        if not tls_established:
                            warnings.append(f"CLEARTEXT_{cmd}_TRANSMITTED: Client issued cleartext {cmd} without encryption")
                        events.append({
                            "direction": "c2s",
                            "event_type": "AUTH_EXCHANGE",
                            "command": cmd,
                            "argument": sanitized_arg,
                            "raw_text": f"{tag} {cmd} {sanitized_arg}",
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "SELECT":
                        session_state = "SELECTED"
                        events.append({
                            "direction": "c2s",
                            "event_type": "COMMAND",
                            "command": "SELECT",
                            "argument": arg,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "LOGOUT":
                        session_state = "LOGOUT"
                        events.append({
                            "direction": "c2s",
                            "event_type": "CLOSING",
                            "command": "LOGOUT",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    else:
                        events.append({
                            "direction": "c2s",
                            "event_type": "COMMAND",
                            "command": cmd,
                            "argument": arg,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })

        # Process extracted capabilities
        for c in capabilities:
            if c == "STARTTLS":
                starttls_advertised = True
            if c.startswith("AUTH="):
                mech = c[5:]
                if mech not in auth_mechanisms:
                    auth_mechanisms.append(mech)

        if capabilities and not starttls_advertised and not tls_established:
            warnings.append("STARTTLS_NOT_ADVERTISED: IMAP server does not advertise STARTTLS in capabilities")
        if ("AUTH=PLAIN" in capabilities or "AUTH=LOGIN" in capabilities) and not tls_established:
            warnings.append("CLEARTEXT_AUTH_OFFERED: IMAP server offers plain/login authentication without TLS")

        return EmailSessionAnalysis(
            job_id=sess.job_id,
            tcp_session_id=sess.id,
            tcp_stream=sess.tcp_stream,
            protocol="IMAP",
            client_ip=sess.client_ip,
            server_ip=sess.server_ip,
            client_port=sess.client_port,
            server_port=sess.server_port,
            server_banner=server_banner,
            session_state=session_state,
            capabilities=capabilities if capabilities else None,
            starttls_advertised=starttls_advertised,
            starttls_requested=starttls_requested,
            starttls_accepted=starttls_accepted,
            auth_mechanisms=auth_mechanisms if auth_mechanisms else None,
            auth_attempted=auth_attempted,
            auth_successful=auth_successful,
            auth_usernames=sorted(list(auth_usernames)) if auth_usernames else None,
            commands_count=commands_count,
            events=events,
            security_warnings=list(dict.fromkeys(warnings)),
            first_frame_number=sess.first_frame_number,
            last_frame_number=sess.last_frame_number,
        )

    # ==========================================
    # POP3 State Machine & Event Parsing
    # ==========================================

    def _analyze_pop3_session(self, sess: TcpSession) -> EmailSessionAnalysis:
        turns = sess.conversation_flow or []
        events: List[Dict[str, Any]] = []
        warnings: List[str] = []
        capabilities: List[str] = []
        auth_mechanisms: List[str] = []
        auth_usernames: Set[str] = set()

        server_banner: Optional[str] = None
        session_state = "AUTHORIZATION"
        starttls_advertised = False
        starttls_requested = False
        starttls_accepted = False
        auth_attempted = False
        auth_successful: Optional[bool] = None
        commands_count = 0
        tls_established = False

        in_capa_response = False

        for turn in turns:
            direction = turn.get("direction", "c2s")
            preview = turn.get("text_preview", "")
            frame = turn.get("start_frame")
            t_time = turn.get("start_time")
            lines = [l.strip() for l in preview.splitlines() if l.strip()]

            for line in lines:
                if direction == "s2c":
                    if line.startswith("+OK"):
                        if server_banner is None and not tls_established:
                            server_banner = line
                            events.append({
                                "direction": "s2c",
                                "event_type": "BANNER",
                                "response_code": "+OK",
                                "raw_text": line,
                                "frame_number": frame,
                                "timestamp": t_time,
                            })
                        elif starttls_requested and not tls_established:
                            starttls_accepted = True
                            tls_established = True
                            session_state = "STARTTLS_NEGOTIATED"
                            events.append({
                                "direction": "s2c",
                                "event_type": "STARTTLS_NEGOTIATION",
                                "response_code": "+OK",
                                "raw_text": line,
                                "frame_number": frame,
                                "timestamp": t_time,
                            })
                        elif in_capa_response:
                            # Start of capa multi-line
                            pass
                        elif auth_attempted and auth_successful is None:
                            auth_successful = True
                            session_state = "TRANSACTION"
                            events.append({
                                "direction": "s2c",
                                "event_type": "AUTH_EXCHANGE",
                                "response_code": "+OK",
                                "raw_text": line,
                                "frame_number": frame,
                                "timestamp": t_time,
                            })
                        else:
                            events.append({
                                "direction": "s2c",
                                "event_type": "RESPONSE",
                                "response_code": "+OK",
                                "raw_text": line,
                                "frame_number": frame,
                                "timestamp": t_time,
                            })
                    elif line.startswith("-ERR"):
                        if auth_attempted and auth_successful is None:
                            auth_successful = False
                            warnings.append("AUTH_FAILURE: POP3 server returned -ERR for credentials")
                        events.append({
                            "direction": "s2c",
                            "event_type": "RESPONSE",
                            "response_code": "-ERR",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif in_capa_response:
                        if line == ".":
                            in_capa_response = False
                        else:
                            cap_clean = line.strip().upper()
                            if cap_clean and cap_clean not in capabilities:
                                capabilities.append(cap_clean)
                            if cap_clean == "STLS":
                                starttls_advertised = True
                            if cap_clean.startswith("SASL"):
                                for m in cap_clean.split()[1:]:
                                    if m not in auth_mechanisms:
                                        auth_mechanisms.append(m)
                            events.append({
                                "direction": "s2c",
                                "event_type": "CAPABILITY_LIST",
                                "argument": line,
                                "raw_text": line,
                                "frame_number": frame,
                                "timestamp": t_time,
                            })

                else:
                    # Client commands (c2s)
                    commands_count += 1
                    parts = line.split(" ", 1)
                    cmd = parts[0].upper()
                    arg = parts[1] if len(parts) > 1 else ""

                    if cmd == "CAPA":
                        in_capa_response = True
                        events.append({
                            "direction": "c2s",
                            "event_type": "COMMAND",
                            "command": "CAPA",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "STLS":
                        starttls_requested = True
                        events.append({
                            "direction": "c2s",
                            "event_type": "STARTTLS_NEGOTIATION",
                            "command": "STLS",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "USER":
                        auth_attempted = True
                        sanitized_arg, extracted_user = redact_auth_argument(cmd, arg)
                        if extracted_user:
                            auth_usernames.add(extracted_user)
                        events.append({
                            "direction": "c2s",
                            "event_type": "AUTH_EXCHANGE",
                            "command": "USER",
                            "argument": sanitized_arg,
                            "raw_text": f"USER {sanitized_arg}",
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "PASS":
                        sanitized_arg, _ = redact_auth_argument(cmd, arg)
                        if not tls_established:
                            warnings.append("CLEARTEXT_PASS_TRANSMITTED: Client transmitted cleartext PASS command without encryption")
                        events.append({
                            "direction": "c2s",
                            "event_type": "AUTH_EXCHANGE",
                            "command": "PASS",
                            "argument": sanitized_arg,
                            "raw_text": f"PASS {sanitized_arg}",
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    elif cmd == "QUIT":
                        session_state = "UPDATE"
                        events.append({
                            "direction": "c2s",
                            "event_type": "CLOSING",
                            "command": "QUIT",
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })
                    else:
                        events.append({
                            "direction": "c2s",
                            "event_type": "COMMAND",
                            "command": cmd,
                            "argument": arg,
                            "raw_text": line,
                            "frame_number": frame,
                            "timestamp": t_time,
                        })

        if capabilities and not starttls_advertised and not tls_established:
            warnings.append("STLS_NOT_ADVERTISED: POP3 server does not advertise STLS in capabilities")

        return EmailSessionAnalysis(
            job_id=sess.job_id,
            tcp_session_id=sess.id,
            tcp_stream=sess.tcp_stream,
            protocol="POP3",
            client_ip=sess.client_ip,
            server_ip=sess.server_ip,
            client_port=sess.client_port,
            server_port=sess.server_port,
            server_banner=server_banner,
            session_state=session_state,
            capabilities=capabilities if capabilities else None,
            starttls_advertised=starttls_advertised,
            starttls_requested=starttls_requested,
            starttls_accepted=starttls_accepted,
            auth_mechanisms=auth_mechanisms if auth_mechanisms else None,
            auth_attempted=auth_attempted,
            auth_successful=auth_successful,
            auth_usernames=sorted(list(auth_usernames)) if auth_usernames else None,
            commands_count=commands_count,
            events=events,
            security_warnings=list(dict.fromkeys(warnings)),
            first_frame_number=sess.first_frame_number,
            last_frame_number=sess.last_frame_number,
        )
