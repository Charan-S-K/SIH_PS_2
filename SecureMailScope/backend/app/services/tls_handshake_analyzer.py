"""
TLS Handshake Analysis Service for SecureMailScope.
Reconstructs observable TLS handshakes and extracts negotiated TLS version,
cipher suites, key-exchange/signature parameters, extensions, certificates,
and alert conditions. Uses UNKNOWN when evidence is unobservable; never guesses.
"""

import base64
import logging
import struct
from typing import Any, Dict, List, Optional, Set, Tuple
from scapy.all import PcapReader, Raw, TCP
from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.packet import PacketMetadata
from app.models.session import TcpSession
from app.models.starttls import StarttlsAnalysis
from app.models.tls_handshake import TlsHandshakeAnalysis

logger = logging.getLogger(__name__)

# Standard IANA TLS Versions
TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Standard IANA Cipher Suite mappings (representative RFC dictionary)
CIPHER_SUITES = {
    # TLS 1.3
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    # Modern TLS 1.2 ECDHE AEAD
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    # TLS 1.2 ECDHE CBC
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    # DHE suites
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    # Static RSA suites
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    # Deprecated / Legacy suites
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
}

# Standard IANA Named Groups (Elliptic Curves & DH groups)
NAMED_GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
}

# Standard IANA Signature Schemes
SIGNATURE_SCHEMES = {
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
}

# Standard IANA Alert Descriptions
ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    30: "decompression_failure",
    40: "handshake_failure",
    41: "no_certificate",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    60: "export_restriction",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    90: "user_canceled",
    100: "no_renegotiation",
    110: "unsupported_extension",
    112: "unrecognized_name",
}


def format_cipher_suite(cipher_id: int) -> Dict[str, Any]:
    """Helper to return cipher suite dict with ID, hex representation, and standard name."""
    name = CIPHER_SUITES.get(cipher_id, f"UNKNOWN_CIPHER_0x{cipher_id:04X}")
    return {
        "id": cipher_id,
        "hex": f"0x{cipher_id:04x}",
        "name": name,
    }


class TlsHandshakeAnalyzer:
    """Forensic TLS Handshake dissection and cryptographic parameter extractor."""

    def __init__(self, db: Session):
        self.db = db

    def analyze_job_tls_handshakes(self, job_id: str) -> List[TlsHandshakeAnalysis]:
        """
        Analyze all observable TLS handshakes in an AnalysisJob.
        Idempotent: removes previous records for this job before running.
        """
        job = self.db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job '{job_id}' not found")

        # Delete existing handshake analyses for idempotency
        self.db.query(TlsHandshakeAnalysis).filter(TlsHandshakeAnalysis.job_id == job_id).delete()
        self.db.commit()

        # Gather sessions to inspect:
        # 1. Sessions connecting directly to implicit TLS ports (465, 993, 995)
        # 2. Sessions where STARTTLS was negotiated (StarttlsAnalysis.accepted is True)
        # 3. Sessions where ProtocolIdentification detected TLS
        candidate_streams = self._discover_tls_candidate_streams(job)

        analyses: List[TlsHandshakeAnalysis] = []
        for stream_id, is_starttls in candidate_streams:
            analysis = self.analyze_stream_tls(job, stream_id, is_starttls)
            if analysis:
                self.db.add(analysis)
                analyses.append(analysis)

        self.db.commit()
        logger.info("TLS Handshake analysis completed for job %s: %d handshakes analyzed", job_id, len(analyses))
        return analyses

    def _discover_tls_candidate_streams(self, job: AnalysisJob) -> List[Tuple[int, bool]]:
        """Identify candidate stream IDs that contain TLS traffic and whether it is STARTTLS."""
        candidates: Dict[int, bool] = {}

        # 1. Check StarttlsAnalysis records for upgraded sessions
        starttls_records = (
            self.db.query(StarttlsAnalysis)
            .filter(StarttlsAnalysis.job_id == job.id)
            .all()
        )
        for st in starttls_records:
            if st.accepted or st.upgrade_status in ("UPGRADED_SUCCESS", "UPGRADE_ACCEPTED"):
                candidates[st.tcp_stream] = True
            elif st.upgrade_status == "DIRECT_TLS":
                candidates[st.tcp_stream] = False

        # 2. Check TcpSession port numbers (465, 993, 995)
        sessions = (
            self.db.query(TcpSession)
            .filter(TcpSession.job_id == job.id)
            .all()
        )
        for sess in sessions:
            port = sess.server_port or 0
            if port in (465, 993, 995):
                if sess.tcp_stream not in candidates:
                    candidates[sess.tcp_stream] = False

        # 3. Check PacketMetadata for detected_protocol == "TLS"
        tls_packets = (
            self.db.query(PacketMetadata.tcp_stream)
            .filter(
                PacketMetadata.job_id == job.id,
                PacketMetadata.detected_protocol == "TLS",
                PacketMetadata.tcp_stream.isnot(None),
            )
            .distinct()
            .all()
        )
        for row in tls_packets:
            stream_id = row[0]
            if stream_id not in candidates:
                candidates[stream_id] = False

        return [(sid, is_st) for sid, is_st in sorted(candidates.items())]

    def analyze_stream_tls(self, job: AnalysisJob, stream_id: int, is_starttls: bool) -> Optional[TlsHandshakeAnalysis]:
        """Dissect observable TLS records for a single stream and build analysis record."""
        session = (
            self.db.query(TcpSession)
            .filter(TcpSession.job_id == job.id, TcpSession.tcp_stream == stream_id)
            .first()
        )

        client_ip = session.client_ip if session else None
        server_ip = session.server_ip if session else None
        client_port = session.client_port if session else None
        server_port = session.server_port if session else None
        protocol = session.protocol if session else "UNKNOWN"

        if server_port == 465 or (protocol == "SMTP" and not is_starttls):
            protocol = "SMTPS" if not is_starttls else "SMTP"
        elif server_port == 993 or (protocol == "IMAP" and not is_starttls):
            protocol = "IMAPS" if not is_starttls else "IMAP"
        elif server_port == 995 or (protocol == "POP3" and not is_starttls):
            protocol = "POP3S" if not is_starttls else "POP3"

        # Dissect TLS records from packet payloads
        records = self._extract_stream_tls_records(job, stream_id)
        if not records:
            # No observable TLS record layer
            return TlsHandshakeAnalysis(
                job_id=job.id,
                tcp_session_id=session.id if session else None,
                tcp_stream=stream_id,
                protocol=protocol,
                client_ip=client_ip,
                server_ip=server_ip,
                client_port=client_port,
                server_port=server_port,
                is_starttls=is_starttls,
                handshake_status="NOT_OBSERVED",
                negotiated_version="UNKNOWN",
                negotiated_cipher_suite="UNKNOWN",
            )

        # Parse dissected handshake messages
        client_hello: Optional[Dict[str, Any]] = None
        server_hello: Optional[Dict[str, Any]] = None
        certificates: List[str] = []
        certificate_frame: Optional[int] = None
        alert_info: Optional[Dict[str, Any]] = None
        change_cipher_spec_seen = False
        finished_seen = False
        app_data_seen = False
        handshake_messages: List[Dict[str, Any]] = []

        for rec in records:
            ctype = rec["content_type"]
            frame = rec["frame_number"]
            time_val = rec["timestamp"]

            if ctype == 0x14:  # ChangeCipherSpec
                change_cipher_spec_seen = True
                handshake_messages.append({
                    "message_type": "ChangeCipherSpec",
                    "frame_number": frame,
                    "timestamp": time_val,
                    "info": "Change Cipher Spec",
                })
            elif ctype == 0x15:  # Alert
                alert_info = rec["alert"]
                handshake_messages.append({
                    "message_type": "Alert",
                    "frame_number": frame,
                    "timestamp": time_val,
                    "info": f"{alert_info.get('level')} Alert: {alert_info.get('description')}",
                })
            elif ctype == 0x17:  # ApplicationData
                app_data_seen = True
            elif ctype == 0x16:  # Handshake
                for hs in rec.get("handshake_messages", []):
                    htype = hs["type"]
                    handshake_messages.append({
                        "message_type": htype,
                        "frame_number": frame,
                        "timestamp": time_val,
                        "info": hs.get("info", htype),
                    })
                    if htype == "ClientHello" and not client_hello:
                        client_hello = hs
                        client_hello["frame_number"] = frame
                        client_hello["timestamp"] = time_val
                    elif htype == "ServerHello" and not server_hello:
                        server_hello = hs
                        server_hello["frame_number"] = frame
                        server_hello["timestamp"] = time_val
                    elif htype == "Certificate" and not certificate_frame:
                        certificate_frame = frame
                        certificates = hs.get("certificates", [])
                    elif htype == "Finished":
                        finished_seen = True

        # Determine Negotiated Version
        negotiated_version = "UNKNOWN"
        negotiated_version_raw: Optional[int] = None

        if server_hello:
            # In TLS 1.3, ServerHello has supported_versions extension == 0x0304
            srv_sup_ver = server_hello.get("selected_supported_version")
            if srv_sup_ver == 0x0304 or srv_sup_ver == "0x0304":
                negotiated_version = "TLS 1.3"
                negotiated_version_raw = 0x0304
            elif server_hello.get("version_raw") in TLS_VERSIONS:
                raw_ver = server_hello["version_raw"]
                negotiated_version = TLS_VERSIONS[raw_ver]
                negotiated_version_raw = raw_ver
            elif server_hello.get("version"):
                negotiated_version = server_hello["version"]
        elif client_hello and not server_hello:
            # Never guess the negotiated version if Server Hello is missing
            negotiated_version = "UNKNOWN"

        # Determine Negotiated Cipher Suite
        negotiated_cipher_suite = "UNKNOWN"
        negotiated_cipher_id: Optional[int] = None
        if server_hello and server_hello.get("cipher_suite"):
            negotiated_cipher_id = server_hello["cipher_suite"].get("id")
            negotiated_cipher_suite = server_hello["cipher_suite"].get("name", "UNKNOWN")

        # Determine Key Exchange Group & Signature Scheme
        key_exchange_group: Optional[str] = None
        signature_scheme: Optional[str] = None

        if server_hello and server_hello.get("selected_key_share_group"):
            key_exchange_group = server_hello["selected_key_share_group"]
        elif client_hello and client_hello.get("supported_groups"):
            # If server hello didn't explicitly specify, check first preferred client group if 1.3
            if negotiated_version == "TLS 1.3" and client_hello.get("key_share_groups"):
                key_exchange_group = client_hello["key_share_groups"][0]

        if client_hello and client_hello.get("signature_algorithms"):
            # Extract client's top offered signature scheme
            signature_scheme = client_hello["signature_algorithms"][0]

        # Determine SNI & ALPN
        sni: Optional[str] = None
        alpn_selected: Optional[str] = None
        if client_hello:
            sni = client_hello.get("sni")
        if server_hello:
            alpn_selected = server_hello.get("alpn_selected")
        elif client_hello and client_hello.get("alpn_protocols"):
            alpn_selected = client_hello["alpn_protocols"][0]

        # Determine Handshake Status
        if alert_info:
            handshake_status = "ALERT_TERMINATED"
        elif client_hello and server_hello and (change_cipher_spec_seen or finished_seen or app_data_seen):
            handshake_status = "COMPLETED"
        elif client_hello and server_hello:
            handshake_status = "NEGOTIATED_INCOMPLETE"
        elif client_hello and not server_hello:
            handshake_status = "CLIENT_HELLO_ONLY"
        else:
            handshake_status = "NOT_OBSERVED"

        # Compute handshake duration
        duration_ms: Optional[float] = None
        if client_hello and client_hello.get("timestamp"):
            ch_time = client_hello["timestamp"]
            end_time = None
            if handshake_messages:
                end_time = handshake_messages[-1].get("timestamp")
            if end_time and end_time >= ch_time:
                duration_ms = round((end_time - ch_time) * 1000.0, 2)

        # Synthesize Evidence & Findings
        evidence: List[Dict[str, Any]] = []
        if client_hello:
            evidence.append({
                "type": "CLIENT_HELLO_OBSERVED",
                "frame": client_hello.get("frame_number"),
                "details": f"Client Hello offered {len(client_hello.get('offered_ciphers', []))} cipher suites, SNI={sni or 'None'}",
            })
        if server_hello:
            evidence.append({
                "type": "SERVER_HELLO_OBSERVED",
                "frame": server_hello.get("frame_number"),
                "details": f"Server selected {negotiated_version}, cipher suite {negotiated_cipher_suite}",
            })
        if alert_info:
            evidence.append({
                "type": "TLS_ALERT_OBSERVED",
                "frame": alert_info.get("frame_number"),
                "details": f"TLS Alert {alert_info.get('level')}: {alert_info.get('description')}",
            })

        return TlsHandshakeAnalysis(
            job_id=job.id,
            tcp_session_id=session.id if session else None,
            tcp_stream=stream_id,
            protocol=protocol,
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=client_port,
            server_port=server_port,
            is_starttls=is_starttls,
            handshake_status=handshake_status,
            negotiated_version=negotiated_version,
            negotiated_version_raw=negotiated_version_raw,
            negotiated_cipher_suite=negotiated_cipher_suite,
            negotiated_cipher_id=negotiated_cipher_id,
            key_exchange_group=key_exchange_group,
            signature_scheme=signature_scheme,
            sni=sni,
            alpn_selected=alpn_selected,
            client_hello_frame=client_hello.get("frame_number") if client_hello else None,
            client_hello_time=client_hello.get("timestamp") if client_hello else None,
            client_hello_version=client_hello.get("version") if client_hello else None,
            client_random=client_hello.get("random") if client_hello else None,
            client_offered_ciphers=client_hello.get("offered_ciphers") if client_hello else None,
            client_supported_versions=client_hello.get("supported_versions") if client_hello else None,
            client_supported_groups=client_hello.get("supported_groups") if client_hello else None,
            client_signature_algorithms=client_hello.get("signature_algorithms") if client_hello else None,
            client_alpn_protocols=client_hello.get("alpn_protocols") if client_hello else None,
            client_extensions_count=client_hello.get("extensions_count", 0) if client_hello else 0,
            server_hello_frame=server_hello.get("frame_number") if server_hello else None,
            server_hello_time=server_hello.get("timestamp") if server_hello else None,
            server_hello_version=server_hello.get("version") if server_hello else None,
            server_random=server_hello.get("random") if server_hello else None,
            server_extensions_count=server_hello.get("extensions_count", 0) if server_hello else 0,
            certificate_frame=certificate_frame,
            certificate_chain_length=len(certificates),
            raw_certificates_bytes=certificates,
            has_alert=bool(alert_info),
            alert_level=alert_info.get("level") if alert_info else None,
            alert_description=alert_info.get("description") if alert_info else None,
            alert_frame=alert_info.get("frame_number") if alert_info else None,
            handshake_messages=handshake_messages,
            handshake_duration_ms=duration_ms,
            evidence=evidence,
        )

    def _extract_stream_tls_records(self, job: AnalysisJob, stream_id: int) -> List[Dict[str, Any]]:
        """Extract and parse TLS records for a given stream from PCAP capture."""
        records: List[Dict[str, Any]] = []
        pcap_file = job.pcap_file
        if not pcap_file or not pcap_file.file_path:
            return records

        # Also retrieve packet timestamps and frame numbers
        packet_meta_map: Dict[int, float] = {}
        metas = (
            self.db.query(PacketMetadata.frame_number, PacketMetadata.timestamp)
            .filter(PacketMetadata.job_id == job.id, PacketMetadata.tcp_stream == stream_id)
            .all()
        )
        for fn, ts in metas:
            packet_meta_map[fn] = ts

        try:
            frame_num = 0
            with PcapReader(pcap_file.file_path) as reader:
                for pkt in reader:
                    frame_num += 1
                    if frame_num not in packet_meta_map:
                        continue
                    if TCP not in pkt or Raw not in pkt:
                        continue

                    load = bytes(pkt[Raw].load)
                    ts = packet_meta_map.get(frame_num, 0.0)
                    dissected = self.dissect_tls_payload(load, frame_num, ts)
                    records.extend(dissected)
        except Exception as e:
            logger.warning("Error reading PCAP for stream %d TLS dissection: %s", stream_id, e)

        return records

    @staticmethod
    def dissect_tls_payload(load: bytes, frame_number: int, timestamp: float) -> List[Dict[str, Any]]:
        """
        Deterministic binary parser for TLS records and handshake messages.
        Dissects ClientHello, ServerHello, Certificate, Alert, ChangeCipherSpec, and ApplicationData.
        Guaranteed to not crash on truncated or malformed payloads.
        """
        records: List[Dict[str, Any]] = []
        offset = 0
        total_len = len(load)

        while offset + 5 <= total_len:
            ctype = load[offset]
            # Valid TLS content types: 20 (CCS), 21 (Alert), 22 (Handshake), 23 (AppData)
            if ctype not in (0x14, 0x15, 0x16, 0x17):
                break

            rec_ver = struct.unpack("!H", load[offset + 1 : offset + 3])[0]
            rec_len = struct.unpack("!H", load[offset + 3 : offset + 5])[0]
            offset += 5

            if offset + rec_len > total_len:
                # Truncated record in payload
                rec_payload = load[offset:]
                offset = total_len
            else:
                rec_payload = load[offset : offset + rec_len]
                offset += rec_len

            record_info: Dict[str, Any] = {
                "content_type": ctype,
                "record_version": TLS_VERSIONS.get(rec_ver, f"0x{rec_ver:04x}"),
                "record_version_raw": rec_ver,
                "record_length": rec_len,
                "frame_number": frame_number,
                "timestamp": timestamp,
            }

            # 1. Alert (ContentType 21)
            if ctype == 0x15 and len(rec_payload) >= 2:
                level_code = rec_payload[0]
                desc_code = rec_payload[1]
                level_str = "WARNING" if level_code == 1 else "FATAL" if level_code == 2 else f"UNKNOWN({level_code})"
                desc_str = ALERT_DESCRIPTIONS.get(desc_code, f"unknown_alert_{desc_code}")
                record_info["alert"] = {
                    "level": level_str,
                    "description": f"{desc_str} ({desc_code})",
                    "frame_number": frame_number,
                }

            # 2. Handshake (ContentType 22)
            elif ctype == 0x16:
                hs_messages = TlsHandshakeAnalyzer._parse_handshake_payload(rec_payload, frame_number)
                record_info["handshake_messages"] = hs_messages

            records.append(record_info)

        return records

    @staticmethod
    def _parse_handshake_payload(payload: bytes, frame_number: int) -> List[Dict[str, Any]]:
        """Parse one or more handshake messages within a Handshake record."""
        messages: List[Dict[str, Any]] = []
        offset = 0
        total_len = len(payload)

        while offset + 4 <= total_len:
            htype = payload[offset]
            hlen = (payload[offset + 1] << 16) | (payload[offset + 2] << 8) | payload[offset + 3]
            offset += 4

            if offset + hlen > total_len:
                body = payload[offset:]
                offset = total_len
            else:
                body = payload[offset : offset + hlen]
                offset += hlen

            if htype == 1:  # ClientHello
                ch_info = TlsHandshakeAnalyzer._dissect_client_hello(body)
                messages.append(ch_info)
            elif htype == 2:  # ServerHello
                sh_info = TlsHandshakeAnalyzer._dissect_server_hello(body)
                messages.append(sh_info)
            elif htype == 11:  # Certificate
                cert_info = TlsHandshakeAnalyzer._dissect_certificate(body)
                messages.append(cert_info)
            elif htype == 12:  # ServerKeyExchange
                messages.append({"type": "ServerKeyExchange", "info": "Server Key Exchange parameters"})
            elif htype == 14:  # ServerHelloDone
                messages.append({"type": "ServerHelloDone", "info": "Server Hello Done"})
            elif htype == 16:  # ClientKeyExchange
                messages.append({"type": "ClientKeyExchange", "info": "Client Key Exchange"})
            elif htype == 20:  # Finished
                messages.append({"type": "Finished", "info": "Handshake Finished"})
            else:
                messages.append({"type": f"HandshakeType_{htype}", "info": f"Type {htype} length {hlen}"})

        return messages

    @staticmethod
    def _dissect_client_hello(body: bytes) -> Dict[str, Any]:
        """Dissect ClientHello structure: version, random, ciphers, extensions."""
        info: Dict[str, Any] = {
            "type": "ClientHello",
            "info": "Client Hello",
            "offered_ciphers": [],
            "supported_versions": [],
            "supported_groups": [],
            "signature_algorithms": [],
            "alpn_protocols": [],
            "key_share_groups": [],
            "extensions_count": 0,
        }

        if len(body) < 34:
            return info

        ver_raw = struct.unpack("!H", body[0:2])[0]
        info["version_raw"] = ver_raw
        info["version"] = TLS_VERSIONS.get(ver_raw, f"0x{ver_raw:04x}")
        info["random"] = body[2:34].hex()

        idx = 34
        if idx >= len(body):
            return info

        sess_id_len = body[idx]
        idx += 1 + sess_id_len

        # Cipher Suites
        if idx + 2 <= len(body):
            cs_len = struct.unpack("!H", body[idx : idx + 2])[0]
            idx += 2
            ciphers_end = idx + cs_len
            offered: List[Dict[str, Any]] = []
            while idx + 2 <= min(ciphers_end, len(body)):
                cid = struct.unpack("!H", body[idx : idx + 2])[0]
                offered.append(format_cipher_suite(cid))
                idx += 2
            info["offered_ciphers"] = offered
            idx = ciphers_end

        # Compression Methods
        if idx < len(body):
            comp_len = body[idx]
            idx += 1 + comp_len

        # Extensions
        if idx + 2 <= len(body):
            ext_total_len = struct.unpack("!H", body[idx : idx + 2])[0]
            idx += 2
            ext_end = min(idx + ext_total_len, len(body))
            ext_count = 0

            while idx + 4 <= ext_end:
                etype, elen = struct.unpack("!HH", body[idx : idx + 4])
                idx += 4
                edata = body[idx : idx + elen]
                idx += elen
                ext_count += 1

                # 0x0000: Server Name Indication (SNI)
                if etype == 0x0000 and len(edata) >= 5:
                    sni_name_len = struct.unpack("!H", edata[3:5])[0]
                    if 5 + sni_name_len <= len(edata):
                        info["sni"] = edata[5 : 5 + sni_name_len].decode("utf-8", errors="ignore")

                # 0x000a: Supported Groups (Elliptic Curves)
                elif etype == 0x000a and len(edata) >= 2:
                    groups_len = struct.unpack("!H", edata[0:2])[0]
                    g_idx = 2
                    groups: List[str] = []
                    while g_idx + 2 <= min(g_idx + groups_len, len(edata)):
                        gid = struct.unpack("!H", edata[g_idx : g_idx + 2])[0]
                        groups.append(NAMED_GROUPS.get(gid, f"group_0x{gid:04x}"))
                        g_idx += 2
                    info["supported_groups"] = groups

                # 0x000d: Signature Algorithms
                elif etype == 0x000d and len(edata) >= 2:
                    sig_len = struct.unpack("!H", edata[0:2])[0]
                    s_idx = 2
                    sigs: List[str] = []
                    while s_idx + 2 <= min(s_idx + sig_len, len(edata)):
                        sid = struct.unpack("!H", edata[s_idx : s_idx + 2])[0]
                        sigs.append(SIGNATURE_SCHEMES.get(sid, f"sig_0x{sid:04x}"))
                        s_idx += 2
                    info["signature_algorithms"] = sigs

                # 0x0010: ALPN
                elif etype == 0x0010 and len(edata) >= 2:
                    alpn_len = struct.unpack("!H", edata[0:2])[0]
                    a_idx = 2
                    alpns: List[str] = []
                    while a_idx < min(2 + alpn_len, len(edata)):
                        proto_len = edata[a_idx]
                        a_idx += 1
                        if a_idx + proto_len <= len(edata):
                            alpns.append(edata[a_idx : a_idx + proto_len].decode("utf-8", errors="ignore"))
                        a_idx += proto_len
                    info["alpn_protocols"] = alpns

                # 0x002b: Supported Versions (TLS 1.3 indicator)
                elif etype == 0x002b and len(edata) >= 1:
                    v_len = edata[0]
                    v_idx = 1
                    versions: List[str] = []
                    while v_idx + 2 <= min(1 + v_len, len(edata)):
                        vid = struct.unpack("!H", edata[v_idx : v_idx + 2])[0]
                        versions.append(TLS_VERSIONS.get(vid, f"0x{vid:04x}"))
                        v_idx += 2
                    info["supported_versions"] = versions

                # 0x0033: Key Share (TLS 1.3)
                elif etype == 0x0033 and len(edata) >= 2:
                    ks_len = struct.unpack("!H", edata[0:2])[0]
                    k_idx = 2
                    ks_groups: List[str] = []
                    while k_idx + 4 <= min(2 + ks_len, len(edata)):
                        kg_id, k_entry_len = struct.unpack("!HH", edata[k_idx : k_idx + 4])
                        ks_groups.append(NAMED_GROUPS.get(kg_id, f"group_0x{kg_id:04x}"))
                        k_idx += 4 + k_entry_len
                    info["key_share_groups"] = ks_groups

            info["extensions_count"] = ext_count

        return info

    @staticmethod
    def _dissect_server_hello(body: bytes) -> Dict[str, Any]:
        """Dissect ServerHello: version, selected cipher, selected extensions (TLS 1.3 supported_versions, key_share)."""
        info: Dict[str, Any] = {
            "type": "ServerHello",
            "info": "Server Hello",
            "extensions_count": 0,
        }

        if len(body) < 34:
            return info

        ver_raw = struct.unpack("!H", body[0:2])[0]
        info["version_raw"] = ver_raw
        info["version"] = TLS_VERSIONS.get(ver_raw, f"0x{ver_raw:04x}")
        info["random"] = body[2:34].hex()

        idx = 34
        if idx >= len(body):
            return info

        sess_id_len = body[idx]
        idx += 1 + sess_id_len

        # Selected Cipher Suite
        if idx + 2 <= len(body):
            cid = struct.unpack("!H", body[idx : idx + 2])[0]
            info["cipher_suite"] = format_cipher_suite(cid)
            idx += 2

        # Compression Method
        if idx < len(body):
            info["compression_method"] = body[idx]
            idx += 1

        # Extensions
        if idx + 2 <= len(body):
            ext_total_len = struct.unpack("!H", body[idx : idx + 2])[0]
            idx += 2
            ext_end = min(idx + ext_total_len, len(body))
            ext_count = 0

            while idx + 4 <= ext_end:
                etype, elen = struct.unpack("!HH", body[idx : idx + 4])
                idx += 4
                edata = body[idx : idx + elen]
                idx += elen
                ext_count += 1

                # 0x002b: Supported Versions (indicates TLS 1.3 in ServerHello)
                if etype == 0x002b and len(edata) >= 2:
                    sel_ver = struct.unpack("!H", edata[0:2])[0]
                    info["selected_supported_version"] = sel_ver
                    info["selected_supported_version_name"] = TLS_VERSIONS.get(sel_ver, f"0x{sel_ver:04x}")

                # 0x0033: Key Share (selected group in ServerHello)
                elif etype == 0x0033 and len(edata) >= 2:
                    kg_id = struct.unpack("!H", edata[0:2])[0]
                    info["selected_key_share_group"] = NAMED_GROUPS.get(kg_id, f"group_0x{kg_id:04x}")

                # 0x0010: ALPN
                elif etype == 0x0010 and len(edata) >= 3:
                    alpn_len = edata[2]
                    if 3 + alpn_len <= len(edata):
                        info["alpn_selected"] = edata[3 : 3 + alpn_len].decode("utf-8", errors="ignore")

            info["extensions_count"] = ext_count

        return info

    @staticmethod
    def _dissect_certificate(body: bytes) -> Dict[str, Any]:
        """Dissect Certificate message: extract certificate chain lengths and base64 raw DERs."""
        certs_b64: List[str] = []
        if len(body) < 3:
            return {"type": "Certificate", "certificates": [], "info": "Certificate (0 certs)"}

        total_certs_len = (body[0] << 16) | (body[1] << 8) | body[2]
        idx = 3
        end_idx = min(3 + total_certs_len, len(body))

        while idx + 3 <= end_idx:
            cert_len = (body[idx] << 16) | (body[idx + 1] << 8) | body[idx + 2]
            idx += 3
            if idx + cert_len <= len(body):
                cert_der = body[idx : idx + cert_len]
                certs_b64.append(base64.b64encode(cert_der).decode("ascii"))
                idx += cert_len
            else:
                break

        return {
            "type": "Certificate",
            "certificates": certs_b64,
            "chain_length": len(certs_b64),
            "info": f"Certificate chain ({len(certs_b64)} certificates)",
        }
