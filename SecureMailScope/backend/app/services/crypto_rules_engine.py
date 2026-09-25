"""
Service for Stage 09: Cryptographic Rules Engine.
Loads configurable YAML/JSON security rules and evaluates passive forensic evidence
from TLS handshakes, certificates, STARTTLS analyses, and email protocol sessions.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml
except ImportError:
    yaml = None

from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.session import TcpSession
from app.models.email_analysis import EmailSessionAnalysis
from app.models.starttls import StarttlsAnalysis
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.certificate import X509CertificateAnalysis
from app.models.rule_result import CryptoRuleResult
from app.schemas.rule_engine import (
    CryptoRuleDefinition,
    CryptoFindingResponse,
    JobFindingsSummary,
)

logger = logging.getLogger(__name__)

# Path to default YAML rule definitions file
DEFAULT_RULES_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "rules",
    "crypto_rules.yaml"
)

# Internal fallback rules dictionary if YAML file is unavailable
FALLBACK_RULES = [
    {
        "id": "RULE-TLS-001",
        "name": "Deprecated TLS Protocol Version (SSLv2 / SSLv3)",
        "category": "TLS_PROTOCOL",
        "severity": "CRITICAL",
        "description": "SSLv2 and SSLv3 protocols are obsolete, insecure, and vulnerable to POODLE, DROWN, and key extraction attacks.",
        "remediation": "Disable SSLv2 and SSLv3 on all mail servers and clients immediately. Enforce TLS 1.2 or TLS 1.3 minimum.",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-TLS-002",
        "name": "Deprecated TLS Protocol Version (TLS 1.0 / TLS 1.1)",
        "category": "TLS_PROTOCOL",
        "severity": "HIGH",
        "description": "TLS 1.0 and TLS 1.1 are deprecated by IETF RFC 8996 due to reliance on SHA-1/MD5 and CBC cipher vulnerabilities.",
        "remediation": "Deprecate TLS 1.0 and TLS 1.1 in mail server configurations (Postfix, Dovecot, Exchange). Require TLS 1.2 or TLS 1.3.",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-CIPHER-001",
        "name": "Insecure Cipher Suite (NULL / Anonymous / EXPORT / DES / RC4 / 3DES)",
        "category": "CIPHER_SUITE",
        "severity": "CRITICAL",
        "description": "Negotiated cipher suite provides zero encryption (NULL), no authentication (anon), or uses broken legacy ciphers.",
        "remediation": "Remove insecure cipher suites from server priority lists. Restrict allowed ciphers to modern AEAD suites.",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-CIPHER-002",
        "name": "Weak Cipher Suite (MD5 / SHA-1 MAC or Non-PFS Key Exchange)",
        "category": "CIPHER_SUITE",
        "severity": "HIGH",
        "description": "Cipher suite uses weak integrity MACs (MD5/SHA1), legacy CBC mode, or non-Forward-Secret RSA key exchange.",
        "remediation": "Configure Perfect Forward Secrecy (ECDHE / DHE) with SHA-256 or SHA-384 MAC algorithms. Prefer TLS 1.3 AEAD ciphers.",
        "default_confidence": 0.95,
    },
    {
        "id": "RULE-CERT-001",
        "name": "Expired X.509 Certificate",
        "category": "CERTIFICATE",
        "severity": "HIGH",
        "description": "The presented X.509 server or client certificate has passed its validity expiration date.",
        "remediation": "Renew the X.509 certificate immediately with a trusted Certificate Authority or ACME/Let's Encrypt.",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-CERT-002",
        "name": "Not Yet Valid X.509 Certificate",
        "category": "CERTIFICATE",
        "severity": "HIGH",
        "description": "The presented certificate validity start time (NotBefore) is in the future relative to observation timestamp.",
        "remediation": "Check server clock synchronization (NTP) and ensure valid certificate issuance timelines.",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-CERT-003",
        "name": "Self-Signed Certificate in Trust Chain",
        "category": "CERTIFICATE",
        "severity": "MEDIUM",
        "description": "The certificate issuer matches its own subject (self-signed) and is not issued by a public/trusted enterprise CA.",
        "remediation": "Replace self-signed certificates with certificates issued by a publicly trusted CA or enterprise PKI CA.",
        "default_confidence": 0.9,
    },
    {
        "id": "RULE-CERT-004",
        "name": "Weak Certificate Signature Algorithm (MD5 / SHA-1)",
        "category": "CERTIFICATE",
        "severity": "HIGH",
        "description": "The X.509 certificate was signed using a collision-vulnerable hash function (MD5 or SHA-1).",
        "remediation": "Reissue the certificate signed with SHA-256, SHA-384, or SHA-512.",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-CERT-005",
        "name": "Weak RSA Key Length (< 2048 bits)",
        "category": "CERTIFICATE",
        "severity": "HIGH",
        "description": "The RSA public key size in the certificate is less than 2048 bits, making it vulnerable to prime factorization attacks.",
        "remediation": "Generate new key pairs with RSA 2048-bit minimum (RSA 3072/4096 recommended) or NIST P-256 / Ed25519.",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-CERT-006",
        "name": "Weak Elliptic Curve Key Length (< 256 bits)",
        "category": "CERTIFICATE",
        "severity": "HIGH",
        "description": "The Elliptic Curve (EC) public key size is less than 256 bits.",
        "remediation": "Use standard curves with key length >= 256 bits (secp256r1 / secp384r1 / X25519).",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-CERT-007",
        "name": "Subject Alternative Name (SAN) Mismatch or Missing SAN",
        "category": "CERTIFICATE",
        "severity": "MEDIUM",
        "description": "The server hostname or IP address does not match any entry in the Subject Alternative Name (SAN) extension, or SAN is missing.",
        "remediation": "Reissue certificate ensuring all server FQDNs and IP addresses are included in the Subject Alternative Name (SAN) extension.",
        "default_confidence": 0.85,
    },
    {
        "id": "RULE-AUTH-001",
        "name": "Cleartext Credential Transmission over Unencrypted Channel",
        "category": "PROTOCOL_BEHAVIOR",
        "severity": "CRITICAL",
        "description": "User authentication credentials (passwords, AUTH LOGIN, AUTH PLAIN, USER/PASS) were observed in cleartext over non-TLS connections.",
        "remediation": "Enforce TLS encryption prior to allowing authentication commands. Disable plain authentication over cleartext ports 25, 110, 143.",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-AUTH-002",
        "name": "Insecure Authentication Mechanisms Offered Without TLS",
        "category": "PROTOCOL_BEHAVIOR",
        "severity": "HIGH",
        "description": "Mail server advertised plain/login authentication mechanisms on an unencrypted TCP stream.",
        "remediation": "Configure mail servers to advertise AUTH only after STARTTLS or implicit TLS is established.",
        "default_confidence": 0.95,
    },
    {
        "id": "RULE-STARTTLS-001",
        "name": "STARTTLS Advertised But Not Negotiated (Plaintext Fallback)",
        "category": "STARTTLS",
        "severity": "HIGH",
        "description": "The server advertised STARTTLS capability, but the client opted not to issue STARTTLS and continued in cleartext.",
        "remediation": "Configure mail clients and MTA peers to enforce mandatory TLS (Opportunistic TLS upgrade -> Strict TLS enforcement).",
        "default_confidence": 0.9,
    },
    {
        "id": "RULE-STARTTLS-002",
        "name": "STARTTLS Stripping Risk (Plaintext Auth After Failed STARTTLS)",
        "category": "STARTTLS",
        "severity": "CRITICAL",
        "description": "STARTTLS command failed or was stripped by a Man-in-the-Middle (MitM) actor, followed by cleartext email or credential transmission.",
        "remediation": "Enable MTA-STS (RFC 8461) and DANE TLSA (RFC 6698) to enforce TLS negotiation and reject cleartext downgrades.",
        "default_confidence": 0.95,
    },
    {
        "id": "RULE-STARTTLS-003",
        "name": "STARTTLS Command Execution Failed / Rejected",
        "category": "STARTTLS",
        "severity": "MEDIUM",
        "description": "The STARTTLS command resulted in a server error response (e.g. 454 TLS not available, 554 transaction failed).",
        "remediation": "Check server TLS configuration, certificate permissions, and crypto library initialization on the mail server.",
        "default_confidence": 1.0,
    },
    {
        "id": "RULE-EVIDENCE-001",
        "name": "Insufficient Evidence for TLS Assessment",
        "category": "EVIDENCE",
        "severity": "INFO",
        "description": "Email protocol session was observed, but TLS handshake evidence was missing or incomplete in the passive packet capture.",
        "remediation": "Ensure packet capture includes initial connection setup and complete handshake packet ranges.",
        "default_confidence": 0.7,
    }
]


def load_rules_definitions(filepath: Optional[str] = None) -> List[CryptoRuleDefinition]:
    """
    Loads rule definitions from YAML file or internal fallback list.
    """
    target_path = filepath or DEFAULT_RULES_FILE
    raw_rules = []

    if os.path.exists(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                if yaml is not None:
                    data = yaml.safe_load(f)
                    if isinstance(data, dict) and "rules" in data:
                        raw_rules = data["rules"]
                else:
                    logger.warning("PyYAML not installed, falling back to internal rules list.")
        except Exception as e:
            logger.error(f"Error reading rules YAML file {target_path}: {e}")

    if not raw_rules:
        raw_rules = FALLBACK_RULES

    rules = []
    for item in raw_rules:
        try:
            rule_def = CryptoRuleDefinition(
                id=item["id"],
                name=item["name"],
                category=item["category"],
                severity=item["severity"],
                description=item["description"],
                remediation=item["remediation"],
                default_confidence=item.get("default_confidence", 1.0),
            )
            rules.append(rule_def)
        except Exception as err:
            logger.warning(f"Failed to parse rule definition {item.get('id')}: {err}")

    return rules


class CryptographicRulesEngine:
    """
    Evaluator engine for Stage 09 Cryptographic Rules.
    Scans passive job analysis models and outputs structured findings.
    """

    def __init__(self, rules_filepath: Optional[str] = None):
        self.rules_filepath = rules_filepath
        self.rules = load_rules_definitions(rules_filepath)
        self.rules_map = {r.id: r for r in self.rules}

    def list_rules(self) -> List[CryptoRuleDefinition]:
        """Return all loaded rule definitions."""
        return self.rules

    def evaluate_job(
        self,
        db: Session,
        job_id: str,
        force_reevaluate: bool = False,
        custom_rules: Optional[List[CryptoRuleDefinition]] = None
    ) -> Tuple[JobFindingsSummary, List[CryptoRuleResult]]:
        """
        Evaluates cryptographic rules against an AnalysisJob and persists results.
        """
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job {job_id} not found")

        # If existing findings exist and force_reevaluate is False, return existing
        existing_findings = (
            db.query(CryptoRuleResult)
            .filter(CryptoRuleResult.job_id == job_id)
            .order_by(CryptoRuleResult.created_at.asc())
            .all()
        )

        if existing_findings and not force_reevaluate:
            summary = self._build_summary(job_id, existing_findings)
            return summary, existing_findings

        # Clear existing findings if re-evaluating
        if force_reevaluate:
            db.query(CryptoRuleResult).filter(CryptoRuleResult.job_id == job_id).delete()
            db.commit()

        # Merge active rules
        active_rules_map = dict(self.rules_map)
        if custom_rules:
            for cr in custom_rules:
                active_rules_map[cr.id] = cr

        # Query stage artifacts
        tls_handshakes = (
            db.query(TlsHandshakeAnalysis)
            .filter(TlsHandshakeAnalysis.job_id == job_id)
            .all()
        )
        certificates = (
            db.query(X509CertificateAnalysis)
            .filter(X509CertificateAnalysis.job_id == job_id)
            .all()
        )
        starttls_analyses = (
            db.query(StarttlsAnalysis)
            .filter(StarttlsAnalysis.job_id == job_id)
            .all()
        )
        email_sessions = (
            db.query(EmailSessionAnalysis)
            .filter(EmailSessionAnalysis.job_id == job_id)
            .all()
        )
        tcp_sessions = (
            db.query(TcpSession)
            .filter(TcpSession.job_id == job_id)
            .all()
        )

        session_by_stream = {s.tcp_stream: s for s in tcp_sessions}
        tls_streams = {h.tcp_stream for h in tls_handshakes}
        stts_streams = {s.tcp_stream for s in starttls_analyses}
        findings: List[CryptoRuleResult] = []
        dedup_keys = set()

        # -----------------------------------------------------------------
        # 1. Evaluate TLS Handshake Rules (Protocol Version & Cipher Suite)
        # -----------------------------------------------------------------
        for handshake in tls_handshakes:
            stream_id = handshake.tcp_stream
            session = session_by_stream.get(stream_id)
            session_db_id = session.id if session else handshake.tcp_session_id

            version = handshake.negotiated_version or "UNKNOWN"
            client_ver = handshake.client_hello_version or ""
            server_ver = handshake.server_hello_version or ""

            # Check RULE-TLS-001 (SSLv2 / SSLv3)
            if any(v in ["SSLv2", "SSLv3"] for v in [version, client_ver, server_ver]):
                rule = active_rules_map.get("RULE-TLS-001")
                if rule:
                    key = (job_id, rule.id, stream_id, "SSLv2_SSLv3")
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Observed obsolete protocol version '{version}' (Client Hello: '{client_ver}', Server Hello: '{server_ver}') on TCP stream {stream_id}.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "protocol": handshake.protocol,
                                "negotiated_version": version,
                                "client_hello_version": client_ver,
                                "server_hello_version": server_ver,
                                "client_hello_frame": handshake.client_hello_frame,
                                "server_hello_frame": handshake.server_hello_frame,
                                "client_ip": handshake.client_ip,
                                "server_ip": handshake.server_ip,
                            },
                            remediation=rule.remediation
                        ))

            # Check RULE-TLS-002 (TLS 1.0 / TLS 1.1)
            elif any(v in ["TLS 1.0", "TLS 1.1"] for v in [version, client_ver, server_ver]):
                rule = active_rules_map.get("RULE-TLS-002")
                if rule:
                    key = (job_id, rule.id, stream_id, "TLS10_TLS11")
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Observed deprecated protocol version '{version}' on TCP stream {stream_id}.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "protocol": handshake.protocol,
                                "negotiated_version": version,
                                "client_hello_version": client_ver,
                                "server_hello_version": server_ver,
                                "client_hello_frame": handshake.client_hello_frame,
                                "server_hello_frame": handshake.server_hello_frame,
                            },
                            remediation=rule.remediation
                        ))

            # Check Cipher Suite Rules
            cipher = handshake.negotiated_cipher_suite or "UNKNOWN"
            cipher_upper = cipher.upper()

            # Check RULE-CIPHER-001 (Insecure Ciphers: NULL, anon, EXPORT, DES, RC4, 3DES)
            insecure_keywords = ["NULL", "ANON", "EXPORT", "DES", "RC4", "3DES"]
            if any(kw in cipher_upper for kw in insecure_keywords) and cipher_upper != "UNKNOWN":
                rule = active_rules_map.get("RULE-CIPHER-001")
                if rule:
                    key = (job_id, rule.id, stream_id, cipher)
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Negotiated insecure cipher suite '{cipher}' on TCP stream {stream_id}.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "protocol": handshake.protocol,
                                "negotiated_cipher_suite": cipher,
                                "negotiated_cipher_id": handshake.negotiated_cipher_id,
                                "server_hello_frame": handshake.server_hello_frame,
                            },
                            remediation=rule.remediation
                        ))

            # Check RULE-CIPHER-002 (Weak Ciphers: MD5, SHA1 MAC, CBC mode, non-PFS RSA)
            weak_mac_cbc_pfs = (
                ("MD5" in cipher_upper or "SHA" in cipher_upper and not any(k in cipher_upper for k in ["SHA256", "SHA384", "SHA512"])) or
                ("CBC" in cipher_upper) or
                (cipher_upper.startswith("TLS_RSA_WITH_") and not any(k in cipher_upper for k in ["ECDHE", "DHE"]))
            )
            if weak_mac_cbc_pfs and cipher_upper != "UNKNOWN" and not any(kw in cipher_upper for kw in insecure_keywords):
                rule = active_rules_map.get("RULE-CIPHER-002")
                if rule:
                    key = (job_id, rule.id, stream_id, cipher)
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Negotiated weak cipher suite '{cipher}' (CBC mode / weak MAC / non-PFS RSA key exchange) on TCP stream {stream_id}.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "protocol": handshake.protocol,
                                "negotiated_cipher_suite": cipher,
                                "key_exchange_group": handshake.key_exchange_group,
                                "signature_scheme": handshake.signature_scheme,
                                "server_hello_frame": handshake.server_hello_frame,
                            },
                            remediation=rule.remediation
                        ))

        # -----------------------------------------------------------------
        # 2. Evaluate Certificate Rules
        # -----------------------------------------------------------------
        for cert in certificates:
            stream_id = cert.tcp_stream
            session = session_by_stream.get(stream_id)
            session_db_id = session.id if session else cert.tcp_session_id
            fp = cert.fingerprint_sha256 or str(cert.id)

            # RULE-CERT-001: Expired Certificate
            if cert.validity_status == "EXPIRED":
                rule = active_rules_map.get("RULE-CERT-001")
                if rule:
                    key = (job_id, rule.id, stream_id, fp)
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Certificate for '{cert.subject_cn or cert.subject_dn}' expired on {cert.not_after}.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "subject": cert.subject_dn,
                                "issuer": cert.issuer_dn,
                                "not_after": cert.not_after.isoformat() if cert.not_after else None,
                                "days_until_expiration": cert.days_until_expiration,
                                "fingerprint_sha256": fp,
                            },
                            remediation=rule.remediation
                        ))

            # RULE-CERT-002: Not Yet Valid Certificate
            if cert.validity_status == "NOT_YET_VALID":
                rule = active_rules_map.get("RULE-CERT-002")
                if rule:
                    key = (job_id, rule.id, stream_id, fp)
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Certificate for '{cert.subject_cn or cert.subject_dn}' is not valid until {cert.not_before}.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "subject": cert.subject_dn,
                                "issuer": cert.issuer_dn,
                                "not_before": cert.not_before.isoformat() if cert.not_before else None,
                                "fingerprint_sha256": fp,
                            },
                            remediation=rule.remediation
                        ))

            # RULE-CERT-003: Self-Signed Certificate
            if cert.is_self_signed:
                rule = active_rules_map.get("RULE-CERT-003")
                if rule:
                    key = (job_id, rule.id, stream_id, fp)
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Certificate for '{cert.subject_cn or cert.subject_dn}' is self-signed.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "subject": cert.subject_dn,
                                "issuer": cert.issuer_dn,
                                "fingerprint_sha256": fp,
                            },
                            remediation=rule.remediation
                        ))

            # RULE-CERT-004: Weak Signature Algorithm (MD5 / SHA-1)
            sig_algo = (cert.signature_algorithm or "").lower()
            sig_digest = (cert.signature_digest or "").upper()
            if sig_digest in ["MD5", "SHA-1"] or "md5" in sig_algo or "sha1" in sig_algo:
                rule = active_rules_map.get("RULE-CERT-004")
                if rule:
                    key = (job_id, rule.id, stream_id, fp)
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Certificate uses weak signature hash algorithm '{cert.signature_digest or cert.signature_algorithm}'.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "subject": cert.subject_dn,
                                "signature_algorithm": cert.signature_algorithm,
                                "signature_digest": cert.signature_digest,
                                "fingerprint_sha256": fp,
                            },
                            remediation=rule.remediation
                        ))

            # RULE-CERT-005: Weak RSA Key Length (< 2048)
            key_type = (cert.public_key_algorithm or "").upper()
            key_bits = cert.key_size_bits or 0
            if key_type == "RSA" and 0 < key_bits < 2048:
                rule = active_rules_map.get("RULE-CERT-005")
                if rule:
                    key = (job_id, rule.id, stream_id, fp)
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Certificate uses weak RSA public key length of {key_bits} bits (< 2048 bits).",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "subject": cert.subject_dn,
                                "key_type": cert.public_key_algorithm,
                                "key_size_bits": cert.key_size_bits,
                                "fingerprint_sha256": fp,
                            },
                            remediation=rule.remediation
                        ))

            # RULE-CERT-006: Weak EC Key Length (< 256)
            if key_type in ["EC", "ECDSA"] and 0 < key_bits < 256:
                rule = active_rules_map.get("RULE-CERT-006")
                if rule:
                    key = (job_id, rule.id, stream_id, fp)
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Certificate uses weak Elliptic Curve key length of {key_bits} bits (< 256 bits).",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "subject": cert.subject_dn,
                                "key_type": cert.public_key_algorithm,
                                "key_size_bits": cert.key_size_bits,
                                "fingerprint_sha256": fp,
                            },
                            remediation=rule.remediation
                        ))

            # RULE-CERT-007: SAN Mismatch or Missing SAN
            san_list = cert.sans or []
            san_count = len(san_list)
            if san_count == 0:
                rule = active_rules_map.get("RULE-CERT-007")
                if rule:
                    key = (job_id, rule.id, stream_id, fp)
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Certificate for '{cert.subject_cn or cert.subject_dn}' lacks Subject Alternative Name (SAN) entries.",
                            confidence=rule.default_confidence,
                            confidence_label="MEDIUM",
                            evidence={
                                "tcp_stream": stream_id,
                                "subject": cert.subject_dn,
                                "san_count": san_count,
                                "fingerprint_sha256": fp,
                            },
                            remediation=rule.remediation
                        ))

        # -----------------------------------------------------------------
        # 3. Evaluate Protocol & Authentication Behavior Rules
        # -----------------------------------------------------------------
        for email_sess in email_sessions:
            stream_id = email_sess.tcp_stream
            session = session_by_stream.get(stream_id)
            session_db_id = session.id if session else email_sess.tcp_session_id

            # Determine if session is encrypted via TLS or port
            is_enc = (
                stream_id in tls_streams or
                any(st.tcp_stream == stream_id and st.accepted for st in starttls_analyses) or
                email_sess.protocol in ["SMTPS", "IMAPS", "POP3S"] or
                email_sess.server_port in [465, 993, 995]
            )

            auth_attempted = getattr(email_sess, "auth_attempted", False)
            auth_mechs = getattr(email_sess, "auth_mechanisms", None) or []
            security_warns = getattr(email_sess, "security_warnings", None) or []
            has_cleartext = any("cleartext" in str(w).lower() for w in security_warns)

            # RULE-AUTH-001: Cleartext Credential Transmission
            if not is_enc and (has_cleartext or auth_attempted):
                rule = active_rules_map.get("RULE-AUTH-001")
                if rule:
                    key = (job_id, rule.id, stream_id, "CLEARTEXT_AUTH")
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Cleartext credentials / authentication commands observed on unencrypted {email_sess.protocol} stream {stream_id}.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "protocol": email_sess.protocol,
                                "auth_attempted": auth_attempted,
                                "auth_mechanisms": auth_mechs,
                                "commands_count": getattr(email_sess, "commands_count", 0),
                            },
                            remediation=rule.remediation
                        ))

            # RULE-AUTH-002: Insecure Auth Offered Without TLS
            if not is_enc and auth_mechs:
                if any(str(m).upper() in ["PLAIN", "LOGIN"] for m in auth_mechs):
                    rule = active_rules_map.get("RULE-AUTH-002")
                    if rule:
                        key = (job_id, rule.id, stream_id, "AUTH_OFFERED")
                        if key not in dedup_keys:
                            dedup_keys.add(key)
                            findings.append(CryptoRuleResult(
                                job_id=job_id,
                                tcp_session_id=session_db_id,
                                tcp_stream=stream_id,
                                rule_id=rule.id,
                                name=rule.name,
                                category=rule.category,
                                severity=rule.severity,
                                reason=f"Insecure plain/login authentication mechanisms {auth_mechs} offered without TLS encryption on {email_sess.protocol} stream {stream_id}.",
                                confidence=rule.default_confidence,
                                confidence_label="HIGH",
                                evidence={
                                    "tcp_stream": stream_id,
                                    "protocol": email_sess.protocol,
                                    "auth_mechanisms": auth_mechs,
                                },
                                remediation=rule.remediation
                            ))

        # -----------------------------------------------------------------
        # 4. Evaluate STARTTLS Behavior Rules
        # -----------------------------------------------------------------
        for stts in starttls_analyses:
            stream_id = stts.tcp_stream
            session = session_by_stream.get(stream_id)
            session_db_id = session.id if session else stts.tcp_session_id
            status = stts.upgrade_status or "UNKNOWN"

            # RULE-STARTTLS-001: STARTTLS Advertised But Not Negotiated
            if stts.advertised and not stts.accepted and status != "STRIPPING_DETECTED":
                rule = active_rules_map.get("RULE-STARTTLS-001")
                if rule:
                    key = (job_id, rule.id, stream_id, "STARTTLS_NOT_NEGOTIATED")
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Server advertised STARTTLS on {stts.protocol} stream {stream_id}, but client did not negotiate TLS (plaintext fallback).",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "protocol": stts.protocol,
                                "advertised": stts.advertised,
                                "accepted": stts.accepted,
                                "upgrade_status": status,
                                "advertised_frame": stts.advertised_frame,
                            },
                            remediation=rule.remediation
                        ))

            # RULE-STARTTLS-002: STARTTLS Stripping Risk
            if status in ["STRIPPING_DETECTED", "PLAIN_FALLBACK_AFTER_FAILURE", "NOT_REQUESTED_IGNORED", "CLEARTEXT_AUTH_AFTER_ADVERTISED"] or stts.cleartext_auth_observed:
                rule = active_rules_map.get("RULE-STARTTLS-002")
                if rule:
                    key = (job_id, rule.id, stream_id, "STARTTLS_STRIPPING")
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"STARTTLS stripping or plaintext fallback risk detected on {stts.protocol} stream {stream_id} (Status: {status}).",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "protocol": stts.protocol,
                                "upgrade_status": status,
                                "cleartext_auth_observed": stts.cleartext_auth_observed,
                                "requested_frame": stts.requested_frame,
                                "response_frame": stts.response_frame,
                            },
                            remediation=rule.remediation
                        ))

            # RULE-STARTTLS-003: STARTTLS Execution Failed
            if status == "UPGRADE_REJECTED" or (stts.response_code and str(stts.response_code).startswith(("4", "5"))):
                rule = active_rules_map.get("RULE-STARTTLS-003")
                if rule:
                    key = (job_id, rule.id, stream_id, "STARTTLS_FAILED")
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_db_id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"STARTTLS command failed with response '{stts.response_code} {stts.response_text}' on stream {stream_id}.",
                            confidence=rule.default_confidence,
                            confidence_label="HIGH",
                            evidence={
                                "tcp_stream": stream_id,
                                "protocol": stts.protocol,
                                "response_code": stts.response_code,
                                "response_text": stts.response_text,
                                "response_frame": stts.response_frame,
                            },
                            remediation=rule.remediation
                        ))

        # -----------------------------------------------------------------
        # 5. Evaluate Evidence & Missing Facts Rule
        # -----------------------------------------------------------------
        for email_sess in email_sessions:
            stream_id = email_sess.tcp_stream
            is_unenc = (
                stream_id not in tls_streams and
                stream_id not in stts_streams and
                email_sess.protocol not in ["SMTPS", "IMAPS", "POP3S"] and
                email_sess.server_port not in [465, 993, 995]
            )
            if is_unenc:
                rule = active_rules_map.get("RULE-EVIDENCE-001")
                if rule:
                    key = (job_id, rule.id, stream_id, "MISSING_TLS_EVIDENCE")
                    if key not in dedup_keys:
                        dedup_keys.add(key)
                        findings.append(CryptoRuleResult(
                            job_id=job_id,
                            tcp_session_id=session_by_stream.get(stream_id, email_sess).id,
                            tcp_stream=stream_id,
                            rule_id=rule.id,
                            name=rule.name,
                            category=rule.category,
                            severity=rule.severity,
                            reason=f"Email protocol stream {stream_id} ({email_sess.protocol}) was observed in cleartext without TLS handshake or STARTTLS exchange.",
                            confidence=rule.default_confidence,
                            confidence_label="MEDIUM",
                            evidence={
                                "tcp_stream": stream_id,
                                "protocol": email_sess.protocol,
                                "is_encrypted": False,
                                "tls_handshake_observed": False,
                                "starttls_observed": False,
                            },
                            remediation=rule.remediation
                        ))

        # Persist findings to database
        db.add_all(findings)
        db.commit()

        # Build and return summary
        summary = self._build_summary(job_id, findings)
        return summary, findings

    def _build_summary(
        self, job_id: str, findings: List[CryptoRuleResult]
    ) -> JobFindingsSummary:
        """Helper to construct JobFindingsSummary from a list of findings."""
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in findings if f.severity == "LOW")
        info_count = sum(1 for f in findings if f.severity == "INFO")

        category_counts: Dict[str, int] = {}
        unique_rules = set()

        for f in findings:
            category_counts[f.category] = category_counts.get(f.category, 0) + 1
            unique_rules.add(f.rule_id)

        return JobFindingsSummary(
            job_id=job_id,
            total_findings=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            category_counts=category_counts,
            rules_triggered_count=len(unique_rules),
            evaluated_at=datetime.now(timezone.utc),
        )
