"""
Curated Test PCAP Suite Definitions & Binary Generators (Stage 24).
Provides 8 deterministic regression scenarios with expected findings, rules, evidence status,
and posture outcomes for secure, weak, expired, cleartext, truncated, and anomalous email PCAP traffic.
"""

import struct
from typing import Dict, List, Any, Optional
from pydantic import BaseModel


class ExpectedOutcome(BaseModel):
    expected_mail_protocols: List[str]
    expected_tls_versions: List[str]
    expected_rule_ids: List[str]
    expected_severity_counts: Dict[str, int]
    expected_posture_range: List[float]  # [min_score, max_score]
    expected_evidence_status: str  # COMPLETE_EVIDENCE, PARTIAL_EVIDENCE, INSUFFICIENT_EVIDENCE
    is_anomaly_expected: bool


class PcapSuiteScenario(BaseModel):
    scenario_id: str
    name: str
    description: str
    category: str  # SECURE, WEAK_CRYPTO, EXPIRED_CERT, CLEAR_AUTH, INCOMPLETE, MIXED, ANOMALY
    expected_outcome: ExpectedOutcome


# -----------------------------------------------------------------------------
# Curated Scenario Catalog
# -----------------------------------------------------------------------------

CURATED_PCAP_SUITE: Dict[str, PcapSuiteScenario] = {
    "SECURE_TLS13_SMTP": PcapSuiteScenario(
        scenario_id="SECURE_TLS13_SMTP",
        name="Hardened SMTP over TLS 1.3",
        description="Clean, secure SMTP session with valid TLS 1.3 handshake, strong cipher suite (TLS_AES_256_GCM_SHA384), and valid X.509 server certificate.",
        category="SECURE",
        expected_outcome=ExpectedOutcome(
            expected_mail_protocols=["SMTP"],
            expected_tls_versions=["TLS 1.3"],
            expected_rule_ids=[],
            expected_severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            expected_posture_range=[90.0, 100.0],
            expected_evidence_status="COMPLETE_EVIDENCE",
            is_anomaly_expected=False
        )
    ),
    "WEAK_TLS10_IMAP": PcapSuiteScenario(
        scenario_id="WEAK_TLS10_IMAP",
        name="Deprecated TLS 1.0 IMAP Traffic",
        description="IMAP email session utilizing deprecated, vulnerable TLS 1.0 protocol version.",
        category="WEAK_CRYPTO",
        expected_outcome=ExpectedOutcome(
            expected_mail_protocols=["IMAP"],
            expected_tls_versions=["TLS 1.0"],
            expected_rule_ids=["RULE_DEPRECATED_TLS_10"],
            expected_severity_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
            expected_posture_range=[40.0, 70.0],
            expected_evidence_status="COMPLETE_EVIDENCE",
            is_anomaly_expected=False
        )
    ),
    "EXPIRED_CERTIFICATE_POP3": PcapSuiteScenario(
        scenario_id="EXPIRED_CERTIFICATE_POP3",
        name="POP3 Session with Expired X.509 Certificate",
        description="POP3 TLS session presenting an expired server certificate during handshake.",
        category="EXPIRED_CERT",
        expected_outcome=ExpectedOutcome(
            expected_mail_protocols=["POP3"],
            expected_tls_versions=["TLS 1.2"],
            expected_rule_ids=["RULE_EXPIRED_CERTIFICATE"],
            expected_severity_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
            expected_posture_range=[30.0, 65.0],
            expected_evidence_status="COMPLETE_EVIDENCE",
            is_anomaly_expected=False
        )
    ),
    "WEAK_CIPHER_RC4_SMTP": PcapSuiteScenario(
        scenario_id="WEAK_CIPHER_RC4_SMTP",
        name="Weak RC4/DES Cipher Suite Negotiation",
        description="SMTP TLS handshake negotiating deprecated TLS_RSA_WITH_RC4_128_SHA cipher suite.",
        category="WEAK_CRYPTO",
        expected_outcome=ExpectedOutcome(
            expected_mail_protocols=["SMTP"],
            expected_tls_versions=["TLS 1.2"],
            expected_rule_ids=["RULE_WEAK_CIPHER_SUITE"],
            expected_severity_counts={"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
            expected_posture_range=[35.0, 70.0],
            expected_evidence_status="COMPLETE_EVIDENCE",
            is_anomaly_expected=False
        )
    ),
    "STARTTLS_CLEAR_AUTH_FAILURE": PcapSuiteScenario(
        scenario_id="STARTTLS_CLEAR_AUTH_FAILURE",
        name="STARTTLS Downgrade & Plaintext Auth Leak",
        description="SMTP session advertising STARTTLS, but client transmits plaintext AUTH PLAIN prior to completing TLS upgrade.",
        category="CLEAR_AUTH",
        expected_outcome=ExpectedOutcome(
            expected_mail_protocols=["SMTP"],
            expected_tls_versions=["NONE"],
            expected_rule_ids=["RULE_STARTTLS_CLEARTEXT_AUTH"],
            expected_severity_counts={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            expected_posture_range=[0.0, 30.0],
            expected_evidence_status="COMPLETE_EVIDENCE",
            is_anomaly_expected=True
        )
    ),
    "INCOMPLETE_EVIDENCE_TRUNCATED": PcapSuiteScenario(
        scenario_id="INCOMPLETE_EVIDENCE_TRUNCATED",
        name="Truncated Stream with Incomplete Evidence",
        description="Partial PCAP capture missing TCP SYN or TLS Client Hello frames, testing zero-hallucination handling.",
        category="INCOMPLETE",
        expected_outcome=ExpectedOutcome(
            expected_mail_protocols=["UNKNOWN"],
            expected_tls_versions=["UNKNOWN"],
            expected_rule_ids=[],
            expected_severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            expected_posture_range=[50.0, 100.0],
            expected_evidence_status="INSUFFICIENT_EVIDENCE",
            is_anomaly_expected=False
        )
    ),
    "MIXED_SESSIONS_MULTI_PROTOCOL": PcapSuiteScenario(
        scenario_id="MIXED_SESSIONS_MULTI_PROTOCOL",
        name="Multi-Protocol Mixed Environment Capture",
        description="Complex capture with parallel SMTP (TLS 1.3), IMAP (TLS 1.0), and POP3 (expired cert) sessions.",
        category="MIXED",
        expected_outcome=ExpectedOutcome(
            expected_mail_protocols=["SMTP", "IMAP", "POP3"],
            expected_tls_versions=["TLS 1.3", "TLS 1.0", "TLS 1.2"],
            expected_rule_ids=["RULE_DEPRECATED_TLS_10", "RULE_EXPIRED_CERTIFICATE"],
            expected_severity_counts={"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0},
            expected_posture_range=[30.0, 60.0],
            expected_evidence_status="COMPLETE_EVIDENCE",
            is_anomaly_expected=True
        )
    ),
    "TLS_ANOMALOUS_MUTATION": PcapSuiteScenario(
        scenario_id="TLS_ANOMALOUS_MUTATION",
        name="Anomalous TLS Handshake Mutation Storm",
        description="Session exhibiting unexpected burst mutation, malformed extensions, and high alert frequency.",
        category="ANOMALY",
        expected_outcome=ExpectedOutcome(
            expected_mail_protocols=["SMTP"],
            expected_tls_versions=["TLS 1.2"],
            expected_rule_ids=[],
            expected_severity_counts={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            expected_posture_range=[40.0, 80.0],
            expected_evidence_status="PARTIAL_EVIDENCE",
            is_anomaly_expected=True
        )
    ),
}


def generate_scenario_pcap_bytes(scenario_id: str) -> bytes:
    """
    Generates deterministic PCAP file binary content for the specified scenario.
    Constructs PCAP global header (24 bytes) and sample packet records.
    """
    # Standard PCAP Global Header: Magic 0xa1b2c3d4, v2.4, tz 0, flags 0, snaplen 65535, network 1 (Ethernet)
    pcap_global_header = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    
    # Deterministic dummy packet payloads per scenario ID
    dummy_payload = f"SecureMailScope Test PCAP Suite Scenario: {scenario_id}\r\n".encode('utf-8')
    packet_len = len(dummy_payload)
    
    # Packet Record Header: ts_sec (4B), ts_usec (4B), incl_len (4B), orig_len (4B)
    packet_header = struct.pack('<IIII', 1700000000, 100000, packet_len, packet_len)
    
    return pcap_global_header + packet_header + dummy_payload
