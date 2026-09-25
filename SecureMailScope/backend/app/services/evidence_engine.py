"""
Evidence Engine Service for Stage 11: Traceability, Evidence Chain & Missing Fact Verification.
Links Finding -> Rule -> TCP Session -> Packet Range -> Observed Protocol/TLS/Certificate Field -> Rule.
Ensures missing source evidence becomes INSUFFICIENT_EVIDENCE / PARTIAL_EVIDENCE rather than invented facts.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.packet import PacketMetadata
from app.models.session import TcpSession
from app.models.email_analysis import EmailSessionAnalysis
from app.models.starttls import StarttlsAnalysis
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.certificate import X509CertificateAnalysis
from app.models.rule_result import CryptoRuleResult
from app.models.finding import UnifiedFinding
from app.schemas.evidence import (
    PacketEvidenceItem,
    FieldEvidenceItem,
    ForensicEvidenceChain,
    JobEvidenceSummaryResponse,
)

logger = logging.getLogger(__name__)


class EvidenceEngine:
    """
    Forensic Evidence Engine responsible for assembling complete, verifiable evidence chains
    and guaranteeing evidence-first integrity without fact fabrication.
    """

    def build_finding_evidence_chain(
        self,
        db: Session,
        finding_id: str
    ) -> ForensicEvidenceChain:
        """
        Assembles a full evidence chain linking Finding -> Rule -> Session -> Packet Range -> Observed Fields.
        """
        finding = db.query(UnifiedFinding).filter(UnifiedFinding.id == finding_id).first()
        if not finding:
            raise ValueError(f"UnifiedFinding with ID '{finding_id}' not found")

        job_id = finding.job_id
        tcp_stream = finding.tcp_stream
        tcp_session_id = finding.tcp_session_id

        # 1. Fetch Session Evidence
        session: Optional[TcpSession] = None
        if tcp_session_id:
            session = db.query(TcpSession).filter(TcpSession.id == tcp_session_id).first()
        elif tcp_stream is not None:
            session = (
                db.query(TcpSession)
                .filter(TcpSession.job_id == job_id, TcpSession.tcp_stream == tcp_stream)
                .first()
            )

        session_evidence_dict: Optional[Dict[str, Any]] = None
        if session:
            session_evidence_dict = {
                "session_id": session.id,
                "tcp_stream": session.tcp_stream,
                "client_ip": session.client_ip,
                "server_ip": session.server_ip,
                "client_port": session.client_port,
                "server_port": session.server_port,
                "protocol": session.protocol,
                "start_time": session.start_time,
                "end_time": session.end_time,
                "first_frame_number": session.first_frame_number,
                "last_frame_number": session.last_frame_number,
            }

        # 2. Fetch Packet Range and Sample Packets
        packet_range_dict: Optional[Dict[str, Any]] = None
        sample_packets: List[PacketEvidenceItem] = []

        if tcp_stream is not None:
            packets = (
                db.query(PacketMetadata)
                .filter(PacketMetadata.job_id == job_id, PacketMetadata.tcp_stream == tcp_stream)
                .order_by(PacketMetadata.frame_number.asc())
                .all()
            )
            total_pkts = len(packets)
            if total_pkts > 0:
                first_pkt = packets[0]
                last_pkt = packets[-1]

                packet_range_dict = {
                    "first_frame": first_pkt.frame_number,
                    "last_frame": last_pkt.frame_number,
                    "total_packets_in_stream": total_pkts,
                    "stream_id": tcp_stream
                }

                # Sample up to 10 packet frames
                for p in packets[:10]:
                    sample_packets.append(
                        PacketEvidenceItem(
                            frame_number=p.frame_number,
                            timestamp=p.timestamp,
                            src_ip=p.src_ip or "0.0.0.0",
                            dst_ip=p.dst_ip or "0.0.0.0",
                            src_port=p.src_port or 0,
                            dst_port=p.dst_port or 0,
                            detected_protocol=p.detected_protocol,
                            length_bytes=p.frame_length,
                            summary=p.payload_preview or f"{p.transport_protocol} frame #{p.frame_number}"
                        )
                    )

        # 3. Assemble Field Observations and Track Missing Facts
        field_evidence: List[FieldEvidenceItem] = []
        missing_reasons: List[str] = []

        # Add initial rule result / finding references as fields
        if finding.rule_id:
            field_evidence.append(
                FieldEvidenceItem(
                    field_name="rule_id",
                    observed_value=finding.rule_id,
                    is_present=True,
                    source_stage="CRYPTO_RULES",
                    description="Triggered cryptographic or behavioral rule definition ID"
                )
            )

        if finding.fingerprint:
            field_evidence.append(
                FieldEvidenceItem(
                    field_name="finding_fingerprint",
                    observed_value=finding.fingerprint,
                    is_present=True,
                    source_stage="FINDINGS_MODEL",
                    description="SHA-256 deterministic finding fingerprint"
                )
            )

        # Retrieve specific stage artifacts for the stream
        tls_handshake: Optional[TlsHandshakeAnalysis] = None
        cert_analysis: Optional[X509CertificateAnalysis] = None
        starttls_analysis: Optional[StarttlsAnalysis] = None
        email_analysis: Optional[EmailSessionAnalysis] = None

        if tcp_stream is not None:
            tls_handshake = (
                db.query(TlsHandshakeAnalysis)
                .filter(TlsHandshakeAnalysis.job_id == job_id, TlsHandshakeAnalysis.tcp_stream == tcp_stream)
                .first()
            )
            cert_analysis = (
                db.query(X509CertificateAnalysis)
                .filter(X509CertificateAnalysis.job_id == job_id, X509CertificateAnalysis.tcp_stream == tcp_stream)
                .first()
            )
            starttls_analysis = (
                db.query(StarttlsAnalysis)
                .filter(StarttlsAnalysis.job_id == job_id, StarttlsAnalysis.tcp_stream == tcp_stream)
                .first()
            )
            email_analysis = (
                db.query(EmailSessionAnalysis)
                .filter(EmailSessionAnalysis.job_id == job_id, EmailSessionAnalysis.tcp_stream == tcp_stream)
                .first()
            )

        # TLS Handshake Evidence Inspection
        if tls_handshake:
            field_evidence.extend([
                FieldEvidenceItem(
                    field_name="tls_version",
                    observed_value=tls_handshake.negotiated_version,
                    is_present=bool(tls_handshake.negotiated_version and tls_handshake.negotiated_version != "UNKNOWN"),
                    source_stage="TLS_HANDSHAKE",
                    description="Negotiated TLS Protocol Version"
                ),
                FieldEvidenceItem(
                    field_name="cipher_suite_name",
                    observed_value=tls_handshake.negotiated_cipher_suite,
                    is_present=bool(tls_handshake.negotiated_cipher_suite and tls_handshake.negotiated_cipher_suite != "UNKNOWN"),
                    source_stage="TLS_HANDSHAKE",
                    description="Negotiated Cipher Suite"
                ),
                FieldEvidenceItem(
                    field_name="key_exchange_group",
                    observed_value=tls_handshake.key_exchange_group,
                    is_present=bool(tls_handshake.key_exchange_group and tls_handshake.key_exchange_group != "UNKNOWN"),
                    source_stage="TLS_HANDSHAKE",
                    description="Key Exchange Group"
                )
            ])
        else:
            missing_reasons.append("No TLS Handshake record observed in network capture for this stream")

        # Certificate Evidence Inspection
        if cert_analysis:
            field_evidence.extend([
                FieldEvidenceItem(
                    field_name="cert_subject",
                    observed_value=cert_analysis.subject_dn,
                    is_present=bool(cert_analysis.subject_dn),
                    source_stage="X509_CERT",
                    description="X.509 Certificate Subject DN"
                ),
                FieldEvidenceItem(
                    field_name="cert_validity_status",
                    observed_value=cert_analysis.validity_status,
                    is_present=bool(cert_analysis.validity_status),
                    source_stage="X509_CERT",
                    description="Certificate Temporal Validity Status"
                ),
                FieldEvidenceItem(
                    field_name="cert_is_self_signed",
                    observed_value=cert_analysis.is_self_signed,
                    is_present=cert_analysis.is_self_signed is not None,
                    source_stage="X509_CERT",
                    description="Self-Signed Root/Leaf Flag"
                )
            ])
        elif finding.finding_type == "CERTIFICATE_FORENSIC":
            missing_reasons.append("No X.509 Certificate record observable in handshake traffic")

        # STARTTLS Evidence Inspection
        if starttls_analysis:
            field_evidence.extend([
                FieldEvidenceItem(
                    field_name="starttls_advertised",
                    observed_value=starttls_analysis.advertised,
                    is_present=starttls_analysis.advertised is not None,
                    source_stage="STARTTLS",
                    description="STARTTLS Feature Advertised by Server"
                ),
                FieldEvidenceItem(
                    field_name="starttls_accepted",
                    observed_value=starttls_analysis.accepted,
                    is_present=starttls_analysis.accepted is not None,
                    source_stage="STARTTLS",
                    description="STARTTLS Command Accepted by Server"
                ),
                FieldEvidenceItem(
                    field_name="upgrade_status",
                    observed_value=starttls_analysis.upgrade_status,
                    is_present=bool(starttls_analysis.upgrade_status),
                    source_stage="STARTTLS",
                    description="TLS Upgrade Execution State"
                )
            ])
        elif finding.finding_type == "STARTTLS_INTEGRITY":
            missing_reasons.append("No STARTTLS negotiation frames present in traffic")

        # Email Session Evidence Inspection
        if email_analysis:
            field_evidence.extend([
                FieldEvidenceItem(
                    field_name="email_protocol",
                    observed_value=email_analysis.protocol,
                    is_present=bool(email_analysis.protocol),
                    source_stage="EMAIL_ANALYSIS",
                    description="Detected Email Application Protocol"
                ),
                FieldEvidenceItem(
                    field_name="auth_attempted",
                    observed_value=email_analysis.auth_attempted,
                    is_present=email_analysis.auth_attempted is not None,
                    source_stage="EMAIL_ANALYSIS",
                    description="Authentication Command Attempted Flag"
                )
            ])

        # Evaluate Evidence Status Completeness
        evidence_status = "COMPLETE_EVIDENCE"
        if len(missing_reasons) > 0 and len(field_evidence) == 0:
            evidence_status = "INSUFFICIENT_EVIDENCE"
        elif len(missing_reasons) > 0:
            evidence_status = "PARTIAL_EVIDENCE"
        elif finding.severity == "INFO" and "EVIDENCE" in (finding.rule_id or ""):
            evidence_status = "INSUFFICIENT_EVIDENCE"

        # Construct Provenance Metadata
        provenance = {
            "finding_id": finding.id,
            "rule_id": finding.rule_id,
            "fingerprint": finding.fingerprint,
            "session_id": session.id if session else None,
            "tcp_stream": tcp_stream,
            "has_tls_handshake": tls_handshake is not None,
            "has_certificate": cert_analysis is not None,
            "has_starttls": starttls_analysis is not None,
            "has_email_analysis": email_analysis is not None,
            "total_sample_packets": len(sample_packets),
            "total_field_observations": len(field_evidence)
        }

        return ForensicEvidenceChain(
            finding_id=finding.id,
            job_id=job_id,
            tcp_session_id=tcp_session_id,
            tcp_stream=tcp_stream,
            rule_id=finding.rule_id,
            finding_title=finding.title,
            finding_type=finding.finding_type,
            severity=finding.severity,
            confidence=finding.confidence,
            confidence_label=finding.confidence_label,
            evidence_status=evidence_status,
            session_evidence=session_evidence_dict,
            packet_range=packet_range_dict,
            sample_packets=sample_packets,
            field_evidence=field_evidence,
            missing_evidence_reasons=missing_reasons,
            traceability_provenance=provenance,
            remediation=finding.remediation,
            generated_at=datetime.now(timezone.utc)
        )

    def build_job_evidence_summary(
        self,
        db: Session,
        job_id: str
    ) -> JobEvidenceSummaryResponse:
        """
        Computes aggregate evidence completeness metrics across all findings in an analysis job.
        """
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job with ID '{job_id}' not found")

        findings = db.query(UnifiedFinding).filter(UnifiedFinding.job_id == job_id).all()

        complete_cnt = 0
        partial_cnt = 0
        insufficient_cnt = 0

        for f in findings:
            chain = self.build_finding_evidence_chain(db, f.id)
            if chain.evidence_status == "COMPLETE_EVIDENCE":
                complete_cnt += 1
            elif chain.evidence_status == "PARTIAL_EVIDENCE":
                partial_cnt += 1
            else:
                insufficient_cnt += 1

        active_stages = [
            "PROTOCOL_ID",
            "TCP_RECONSTRUCT",
            "EMAIL_ANALYSIS",
            "STARTTLS",
            "TLS_HANDSHAKE",
            "X509_CERT",
            "CRYPTO_RULES",
            "FINDINGS_MODEL"
        ]

        return JobEvidenceSummaryResponse(
            job_id=job_id,
            total_findings=len(findings),
            complete_evidence_count=complete_cnt,
            partial_evidence_count=partial_cnt,
            insufficient_evidence_count=insufficient_cnt,
            provenance_stages_active=active_stages,
            evaluated_at=datetime.now(timezone.utc)
        )
