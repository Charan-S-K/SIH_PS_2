"""
Service for Stage 10: Unified Findings Model & Correlation Engine.
Consolidates forensic evidence, cryptographic rule results, certificate flaws, and protocol behavior
into unified, correlated, and deduplicated finding records.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Set

from sqlalchemy.orm import Session

from app.models.job import AnalysisJob
from app.models.session import TcpSession
from app.models.email_analysis import EmailSessionAnalysis
from app.models.starttls import StarttlsAnalysis
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.models.certificate import X509CertificateAnalysis
from app.models.rule_result import CryptoRuleResult
from app.models.finding import UnifiedFinding
from app.schemas.finding import (
    UnifiedFindingResponse,
    FindingsSummaryResponse,
)

logger = logging.getLogger(__name__)


class FindingsService:
    """
    Correlation and deduplication service for Stage 10 Unified Findings Model.
    """

    @staticmethod
    def map_category_to_type(category: str) -> str:
        """Map rule category to unified finding_type."""
        cat_upper = (category or "").upper()
        if "STARTTLS" in cat_upper:
            return "STARTTLS_INTEGRITY"
        elif "CERT" in cat_upper:
            return "CERTIFICATE_FORENSIC"
        elif "TLS" in cat_upper or "CIPHER" in cat_upper:
            return "CRYPTOGRAPHIC_WEAKNESS"
        elif "PROTOCOL" in cat_upper or "AUTH" in cat_upper:
            return "PROTOCOL_SECURITY"
        elif "EVIDENCE" in cat_upper:
            return "EVIDENCE_GAP"
        return "GENERAL_SECURITY"

    def consolidate_job_findings(
        self,
        db: Session,
        job_id: str,
        force_refresh: bool = True
    ) -> Tuple[FindingsSummaryResponse, List[UnifiedFinding]]:
        """
        Consolidates all stage findings into unified, correlated, and deduplicated records.
        """
        job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
        if not job:
            raise ValueError(f"Job {job_id} not found")

        # Return existing consolidated findings if force_refresh is False
        existing = (
            db.query(UnifiedFinding)
            .filter(UnifiedFinding.job_id == job_id)
            .order_by(UnifiedFinding.created_at.asc())
            .all()
        )
        if existing and not force_refresh:
            summary = self._build_summary(job_id, existing)
            return summary, existing

        # Clear existing unified findings if force_refresh is True
        if force_refresh:
            db.query(UnifiedFinding).filter(UnifiedFinding.job_id == job_id).delete()
            db.commit()

        # Query all source stage artifacts
        rule_results = (
            db.query(CryptoRuleResult)
            .filter(CryptoRuleResult.job_id == job_id)
            .all()
        )
        tcp_sessions = (
            db.query(TcpSession)
            .filter(TcpSession.job_id == job_id)
            .all()
        )
        session_by_stream = {s.tcp_stream: s for s in tcp_sessions}

        findings_to_insert: List[UnifiedFinding] = []
        fingerprint_primary_map: Dict[str, UnifiedFinding] = {}

        # -----------------------------------------------------------------
        # Process CryptoRuleResult artifacts into UnifiedFindings
        # -----------------------------------------------------------------
        for rr in rule_results:
            finding_type = self.map_category_to_type(rr.category)
            stream_id = rr.tcp_stream
            session = session_by_stream.get(stream_id) if stream_id is not None else None
            session_db_id = session.id if session else rr.tcp_session_id

            fp = UnifiedFinding.generate_fingerprint(
                job_id=job_id,
                finding_type=finding_type,
                rule_id=rr.rule_id,
                tcp_stream=stream_id,
                title=rr.name
            )

            evidence_refs = rr.evidence or {}
            analysis_refs = {
                "rule_result_id": rr.id,
                "rule_id": rr.rule_id,
                "category": rr.category,
                "tcp_stream": stream_id,
            }

            if fp in fingerprint_primary_map:
                # Deduplicate: increment primary occurrence count and merge evidence
                primary = fingerprint_primary_map[fp]
                primary.occurrence_count += 1
                
                # Create duplicate finding record for correlation trail
                dup_finding = UnifiedFinding(
                    job_id=job_id,
                    tcp_session_id=session_db_id,
                    tcp_stream=stream_id,
                    finding_type=finding_type,
                    severity=rr.severity,
                    title=rr.name,
                    reason=rr.reason,
                    confidence=rr.confidence,
                    confidence_label=rr.confidence_label,
                    rule_id=rr.rule_id,
                    fingerprint=fp,
                    is_duplicate=True,
                    occurrence_count=1,
                    analysis_references=analysis_refs,
                    evidence_references=evidence_refs,
                    remediation=rr.remediation
                )
                findings_to_insert.append(dup_finding)
            else:
                primary_finding = UnifiedFinding(
                    job_id=job_id,
                    tcp_session_id=session_db_id,
                    tcp_stream=stream_id,
                    finding_type=finding_type,
                    severity=rr.severity,
                    title=rr.name,
                    reason=rr.reason,
                    confidence=rr.confidence,
                    confidence_label=rr.confidence_label,
                    rule_id=rr.rule_id,
                    fingerprint=fp,
                    is_duplicate=False,
                    occurrence_count=1,
                    analysis_references=analysis_refs,
                    evidence_references=evidence_refs,
                    remediation=rr.remediation
                )
                fingerprint_primary_map[fp] = primary_finding
                findings_to_insert.append(primary_finding)

        # Save all findings to database
        db.add_all(findings_to_insert)
        db.commit()

        # Build summary metrics
        summary = self._build_summary(job_id, findings_to_insert)
        return summary, findings_to_insert

    def _build_summary(
        self, job_id: str, findings: List[UnifiedFinding]
    ) -> FindingsSummaryResponse:
        """Constructs FindingsSummaryResponse from consolidated findings."""
        unique_findings = [f for f in findings if not f.is_duplicate]
        duplicate_findings = [f for f in findings if f.is_duplicate]

        critical_count = sum(1 for f in unique_findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in unique_findings if f.severity == "HIGH")
        medium_count = sum(1 for f in unique_findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in unique_findings if f.severity == "LOW")
        info_count = sum(1 for f in unique_findings if f.severity == "INFO")

        type_counts: Dict[str, int] = {}
        for f in unique_findings:
            type_counts[f.finding_type] = type_counts.get(f.finding_type, 0) + 1

        return FindingsSummaryResponse(
            job_id=job_id,
            total_findings=len(findings),
            unique_findings=len(unique_findings),
            duplicate_findings=len(duplicate_findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            info_count=info_count,
            type_counts=type_counts,
            consolidated_at=datetime.now(timezone.utc)
        )
