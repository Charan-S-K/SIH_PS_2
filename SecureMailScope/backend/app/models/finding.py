"""
SQLAlchemy database model for Stage 10: Unified Findings Model.
Provides a standardized finding schema for all passive forensic analysis artifacts,
incorporating correlation, deduplication, confidence scoring, evidence traceability, and remediation.
"""

import uuid
import hashlib
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Column, String, Integer, Float, Text, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.database import Base


class UnifiedFinding(Base):
    """
    Standardized, correlated finding representing a security posture issue,
    protocol vulnerability, certificate flaw, or anomaly.
    """
    __tablename__ = "unified_findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(
        String(36),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    tcp_session_id = Column(
        String(36),
        ForeignKey("tcp_sessions.id", ondelete="SET NULL"),
        nullable=True,
        index=True
    )
    tcp_stream = Column(Integer, nullable=True, index=True)

    # Classification & Severity
    finding_type = Column(
        String(64),
        nullable=False,
        index=True
    ) # PROTOCOL_SECURITY, CRYPTOGRAPHIC_WEAKNESS, CERTIFICATE_FORENSIC, STARTTLS_INTEGRITY, ANOMALY_DETECTION, EVIDENCE_GAP
    
    severity = Column(
        String(32),
        nullable=False,
        index=True
    ) # CRITICAL, HIGH, MEDIUM, LOW, INFO

    title = Column(String(255), nullable=False)
    reason = Column(Text, nullable=False)

    # Confidence Rating
    confidence = Column(Float, default=1.0, nullable=False)
    confidence_label = Column(String(32), default="HIGH", nullable=False) # HIGH, MEDIUM, LOW

    # Traceability & Correlation
    rule_id = Column(String(64), nullable=True, index=True)
    fingerprint = Column(String(64), nullable=False, index=True) # SHA-256 correlation key for deduplication
    is_duplicate = Column(Boolean, default=False, nullable=False, index=True)
    occurrence_count = Column(Integer, default=1, nullable=False)

    # Detailed Evidence & References
    analysis_references = Column(JSON, nullable=True) # Pointers: session_id, handshake_id, cert_id, starttls_id
    evidence_references = Column(JSON, nullable=True) # Packet frame numbers, timestamp, field name, observed value
    remediation = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    job = relationship("AnalysisJob", back_populates="unified_findings")
    tcp_session = relationship("TcpSession", back_populates="unified_findings")

    @staticmethod
    def generate_fingerprint(job_id: str, finding_type: str, rule_id: str, tcp_stream: Optional[int], title: str) -> str:
        """Computes deterministic SHA-256 fingerprint for correlation and deduplication."""
        raw_key = f"{job_id}:{finding_type}:{rule_id or 'NORULE'}:{tcp_stream if tcp_stream is not None else 'NOSTREAM'}:{title.lower().strip()}"
        return hashlib.sha256(raw_key.encode('utf-8')).hexdigest()
