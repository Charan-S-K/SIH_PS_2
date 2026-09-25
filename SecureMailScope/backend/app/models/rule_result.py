"""
SQLAlchemy database model for Stage 09: Cryptographic Rules Engine Findings.
Stores structured security finding rule results evaluated against passive job analysis data.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.database import Base


class CryptoRuleResult(Base):
    """
    Structured security finding evaluated by the Cryptographic Rules Engine.
    Correlates evidence from TLS handshakes, certificates, STARTTLS, and email sessions.
    """
    __tablename__ = "crypto_rule_results"

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

    # Rule Metadata
    rule_id = Column(String(64), nullable=False, index=True)  # e.g., "RULE-TLS-001"
    name = Column(String(255), nullable=False)                # e.g., "Deprecated TLS Version (TLS 1.0)"
    category = Column(String(64), nullable=False, index=True) # TLS_PROTOCOL, CIPHER_SUITE, CERTIFICATE, PROTOCOL_BEHAVIOR, STARTTLS, EVIDENCE
    severity = Column(String(32), nullable=False, index=True) # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    # Audit & Rationale
    reason = Column(Text, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    confidence_label = Column(String(32), default="HIGH", nullable=False) # HIGH, MEDIUM, LOW

    # Evidence & Mitigation
    evidence = Column(JSON, nullable=True)     # Pointers to frame, stream, field name, observed value, timestamp
    remediation = Column(Text, nullable=True)  # Actionable remediation advice

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    job = relationship("AnalysisJob", back_populates="crypto_findings")
    tcp_session = relationship("TcpSession", back_populates="crypto_findings")
