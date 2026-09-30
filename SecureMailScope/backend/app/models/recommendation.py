"""
SQLAlchemy database model for Recommendations Engine.
Stores deterministic remediation recommendations tied to security rules,
findings, affected components, exact configuration actions, and compliance controls.
"""

import uuid
from sqlalchemy import Column, String, Integer, Float, Text, JSON, ForeignKey
from app.database import Base
from app.models.base import TimestampMixin


class RemediationRecommendation(Base, TimestampMixin):
    """Deterministic remediation recommendation tied directly to rule findings."""
    __tablename__ = "remediation_recommendations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("unified_findings.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_id = Column(String(64), nullable=False, index=True)

    # Core Recommendation Fields
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    affected_component = Column(String(128), nullable=False)  # e.g., Postfix SMTP Server, Dovecot IMAP Server, OpenSSL Crypto Library
    
    recommended_action = Column(Text, nullable=False)  # Exact configuration snippet/steps
    rationale = Column(Text, nullable=False)  # Evidence-backed justification
    
    # Metadata & Compliance
    implementation_effort = Column(String(32), default="MEDIUM", nullable=False)  # LOW, MEDIUM, HIGH
    compliance_frameworks = Column(JSON, nullable=True)  # List of frameworks e.g. ["NIST SP 800-52", "PCI-DSS 4.0"]
    triggering_evidence_json = Column(JSON, nullable=True)  # Packet frames, TLS version, cipher code
