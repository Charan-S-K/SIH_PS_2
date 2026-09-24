"""
StarttlsAnalysis database model representing opportunistic TLS (STARTTLS/STLS)
negotiations, upgrade tracking, failure handling, and downgrade risk detection.
"""

import uuid
from sqlalchemy import Column, String, Integer, Boolean, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin


class StarttlsAnalysis(Base, TimestampMixin):
    """Forensic STARTTLS negotiation and cryptographic upgrade posture analysis."""
    __tablename__ = "starttls_analyses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tcp_session_id = Column(String(36), ForeignKey("tcp_sessions.id", ondelete="CASCADE"), nullable=True, index=True)
    tcp_stream = Column(Integer, nullable=False, index=True)

    # Protocol
    protocol = Column(String(32), default="UNKNOWN", nullable=False, index=True)

    # Endpoints
    client_ip = Column(String(45), nullable=True)
    server_ip = Column(String(45), nullable=True)
    client_port = Column(Integer, nullable=True)
    server_port = Column(Integer, nullable=True)

    # Step 1: Advertisement
    advertised = Column(Boolean, default=False, nullable=False)
    advertised_frame = Column(Integer, nullable=True)
    advertised_command = Column(String(255), nullable=True)

    # Step 2: Client Request
    requested = Column(Boolean, default=False, nullable=False)
    requested_frame = Column(Integer, nullable=True)
    requested_command = Column(String(255), nullable=True)

    # Step 3: Server Response
    accepted = Column(Boolean, default=False, nullable=False)
    response_frame = Column(Integer, nullable=True)
    response_code = Column(String(32), nullable=True)
    response_text = Column(String(255), nullable=True)

    # Step 4: TLS Transition & Status
    upgrade_status = Column(String(64), default="NOT_ADVERTISED", nullable=False, index=True)
    tls_record_detected = Column(Boolean, default=False, nullable=False)
    tls_start_frame = Column(Integer, nullable=True)

    # Step 5: Cleartext Authentication Anomalies
    cleartext_auth_observed = Column(Boolean, default=False, nullable=False)
    cleartext_auth_frame = Column(Integer, nullable=True)
    cleartext_auth_command = Column(String(255), nullable=True)

    # Security & Posture Findings
    findings = Column(JSON, nullable=True)  # List[Dict[str, Any]]

    # Relationships
    job = relationship("AnalysisJob", back_populates="starttls_analyses")
    tcp_session = relationship("TcpSession", back_populates="starttls_analysis")
