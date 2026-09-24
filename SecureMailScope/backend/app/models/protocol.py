"""
ProtocolIdentification database model representing passive protocol classification and forensic evidence.
"""

import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin


class ProtocolIdentification(Base, TimestampMixin):
    """Forensic protocol identification record per TCP stream or flow."""
    __tablename__ = "protocol_identifications"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tcp_stream = Column(Integer, nullable=True, index=True)
    protocol = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=0.0)
    confidence_level = Column(String(16), nullable=False, default="UNKNOWN")  # HIGH, MEDIUM, LOW, UNKNOWN
    classification_method = Column(String(64), nullable=False, default="UNKNOWN")  # SIGNATURE_AND_BEHAVIOR, TLS_INSPECTION, PORT_FALLBACK, INSUFFICIENT_EVIDENCE
    is_mail_protocol = Column(Boolean, nullable=False, default=False)

    # 4-tuple conversation details
    client_ip = Column(String(45), nullable=True)
    server_ip = Column(String(45), nullable=True)
    client_port = Column(Integer, nullable=True)
    server_port = Column(Integer, nullable=True)

    # Forensic Evidence & Summary
    summary = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)  # Matched signatures, frame evidence, port analysis, anomalies

    packet_count = Column(Integer, default=0, nullable=False)
    total_bytes = Column(Integer, default=0, nullable=False)

    # Relationships
    job = relationship("AnalysisJob", back_populates="protocol_identifications")
