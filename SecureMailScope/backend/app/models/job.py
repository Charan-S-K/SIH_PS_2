"""
AnalysisJob database model representing processing jobs.
"""

import uuid
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin


class AnalysisJob(Base, TimestampMixin):
    """Analysis job orchestrating capture inspection and forensics."""
    __tablename__ = "analysis_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    pcap_file_id = Column(String(36), ForeignKey("pcap_files.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="PENDING", index=True)
    progress_percent = Column(Integer, default=0, nullable=False)
    stage_message = Column(String(255), default="File uploaded and queued for processing", nullable=False)
    error_message = Column(Text, nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Forensic capture statistics (Stage 02)
    total_packets = Column(Integer, default=0, nullable=False)
    tcp_packets = Column(Integer, default=0, nullable=False)
    udp_packets = Column(Integer, default=0, nullable=False)
    other_packets = Column(Integer, default=0, nullable=False)
    duration_seconds = Column(Float, default=0.0, nullable=False)
    capture_start_time = Column(Float, nullable=True)
    capture_end_time = Column(Float, nullable=True)
    detected_protocols = Column(Text, nullable=True)  # JSON-encoded array of distinct protocols

    # Relationships
    pcap_file = relationship("PcapFile", back_populates="jobs")
    packets = relationship("PacketMetadata", back_populates="job", cascade="all, delete-orphan")
    protocol_identifications = relationship("ProtocolIdentification", back_populates="job", cascade="all, delete-orphan")
    tcp_sessions = relationship("TcpSession", back_populates="job", cascade="all, delete-orphan")
    email_sessions = relationship("EmailSessionAnalysis", back_populates="job", cascade="all, delete-orphan")
    starttls_analyses = relationship("StarttlsAnalysis", back_populates="job", cascade="all, delete-orphan")
    tls_handshakes = relationship("TlsHandshakeAnalysis", back_populates="job", cascade="all, delete-orphan")
    certificates = relationship("X509CertificateAnalysis", back_populates="job", cascade="all, delete-orphan")
    crypto_findings = relationship("CryptoRuleResult", back_populates="job", cascade="all, delete-orphan")
    unified_findings = relationship("UnifiedFinding", back_populates="job", cascade="all, delete-orphan")




