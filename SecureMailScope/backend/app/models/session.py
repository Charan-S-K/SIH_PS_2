"""
TcpSession database model representing reconstructed TCP conversations,
bidirectional byte streams, and forensic reassembly metadata.
"""

import uuid
from sqlalchemy import Column, String, Integer, Float, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin


class TcpSession(Base, TimestampMixin):
    """Forensic reconstructed TCP conversation session."""
    __tablename__ = "tcp_sessions"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tcp_stream = Column(Integer, nullable=False, index=True)

    # Conversation endpoints
    client_ip = Column(String(45), nullable=True)
    server_ip = Column(String(45), nullable=True)
    client_port = Column(Integer, nullable=True)
    server_port = Column(Integer, nullable=True)

    # Protocol classification
    protocol = Column(String(32), default="UNKNOWN", index=True)

    # Lifecycle & state: CLOSED_FIN, RESET, ESTABLISHED, INCOMPLETE
    session_state = Column(String(32), default="ESTABLISHED", nullable=False)

    # Timing metrics
    start_time = Column(Float, nullable=False, default=0.0)
    end_time = Column(Float, nullable=False, default=0.0)
    duration_seconds = Column(Float, nullable=False, default=0.0)

    # Frame range evidence
    first_frame_number = Column(Integer, nullable=False)
    last_frame_number = Column(Integer, nullable=False)
    packet_count = Column(Integer, default=0, nullable=False)
    c2s_packet_count = Column(Integer, default=0, nullable=False)
    s2c_packet_count = Column(Integer, default=0, nullable=False)

    # Byte metrics
    c2s_bytes = Column(Integer, default=0, nullable=False)
    s2c_bytes = Column(Integer, default=0, nullable=False)
    total_payload_bytes = Column(Integer, default=0, nullable=False)

    # Diagnostic & quality metrics
    retransmissions_count = Column(Integer, default=0, nullable=False)
    out_of_order_count = Column(Integer, default=0, nullable=False)
    gaps_count = Column(Integer, default=0, nullable=False)

    # Handshake frame numbers
    syn_frame_number = Column(Integer, nullable=True)
    syn_ack_frame_number = Column(Integer, nullable=True)
    fin_frame_numbers = Column(JSON, nullable=True)
    rst_frame_numbers = Column(JSON, nullable=True)

    # Reconstructed payloads & conversation turns
    c2s_payload_preview = Column(Text, nullable=True)
    s2c_payload_preview = Column(Text, nullable=True)
    conversation_flow = Column(JSON, nullable=True)  # List of chronological conversation turns
    reconstruction_metadata = Column(JSON, nullable=True)  # Detailed list of gaps, retransmissions, out-of-order

    # Relationships
    job = relationship("AnalysisJob", back_populates="tcp_sessions")
    email_analysis = relationship("EmailSessionAnalysis", back_populates="tcp_session", uselist=False, cascade="all, delete-orphan")
    starttls_analysis = relationship("StarttlsAnalysis", back_populates="tcp_session", uselist=False, cascade="all, delete-orphan")
    tls_handshake = relationship("TlsHandshakeAnalysis", back_populates="tcp_session", uselist=False, cascade="all, delete-orphan")
    certificates = relationship("X509CertificateAnalysis", back_populates="session", cascade="all, delete-orphan")


