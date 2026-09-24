"""
SQLAlchemy model for Stage 07: TLS Handshake Analysis.
Stores parsed TLS handshake parameters, negotiated cryptographic parameters,
extensions, and forensic message timeline.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.database import Base


class TlsHandshakeAnalysis(Base):
    """
    Forensic record of observable TLS Handshake messages and negotiated parameters
    for a TCP conversation stream.
    """
    __tablename__ = "tls_handshake_analyses"

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
    tcp_stream = Column(Integer, nullable=False, index=True)
    protocol = Column(String(32), default="UNKNOWN", nullable=False)
    client_ip = Column(String(45), nullable=True)
    server_ip = Column(String(45), nullable=True)
    client_port = Column(Integer, nullable=True)
    server_port = Column(Integer, nullable=True)

    # Handshake State & Type
    handshake_status = Column(String(32), default="UNKNOWN", nullable=False)
    # Statuses: "COMPLETED", "NEGOTIATED_INCOMPLETE", "CLIENT_HELLO_ONLY", "ALERT_TERMINATED", "NOT_OBSERVED"
    is_starttls = Column(Boolean, default=False, nullable=False)

    # Negotiated Cryptographic Parameters
    negotiated_version = Column(String(32), default="UNKNOWN", nullable=False)  # e.g. "TLS 1.3", "TLS 1.2"
    negotiated_version_raw = Column(Integer, nullable=True)  # e.g. 0x0304, 0x0303
    negotiated_cipher_suite = Column(String(128), default="UNKNOWN", nullable=False)
    negotiated_cipher_id = Column(Integer, nullable=True)
    key_exchange_group = Column(String(64), nullable=True)  # e.g. "x25519", "secp256r1"
    signature_scheme = Column(String(64), nullable=True)  # e.g. "rsa_pss_rsae_sha256"
    sni = Column(String(255), nullable=True)  # Server Name Indication
    alpn_selected = Column(String(64), nullable=True)

    # Client Hello Dissection
    client_hello_frame = Column(Integer, nullable=True)
    client_hello_time = Column(Float, nullable=True)
    client_hello_version = Column(String(32), nullable=True)
    client_random = Column(String(64), nullable=True)  # 32 bytes hex
    client_offered_ciphers = Column(JSON, nullable=True)  # List[Dict[str, Any]]
    client_supported_versions = Column(JSON, nullable=True)  # List[str]
    client_supported_groups = Column(JSON, nullable=True)  # List[str]
    client_signature_algorithms = Column(JSON, nullable=True)  # List[str]
    client_alpn_protocols = Column(JSON, nullable=True)  # List[str]
    client_extensions_count = Column(Integer, default=0, nullable=False)

    # Server Hello Dissection
    server_hello_frame = Column(Integer, nullable=True)
    server_hello_time = Column(Float, nullable=True)
    server_hello_version = Column(String(32), nullable=True)
    server_random = Column(String(64), nullable=True)  # 32 bytes hex
    server_extensions_count = Column(Integer, default=0, nullable=False)

    # Certificate & Alert Observations
    certificate_frame = Column(Integer, nullable=True)
    certificate_chain_length = Column(Integer, default=0, nullable=False)
    raw_certificates_bytes = Column(JSON, nullable=True)  # List of base64 DER certificates for Stage 08

    has_alert = Column(Boolean, default=False, nullable=False)
    alert_level = Column(String(16), nullable=True)  # "WARNING", "FATAL"
    alert_description = Column(String(64), nullable=True)  # e.g. "handshake_failure (40)"
    alert_frame = Column(Integer, nullable=True)

    # Flow Evidence & Metrics
    handshake_messages = Column(JSON, nullable=True)  # Chronological list of parsed handshake frames
    handshake_duration_ms = Column(Float, nullable=True)
    evidence = Column(JSON, nullable=True)  # Structured forensic findings & frame pointers

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    job = relationship("AnalysisJob", back_populates="tls_handshakes")
    tcp_session = relationship("TcpSession", back_populates="tls_handshake")
