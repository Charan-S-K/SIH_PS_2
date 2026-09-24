"""
EmailSessionAnalysis database model representing higher-level email protocol transactions
(SMTP, IMAP, POP3) state machines, commands, capabilities, and authentication events.
"""

import uuid
from sqlalchemy import Column, String, Integer, Boolean, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin


class EmailSessionAnalysis(Base, TimestampMixin):
    """Forensic email protocol session analysis and state tracking."""
    __tablename__ = "email_session_analyses"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    tcp_session_id = Column(String(36), ForeignKey("tcp_sessions.id", ondelete="CASCADE"), nullable=True, index=True)
    tcp_stream = Column(Integer, nullable=False, index=True)

    # Protocol classification (SMTP, IMAP, POP3, UNKNOWN)
    protocol = Column(String(32), default="UNKNOWN", nullable=False, index=True)

    # Endpoints
    client_ip = Column(String(45), nullable=True)
    server_ip = Column(String(45), nullable=True)
    client_port = Column(Integer, nullable=True)
    server_port = Column(Integer, nullable=True)

    # Initial greetings
    server_banner = Column(String(512), nullable=True)
    client_greeting = Column(String(512), nullable=True)

    # Session state machine tracking
    session_state = Column(String(64), default="INIT", nullable=False)

    # Capabilities & Extensions (EHLO/CAPABILITY/CAPA)
    capabilities = Column(JSON, nullable=True)  # List[str]

    # STARTTLS / STLS Negotiation
    starttls_advertised = Column(Boolean, default=False, nullable=False)
    starttls_requested = Column(Boolean, default=False, nullable=False)
    starttls_accepted = Column(Boolean, default=False, nullable=False)

    # Authentication Analysis
    auth_mechanisms = Column(JSON, nullable=True)  # List[str]
    auth_attempted = Column(Boolean, default=False, nullable=False)
    auth_successful = Column(Boolean, nullable=True)
    auth_usernames = Column(JSON, nullable=True)  # List[str]

    # Counts and Timeline Events
    commands_count = Column(Integer, default=0, nullable=False)
    events = Column(JSON, nullable=True)  # List[Dict[str, Any]]
    security_warnings = Column(JSON, nullable=True)  # List[str]

    # Frame references
    first_frame_number = Column(Integer, nullable=True)
    last_frame_number = Column(Integer, nullable=True)

    # Relationships
    job = relationship("AnalysisJob", back_populates="email_sessions")
    tcp_session = relationship("TcpSession", back_populates="email_analysis")
