"""
PacketMetadata database model representing passive packet forensic records.
"""

import uuid
from sqlalchemy import Column, String, Integer, Float, BigInteger, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class PacketMetadata(Base):
    """Forensic packet metadata extracted from passive capture files."""
    __tablename__ = "packet_metadata"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    frame_number = Column(Integer, nullable=False, index=True)
    timestamp = Column(Float, nullable=False)
    frame_length = Column(Integer, nullable=False)
    ip_version = Column(Integer, default=4, nullable=False)
    src_ip = Column(String(45), nullable=True, index=True)
    dst_ip = Column(String(45), nullable=True, index=True)
    transport_protocol = Column(String(16), nullable=False, default="OTHER")
    src_port = Column(Integer, nullable=True, index=True)
    dst_port = Column(Integer, nullable=True, index=True)
    detected_protocol = Column(String(32), default="UNKNOWN", index=True)
    tcp_stream = Column(Integer, nullable=True, index=True)
    tcp_seq = Column(BigInteger, nullable=True)
    tcp_ack = Column(BigInteger, nullable=True)
    tcp_flags = Column(String(32), nullable=True)
    payload_size = Column(Integer, default=0, nullable=False)
    payload_preview = Column(String(128), nullable=True)

    # Relationships
    job = relationship("AnalysisJob", back_populates="packets")
