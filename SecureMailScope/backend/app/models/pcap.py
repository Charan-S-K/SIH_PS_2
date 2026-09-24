"""
PcapFile database model representing uploaded capture artifacts.
"""

import uuid
from sqlalchemy import Column, String, BigInteger, Boolean
from sqlalchemy.orm import relationship
from app.database import Base
from app.models.base import TimestampMixin


class PcapFile(Base, TimestampMixin):
    """Uploaded PCAP / PCAPNG capture record with cryptographic hashes."""
    __tablename__ = "pcap_files"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False, unique=True)
    file_path = Column(String(1024), nullable=False)
    file_size_bytes = Column(BigInteger, nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    md5 = Column(String(32), nullable=False)
    file_format = Column(String(32), nullable=False, default="pcap")
    is_valid = Column(Boolean, default=True, nullable=False)

    # Relationships
    jobs = relationship("AnalysisJob", back_populates="pcap_file", cascade="all, delete-orphan")
