"""
AnalysisJob database model representing processing jobs.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Text, DateTime, ForeignKey
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

    # Relationships
    pcap_file = relationship("PcapFile", back_populates="jobs")
