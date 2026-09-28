"""
Report Metadata database model for persisting generated forensic report exports.
Stores report format, sha256 checksum, storage path, findings summary, and timestamp.
"""

import uuid
from sqlalchemy import Column, String, Integer, Float, ForeignKey, Text
from sqlalchemy.orm import relationship

from app.database import Base
from app.models.base import TimestampMixin


class ReportMetadata(Base, TimestampMixin):
    """
    SQLAlchemy model representing a generated forensic report metadata record.
    Tied to an AnalysisJob with CASCADE deletion.
    """
    __tablename__ = "report_metadata"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    
    report_title = Column(String(255), nullable=False)
    export_format = Column(String(32), nullable=False, index=True)  # PDF, JSON, HTML, CSV
    report_hash_sha256 = Column(String(64), nullable=False, index=True)
    file_path = Column(String(512), nullable=True)
    file_size_bytes = Column(Integer, default=0)
    
    total_findings_included = Column(Integer, default=0)
    posture_score = Column(Float, nullable=True)
    generated_by = Column(String(128), default="SecureMailScope Core Engine")
    notes = Column(Text, nullable=True)

    # Relationships
    job = relationship("AnalysisJob", back_populates="report_records")

    def __repr__(self) -> str:
        return f"<ReportMetadata id={self.id} job_id={self.job_id} format={self.export_format} title={self.report_title}>"
