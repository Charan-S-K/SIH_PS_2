"""
SQLAlchemy database model for Stage 12: Security Posture Engine.
Stores explainable session-, server-, and job-level security posture scores, risk grades,
deduction breakdowns, and contributing finding rationales.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.database import Base


class SecurityPostureScore(Base):
    """
    Explainable security posture score and risk rating for an analysis job, server IP, or stream.
    """
    __tablename__ = "security_posture_scores"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(
        String(36),
        ForeignKey("analysis_jobs.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    tcp_stream = Column(Integer, nullable=True, index=True)
    server_ip = Column(String(45), nullable=True, index=True)

    # Posture Rating & Scores
    overall_score = Column(Integer, nullable=False, default=100)  # 0 to 100 (100 = Perfect)
    overall_grade = Column(String(32), nullable=False, default="EXCELLENT")  # EXCELLENT, GOOD, FAIR, POOR, CRITICAL_RISK
    risk_level = Column(String(32), nullable=False, default="LOW")  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    
    # Rationale & Breakdown
    posture_summary = Column(Text, nullable=False)  # Human-readable posture explanation
    total_deduction = Column(Float, nullable=False, default=0.0)
    findings_count = Column(Integer, nullable=False, default=0)
    contributing_findings_json = Column(JSON, nullable=True)  # List of contributing findings with point deductions
    scoring_breakdown_json = Column(JSON, nullable=True)  # Categorical deduction details

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    job = relationship("AnalysisJob", back_populates="posture_scores")
