"""
SQLAlchemy models for Prioritization & Explainability Engine.
Stores transparent evidence-backed risk priority scores, weights configurations,
and SHAP / feature attribution explainability metadata for findings and jobs.
"""

import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, JSON, ForeignKey
from app.database import Base
from app.models.base import TimestampMixin


class FindingPrioritization(Base, TimestampMixin):
    """Prioritization score and evidence-backed ranking for an individual finding or session."""
    __tablename__ = "finding_prioritizations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("unified_findings.id", ondelete="CASCADE"), nullable=True, index=True)
    tcp_stream = Column(Integer, nullable=True)

    # Priority Scores & Ranking
    priority_score = Column(Float, nullable=False)  # 0.0 to 100.0
    priority_level = Column(String(32), nullable=False)  # CRITICAL_ACTION_REQUIRED, HIGH_PRIORITY, MEDIUM_PRIORITY, LOW_PRIORITY
    rank = Column(Integer, nullable=False, default=1)

    # Sub-component score breakdown
    severity_score = Column(Float, nullable=False, default=0.0)
    confidence_score = Column(Float, nullable=False, default=0.0)
    exposure_score = Column(Float, nullable=False, default=0.0)
    affected_score = Column(Float, nullable=False, default=0.0)
    ml_risk_score = Column(Float, nullable=False, default=0.0)

    # Rationale & Feature Attribution Explanations
    explanation_summary = Column(String(512), nullable=False)
    factor_breakdown_json = Column(JSON, nullable=False)  # Detailed score weights and factors
    feature_attributions_json = Column(JSON, nullable=True)  # SHAP / Feature importances


class JobPrioritizationSummary(Base, TimestampMixin):
    """Aggregated prioritization rankings and configurable weights summary for an analysis job."""
    __tablename__ = "job_prioritization_summaries"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id = Column(String(36), ForeignKey("analysis_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    
    total_findings_evaluated = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    
    weights_config_json = Column(JSON, nullable=False)  # Weights used for severity, confidence, exposure, affected, ml
    metadata_json = Column(JSON, nullable=True)
