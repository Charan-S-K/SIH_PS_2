"""
Pydantic Schemas for Prioritization Engine.
Defines configurable weights, prioritized findings responses, SHAP feature attributions,
and job prioritization summary outputs.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PrioritizationWeightsConfig(BaseModel):
    """Configurable weights for prioritization score calculation."""
    weight_severity: float = Field(default=0.35, ge=0.0, le=1.0, description="Weight for finding severity")
    weight_confidence: float = Field(default=0.20, ge=0.0, le=1.0, description="Weight for rule confidence")
    weight_exposure: float = Field(default=0.20, ge=0.0, le=1.0, description="Weight for network exposure")
    weight_affected: float = Field(default=0.15, ge=0.0, le=1.0, description="Weight for affected session count")
    weight_ml: float = Field(default=0.10, ge=0.0, le=1.0, description="Weight for ML risk classifier signal")


class PrioritizationCalculateRequest(BaseModel):
    """Request payload to calculate prioritization ranking for a job."""
    weights: Optional[PrioritizationWeightsConfig] = Field(default=None, description="Custom weights configuration")


class FindingPrioritizationResponse(BaseModel):
    """Schema for individual finding prioritization score & feature attributions."""
    id: str
    job_id: str
    finding_id: Optional[str] = None
    tcp_stream: Optional[int] = None
    priority_score: float
    priority_level: str
    rank: int
    severity_score: float
    confidence_score: float
    exposure_score: float
    affected_score: float
    ml_risk_score: float
    explanation_summary: str
    factor_breakdown_json: Dict[str, Any]
    feature_attributions_json: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class JobPrioritizationSummaryResponse(BaseModel):
    """Schema for job-level prioritization summary and ranked findings list."""
    id: str
    job_id: str
    total_findings_evaluated: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    weights_config_json: Dict[str, Any]
    rankings: List[FindingPrioritizationResponse]
    created_at: datetime

    class Config:
        from_attributes = True
