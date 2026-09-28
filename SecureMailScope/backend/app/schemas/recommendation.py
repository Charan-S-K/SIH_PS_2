"""
Pydantic Schemas for Stage 19: Recommendations Engine.
Defines schemas for deterministic remediation recommendations, affected components,
configuration snippets, and job summary outputs.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RecommendationResponse(BaseModel):
    """Schema for individual remediation recommendation."""
    id: str
    job_id: str
    finding_id: Optional[str] = None
    rule_id: str
    title: str
    severity: str
    affected_component: str
    recommended_action: str
    rationale: str
    implementation_effort: str
    compliance_frameworks: Optional[List[str]] = None
    triggering_evidence_json: Optional[Dict[str, Any]] = None
    created_at: datetime

    class Config:
        from_attributes = True


class JobRecommendationsSummaryResponse(BaseModel):
    """Schema for job-level remediation recommendations summary."""
    job_id: str
    total_recommendations: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    recommendations: List[RecommendationResponse]
