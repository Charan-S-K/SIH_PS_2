"""
Pydantic schemas for Stage 12: Security Posture Engine.
Provides request/response schemas for explainable security posture ratings, deduction scoring, and server breakdowns.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ContributingFindingItem(BaseModel):
    """Detailed deduction item for a contributing security finding."""
    finding_id: str
    rule_id: Optional[str] = None
    title: str
    severity: str
    confidence: float
    confidence_label: str
    deduction_points: float = Field(..., description="Calculated point deduction applied to score")
    rationale: str = Field(..., description="Human-readable explanation of why points were deducted")


class SecurityPostureResponse(BaseModel):
    """API response schema for explainable security posture rating and score."""
    id: str
    job_id: str
    tcp_stream: Optional[int] = None
    server_ip: Optional[str] = None
    overall_score: int = Field(..., description="Posture score from 0 to 100 (100 = Perfect)")
    overall_grade: str = Field(..., description="EXCELLENT, GOOD, FAIR, POOR, or CRITICAL_RISK")
    risk_level: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW, or INFO")
    posture_summary: str = Field(..., description="Human-readable posture summary rationale")
    total_deduction: float
    findings_count: int
    contributing_findings: List[ContributingFindingItem] = Field(default_factory=list)
    scoring_breakdown: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class ServerPostureSummaryItem(BaseModel):
    """Summary of posture rating for a specific target server IP address."""
    server_ip: str
    stream_count: int
    overall_score: int
    overall_grade: str
    risk_level: str
    critical_findings_count: int
    high_findings_count: int


class JobPostureDashboardResponse(BaseModel):
    """Complete security posture dashboard response container."""
    job_id: str
    job_posture: SecurityPostureResponse
    server_postures: List[ServerPostureSummaryItem] = Field(default_factory=list)
    evaluated_at: datetime
