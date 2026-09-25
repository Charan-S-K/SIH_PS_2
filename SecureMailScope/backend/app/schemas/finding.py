"""
Pydantic schemas for Stage 10: Unified Findings Model.
Defines API request/response structures for unified findings, correlation summaries, and filtering.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class UnifiedFindingResponse(BaseModel):
    """Response schema for a single correlated unified finding."""
    id: str
    job_id: str
    tcp_session_id: Optional[str] = None
    tcp_stream: Optional[int] = None
    finding_type: str
    severity: str
    title: str
    reason: str
    confidence: float
    confidence_label: str
    rule_id: Optional[str] = None
    fingerprint: str
    is_duplicate: bool
    occurrence_count: int
    analysis_references: Optional[Dict[str, Any]] = None
    evidence_references: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class FindingsSummaryResponse(BaseModel):
    """Aggregate summary of unified findings and correlation metrics for an analysis job."""
    job_id: str
    total_findings: int
    unique_findings: int
    duplicate_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    type_counts: Dict[str, int]
    consolidated_at: datetime


class UnifiedFindingsListResponse(BaseModel):
    """API response container for findings list with summary."""
    job_id: str
    summary: FindingsSummaryResponse
    findings: List[UnifiedFindingResponse]


class ConsolidateFindingsRequest(BaseModel):
    """Request parameters for triggering findings consolidation and correlation."""
    force_refresh: bool = Field(True, description="Whether to clear existing unified findings and re-consolidate")
