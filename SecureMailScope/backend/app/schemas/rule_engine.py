"""
Pydantic schemas for Stage 09: Cryptographic Rules Engine.
Defines API request/response contracts for rule definitions, evaluated findings, and summary metrics.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CryptoRuleDefinition(BaseModel):
    """Schema representing a rule definition configured in YAML or JSON."""
    id: str = Field(..., description="Unique rule identifier, e.g. RULE-TLS-001")
    name: str = Field(..., description="Human-readable rule title")
    category: str = Field(..., description="Category: TLS_PROTOCOL, CIPHER_SUITE, CERTIFICATE, PROTOCOL_BEHAVIOR, STARTTLS, EVIDENCE")
    severity: str = Field(..., description="Severity level: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    description: str = Field(..., description="Detailed explanation of the security risk")
    remediation: str = Field(..., description="Actionable remediation advice")
    default_confidence: float = Field(1.0, ge=0.0, le=1.0, description="Base confidence score (0.0 to 1.0)")


class CryptoFindingResponse(BaseModel):
    """Schema representing an evaluated cryptographic finding stored in the database."""
    id: str
    job_id: str
    tcp_session_id: Optional[str] = None
    tcp_stream: Optional[int] = None
    rule_id: str
    name: str
    category: str
    severity: str
    reason: str
    confidence: float
    confidence_label: str
    evidence: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class CategorySummary(BaseModel):
    """Counts per category."""
    category: str
    count: int


class JobFindingsSummary(BaseModel):
    """Aggregated summary of cryptographic findings for an analysis job."""
    job_id: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    category_counts: Dict[str, int]
    rules_triggered_count: int
    evaluated_at: datetime


class CryptoFindingsListResponse(BaseModel):
    """API response container for findings list with job summary."""
    job_id: str
    summary: JobFindingsSummary
    findings: List[CryptoFindingResponse]


class EvaluateRulesRequest(BaseModel):
    """Request payload for triggering rule engine evaluation."""
    force_reevaluate: bool = Field(False, description="Whether to clear existing findings and re-evaluate rules")
    custom_rules: Optional[List[CryptoRuleDefinition]] = Field(None, description="Optional custom rules to evaluate")
