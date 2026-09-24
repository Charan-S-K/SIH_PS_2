"""
Pydantic schemas for Stage 06: STARTTLS Analysis.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class StarttlsFinding(BaseModel):
    """A forensic finding or security posture alert relating to opportunistic TLS."""
    code: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    message: str
    evidence_frame: Optional[int] = None


class StarttlsAnalysisResponse(BaseModel):
    """Response model for opportunistic TLS (STARTTLS/STLS) analysis of a stream."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    tcp_session_id: Optional[str] = None
    tcp_stream: int
    protocol: str = "UNKNOWN"
    client_ip: Optional[str] = None
    server_ip: Optional[str] = None
    client_port: Optional[int] = None
    server_port: Optional[int] = None
    advertised: bool = False
    advertised_frame: Optional[int] = None
    advertised_command: Optional[str] = None
    requested: bool = False
    requested_frame: Optional[int] = None
    requested_command: Optional[str] = None
    accepted: bool = False
    response_frame: Optional[int] = None
    response_code: Optional[str] = None
    response_text: Optional[str] = None
    upgrade_status: str = "NOT_ADVERTISED"
    tls_record_detected: bool = False
    tls_start_frame: Optional[int] = None
    cleartext_auth_observed: bool = False
    cleartext_auth_frame: Optional[int] = None
    cleartext_auth_command: Optional[str] = None
    findings: Optional[List[StarttlsFinding]] = None
    created_at: Optional[datetime] = None


class StarttlsAnalysisListResponse(BaseModel):
    """Response model for all STARTTLS analyses in an analysis job."""
    job_id: str
    total_streams: int
    upgraded_count: int
    downgrade_risk_count: int
    critical_findings_count: int
    analyses: List[StarttlsAnalysisResponse]
