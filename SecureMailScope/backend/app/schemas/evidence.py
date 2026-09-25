"""
Pydantic schemas for Stage 11: Evidence Engine.
Provides structured evidence chain, packet range tracing, and field provenance schemas.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PacketEvidenceItem(BaseModel):
    """Forensic summary of an individual packet frame within an evidence chain."""
    frame_number: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    detected_protocol: Optional[str] = None
    length_bytes: int
    summary: Optional[str] = None


class FieldEvidenceItem(BaseModel):
    """Specific protocol, TLS, or certificate field observation with provenance."""
    field_name: str
    observed_value: Optional[Any] = None
    is_present: bool = True
    source_stage: str = Field(..., description="Stage providing evidence: PROTOCOL_ID, TCP_RECONSTRUCT, EMAIL_ANALYSIS, STARTTLS, TLS_HANDSHAKE, X509_CERT, CRYPTO_RULES")
    description: Optional[str] = None


class ForensicEvidenceChain(BaseModel):
    """
    Complete evidence chain linking Finding -> Rule -> TCP Session -> Packet Range -> Observed Fields.
    Supports proof of missing facts without fabrication (INSUFFICIENT_EVIDENCE / PARTIAL_EVIDENCE / COMPLETE_EVIDENCE).
    """
    finding_id: str
    job_id: str
    tcp_session_id: Optional[str] = None
    tcp_stream: Optional[int] = None
    rule_id: Optional[str] = None
    finding_title: str
    finding_type: str
    severity: str
    confidence: float
    confidence_label: str
    evidence_status: str = Field("COMPLETE_EVIDENCE", description="COMPLETE_EVIDENCE, PARTIAL_EVIDENCE, or INSUFFICIENT_EVIDENCE")
    
    session_evidence: Optional[Dict[str, Any]] = None
    packet_range: Optional[Dict[str, Any]] = Field(
        None,
        description="First frame, last frame, packet count, and sample packet frame metadata"
    )
    sample_packets: List[PacketEvidenceItem] = Field(default_factory=list)
    field_evidence: List[FieldEvidenceItem] = Field(default_factory=list)
    missing_evidence_reasons: List[str] = Field(default_factory=list)
    traceability_provenance: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    generated_at: datetime


class JobEvidenceSummaryResponse(BaseModel):
    """Aggregate forensic evidence completeness metrics for an analysis job."""
    job_id: str
    total_findings: int
    complete_evidence_count: int
    partial_evidence_count: int
    insufficient_evidence_count: int
    provenance_stages_active: List[str]
    evaluated_at: datetime
