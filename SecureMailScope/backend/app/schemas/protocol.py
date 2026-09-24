"""
Pydantic schemas for Protocol Identification and Forensic Evidence.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EvidenceFrame(BaseModel):
    """Forensic evidence from a specific frame."""
    frame_number: int
    timestamp: float
    direction: str  # "client_to_server" | "server_to_client" | "unknown"
    signature_matched: str
    matched_text: Optional[str] = None


class PortAnalysis(BaseModel):
    """Port contextual corroboration."""
    server_port: Optional[int] = None
    standard_port_for: Optional[str] = None
    matches_detected_protocol: bool = False
    notes: Optional[str] = None


class ProtocolEvidence(BaseModel):
    """Structured forensic evidence supporting the protocol identification."""
    matched_signatures: List[str] = Field(default_factory=list)
    evidence_frames: List[EvidenceFrame] = Field(default_factory=list)
    port_analysis: Optional[PortAnalysis] = None
    insufficient_evidence_reason: Optional[str] = None
    anomalies: List[str] = Field(default_factory=list)
    tshark_protocol: Optional[str] = None


class ProtocolIdentificationResponse(BaseModel):
    """Response model for a stream protocol identification."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    tcp_stream: Optional[int] = None
    protocol: str
    confidence: float
    confidence_level: str
    classification_method: str
    is_mail_protocol: bool
    client_ip: Optional[str] = None
    server_ip: Optional[str] = None
    client_port: Optional[int] = None
    server_port: Optional[int] = None
    summary: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    packet_count: int = 0
    total_bytes: int = 0
    created_at: Optional[datetime] = None


class ProtocolListResponse(BaseModel):
    """Response model for all identified protocols in an analysis job."""
    job_id: str
    total_streams: int
    mail_streams: int
    protocols: List[ProtocolIdentificationResponse]
