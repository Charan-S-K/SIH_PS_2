"""
Pydantic schemas for Stage 07: TLS Handshake Analysis.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class TlsCipherSuiteItem(BaseModel):
    """Represent an individual cipher suite ID and human-readable RFC name."""
    id: int
    hex: str
    name: str


class TlsHandshakeMessageItem(BaseModel):
    """A single dissected message record in the TLS handshake."""
    message_type: str  # "ClientHello", "ServerHello", "Certificate", "Alert", etc.
    frame_number: Optional[int] = None
    timestamp: Optional[float] = None
    length: Optional[int] = None
    info: Optional[str] = None


class TlsHandshakeAnalysisResponse(BaseModel):
    """Response model for a single stream's reconstructed TLS Handshake analysis."""
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

    handshake_status: str = "UNKNOWN"
    is_starttls: bool = False

    negotiated_version: str = "UNKNOWN"
    negotiated_version_raw: Optional[int] = None
    negotiated_cipher_suite: str = "UNKNOWN"
    negotiated_cipher_id: Optional[int] = None
    key_exchange_group: Optional[str] = None
    signature_scheme: Optional[str] = None
    sni: Optional[str] = None
    alpn_selected: Optional[str] = None

    client_hello_frame: Optional[int] = None
    client_hello_time: Optional[float] = None
    client_hello_version: Optional[str] = None
    client_random: Optional[str] = None
    client_offered_ciphers: Optional[List[Dict[str, Any]]] = None
    client_supported_versions: Optional[List[str]] = None
    client_supported_groups: Optional[List[str]] = None
    client_signature_algorithms: Optional[List[str]] = None
    client_alpn_protocols: Optional[List[str]] = None
    client_extensions_count: int = 0

    server_hello_frame: Optional[int] = None
    server_hello_time: Optional[float] = None
    server_hello_version: Optional[str] = None
    server_random: Optional[str] = None
    server_extensions_count: int = 0

    certificate_frame: Optional[int] = None
    certificate_chain_length: int = 0

    has_alert: bool = False
    alert_level: Optional[str] = None
    alert_description: Optional[str] = None
    alert_frame: Optional[int] = None

    handshake_messages: Optional[List[Dict[str, Any]]] = None
    handshake_duration_ms: Optional[float] = None
    evidence: Optional[List[Dict[str, Any]]] = None
    created_at: Optional[datetime] = None


class TlsHandshakeAnalysisListResponse(BaseModel):
    """Aggregated TLS handshake analyses for an analysis job."""
    job_id: str
    total_handshakes: int
    completed_count: int
    tls13_count: int
    tls12_count: int
    legacy_tls_count: int
    alert_count: int
    analyses: List[TlsHandshakeAnalysisResponse]
