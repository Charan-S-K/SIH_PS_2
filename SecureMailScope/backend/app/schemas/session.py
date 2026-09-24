"""
Pydantic schemas for TCP Session Reconstruction and conversation streams.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ConversationTurn(BaseModel):
    """A conversational exchange in one direction within a TCP session."""
    direction: str  # "c2s" | "s2c"
    start_frame: int
    end_frame: int
    start_time: float
    end_time: float
    byte_length: int
    text_preview: str


class TcpSessionResponse(BaseModel):
    """Response model for a reconstructed TCP conversation session."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    tcp_stream: int
    client_ip: Optional[str] = None
    server_ip: Optional[str] = None
    client_port: Optional[int] = None
    server_port: Optional[int] = None
    protocol: str = "UNKNOWN"
    session_state: str = "ESTABLISHED"
    start_time: float = 0.0
    end_time: float = 0.0
    duration_seconds: float = 0.0
    first_frame_number: int
    last_frame_number: int
    packet_count: int = 0
    c2s_packet_count: int = 0
    s2c_packet_count: int = 0
    c2s_bytes: int = 0
    s2c_bytes: int = 0
    total_payload_bytes: int = 0
    retransmissions_count: int = 0
    out_of_order_count: int = 0
    gaps_count: int = 0
    syn_frame_number: Optional[int] = None
    syn_ack_frame_number: Optional[int] = None
    fin_frame_numbers: Optional[List[int]] = None
    rst_frame_numbers: Optional[List[int]] = None
    c2s_payload_preview: Optional[str] = None
    s2c_payload_preview: Optional[str] = None
    conversation_flow: Optional[List[Dict[str, Any]]] = None
    reconstruction_metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None


class TcpSessionListResponse(BaseModel):
    """Response model for all reconstructed TCP sessions in a capture."""
    job_id: str
    total_sessions: int
    sessions: List[TcpSessionResponse]
