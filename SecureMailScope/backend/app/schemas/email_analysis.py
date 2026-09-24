"""
Pydantic schemas for Stage 05: Email Protocol Analysis (SMTP, IMAP, POP3).
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EmailProtocolEvent(BaseModel):
    """A discrete email protocol event (command, response, banner, capability exchange)."""
    direction: str  # "c2s" | "s2c"
    event_type: str  # "BANNER" | "COMMAND" | "RESPONSE" | "CAPABILITY_LIST" | "STARTTLS_NEGOTIATION" | "AUTH_EXCHANGE" | "DATA_TRANSFER" | "CLOSING"
    command: Optional[str] = None
    argument: Optional[str] = None
    response_code: Optional[str] = None
    raw_text: str
    frame_number: Optional[int] = None
    timestamp: Optional[float] = None


class EmailSessionAnalysisResponse(BaseModel):
    """Response model for a analyzed email protocol session."""
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
    server_banner: Optional[str] = None
    client_greeting: Optional[str] = None
    session_state: str = "INIT"
    capabilities: Optional[List[str]] = None
    starttls_advertised: bool = False
    starttls_requested: bool = False
    starttls_accepted: bool = False
    auth_mechanisms: Optional[List[str]] = None
    auth_attempted: bool = False
    auth_successful: Optional[bool] = None
    auth_usernames: Optional[List[str]] = None
    commands_count: int = 0
    events: Optional[List[EmailProtocolEvent]] = None
    security_warnings: Optional[List[str]] = None
    first_frame_number: Optional[int] = None
    last_frame_number: Optional[int] = None
    created_at: Optional[datetime] = None


class EmailSessionAnalysisListResponse(BaseModel):
    """Response model for all analyzed email protocol sessions in a capture."""
    job_id: str
    total_email_sessions: int
    sessions: List[EmailSessionAnalysisResponse]
