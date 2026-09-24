"""Pydantic schemas for packet metadata and capture summaries."""

from typing import List, Optional
from pydantic import BaseModel, ConfigDict


class PacketMetadataResponse(BaseModel):
    """Forensic packet metadata item."""
    id: str
    frame_number: int
    timestamp: float
    frame_length: int
    ip_version: int
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    transport_protocol: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    detected_protocol: str
    tcp_stream: Optional[int] = None
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: Optional[str] = None
    payload_size: int
    payload_preview: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class PacketListResponse(BaseModel):
    """Paginated list of forensic packets."""
    total: int
    limit: int
    offset: int
    packets: List[PacketMetadataResponse]


class CaptureSummaryResponse(BaseModel):
    """High-level summary of processed capture."""
    job_id: str
    status: str
    total_packets: int
    tcp_packets: int
    udp_packets: int
    other_packets: int
    duration_seconds: float
    capture_start_time: Optional[float] = None
    capture_end_time: Optional[float] = None
    detected_protocols: List[str] = []
    distinct_conversations: int = 0
