"""Pydantic schemas for PCAP files."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class PcapFileResponse(BaseModel):
    """PCAP file metadata response schema."""
    id: str
    original_filename: str
    file_size_bytes: int
    sha256: str
    md5: str
    file_format: str
    is_valid: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PcapUploadResponse(BaseModel):
    """Response returned upon successful PCAP upload and job creation."""
    job_id: str
    file_id: str
    filename: str
    file_size_bytes: int
    sha256: str
    md5: str
    file_format: str
    status: str
    created_at: datetime
