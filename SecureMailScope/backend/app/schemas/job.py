"""Pydantic schemas for analysis jobs."""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict
from app.schemas.pcap import PcapFileResponse


class AnalysisJobResponse(BaseModel):
    """Analysis job detail schema."""
    id: str
    pcap_file_id: str
    status: str
    progress_percent: int
    stage_message: str
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None
    pcap_file: Optional[PcapFileResponse] = None

    model_config = ConfigDict(from_attributes=True)


class JobListResponse(BaseModel):
    """Paginated list of analysis jobs."""
    total: int
    limit: int
    offset: int
    jobs: List[AnalysisJobResponse]
