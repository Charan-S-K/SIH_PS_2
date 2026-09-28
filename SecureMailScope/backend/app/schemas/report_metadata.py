"""
Pydantic schemas for ReportMetadata API validation and response serialization.
"""

from typing import Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict


class ReportMetadataBase(BaseModel):
    report_title: str
    export_format: str
    notes: Optional[str] = None


class ReportMetadataCreate(ReportMetadataBase):
    job_id: str
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = 0
    report_hash_sha256: Optional[str] = None
    total_findings_included: Optional[int] = 0
    posture_score: Optional[float] = None
    generated_by: Optional[str] = "SecureMailScope Core Engine"


class ReportMetadataResponse(ReportMetadataBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    job_id: str
    report_hash_sha256: str
    file_path: Optional[str] = None
    file_size_bytes: int
    total_findings_included: int
    posture_score: Optional[float] = None
    generated_by: str
    created_at: datetime
    updated_at: datetime
