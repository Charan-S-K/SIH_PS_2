"""
REST API endpoints for Report Metadata persistence and job export management.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.report_metadata import ReportMetadataCreate, ReportMetadataResponse
from app.services.persistence_hardening import PersistenceHardeningService

router = APIRouter(prefix="/reports", tags=["Report Metadata"])


@router.post(
    "",
    response_model=ReportMetadataResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Record generated report metadata"
)
def create_report_record(
    report_in: ReportMetadataCreate,
    db: Session = Depends(get_db)
):
    """
    Persists metadata for a generated forensic report (PDF, JSON, HTML, CSV).
    """
    try:
        return PersistenceHardeningService.create_report_metadata(db, report_in)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record report metadata: {str(exc)}"
        )


@router.get(
    "/job/{job_id}",
    response_model=List[ReportMetadataResponse],
    summary="Get all report export metadata records for a job"
)
def get_job_reports(
    job_id: str,
    db: Session = Depends(get_db)
):
    """
    Retrieves all recorded report metadata exports for the specified analysis job.
    """
    return PersistenceHardeningService.list_job_reports(db, job_id)
