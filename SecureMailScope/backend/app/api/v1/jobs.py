"""
Analysis jobs querying and status endpoints.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models.job import AnalysisJob
from app.schemas.job import AnalysisJobResponse, JobListResponse

router = APIRouter()


@router.get(
    "",
    response_model=JobListResponse,
    summary="List analysis jobs",
    description="Retrieves a paginated list of analysis jobs with filtering by status."
)
def list_jobs(
    limit: int = Query(default=50, ge=1, le=100, description="Max jobs to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    status: Optional[str] = Query(default=None, description="Filter by status (QUEUED, PROCESSING, etc.)"),
    db: Session = Depends(get_db)
) -> JobListResponse:
    """List jobs with pagination and status filter."""
    query = db.query(AnalysisJob).options(joinedload(AnalysisJob.pcap_file))
    if status:
        query = query.filter(AnalysisJob.status == status.upper())

    total = query.count()
    jobs = query.order_by(AnalysisJob.created_at.desc()).offset(offset).limit(limit).all()

    return JobListResponse(
        total=total,
        limit=limit,
        offset=offset,
        jobs=[AnalysisJobResponse.model_validate(j) for j in jobs]
    )


@router.get(
    "/{job_id}",
    response_model=AnalysisJobResponse,
    summary="Get analysis job status",
    description="Retrieves the current lifecycle status and metadata of an analysis job."
)
def get_job(job_id: str, db: Session = Depends(get_db)) -> AnalysisJobResponse:
    """Fetch single job by UUID with linked PCAP file metadata."""
    job = (
        db.query(AnalysisJob)
        .options(joinedload(AnalysisJob.pcap_file))
        .filter(AnalysisJob.id == job_id)
        .first()
    )
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )
    return AnalysisJobResponse.model_validate(job)
