"""
Analysis jobs querying, processing, and packet metadata inspection endpoints.
"""

import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models.job import AnalysisJob
from app.models.packet import PacketMetadata
from app.schemas.job import AnalysisJobResponse, JobListResponse
from app.schemas.packet import PacketListResponse, PacketMetadataResponse, CaptureSummaryResponse
from app.services.pcap_processor import PcapProcessor

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


@router.post(
    "/{job_id}/process",
    response_model=AnalysisJobResponse,
    summary="Process capture for job",
    description="Triggers extraction of packet frames, IP/TCP metadata, and forensic protocols."
)
def process_job(job_id: str, db: Session = Depends(get_db)) -> AnalysisJobResponse:
    """Execute PCAP forensic packet extraction."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    processor = PcapProcessor(db)
    result = processor.process_job(job_id)

    db.refresh(job)
    return AnalysisJobResponse.model_validate(job)


@router.get(
    "/{job_id}/packets",
    response_model=PacketListResponse,
    summary="Get extracted packet metadata",
    description="Retrieves paginated packet metadata records with forensic protocol and stream filtering."
)
def get_job_packets(
    job_id: str,
    limit: int = Query(default=50, ge=1, le=500, description="Max packets to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
    protocol: Optional[str] = Query(default=None, description="Filter by detected protocol (SMTP, TLS, TCP, etc.)"),
    tcp_stream: Optional[int] = Query(default=None, description="Filter by TCP conversation stream ID"),
    port: Optional[int] = Query(default=None, description="Filter by port (source or destination)"),
    db: Session = Depends(get_db)
) -> PacketListResponse:
    """Fetch paginated packet metadata for an analysis job."""
    # Verify job existence
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    query = db.query(PacketMetadata).filter(PacketMetadata.job_id == job_id)

    if protocol:
        query = query.filter(PacketMetadata.detected_protocol.ilike(f"%{protocol}%"))
    if tcp_stream is not None:
        query = query.filter(PacketMetadata.tcp_stream == tcp_stream)
    if port is not None:
        query = query.filter(or_(PacketMetadata.src_port == port, PacketMetadata.dst_port == port))

    total = query.count()
    packets = query.order_by(PacketMetadata.frame_number.asc()).offset(offset).limit(limit).all()

    return PacketListResponse(
        total=total,
        limit=limit,
        offset=offset,
        packets=[PacketMetadataResponse.model_validate(p) for p in packets]
    )


@router.get(
    "/{job_id}/summary",
    response_model=CaptureSummaryResponse,
    summary="Get capture summary statistics",
    description="Returns aggregate packet counts, protocol distribution, and duration for a processed capture."
)
def get_job_summary(job_id: str, db: Session = Depends(get_db)) -> CaptureSummaryResponse:
    """Retrieve high-level summary of processed capture."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    protocols_list = []
    if job.detected_protocols:
        try:
            protocols_list = json.loads(job.detected_protocols)
        except Exception:
            protocols_list = []

    # Count distinct TCP streams
    distinct_streams = (
        db.query(PacketMetadata.tcp_stream)
        .filter(PacketMetadata.job_id == job_id, PacketMetadata.tcp_stream.isnot(None))
        .distinct()
        .count()
    )

    return CaptureSummaryResponse(
        job_id=job.id,
        status=job.status,
        total_packets=job.total_packets,
        tcp_packets=job.tcp_packets,
        udp_packets=job.udp_packets,
        other_packets=job.other_packets,
        duration_seconds=job.duration_seconds,
        capture_start_time=job.capture_start_time,
        capture_end_time=job.capture_end_time,
        detected_protocols=protocols_list,
        distinct_conversations=distinct_streams
    )
