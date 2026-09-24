"""
Analysis jobs querying, processing, and packet metadata inspection endpoints.
"""

import json
import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_
from sqlalchemy.orm import Session, joinedload

from app.database import get_db
from app.models.job import AnalysisJob
from app.models.packet import PacketMetadata
from app.models.protocol import ProtocolIdentification
from app.models.session import TcpSession
from app.models.email_analysis import EmailSessionAnalysis
from app.models.starttls import StarttlsAnalysis
from app.models.tls_handshake import TlsHandshakeAnalysis
from app.schemas.job import AnalysisJobResponse, JobListResponse
from app.schemas.packet import PacketListResponse, PacketMetadataResponse, CaptureSummaryResponse
from app.schemas.protocol import ProtocolIdentificationResponse, ProtocolListResponse
from app.schemas.session import TcpSessionResponse, TcpSessionListResponse
from app.schemas.email_analysis import EmailSessionAnalysisResponse, EmailSessionAnalysisListResponse
from app.schemas.starttls import StarttlsAnalysisResponse, StarttlsAnalysisListResponse
from app.schemas.tls_handshake import TlsHandshakeAnalysisResponse, TlsHandshakeAnalysisListResponse
from app.services.pcap_processor import PcapProcessor
from app.services.protocol_identifier import ProtocolIdentifier
from app.services.tcp_reconstructor import TcpReconstructor
from app.services.email_protocol_analyzer import EmailProtocolAnalyzer
from app.services.starttls_analyzer import StarttlsAnalyzer
from app.services.tls_handshake_analyzer import TlsHandshakeAnalyzer


logger = logging.getLogger(__name__)
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


@router.get(
    "/{job_id}/protocols",
    response_model=ProtocolListResponse,
    summary="Get identified protocols and evidence for a job",
    description="Returns all stream-level protocol identifications, confidence ratings, and forensic evidence."
)
def get_job_protocols(job_id: str, db: Session = Depends(get_db)) -> ProtocolListResponse:
    """Retrieve identified protocols and forensic evidence across streams."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    records = db.query(ProtocolIdentification).filter(
        ProtocolIdentification.job_id == job_id
    ).order_by(ProtocolIdentification.tcp_stream.asc().nulls_last()).all()

    # If job is COMPLETED but no protocol records exist (e.g. from previous stages), run identification on the fly
    if not records and job.status == "COMPLETED" and job.pcap_file:
        try:
            identifier = ProtocolIdentifier(db)
            records = identifier.identify_protocols_for_job(job_id)
        except Exception as exc:
            logger.warning("Auto protocol identification failed: %s", exc)

    mail_count = sum(1 for r in records if r.is_mail_protocol)
    return ProtocolListResponse(
        job_id=job.id,
        total_streams=len(records),
        mail_streams=mail_count,
        protocols=[ProtocolIdentificationResponse.model_validate(r) for r in records]
    )


@router.get(
    "/{job_id}/protocols/{tcp_stream}",
    response_model=ProtocolIdentificationResponse,
    summary="Get detailed evidence for a specific stream's protocol",
    description="Returns forensic evidence, matched signatures, frame references, and port analysis for a single stream."
)
def get_stream_protocol(job_id: str, tcp_stream: int, db: Session = Depends(get_db)) -> ProtocolIdentificationResponse:
    """Retrieve protocol identification and forensic evidence for a specific stream."""
    record = db.query(ProtocolIdentification).filter(
        ProtocolIdentification.job_id == job_id,
        ProtocolIdentification.tcp_stream == tcp_stream
    ).first()
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Protocol identification for stream {tcp_stream} in job '{job_id}' not found"
        )
    return ProtocolIdentificationResponse.model_validate(record)


@router.post(
    "/{job_id}/identify-protocols",
    response_model=ProtocolListResponse,
    summary="Run or refresh protocol identification for a job",
    description="Executes forensic protocol identification on all streams in the capture."
)
def identify_job_protocols(job_id: str, db: Session = Depends(get_db)) -> ProtocolListResponse:
    """Execute or refresh protocol identification for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    identifier = ProtocolIdentifier(db)
    try:
        records = identifier.identify_protocols_for_job(job_id)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Protocol identification failed: {str(exc)}"
        )

    mail_count = sum(1 for r in records if r.is_mail_protocol)
    return ProtocolListResponse(
        job_id=job.id,
        total_streams=len(records),
        mail_streams=mail_count,
        protocols=[ProtocolIdentificationResponse.model_validate(r) for r in records]
    )


@router.get(
    "/{job_id}/sessions",
    response_model=TcpSessionListResponse,
    summary="List reconstructed TCP sessions for a job",
    description="Retrieves all reassembled TCP conversation sessions with metadata, lifecycle states, and packet statistics."
)
def list_job_sessions(job_id: str, db: Session = Depends(get_db)) -> TcpSessionListResponse:
    """List all reconstructed TCP sessions for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    sessions = (
        db.query(TcpSession)
        .filter(TcpSession.job_id == job_id)
        .order_by(TcpSession.tcp_stream.asc())
        .all()
    )
    return TcpSessionListResponse(
        job_id=job.id,
        total_sessions=len(sessions),
        sessions=[TcpSessionResponse.model_validate(s) for s in sessions]
    )


@router.get(
    "/{job_id}/sessions/{tcp_stream}",
    response_model=TcpSessionResponse,
    summary="Get reconstructed TCP conversation for a specific stream",
    description="Returns reassembled bidirectional stream data, conversational flow turns, lifecycle flags, and diagnostic anomalies."
)
def get_stream_session(job_id: str, tcp_stream: int, db: Session = Depends(get_db)) -> TcpSessionResponse:
    """Retrieve full reconstructed conversation session for a specific stream."""
    session = db.query(TcpSession).filter(
        TcpSession.job_id == job_id,
        TcpSession.tcp_stream == tcp_stream
    ).first()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"TCP session for stream {tcp_stream} in job '{job_id}' not found"
        )
    return TcpSessionResponse.model_validate(session)


@router.post(
    "/{job_id}/reconstruct-sessions",
    response_model=TcpSessionListResponse,
    summary="Run or refresh TCP session reconstruction for a job",
    description="Executes sequence-number reassembly, out-of-order recovery, and turn generation for all streams."
)
def reconstruct_job_sessions(job_id: str, db: Session = Depends(get_db)) -> TcpSessionListResponse:
    """Execute or refresh TCP session reconstruction for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    reconstructor = TcpReconstructor(db)
    try:
        sessions = reconstructor.reconstruct_job_sessions(job_id)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"TCP session reconstruction failed: {str(exc)}"
        )

    return TcpSessionListResponse(
        job_id=job.id,
        total_sessions=len(sessions),
        sessions=[TcpSessionResponse.model_validate(s) for s in sessions]
    )


@router.get(
    "/{job_id}/email-sessions",
    response_model=EmailSessionAnalysisListResponse,
    summary="List analyzed email protocol sessions for a job",
    description="Retrieves all analyzed SMTP, IMAP, and POP3 sessions with state machine statuses, capabilities, and security warnings."
)
def list_job_email_sessions(job_id: str, db: Session = Depends(get_db)) -> EmailSessionAnalysisListResponse:
    """List all analyzed email protocol sessions for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    sessions = (
        db.query(EmailSessionAnalysis)
        .filter(EmailSessionAnalysis.job_id == job_id)
        .order_by(EmailSessionAnalysis.tcp_stream.asc())
        .all()
    )
    return EmailSessionAnalysisListResponse(
        job_id=job.id,
        total_email_sessions=len(sessions),
        sessions=[EmailSessionAnalysisResponse.model_validate(s) for s in sessions]
    )


@router.get(
    "/{job_id}/email-sessions/{tcp_stream}",
    response_model=EmailSessionAnalysisResponse,
    summary="Get email protocol session analysis for a specific stream",
    description="Returns detailed command-response event timeline, capability list, authentication attempts, and security warnings for a stream."
)
def get_stream_email_session(job_id: str, tcp_stream: int, db: Session = Depends(get_db)) -> EmailSessionAnalysisResponse:
    """Retrieve email protocol analysis for a specific stream."""
    session = db.query(EmailSessionAnalysis).filter(
        EmailSessionAnalysis.job_id == job_id,
        EmailSessionAnalysis.tcp_stream == tcp_stream
    ).first()
    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Email session analysis for stream {tcp_stream} in job '{job_id}' not found"
        )
    return EmailSessionAnalysisResponse.model_validate(session)


@router.post(
    "/{job_id}/analyze-email-protocols",
    response_model=EmailSessionAnalysisListResponse,
    summary="Run or refresh email protocol analysis for a job",
    description="Executes SMTP, IMAP, and POP3 state machine and command-response analysis across all streams."
)
def analyze_job_email_protocols(job_id: str, db: Session = Depends(get_db)) -> EmailSessionAnalysisListResponse:
    """Execute or refresh email protocol analysis for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    analyzer = EmailProtocolAnalyzer(db)
    try:
        sessions = analyzer.analyze_job_sessions(job_id)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Email protocol analysis failed: {str(exc)}"
        )

    return EmailSessionAnalysisListResponse(
        job_id=job.id,
        total_email_sessions=len(sessions),
        sessions=[EmailSessionAnalysisResponse.model_validate(s) for s in sessions]
    )


@router.get(
    "/{job_id}/starttls",
    response_model=StarttlsAnalysisListResponse,
    summary="List STARTTLS and opportunistic TLS analyses for a job",
    description="Retrieves STARTTLS/STLS upgrade negotiation results, downgrade risk alerts, and cleartext credential findings across all streams."
)
def list_job_starttls(job_id: str, db: Session = Depends(get_db)) -> StarttlsAnalysisListResponse:
    """List all opportunistic TLS / STARTTLS analyses for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    analyses = (
        db.query(StarttlsAnalysis)
        .filter(StarttlsAnalysis.job_id == job_id)
        .order_by(StarttlsAnalysis.tcp_stream.asc())
        .all()
    )

    upgraded_count = sum(1 for a in analyses if a.upgrade_status in ("UPGRADED_SUCCESS", "DIRECT_TLS"))
    downgrade_risk_count = sum(1 for a in analyses if a.upgrade_status in ("NOT_REQUESTED_IGNORED", "UPGRADE_REJECTED", "CLEARTEXT_AUTH_AFTER_ADVERTISED"))
    critical_findings_count = sum(
        1 for a in analyses if any(f.get("severity") == "CRITICAL" for f in (a.findings or []))
    )

    return StarttlsAnalysisListResponse(
        job_id=job.id,
        total_streams=len(analyses),
        upgraded_count=upgraded_count,
        downgrade_risk_count=downgrade_risk_count,
        critical_findings_count=critical_findings_count,
        analyses=[StarttlsAnalysisResponse.model_validate(a) for a in analyses]
    )


@router.get(
    "/{job_id}/starttls/{tcp_stream}",
    response_model=StarttlsAnalysisResponse,
    summary="Get STARTTLS analysis for a specific stream",
    description="Returns detailed STARTTLS/STLS negotiation status, evidence frames, response codes, and security findings for a single stream."
)
def get_stream_starttls(job_id: str, tcp_stream: int, db: Session = Depends(get_db)) -> StarttlsAnalysisResponse:
    """Retrieve STARTTLS analysis for a specific stream."""
    analysis = db.query(StarttlsAnalysis).filter(
        StarttlsAnalysis.job_id == job_id,
        StarttlsAnalysis.tcp_stream == tcp_stream
    ).first()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"STARTTLS analysis for stream {tcp_stream} in job '{job_id}' not found"
        )
    return StarttlsAnalysisResponse.model_validate(analysis)


@router.post(
    "/{job_id}/analyze-starttls",
    response_model=StarttlsAnalysisListResponse,
    summary="Run or refresh STARTTLS analysis for a job",
    description="Executes forensic STARTTLS inspection, downgrade detection, and TLS record verification across all streams."
)
def analyze_job_starttls(job_id: str, db: Session = Depends(get_db)) -> StarttlsAnalysisListResponse:
    """Execute or refresh STARTTLS analysis for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    analyzer = StarttlsAnalyzer(db)
    try:
        analyses = analyzer.analyze_job_starttls(job_id)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"STARTTLS analysis failed: {str(exc)}"
        )

    upgraded_count = sum(1 for a in analyses if a.upgrade_status in ("UPGRADED_SUCCESS", "DIRECT_TLS"))
    downgrade_risk_count = sum(1 for a in analyses if a.upgrade_status in ("NOT_REQUESTED_IGNORED", "UPGRADE_REJECTED", "CLEARTEXT_AUTH_AFTER_ADVERTISED"))
    critical_findings_count = sum(
        1 for a in analyses if any(f.get("severity") == "CRITICAL" for f in (a.findings or []))
    )

    return StarttlsAnalysisListResponse(
        job_id=job.id,
        total_streams=len(analyses),
        upgraded_count=upgraded_count,
        downgrade_risk_count=downgrade_risk_count,
        critical_findings_count=critical_findings_count,
        analyses=[StarttlsAnalysisResponse.model_validate(a) for a in analyses]
    )


@router.get(
    "/{job_id}/tls-handshakes",
    response_model=TlsHandshakeAnalysisListResponse,
    summary="List reconstructed TLS Handshake analyses for a job",
    description="Retrieves reconstructed observable TLS Handshake messages, negotiated versions, cipher suites, key-exchange parameters, and alerts across all streams."
)
def list_job_tls_handshakes(job_id: str, db: Session = Depends(get_db)) -> TlsHandshakeAnalysisListResponse:
    """List all observable TLS Handshake analyses for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    analyses = (
        db.query(TlsHandshakeAnalysis)
        .filter(TlsHandshakeAnalysis.job_id == job_id)
        .order_by(TlsHandshakeAnalysis.tcp_stream.asc())
        .all()
    )

    completed_count = sum(1 for a in analyses if a.handshake_status == "COMPLETED")
    tls13_count = sum(1 for a in analyses if a.negotiated_version == "TLS 1.3")
    tls12_count = sum(1 for a in analyses if a.negotiated_version == "TLS 1.2")
    legacy_tls_count = sum(1 for a in analyses if a.negotiated_version in ("TLS 1.1", "TLS 1.0", "SSL 3.0"))
    alert_count = sum(1 for a in analyses if a.has_alert or a.handshake_status == "ALERT_TERMINATED")

    return TlsHandshakeAnalysisListResponse(
        job_id=job.id,
        total_handshakes=len(analyses),
        completed_count=completed_count,
        tls13_count=tls13_count,
        tls12_count=tls12_count,
        legacy_tls_count=legacy_tls_count,
        alert_count=alert_count,
        analyses=[TlsHandshakeAnalysisResponse.model_validate(a) for a in analyses]
    )


@router.get(
    "/{job_id}/tls-handshakes/{tcp_stream}",
    response_model=TlsHandshakeAnalysisResponse,
    summary="Get TLS Handshake analysis for a specific stream",
    description="Returns detailed ClientHello, ServerHello, Certificate, extension parameters, and forensic timeline for a single stream."
)
def get_stream_tls_handshake(job_id: str, tcp_stream: int, db: Session = Depends(get_db)) -> TlsHandshakeAnalysisResponse:
    """Retrieve TLS Handshake analysis for a specific stream."""
    analysis = db.query(TlsHandshakeAnalysis).filter(
        TlsHandshakeAnalysis.job_id == job_id,
        TlsHandshakeAnalysis.tcp_stream == tcp_stream
    ).first()
    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"TLS Handshake analysis for stream {tcp_stream} in job '{job_id}' not found"
        )
    return TlsHandshakeAnalysisResponse.model_validate(analysis)


@router.post(
    "/{job_id}/analyze-tls-handshakes",
    response_model=TlsHandshakeAnalysisListResponse,
    summary="Run or refresh TLS Handshake analysis for a job",
    description="Executes observable TLS record parsing, handshake reconstruction, and cryptographic parameter extraction across all candidate streams."
)
def analyze_job_tls_handshakes(job_id: str, db: Session = Depends(get_db)) -> TlsHandshakeAnalysisListResponse:
    """Execute or refresh TLS Handshake analysis for an analysis job."""
    job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis job with ID '{job_id}' not found"
        )

    analyzer = TlsHandshakeAnalyzer(db)
    try:
        analyses = analyzer.analyze_job_tls_handshakes(job_id)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"TLS Handshake analysis failed: {str(exc)}"
        )

    completed_count = sum(1 for a in analyses if a.handshake_status == "COMPLETED")
    tls13_count = sum(1 for a in analyses if a.negotiated_version == "TLS 1.3")
    tls12_count = sum(1 for a in analyses if a.negotiated_version == "TLS 1.2")
    legacy_tls_count = sum(1 for a in analyses if a.negotiated_version in ("TLS 1.1", "TLS 1.0", "SSL 3.0"))
    alert_count = sum(1 for a in analyses if a.has_alert or a.handshake_status == "ALERT_TERMINATED")

    return TlsHandshakeAnalysisListResponse(
        job_id=job.id,
        total_handshakes=len(analyses),
        completed_count=completed_count,
        tls13_count=tls13_count,
        tls12_count=tls12_count,
        legacy_tls_count=legacy_tls_count,
        alert_count=alert_count,
        analyses=[TlsHandshakeAnalysisResponse.model_validate(a) for a in analyses]
    )



