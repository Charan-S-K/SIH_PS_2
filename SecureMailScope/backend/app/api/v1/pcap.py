"""
PCAP upload and metadata inspection endpoints.
Enforces size limits, magic-byte format validation, SHA-256 hashing, and secure storage.
"""

import hashlib
import logging
import os
import uuid
from typing import Annotated
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.models.pcap import PcapFile
from app.models.job import AnalysisJob
from app.schemas.pcap import PcapFileResponse, PcapUploadResponse
from app.services.pcap_validator import sanitize_filename, validate_pcap_magic_bytes

logger = logging.getLogger(__name__)

router = APIRouter()
settings = get_settings()


@router.post(
    "/upload",
    response_model=PcapUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload PCAP/PCAPNG capture file",
    description="Validates capture file structure, computes cryptographic hashes, and creates an analysis job."
)
async def upload_pcap(
    file: Annotated[UploadFile, File(description="PCAP or PCAPNG packet capture file")],
    db: Session = Depends(get_db)
) -> PcapUploadResponse:
    """Secure upload handler with streaming size checks and magic byte validation."""
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No filename provided in upload")

    # 1. Sanitize filename and verify allowed extension
    clean_filename = sanitize_filename(file.filename)
    _, ext = os.path.splitext(clean_filename.lower())
    if ext not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Allowed extensions: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )

    # 2. Ensure target storage directory exists
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    file_id = str(uuid.uuid4())
    stored_filename = f"{file_id}{ext}"
    target_path = os.path.join(settings.UPLOAD_DIR, stored_filename)

    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    total_bytes = 0
    header_bytes = b""
    is_valid_format = False
    format_type = "pcap"

    try:
        with open(target_path, "wb") as destination:
            while chunk := await file.read(65536):  # 64 KB streaming chunks
                total_bytes += len(chunk)

                # Check file size limit
                if total_bytes > settings.MAX_UPLOAD_SIZE_BYTES:
                    destination.close()
                    if os.path.exists(target_path):
                        os.remove(target_path)
                    raise HTTPException(
                        status_code=getattr(status, "HTTP_413_CONTENT_TOO_LARGE", 413),
                        detail=f"File exceeds maximum allowed size of {settings.MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB"
                    )

                # Sniff initial bytes for PCAP/PCAPNG magic number
                if len(header_bytes) < 16:
                    header_bytes += chunk[:16 - len(header_bytes)]
                    if len(header_bytes) >= 4:
                        valid, fmt, desc = validate_pcap_magic_bytes(header_bytes)
                        if not valid:
                            destination.close()
                            if os.path.exists(target_path):
                                os.remove(target_path)
                            raise HTTPException(
                                status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"Invalid capture header: {desc}"
                            )
                        is_valid_format = valid
                        format_type = fmt

                sha256_hasher.update(chunk)
                md5_hasher.update(chunk)
                destination.write(chunk)

        # Reject empty files
        if total_bytes == 0:
            if os.path.exists(target_path):
                os.remove(target_path)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty file uploaded (0 bytes)"
            )

        # Enforce restricted file permissions (owner read/write only)
        os.chmod(target_path, 0o600)

    except HTTPException:
        raise
    except Exception as exc:
        if os.path.exists(target_path):
            os.remove(target_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to securely store upload: {str(exc)}"
        )

    # 3. Persist PcapFile and AnalysisJob records safely
    sha256_digest = sha256_hasher.hexdigest()
    md5_digest = md5_hasher.hexdigest()

    pcap_record = PcapFile(
        id=file_id,
        original_filename=clean_filename,
        stored_filename=stored_filename,
        file_path=os.path.abspath(target_path),
        file_size_bytes=total_bytes,
        sha256=sha256_digest,
        md5=md5_digest,
        file_format=format_type,
        is_valid=True
    )

    job_id = str(uuid.uuid4())
    job_record = AnalysisJob(
        id=job_id,
        pcap_file_id=file_id,
        status="QUEUED",
        progress_percent=0,
        stage_message="Capture uploaded and queued for processing"
    )

    try:
        db.add(pcap_record)
        db.add(job_record)
        db.commit()
        db.refresh(pcap_record)
        db.refresh(job_record)
    except Exception as db_exc:
        db.rollback()
        if os.path.exists(target_path):
            os.remove(target_path)
        logger.error("Database persistence failed for upload: %s", db_exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database service unavailable. Capture could not be recorded."
        )

    return PcapUploadResponse(
        job_id=job_record.id,
        file_id=pcap_record.id,
        filename=pcap_record.original_filename,
        file_size_bytes=pcap_record.file_size_bytes,
        sha256=pcap_record.sha256,
        md5=pcap_record.md5,
        file_format=pcap_record.file_format,
        status=job_record.status,
        created_at=job_record.created_at
    )


@router.get(
    "/{file_id}",
    response_model=PcapFileResponse,
    summary="Get PCAP file metadata",
    description="Retrieves metadata, cryptographic hashes, and storage status for an uploaded capture."
)
def get_pcap_file(file_id: str, db: Session = Depends(get_db)) -> PcapFileResponse:
    """Retrieve metadata for a specific uploaded file."""
    pcap = db.query(PcapFile).filter(PcapFile.id == file_id).first()
    if not pcap:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PCAP file with ID '{file_id}' not found"
        )
    return PcapFileResponse.model_validate(pcap)
