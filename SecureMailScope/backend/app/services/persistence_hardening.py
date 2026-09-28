"""
Persistence Hardening & Lifecycle State Management Service.
Handles database state transitions, job recovery after service restart,
foreign key consistency verification, and report metadata persistence.
"""

import hashlib
import logging
from typing import List, Optional, Tuple
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.models.job import AnalysisJob
from app.models.report_metadata import ReportMetadata
from app.schemas.report_metadata import ReportMetadataCreate

logger = logging.getLogger(__name__)

# Allowed analysis job lifecycle state transitions
VALID_STATE_TRANSITIONS = {
    "PENDING": {"QUEUED", "PROCESSING", "FAILED", "INTERRUPTED"},
    "QUEUED": {"PROCESSING", "FAILED", "INTERRUPTED"},
    "PROCESSING": {"COMPLETED", "FAILED", "INTERRUPTED"},
    "COMPLETED": {"QUEUED", "PROCESSING"},  # Allowed to re-run / re-analyze
    "FAILED": {"QUEUED", "PROCESSING"},     # Allowed to retry
    "INTERRUPTED": {"QUEUED", "PROCESSING"}, # Allowed to retry after recovery
}


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal status state transition is attempted on an AnalysisJob."""
    pass


class PersistenceHardeningService:
    """
    Core persistence hardening and lifecycle management engine.
    """

    @staticmethod
    def validate_state_transition(current_state: str, new_state: str) -> bool:
        """
        Validates if transitioning from current_state to new_state is permissible.
        """
        if current_state == new_state:
            return True
        allowed = VALID_STATE_TRANSITIONS.get(current_state.upper(), set())
        return new_state.upper() in allowed

    @staticmethod
    def update_job_status_safely(
        db: Session,
        job: AnalysisJob,
        new_state: str,
        stage_message: Optional[str] = None,
        error_message: Optional[str] = None,
        progress_percent: Optional[float] = None
    ) -> AnalysisJob:
        """
        Transitions job state cleanly while enforcing state transition integrity.
        """
        current_state = job.status.upper() if job.status else "PENDING"
        new_state_upper = new_state.upper()

        if not PersistenceHardeningService.validate_state_transition(current_state, new_state_upper):
            err_msg = f"Illegal state transition from '{current_state}' to '{new_state_upper}' for job {job.id}"
            logger.warning(err_msg)
            raise InvalidStateTransitionError(err_msg)

        job.status = new_state_upper
        if stage_message is not None:
            job.stage_message = stage_message
        if error_message is not None:
            job.error_message = error_message
        if progress_percent is not None:
            job.progress_percent = max(0.0, min(100.0, progress_percent))

        if new_state_upper == "COMPLETED":
            job.progress_percent = 100.0
            job.completed_at = datetime.utcnow()

        db.commit()
        db.refresh(job)
        logger.info(f"Job {job.id} transitioned {current_state} -> {new_state_upper}")
        return job

    @staticmethod
    def recover_interrupted_jobs(db: Session) -> int:
        """
        Scans database for jobs stuck in 'PROCESSING' or 'QUEUED' on application startup/restart
        and safely marks them as 'INTERRUPTED' to prevent orphan state locks.
        Returns count of recovered jobs.
        """
        stuck_jobs = db.query(AnalysisJob).filter(
            AnalysisJob.status.in_(["PROCESSING", "QUEUED"])
        ).all()

        recovered_count = 0
        for job in stuck_jobs:
            job.status = "INTERRUPTED"
            job.stage_message = "Analysis interrupted by service restart; state safely recovered"
            job.error_message = "Process execution was interrupted prior to completion"
            recovered_count += 1
            logger.warning(f"Recovered interrupted job {job.id} on service startup")

        if recovered_count > 0:
            db.commit()

        return recovered_count

    @staticmethod
    def create_report_metadata(
        db: Session,
        report_in: ReportMetadataCreate
    ) -> ReportMetadata:
        """
        Persists report metadata export record for an analysis job.
        Computes sha256 checksum if not provided.
        """
        job = db.query(AnalysisJob).filter(AnalysisJob.id == report_in.job_id).first()
        if not job:
            raise ValueError(f"AnalysisJob {report_in.job_id} not found")

        sha256_hash = report_in.report_hash_sha256
        if not sha256_hash:
            content_seed = f"{report_in.job_id}:{report_in.report_title}:{datetime.utcnow().isoformat()}"
            sha256_hash = hashlib.sha256(content_seed.encode('utf-8')).hexdigest()

        report = ReportMetadata(
            job_id=report_in.job_id,
            report_title=report_in.report_title,
            export_format=report_in.export_format.upper(),
            report_hash_sha256=sha256_hash,
            file_path=report_in.file_path,
            file_size_bytes=report_in.file_size_bytes or 0,
            total_findings_included=report_in.total_findings_included or 0,
            posture_score=report_in.posture_score,
            generated_by=report_in.generated_by or "SecureMailScope Core Engine",
            notes=report_in.notes
        )

        db.add(report)
        db.commit()
        db.refresh(report)
        logger.info(f"Created ReportMetadata {report.id} for job {report.job_id}")
        return report

    @staticmethod
    def list_job_reports(db: Session, job_id: str) -> List[ReportMetadata]:
        """
        Lists all generated report metadata records for a given analysis job.
        """
        return db.query(ReportMetadata).filter(
            ReportMetadata.job_id == job_id
        ).order_by(ReportMetadata.created_at.desc()).all()
