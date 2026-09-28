"""
Stage 21 Database & Persistence Hardening Tests.
Tests state transition validation, restart recovery service, report metadata persistence,
foreign key cascade deletion, and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.pcap import PcapFile
from app.models.job import AnalysisJob
from app.models.finding import UnifiedFinding
from app.models.report_metadata import ReportMetadata
from app.schemas.report_metadata import ReportMetadataCreate
from app.services.persistence_hardening import (
    PersistenceHardeningService,
    InvalidStateTransitionError
)


def test_valid_state_transitions(db_session: Session):
    """Test permissible state transitions."""
    pcap = PcapFile(
        original_filename="persistence_test.pcap",
        stored_filename="stored_persistence_test.pcap",
        file_path="/tmp/stored_persistence_test.pcap",
        file_size_bytes=1024,
        sha256="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        md5="1234567890abcdef1234567890abcdef",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(
        pcap_file_id=pcap.id,
        status="PENDING",
        progress_percent=0.0,
        stage_message="Pending execution"
    )
    db_session.add(job)
    db_session.commit()

    # PENDING -> QUEUED
    updated = PersistenceHardeningService.update_job_status_safely(
        db_session, job, "QUEUED", stage_message="Queued in queue"
    )
    assert updated.status == "QUEUED"

    # QUEUED -> PROCESSING
    updated = PersistenceHardeningService.update_job_status_safely(
        db_session, job, "PROCESSING", stage_message="Processing PCAP"
    )
    assert updated.status == "PROCESSING"

    # PROCESSING -> COMPLETED
    updated = PersistenceHardeningService.update_job_status_safely(
        db_session, job, "COMPLETED", stage_message="Analysis completed successfully"
    )
    assert updated.status == "COMPLETED"
    assert updated.progress_percent == 100.0
    assert updated.completed_at is not None


def test_invalid_state_transition_raises_error(db_session: Session):
    """Test illegal state transition attempts raise InvalidStateTransitionError."""
    pcap = PcapFile(
        original_filename="invalid_trans.pcap",
        stored_filename="stored_invalid_trans.pcap",
        file_path="/tmp/stored_invalid_trans.pcap",
        file_size_bytes=1024,
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        md5="abcdef1234567890abcdef1234567890",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(
        pcap_file_id=pcap.id,
        status="COMPLETED",
        progress_percent=100.0,
        stage_message="Already completed"
    )
    db_session.add(job)
    db_session.commit()

    # Attempt illegal transition: COMPLETED -> FAILED
    with pytest.raises(InvalidStateTransitionError):
        PersistenceHardeningService.update_job_status_safely(db_session, job, "FAILED")


def test_recover_interrupted_jobs(db_session: Session):
    """Test recovery of jobs stuck in PROCESSING or QUEUED state upon service restart."""
    pcap = PcapFile(
        original_filename="stuck_job.pcap",
        stored_filename="stored_stuck_job.pcap",
        file_path="/tmp/stored_stuck_job.pcap",
        file_size_bytes=2048,
        sha256="9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef",
        md5="9876543210abcdef9876543210abcdef",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    stuck_job = AnalysisJob(
        pcap_file_id=pcap.id,
        status="PROCESSING",
        progress_percent=45.0,
        stage_message="Processing packets when server restarted"
    )
    db_session.add(stuck_job)
    db_session.commit()

    # Execute recovery service
    recovered_count = PersistenceHardeningService.recover_interrupted_jobs(db_session)
    assert recovered_count >= 1

    db_session.refresh(stuck_job)
    assert stuck_job.status == "INTERRUPTED"
    assert "interrupted" in stuck_job.stage_message.lower()


def test_report_metadata_persistence_and_api(db_session: Session, client: TestClient):
    """Test creating and retrieving ReportMetadata via service and REST API."""
    pcap = PcapFile(
        original_filename="report_test.pcap",
        stored_filename="stored_report_test.pcap",
        file_path="/tmp/stored_report_test.pcap",
        file_size_bytes=512,
        sha256="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        md5="11112222333344445555666677778888",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(
        pcap_file_id=pcap.id,
        status="COMPLETED",
        progress_percent=100.0,
        stage_message="Completed"
    )
    db_session.add(job)
    db_session.commit()

    # 1. Service creation
    report_in = ReportMetadataCreate(
        job_id=job.id,
        report_title="Executive Cryptographic Forensic Audit",
        export_format="PDF",
        file_path="/tmp/reports/audit.pdf",
        file_size_bytes=4096,
        total_findings_included=5,
        posture_score=85.5,
        notes="Stage 21 report metadata test"
    )
    report = PersistenceHardeningService.create_report_metadata(db_session, report_in)
    assert report.id is not None
    assert report.report_title == "Executive Cryptographic Forensic Audit"
    assert report.export_format == "PDF"
    assert len(report.report_hash_sha256) == 64

    # 2. REST API endpoint GET /api/v1/reports/job/{job_id}
    res = client.get(f"/api/v1/reports/job/{job.id}")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    assert data[0]["job_id"] == job.id
    assert data[0]["export_format"] == "PDF"

    # 3. REST API endpoint POST /api/v1/reports
    post_res = client.post("/api/v1/reports", json={
        "job_id": job.id,
        "report_title": "JSON Full Audit Export",
        "export_format": "JSON",
        "notes": "API test"
    })
    assert post_res.status_code == 201
    post_data = post_res.json()
    assert post_data["export_format"] == "JSON"
    assert post_data["job_id"] == job.id


def test_cascade_deletion(db_session: Session):
    """Test foreign key CASCADE deletion from AnalysisJob to ReportMetadata and UnifiedFinding."""
    pcap = PcapFile(
        original_filename="cascade_test.pcap",
        stored_filename="stored_cascade_test.pcap",
        file_path="/tmp/stored_cascade_test.pcap",
        file_size_bytes=1024,
        sha256="4444555566667777888899990000aaaabbbbccccddddeeeeffff111122223333",
        md5="4444555566667777888899990000aaaa",
        file_format="pcap",
        is_valid=True
    )
    db_session.add(pcap)
    db_session.commit()

    job = AnalysisJob(
        pcap_file_id=pcap.id,
        status="COMPLETED",
        progress_percent=100.0,
        stage_message="Completed"
    )
    db_session.add(job)
    db_session.commit()

    finding = UnifiedFinding(
        job_id=job.id,
        finding_type="DEPRECATED_TLS",
        severity="HIGH",
        title="Deprecated TLS 1.0",
        reason="TLS 1.0 detected",
        confidence=0.95,
        confidence_label="HIGH",
        fingerprint="fp_cascade_test"
    )
    db_session.add(finding)

    report = ReportMetadata(
        job_id=job.id,
        report_title="Cascade Test Report",
        export_format="HTML",
        report_hash_sha256="00001111222233334444555566667777888899990000aaaabbbbccccddddeeee"
    )
    db_session.add(report)
    db_session.commit()

    job_id = job.id
    report_id = report.id
    finding_id = finding.id

    # Delete AnalysisJob
    db_session.delete(job)
    db_session.commit()

    # Verify associated entities were cascaded or removed
    assert db_session.query(ReportMetadata).filter(ReportMetadata.id == report_id).first() is None
    assert db_session.query(UnifiedFinding).filter(UnifiedFinding.id == finding_id).first() is None
