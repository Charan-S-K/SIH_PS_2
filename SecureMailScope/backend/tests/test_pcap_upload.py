"""
Tests for PCAP upload, format validation, size limits, hashing, and job querying.
"""

import hashlib
import io
import os
import stat
from unittest import mock
import pytest
from fastapi.testclient import TestClient

from app.models.pcap import PcapFile
from app.models.job import AnalysisJob
from app.services.pcap_validator import sanitize_filename, validate_pcap_magic_bytes


# Helper to create standard 24-byte PCAP file header
def make_pcap_bytes(magic: bytes = b"\xd4\xc3\xb2\xa1", payload: bytes = b"test packet bytes") -> bytes:
    """Generate minimal valid PCAP capture content."""
    # Global header: magic (4B) + major (2B) + minor (2B) + thiszone (4B) + sigfigs (4B) + snaplen (4B) + network (4B) = 24B
    header = magic + b"\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
    return header + payload


# Helper to create PCAPNG Section Header Block
def make_pcapng_bytes() -> bytes:
    """Generate minimal valid PCAPNG Section Header Block."""
    shb_magic = b"\x0a\x0d\x0d\x0a"
    total_len = b"\x1c\x00\x00\x00"  # 28 bytes
    byte_order = b"\x4d\x3c\x2b\x1a"  # Little-endian BOM
    version = b"\x01\x00\x00\x00"  # Major 1, Minor 0
    section_len = b"\xff\xff\xff\xff\xff\xff\xff\xff"
    end_len = b"\x1c\x00\x00\x00"
    return shb_magic + total_len + byte_order + version + section_len + end_len


def test_sanitize_filename():
    """Verify filename sanitization prevents path traversal and injection."""
    assert sanitize_filename("../../../etc/shadow.pcap") == "shadow.pcap"
    assert sanitize_filename("..\\..\\windows\\system32.pcap") == "system32.pcap"
    assert sanitize_filename("safe_capture_123.pcap") == "safe_capture_123.pcap"
    assert sanitize_filename("bad!@#$name.pcapng") == "bad____name.pcapng"
    assert sanitize_filename("") == "unnamed_capture.pcap"
    assert sanitize_filename("....") == "capture.pcap"


def test_validate_pcap_magic_bytes():
    """Verify detection of various capture formats."""
    # Standard PCAP LE & BE
    ok, fmt, _ = validate_pcap_magic_bytes(b"\xd4\xc3\xb2\xa1\x00\x00")
    assert ok and fmt == "pcap"
    ok, fmt, _ = validate_pcap_magic_bytes(b"\xa1\xb2\xc3\xd4\x00\x00")
    assert ok and fmt == "pcap"

    # Nanosecond PCAP LE & BE
    ok, fmt, _ = validate_pcap_magic_bytes(b"\x4d\x3c\xb2\xa1\x00\x00")
    assert ok and fmt == "pcap"
    ok, fmt, _ = validate_pcap_magic_bytes(b"\xa1\xb2\x3c\x4d\x00\x00")
    assert ok and fmt == "pcap"

    # PCAPNG
    ok, fmt, _ = validate_pcap_magic_bytes(make_pcapng_bytes())
    assert ok and fmt == "pcapng"

    # Invalid / too short
    ok, fmt, _ = validate_pcap_magic_bytes(b"\x00\x01")
    assert not ok and fmt == "unknown"

    # Corrupt / random
    ok, fmt, _ = validate_pcap_magic_bytes(b"HELLO_WORLD_BYTES")
    assert not ok and fmt == "unknown"


def test_upload_valid_pcap(client: TestClient, tmp_path):
    """Test successful PCAP file upload creates file and job records."""
    content = make_pcap_bytes()
    expected_sha256 = hashlib.sha256(content).hexdigest()
    expected_md5 = hashlib.md5(content).hexdigest()

    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        response = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("test_capture.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["filename"] == "test_capture.pcap"
        assert data["file_size_bytes"] == len(content)
        assert data["sha256"] == expected_sha256
        assert data["md5"] == expected_md5
        assert data["file_format"] == "pcap"
        assert data["status"] == "QUEUED"
        assert "job_id" in data
        assert "file_id" in data

        # Check file exists and permissions are 0o600
        stored_files = os.listdir(tmp_path)
        assert len(stored_files) == 1
        stored_file_path = os.path.join(tmp_path, stored_files[0])
        mode = stat.S_IMODE(os.stat(stored_file_path).st_mode)
        assert mode == 0o600


def test_upload_valid_pcapng(client: TestClient, tmp_path):
    """Test successful PCAPNG format upload."""
    content = make_pcapng_bytes()
    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        response = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("capture.pcapng", io.BytesIO(content), "application/x-pcapng")}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["file_format"] == "pcapng"


def test_upload_invalid_extension(client: TestClient):
    """Test upload fails with 400 when file extension is not allowed."""
    response = client.post(
        "/api/v1/pcap/upload",
        files={"file": ("malicious.exe", io.BytesIO(b"executable"), "application/octet-stream")}
    )
    assert response.status_code == 400
    assert "Invalid file extension" in response.json()["detail"]


def test_upload_invalid_magic_bytes(client: TestClient, tmp_path):
    """Test upload fails with 400 when magic bytes are invalid and leaves no file on disk."""
    fake_content = b"NOT_A_PCAP_AT_ALL_JUST_TEXT"
    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        response = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("fake.pcap", io.BytesIO(fake_content), "application/vnd.tcpdump.pcap")}
        )
        assert response.status_code == 400
        assert "Invalid capture header" in response.json()["detail"]
        assert len(os.listdir(tmp_path)) == 0


def test_upload_empty_file(client: TestClient, tmp_path):
    """Test upload fails with 400 on zero-byte file."""
    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        response = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("empty.pcap", io.BytesIO(b""), "application/vnd.tcpdump.pcap")}
        )
        assert response.status_code == 400
        assert "Empty file uploaded" in response.json()["detail"]


def test_upload_size_limit_exceeded(client: TestClient, tmp_path):
    """Test upload fails with 413 when file exceeds MAX_UPLOAD_SIZE_BYTES."""
    content = make_pcap_bytes(payload=b"A" * 100)
    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)), \
         mock.patch("app.api.v1.pcap.settings.MAX_UPLOAD_SIZE_BYTES", 30):
        response = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("large.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        assert response.status_code == 413
        assert "exceeds maximum allowed size" in response.json()["detail"]
        assert len(os.listdir(tmp_path)) == 0


def test_path_traversal_filename_prevented(client: TestClient, tmp_path):
    """Test directory traversal filenames are strictly sanitized."""
    content = make_pcap_bytes()
    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        response = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("../../../../etc/passwd.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        assert response.status_code == 201
        data = response.json()
        assert data["filename"] == "passwd.pcap"


def test_get_pcap_file_metadata(client: TestClient, tmp_path):
    """Test retrieving PCAP file metadata via GET /api/v1/pcap/{file_id}."""
    content = make_pcap_bytes()
    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        upload_res = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("lookup.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        file_id = upload_res.json()["file_id"]

        get_res = client.get(f"/api/v1/pcap/{file_id}")
        assert get_res.status_code == 200
        data = get_res.json()
        assert data["id"] == file_id
        assert data["original_filename"] == "lookup.pcap"
        assert data["is_valid"] is True
        assert data["file_size_bytes"] == len(content)


def test_get_pcap_file_not_found(client: TestClient):
    """Test 404 response when querying non-existent PCAP file."""
    response = client.get("/api/v1/pcap/non-existent-uuid")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_get_job_status(client: TestClient, tmp_path):
    """Test retrieving job status via GET /api/v1/jobs/{job_id}."""
    content = make_pcap_bytes()
    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        upload_res = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("job_check.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        job_id = upload_res.json()["job_id"]

        job_res = client.get(f"/api/v1/jobs/{job_id}")
        assert job_res.status_code == 200
        data = job_res.json()
        assert data["id"] == job_id
        assert data["status"] == "QUEUED"
        assert data["progress_percent"] == 0
        assert data["pcap_file"]["original_filename"] == "job_check.pcap"


def test_get_job_not_found(client: TestClient):
    """Test 404 response when querying non-existent job."""
    response = client.get("/api/v1/jobs/unknown-job-id")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"]


def test_list_jobs_and_filter(client: TestClient, tmp_path):
    """Test listing jobs with pagination and status filtering."""
    content = make_pcap_bytes()
    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)):
        # Create 2 jobs
        client.post(
            "/api/v1/pcap/upload",
            files={"file": ("file1.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        client.post(
            "/api/v1/pcap/upload",
            files={"file": ("file2.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )

        # List all
        res = client.get("/api/v1/jobs?limit=10")
        assert res.status_code == 200
        data = res.json()
        assert data["total"] >= 2
        assert len(data["jobs"]) >= 2

        # Filter by QUEUED
        res_queued = client.get("/api/v1/jobs?status=QUEUED")
        assert res_queued.status_code == 200
        assert res_queued.json()["total"] >= 2

        # Filter by FAILED (should be 0)
        res_failed = client.get("/api/v1/jobs?status=FAILED")
        assert res_failed.status_code == 200
        assert res_failed.json()["total"] == 0

def test_upload_database_failure_cleanup(client: TestClient, tmp_path):
    """Test that database failures return 503 and clean up stored file from disk."""
    content = make_pcap_bytes()
    with mock.patch("app.api.v1.pcap.settings.UPLOAD_DIR", str(tmp_path)), \
         mock.patch("sqlalchemy.orm.Session.commit", side_effect=Exception("DB Down")):
        response = client.post(
            "/api/v1/pcap/upload",
            files={"file": ("db_fail.pcap", io.BytesIO(content), "application/vnd.tcpdump.pcap")}
        )
        assert response.status_code == 503
        assert "Database service unavailable" in response.json()["detail"]
        assert len(os.listdir(tmp_path)) == 0
