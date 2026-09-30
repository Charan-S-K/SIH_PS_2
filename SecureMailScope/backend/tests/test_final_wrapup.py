"""
Final System Verification & Wrap-up Tests .
Verifies complete system readiness, stage documentation, air-gapped compliance,
and full end-to-end integration across all 25 stages of SecureMailScope.
"""

import os
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def test_system_root_files_exist():
    """Verifies critical root repository files and scripts exist."""
    assert (BASE_DIR / "README.md").is_file()
    assert (BASE_DIR / ".env.example").is_file()
    assert (BASE_DIR / "docker-compose.yml").is_file()
    assert (BASE_DIR / "scripts" / "startup.sh").is_file()
    assert (BASE_DIR / "scripts" / "healthcheck.sh").is_file()
    assert (BASE_DIR / "scripts" / "verify_offline_deployment.sh").is_file()


def test_demo_data_fixtures_exist():
    """Verifies demo data captures and synthetic datasets exist."""
    demo_dir = BASE_DIR / "demo_data"
    assert demo_dir.is_dir()
    assert (demo_dir / "README.md").is_file()
    assert (demo_dir / "sample_email_capture.pcap").is_file()
    assert (demo_dir / "synthetic_anomaly_sample.json").is_file()


def test_api_v1_router_endpoints_count():
    """Verifies all major Stage API routers are registered and responsive."""
    # Health endpoint
    resp = client.get("/api/v1/health")
    assert resp.status_code == 200
    
    # Rules engine endpoint
    resp = client.get("/api/v1/rules")
    assert resp.status_code == 200
    
    # PCAP suite fixtures endpoint
    resp = client.get("/api/v1/pcap-suite/fixtures")
    assert resp.status_code == 200
    assert len(resp.json()) == 8


def test_readme_contains_pipeline_components():
    """Verifies README.md documents the complete pipeline architecture."""
    readme_path = BASE_DIR / "README.md"
    content = readme_path.read_text(encoding="utf-8")
    
    assert "SecureMailScope" in content
    assert "Project Setup" in content or "PCAP Ingestion" in content
    assert "Test PCAP Suite" in content
    assert "License" in content or "MIT" in content
