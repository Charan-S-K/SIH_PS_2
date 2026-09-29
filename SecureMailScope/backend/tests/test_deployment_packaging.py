"""
Stage 23 Deployment Packaging Verification Test Suite.
Verifies deployment scripts, .env.example configuration keys, demo data fixtures,
and offline execution readiness.
"""

import os
import json
import pytest


@pytest.fixture
def project_root():
    """Returns absolute path to SecureMailScope root directory."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(current_dir, "..", ".."))


def test_scripts_exist_and_executable(project_root):
    """Verifies startup.sh, healthcheck.sh, and verify_offline_deployment.sh exist and have +x execution permissions."""
    scripts_dir = os.path.join(project_root, "scripts")
    assert os.path.exists(scripts_dir), "scripts directory must exist"

    required_scripts = ["startup.sh", "healthcheck.sh", "verify_offline_deployment.sh"]
    for script_name in required_scripts:
        script_path = os.path.join(scripts_dir, script_name)
        assert os.path.exists(script_path), f"Script {script_name} must exist"
        assert os.access(script_path, os.X_OK), f"Script {script_name} must be executable (+x)"


def test_env_example_keys(project_root):
    """Verifies .env.example contains necessary deployment environment keys."""
    env_path = os.path.join(project_root, ".env.example")
    assert os.path.exists(env_path), ".env.example must exist at root"

    with open(env_path, "r", encoding="utf-8") as f:
        content = f.read()

    required_keys = [
        "ENVIRONMENT",
        "DATABASE_URL",
        "OFFLINE_MODE",
        "UPLOAD_DIR",
        "MODELS_CACHE_DIR",
        "REPORTS_STORAGE_DIR",
        "CORS_ORIGINS"
    ]
    for key in required_keys:
        assert key in content, f".env.example must contain key '{key}'"


def test_demo_data_fixtures(project_root):
    """Verifies demo_data directory, README, sample PCAP, and synthetic JSON dataset exist."""
    demo_dir = os.path.join(project_root, "demo_data")
    assert os.path.exists(demo_dir), "demo_data directory must exist"

    readme_path = os.path.join(demo_dir, "README.md")
    json_path = os.path.join(demo_dir, "synthetic_anomaly_sample.json")
    pcap_path = os.path.join(demo_dir, "sample_email_capture.pcap")

    assert os.path.exists(readme_path), "demo_data/README.md must exist"
    assert os.path.exists(json_path), "demo_data/synthetic_anomaly_sample.json must exist"
    assert os.path.exists(pcap_path), "demo_data/sample_email_capture.pcap must exist"

    # Validate synthetic JSON structure
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "samples" in data
    assert len(data["samples"]) > 0


def test_readme_documentation_completeness(project_root):
    """Verifies README.md documents deployment scripts, docker compose, and offline usage."""
    readme_path = os.path.join(project_root, "README.md")
    assert os.path.exists(readme_path), "README.md must exist at root"

    with open(readme_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "startup.sh" in content
    assert "healthcheck.sh" in content
    assert "demo_data" in content
    assert "docker compose" in content.lower()
