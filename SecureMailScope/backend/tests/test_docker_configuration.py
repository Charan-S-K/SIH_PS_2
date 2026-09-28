"""
Stage 22 Docker Configuration Verification Test Suite.
Verifies backend Dockerfile, frontend Dockerfile, docker-compose.yml structure,
volume mappings, healthchecks, and non-root user settings.
"""

import os
import yaml
import pytest


@pytest.fixture
def root_dir():
    """Returns absolute path to project root directory."""
    # Assuming test is in backend/tests/
    current_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(current_dir, "..", ".."))


def test_docker_compose_structure(root_dir):
    """Verifies docker-compose.yml structural validity, service definitions, and healthchecks."""
    compose_path = os.path.join(root_dir, "docker-compose.yml")
    assert os.path.exists(compose_path), "docker-compose.yml must exist at project root"

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_data = yaml.safe_load(f)

    assert "services" in compose_data, "docker-compose.yml must define 'services'"
    services = compose_data["services"]

    # Verify db, backend, and frontend services exist
    assert "db" in services, "db service must be defined"
    assert "backend" in services, "backend service must be defined"
    assert "frontend" in services, "frontend service must be defined"

    # Verify healthchecks are configured
    assert "healthcheck" in services["db"], "db service must have healthcheck"
    assert "healthcheck" in services["backend"], "backend service must have healthcheck"
    assert "healthcheck" in services["frontend"], "frontend service must have healthcheck"

    # Verify volume mounts exist
    assert "volumes" in compose_data, "docker-compose.yml must define persistent volumes"
    volumes = compose_data["volumes"]
    assert "pgdata" in volumes
    assert "pcapdata" in volumes
    assert "modeldata" in volumes
    assert "reportdata" in volumes

    # Verify dependency ordering with service_healthy condition
    backend_depends = services["backend"].get("depends_on", {})
    assert "db" in backend_depends
    assert backend_depends["db"].get("condition") == "service_healthy"


def test_backend_dockerfile_directives(root_dir):
    """Verifies backend Dockerfile multi-stage build, tshark installation, and non-root user."""
    dockerfile_path = os.path.join(root_dir, "backend", "Dockerfile")
    assert os.path.exists(dockerfile_path), "backend/Dockerfile must exist"

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "python:3.11-slim" in content, "Backend Dockerfile must use python:3.11-slim"
    assert "tshark" in content, "Backend Dockerfile must install tshark"
    assert "HEALTHCHECK" in content, "Backend Dockerfile must contain HEALTHCHECK directive"
    assert "USER appuser" in content, "Backend Dockerfile must switch to non-root USER appuser"
    assert "EXPOSE 8000" in content, "Backend Dockerfile must EXPOSE port 8000"
    assert "/app/uploads" in content, "Backend Dockerfile must prepare upload directory"


def test_frontend_dockerfile_directives(root_dir):
    """Verifies frontend Dockerfile multi-stage node build, nginx serving, and healthcheck."""
    dockerfile_path = os.path.join(root_dir, "frontend", "Dockerfile")
    assert os.path.exists(dockerfile_path), "frontend/Dockerfile must exist"

    with open(dockerfile_path, "r", encoding="utf-8") as f:
        content = f.read()

    assert "node:" in content, "Frontend Dockerfile must build using Node"
    assert "nginx:alpine" in content, "Frontend Dockerfile must serve using Nginx Alpine"
    assert "HEALTHCHECK" in content, "Frontend Dockerfile must contain HEALTHCHECK"
    assert "EXPOSE 80" in content, "Frontend Dockerfile must EXPOSE port 80"
