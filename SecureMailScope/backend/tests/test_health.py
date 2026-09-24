"""Tests for health, readiness, and system information endpoints."""

from unittest import mock
from fastapi.testclient import TestClient
from app.main import app


def test_root_endpoint(client: TestClient):
    """Test root API endpoint returns overview links."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["project"] == "SecureMailScope"
    assert "documentation" in data
    assert "health" in data
    assert "readiness" in data


def test_liveness_endpoint(client: TestClient):
    """Test GET /api/v1/health returns healthy liveness state."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data


def test_readiness_healthy(client: TestClient):
    """Test readiness endpoint when database is connected."""
    with mock.patch("app.api.v1.health.check_database_connection", return_value=(True, None)):
        response = client.get("/api/v1/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"]["status"] == "connected"
        assert data["database"]["error"] is None


def test_readiness_database_disconnected(client: TestClient):
    """Test readiness endpoint returns 503 when database is unreachable."""
    with mock.patch(
        "app.api.v1.health.check_database_connection",
        return_value=(False, "Database probe failed: OperationalError: could not connect to server")
    ):
        response = client.get("/api/v1/health/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "not_ready"
        assert data["database"]["status"] == "disconnected"
        assert "OperationalError" in data["database"]["error"]


def test_system_info_endpoint(client: TestClient):
    """Test system info endpoint returns architecture and protocol metadata."""
    response = client.get("/api/v1/health/info")
    assert response.status_code == 200
    data = response.json()
    assert data["project_name"] == "SecureMailScope"
    assert "SMTP" in data["supported_protocols"]
    assert "IMAP" in data["supported_protocols"]
    assert "POP3" in data["supported_protocols"]
    assert "TLS 1.3" in data["cryptographic_standards"]


def test_cors_headers(client: TestClient):
    """Verify CORS preflight handling."""
    headers = {
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "GET"
    }
    response = client.options("/api/v1/health", headers=headers)
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_unhandled_exception_handler():
    """Test that unexpected exceptions trigger global exception handler returning 500 JSON."""
    client_no_raise = TestClient(app, raise_server_exceptions=False)
    with mock.patch("app.api.v1.health.datetime") as mock_dt:
        mock_dt.now.side_effect = RuntimeError("Simulated crash")
        response = client_no_raise.get("/api/v1/health")
        assert response.status_code == 500
        data = response.json()
        assert data["error"] == "InternalServerError"
        assert "path" in data
