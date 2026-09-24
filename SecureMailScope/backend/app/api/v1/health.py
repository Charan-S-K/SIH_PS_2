"""
Health, readiness, and system information endpoints.
Provides liveness, readiness probes for orchestration and UI connectivity verification.
"""

from datetime import datetime, timezone
from typing import Dict, Any, Optional
from fastapi import APIRouter, Response, status
from pydantic import BaseModel, Field

from app.config import get_settings
from app.database import check_database_connection

router = APIRouter()
settings = get_settings()


class HealthLivenessResponse(BaseModel):
    """Liveness probe response."""
    status: str = Field(default="healthy", description="Application operational status")
    version: str = Field(description="Application version")
    environment: str = Field(description="Current deployment environment")
    timestamp: datetime = Field(description="Current UTC timestamp")


class DatabaseStatus(BaseModel):
    """Database connectivity status details."""
    status: str = Field(description="Connection status: connected | disconnected")
    error: Optional[str] = Field(default=None, description="Diagnostic error message if disconnected")


class HealthReadinessResponse(BaseModel):
    """Readiness probe response."""
    status: str = Field(description="Readiness status: ready | not_ready")
    database: DatabaseStatus = Field(description="Database subsystem status")
    timestamp: datetime = Field(description="Current UTC timestamp")


class SystemInfoResponse(BaseModel):
    """System information and environment details."""
    project_name: str
    project_description: str
    version: str
    environment: str
    debug: bool
    api_prefix: str
    supported_protocols: list[str] = ["SMTP", "IMAP", "POP3"]
    cryptographic_standards: list[str] = ["TLS 1.2", "TLS 1.3", "X.509 PKI"]
    current_stage: str = "Stage 00 — Foundation"


@router.get(
    "",
    response_model=HealthLivenessResponse,
    summary="Liveness check",
    description="Returns OK if the FastAPI backend process is running and responding."
)
def get_liveness() -> HealthLivenessResponse:
    """Basic liveness probe."""
    return HealthLivenessResponse(
        status="healthy",
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(timezone.utc)
    )


@router.get(
    "/ready",
    response_model=HealthReadinessResponse,
    summary="Readiness check",
    description="Verifies backend readiness including database connectivity."
)
def get_readiness(response: Response) -> HealthReadinessResponse:
    """Readiness probe checking database connectivity."""
    db_ok, db_err = check_database_connection()
    now = datetime.now(timezone.utc)

    if db_ok:
        return HealthReadinessResponse(
            status="ready",
            database=DatabaseStatus(status="connected", error=None),
            timestamp=now
        )
    else:
        # Set 503 status code for container/load balancer readiness probes
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return HealthReadinessResponse(
            status="not_ready",
            database=DatabaseStatus(status="disconnected", error=db_err),
            timestamp=now
        )


@router.get(
    "/info",
    response_model=SystemInfoResponse,
    summary="System information",
    description="Returns application metadata, configuration status, and supported protocols."
)
def get_system_info() -> SystemInfoResponse:
    """Detailed system and architecture metadata."""
    return SystemInfoResponse(
        project_name=settings.PROJECT_NAME,
        project_description=settings.PROJECT_DESCRIPTION,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        debug=settings.DEBUG,
        api_prefix=settings.API_V1_STR
    )
