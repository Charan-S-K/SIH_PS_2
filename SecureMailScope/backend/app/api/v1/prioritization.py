"""
REST API Endpoints for Prioritization & Explainability Engine.
Exposes evidence-backed finding & session prioritization ranking endpoints
with configurable scoring weights and SHAP feature attribution explanations.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.prioritization import JobPrioritizationSummary, FindingPrioritization
from app.schemas.prioritization import (
    PrioritizationCalculateRequest,
    PrioritizationWeightsConfig,
    FindingPrioritizationResponse,
    JobPrioritizationSummaryResponse
)
from app.services.prioritization_engine import PrioritizationEngineService

router = APIRouter(prefix="/prioritization", tags=["Prioritization Engine"])


@router.post(
    "/calculate/{job_id}",
    response_model=JobPrioritizationSummaryResponse,
    summary="Calculate evidence-backed finding prioritization for a job",
    description="Calculates Risk Priority Scores (0-100) using configurable weights for severity, confidence, exposure, affected sessions, and ML signals."
)
def calculate_prioritization(
    job_id: str,
    req: Optional[PrioritizationCalculateRequest] = None,
    db: Session = Depends(get_db)
) -> JobPrioritizationSummaryResponse:
    """Calculate job prioritization rankings."""
    service = PrioritizationEngineService()
    weights = req.weights if req else None
    try:
        summary_resp = service.calculate_job_prioritization(db, job_id, weights)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prioritization calculation failed: {str(exc)}"
        )

    return summary_resp


@router.get(
    "/job/{job_id}",
    response_model=JobPrioritizationSummaryResponse,
    summary="Get saved prioritization summary for a job",
    description="Retrieves existing saved prioritization rankings and feature attributions for an analysis job."
)
def get_job_prioritization_summary(
    job_id: str,
    db: Session = Depends(get_db)
) -> JobPrioritizationSummaryResponse:
    """Fetch saved job prioritization summary."""
    summary_db = db.query(JobPrioritizationSummary).filter(JobPrioritizationSummary.job_id == job_id).order_by(JobPrioritizationSummary.created_at.desc()).first()

    if not summary_db:
        # Calculate on-the-fly if not previously computed
        service = PrioritizationEngineService()
        try:
            return service.calculate_job_prioritization(db, job_id)
        except ValueError as val_err:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(val_err)
            )

    rankings_db = db.query(FindingPrioritization).filter(FindingPrioritization.job_id == job_id).order_by(FindingPrioritization.rank.asc()).all()
    rankings_resp = [FindingPrioritizationResponse.model_validate(r) for r in rankings_db]

    return JobPrioritizationSummaryResponse(
        id=summary_db.id,
        job_id=job_id,
        total_findings_evaluated=summary_db.total_findings_evaluated,
        critical_count=summary_db.critical_count,
        high_count=summary_db.high_count,
        medium_count=summary_db.medium_count,
        low_count=summary_db.low_count,
        weights_config_json=summary_db.weights_config_json,
        rankings=rankings_resp,
        created_at=summary_db.created_at
    )
