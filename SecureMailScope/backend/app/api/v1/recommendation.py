"""
REST API Endpoints for Stage 19: Recommendations Engine.
Exposes endpoints to generate and retrieve deterministic remediation recommendations
tied to security rules, affected components, configuration snippets, and compliance frameworks.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.recommendation import RemediationRecommendation
from app.schemas.recommendation import (
    RecommendationResponse,
    JobRecommendationsSummaryResponse
)
from app.services.recommendations_engine import RecommendationsEngineService

router = APIRouter(prefix="/recommendations", tags=["Recommendations Engine"])


@router.post(
    "/generate/{job_id}",
    response_model=JobRecommendationsSummaryResponse,
    summary="Generate deterministic remediation recommendations for a job",
    description="Maps rule findings and evidence to step-by-step configuration snippets, affected components, and compliance frameworks."
)
def generate_recommendations(
    job_id: str,
    db: Session = Depends(get_db)
) -> JobRecommendationsSummaryResponse:
    """Generate job remediation recommendations."""
    service = RecommendationsEngineService()
    try:
        summary_resp = service.generate_job_recommendations(db, job_id)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Recommendations generation failed: {str(exc)}"
        )

    return summary_resp


@router.get(
    "/job/{job_id}",
    response_model=JobRecommendationsSummaryResponse,
    summary="Get saved remediation recommendations for a job",
    description="Retrieves existing saved remediation recommendations for an analysis job."
)
def get_job_recommendations_summary(
    job_id: str,
    db: Session = Depends(get_db)
) -> JobRecommendationsSummaryResponse:
    """Fetch saved job recommendations summary."""
    recs_db = db.query(RemediationRecommendation).filter(RemediationRecommendation.job_id == job_id).order_by(RemediationRecommendation.created_at.desc()).all()

    if not recs_db:
        # Calculate on-the-fly if not previously generated
        service = RecommendationsEngineService()
        try:
            return service.generate_job_recommendations(db, job_id)
        except ValueError as val_err:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(val_err)
            )

    crit_c = sum(1 for r in recs_db if r.severity == "CRITICAL")
    high_c = sum(1 for r in recs_db if r.severity == "HIGH")
    med_c = sum(1 for r in recs_db if r.severity == "MEDIUM")
    low_c = sum(1 for r in recs_db if r.severity == "LOW")

    resp_list = [RecommendationResponse.model_validate(r) for r in recs_db]

    return JobRecommendationsSummaryResponse(
        job_id=job_id,
        total_recommendations=len(recs_db),
        critical_count=crit_c,
        high_count=high_c,
        medium_count=med_c,
        low_count=low_c,
        recommendations=resp_list
    )
