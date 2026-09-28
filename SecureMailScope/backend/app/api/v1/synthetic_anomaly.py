"""
REST API Endpoints for Stage 17: Synthetic Anomaly Injection & Evaluation.
Exposes endpoints to inject controlled synthetic anomaly profiles into feature sets
and evaluate anomaly detector performance metrics (precision, recall, F1, FPR).
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.synthetic_anomaly import SyntheticAnomalyBatch, SyntheticAnomalyEvaluation
from app.schemas.synthetic_anomaly import (
    SyntheticAnomalyInjectRequest,
    SyntheticAnomalyBatchResponse,
    SyntheticAnomalyEvaluateRequest,
    SyntheticAnomalyEvaluationResponse
)
from app.services.synthetic_anomaly_injector import SyntheticAnomalyInjectorService

router = APIRouter(prefix="/ml/anomaly/synthetic", tags=["Synthetic Anomaly Injection"])


@router.post(
    "/inject",
    response_model=SyntheticAnomalyBatchResponse,
    summary="Inject synthetic anomaly profile into baseline feature set",
    description="Injects controlled synthetic anomalies (e.g. EXPIRED_CERT_SURGE, DEPRECATED_TLS_SPIKE) into a feature set and records ground truth."
)
def inject_synthetic_anomalies(
    req: SyntheticAnomalyInjectRequest,
    db: Session = Depends(get_db)
) -> SyntheticAnomalyBatchResponse:
    """Inject synthetic anomaly profile."""
    service = SyntheticAnomalyInjectorService()
    try:
        batch_db = service.inject_anomalies(db, req)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Synthetic anomaly injection failed: {str(exc)}"
        )

    return SyntheticAnomalyBatchResponse.model_validate(batch_db)


@router.get(
    "/injections",
    response_model=List[SyntheticAnomalyBatchResponse],
    summary="List all synthetic anomaly injection batches",
    description="Retrieves metadata, profile names, injection rates, and sample counts for all injection batches."
)
def list_synthetic_injections(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db)
) -> List[SyntheticAnomalyBatchResponse]:
    """List injection batches."""
    batches = db.query(SyntheticAnomalyBatch).order_by(SyntheticAnomalyBatch.created_at.desc()).limit(limit).all()
    return [SyntheticAnomalyBatchResponse.model_validate(b) for b in batches]


@router.get(
    "/injections/{injection_id}",
    response_model=SyntheticAnomalyBatchResponse,
    summary="Get synthetic anomaly injection batch details",
    description="Fetches details and injection metadata for a specific injection batch."
)
def get_synthetic_injection_details(
    injection_id: str,
    db: Session = Depends(get_db)
) -> SyntheticAnomalyBatchResponse:
    """Fetch injection batch details."""
    batch_db = db.query(SyntheticAnomalyBatch).filter(SyntheticAnomalyBatch.id == injection_id).first()
    if not batch_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Synthetic anomaly injection batch '{injection_id}' not found"
        )
    return SyntheticAnomalyBatchResponse.model_validate(batch_db)


@router.post(
    "/evaluate",
    response_model=SyntheticAnomalyEvaluationResponse,
    summary="Evaluate anomaly detector performance against injected ground truth",
    description="Evaluates active or specified Isolation Forest detector performance (precision, recall, F1, FPR, confusion matrix)."
)
def evaluate_synthetic_injection(
    req: SyntheticAnomalyEvaluateRequest,
    db: Session = Depends(get_db)
) -> SyntheticAnomalyEvaluationResponse:
    """Evaluate detector against synthetic ground truth."""
    service = SyntheticAnomalyInjectorService()
    try:
        resp = service.evaluate_injection(db, req)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Synthetic anomaly evaluation failed: {str(exc)}"
        )

    return resp
