"""
REST API Endpoints for TLS Anomaly Detection.
Exposes Isolation Forest anomaly detector training, detector listing, details retrieval,
individual session anomaly evaluation, and job-level batch anomaly analysis.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.tls_anomaly import TlsAnomalyDetectorModel, TlsAnomalyResult
from app.schemas.tls_anomaly import (
    TlsAnomalyTrainRequest,
    TlsAnomalyDetectorResponse,
    TlsAnomalyPredictRequest,
    TlsAnomalyResponse,
    JobAnomalySummaryResponse
)
from app.services.tls_anomaly_detector import TlsAnomalyDetectorService, DISCLAIMER_TEXT
from app.services.ml_feature_pipeline import MlFeaturePipeline

router = APIRouter(prefix="/ml/anomaly", tags=["TLS Anomaly Detection"])


@router.post(
    "/train",
    response_model=TlsAnomalyDetectorResponse,
    summary="Train Isolation Forest TLS Anomaly Detector",
    description="Fits an unsupervised Isolation Forest model on a baseline feature set and computes the calibrated contamination threshold."
)
def train_anomaly_detector(
    req: TlsAnomalyTrainRequest,
    db: Session = Depends(get_db)
) -> TlsAnomalyDetectorResponse:
    """Train unsupervised Isolation Forest detector."""
    service = TlsAnomalyDetectorService()
    try:
        model_db = service.train_detector(db, req)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Anomaly detector training failed: {str(exc)}"
        )

    return TlsAnomalyDetectorResponse.model_validate(model_db)


@router.get(
    "/detectors",
    response_model=List[TlsAnomalyDetectorResponse],
    summary="List all trained TLS anomaly detectors",
    description="Retrieves metadata, calibrated thresholds, algorithm params, and active status for all trained detectors."
)
def list_detectors(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db)
) -> List[TlsAnomalyDetectorResponse]:
    """List trained anomaly detectors."""
    models = db.query(TlsAnomalyDetectorModel).order_by(TlsAnomalyDetectorModel.created_at.desc()).limit(limit).all()
    return [TlsAnomalyDetectorResponse.model_validate(m) for m in models]


@router.get(
    "/detectors/{detector_id}",
    response_model=TlsAnomalyDetectorResponse,
    summary="Get trained anomaly detector details",
    description="Retrieves details and calibrated threshold for a specific anomaly detector by ID or version string."
)
def get_detector_details(
    detector_id: str,
    db: Session = Depends(get_db)
) -> TlsAnomalyDetectorResponse:
    """Fetch anomaly detector details."""
    model_db = db.query(TlsAnomalyDetectorModel).filter(TlsAnomalyDetectorModel.id == detector_id).first()
    if not model_db:
        model_db = db.query(TlsAnomalyDetectorModel).filter(TlsAnomalyDetectorModel.version == detector_id).first()
        if not model_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"TLS Anomaly Detector '{detector_id}' not found"
            )
    return TlsAnomalyDetectorResponse.model_validate(model_db)


@router.post(
    "/predict",
    response_model=TlsAnomalyResponse,
    summary="Evaluate anomaly score for single session feature vector",
    description="Evaluates raw anomaly score against calibrated threshold and returns non-malice disclaimer."
)
def predict_anomaly(
    req: TlsAnomalyPredictRequest,
    db: Session = Depends(get_db)
) -> TlsAnomalyResponse:
    """Evaluate single feature vector anomaly score."""
    service = TlsAnomalyDetectorService()
    try:
        resp = service.predict(db, req)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Anomaly evaluation failed: {str(exc)}"
        )

    return resp


@router.post(
    "/predict-job/{job_id}",
    response_model=JobAnomalySummaryResponse,
    summary="Evaluate TLS anomaly scores for all sessions in a job",
    description="Extracts session feature vectors for an analysis job and evaluates active Isolation Forest anomaly scores."
)
def predict_job_anomalies(
    job_id: str,
    model_version: Optional[str] = Query(default=None, description="Target detector model version string"),
    db: Session = Depends(get_db)
) -> JobAnomalySummaryResponse:
    """Batch anomaly evaluation for job sessions."""
    pipeline = MlFeaturePipeline()
    samples = pipeline._extract_features_from_job(db, job_id)

    if not samples:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No TCP sessions found for job '{job_id}'"
        )

    service = TlsAnomalyDetectorService()
    results: List[TlsAnomalyResponse] = []
    model_ver_used = model_version or "active"

    for s in samples:
        req = TlsAnomalyPredictRequest(
            model_version=model_version,
            features_json=s["features"],
            job_id=job_id,
            tcp_stream=s.get("features", {}).get("tcp_stream")
        )
        resp = service.predict(db, req)
        results.append(resp)
        model_ver_used = resp.model_version

    anomalous_count = sum(1 for r in results if r.is_anomalous)
    total_count = len(results)
    rate = round((anomalous_count / total_count) * 100, 2) if total_count > 0 else 0.0
    thresh = results[0].calibrated_threshold if results else 0.0

    return JobAnomalySummaryResponse(
        job_id=job_id,
        model_version=model_ver_used,
        total_sessions_evaluated=total_count,
        anomalous_sessions_count=anomalous_count,
        anomaly_rate_percent=rate,
        calibrated_threshold=thresh,
        disclaimer_text=DISCLAIMER_TEXT,
        results=results
    )


@router.get(
    "/job/{job_id}",
    response_model=JobAnomalySummaryResponse,
    summary="Get saved TLS anomaly summary for a job",
    description="Retrieves existing saved anomaly evaluation results for an analysis job."
)
def get_job_anomaly_summary(
    job_id: str,
    db: Session = Depends(get_db)
) -> JobAnomalySummaryResponse:
    """Retrieve job anomaly evaluation summary."""
    results_db = db.query(TlsAnomalyResult).filter(TlsAnomalyResult.job_id == job_id).order_by(TlsAnomalyResult.created_at.desc()).all()

    if not results_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No saved TLS anomaly evaluation results found for job '{job_id}'"
        )

    model_ver_used = results_db[0].model_version
    thresh = results_db[0].calibrated_threshold
    anomalous_count = sum(1 for r in results_db if r.is_anomalous)
    total_count = len(results_db)
    rate = round((anomalous_count / total_count) * 100, 2) if total_count > 0 else 0.0

    resp_results = [TlsAnomalyResponse.model_validate(r) for r in results_db]

    return JobAnomalySummaryResponse(
        job_id=job_id,
        model_version=model_ver_used,
        total_sessions_evaluated=total_count,
        anomalous_sessions_count=anomalous_count,
        anomaly_rate_percent=rate,
        calibrated_threshold=thresh,
        disclaimer_text=DISCLAIMER_TEXT,
        results=resp_results
    )
