"""
REST API Endpoints for Stage 15: ML Risk Classifier.
Exposes Random Forest model training, evaluation metrics retrieval (precision, recall, F1, confusion matrix),
model version listing, and non-override inference prediction endpoints.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.ml_model import MlTrainedModel, MlPredictionResult
from app.models.session import TcpSession
from app.schemas.ml_model import (
    MlTrainModelRequest,
    MlTrainedModelResponse,
    MlPredictRequest,
    MlPredictionResponse,
    MlJobPredictionListResponse
)
from app.services.ml_risk_classifier import MlRiskClassifierService
from app.services.ml_feature_pipeline import MlFeaturePipeline

router = APIRouter(prefix="/ml/models", tags=["ML Risk Classifier"])


@router.post(
    "/train",
    response_model=MlTrainedModelResponse,
    summary="Train Random Forest ML Risk Classifier",
    description="Trains an explainable Random Forest model on an extracted feature set and computes precision, recall, F1, and confusion matrix."
)
def train_model(
    req: MlTrainModelRequest,
    db: Session = Depends(get_db)
) -> MlTrainedModelResponse:
    """Train and evaluate Random Forest model."""
    service = MlRiskClassifierService()
    try:
        model_db = service.train_model(db, req)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model training failed: {str(exc)}"
        )

    return MlTrainedModelResponse.model_validate(model_db)


@router.get(
    "",
    response_model=List[MlTrainedModelResponse],
    summary="List all trained ML models and versions",
    description="Retrieves metadata, hyperparameters, accuracy, F1 score, and active status for all trained models."
)
def list_models(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db)
) -> List[MlTrainedModelResponse]:
    """List trained models."""
    models = db.query(MlTrainedModel).order_by(MlTrainedModel.created_at.desc()).limit(limit).all()
    return [MlTrainedModelResponse.model_validate(m) for m in models]


@router.get(
    "/{model_id}",
    response_model=MlTrainedModelResponse,
    summary="Get trained model details and evaluation metrics",
    description="Retrieves complete model evaluation metrics including precision, recall, F1, confusion matrix, and feature importances."
)
def get_model_details(
    model_id: str,
    db: Session = Depends(get_db)
) -> MlTrainedModelResponse:
    """Fetch trained model details."""
    model_db = db.query(MlTrainedModel).filter(MlTrainedModel.id == model_id).first()
    if not model_db:
        # Check by version string
        model_db = db.query(MlTrainedModel).filter(MlTrainedModel.version == model_id).first()
        if not model_db:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"ML model '{model_id}' not found"
            )
    return MlTrainedModelResponse.model_validate(model_db)


@router.post(
    "/predict",
    response_model=MlPredictionResponse,
    summary="Execute inference prediction on input feature vector",
    description="Runs inference prediction returning class probabilities and risk class while guaranteeing non-override of deterministic facts."
)
def predict_sample(
    req: MlPredictRequest,
    db: Session = Depends(get_db)
) -> MlPredictionResponse:
    """Run model inference prediction."""
    service = MlRiskClassifierService()
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
            detail=f"Inference prediction failed: {str(exc)}"
        )

    return resp


@router.post(
    "/predict-job/{job_id}",
    response_model=MlJobPredictionListResponse,
    summary="Predict ML risk for all sessions in a job",
    description="Extracts session feature vectors for an analysis job and runs active ML model predictions."
)
def predict_job_sessions(
    job_id: str,
    model_version: Optional[str] = Query(default=None, description="Model version string"),
    db: Session = Depends(get_db)
) -> MlJobPredictionListResponse:
    """Run ML predictions for all sessions in a job."""
    pipeline = MlFeaturePipeline()
    samples = pipeline._extract_features_from_job(db, job_id)

    if not samples:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No TCP sessions found for job '{job_id}'"
        )

    service = MlRiskClassifierService()
    predictions: List[MlPredictionResponse] = []

    model_ver_used = model_version or "active"

    for s in samples:
        req = MlPredictRequest(
            model_version=model_version,
            features_json=s["features"],
            job_id=job_id,
            tcp_stream=s.get("features", {}).get("tcp_stream")
        )
        p_resp = service.predict(db, req)
        predictions.append(p_resp)
        model_ver_used = p_resp.model_version

    return MlJobPredictionListResponse(
        job_id=job_id,
        model_version=model_ver_used,
        total_predicted_sessions=len(predictions),
        predictions=predictions
    )
