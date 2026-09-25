"""
REST API Endpoints for Stage 14: ML Feature Pipeline.
Exposes versioned feature extraction, feature scaling/preprocessing, train/test split matrices, and leakage checks.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.ml_feature_pipeline import MlFeatureSet
from app.schemas.ml_feature_pipeline import (
    MlFeatureExtractionRequest,
    MlFeatureSetResponse,
    MlTrainTestSplitResponse,
    MlDataLeakageReport
)
from app.services.ml_feature_pipeline import MlFeaturePipeline, FEATURE_NAMES

router = APIRouter(prefix="/ml/pipeline", tags=["ML Feature Pipeline"])


@router.post(
    "/extract",
    response_model=MlFeatureSetResponse,
    summary="Extract, preprocess, and split feature matrix",
    description="Extracts versioned feature vectors from a dataset batch or job, fits scaler parameters strictly on train set, and verifies zero data leakage."
)
def extract_feature_set(
    req: MlFeatureExtractionRequest,
    db: Session = Depends(get_db)
) -> MlFeatureSetResponse:
    """Trigger feature extraction and stratified train/test split."""
    pipeline = MlFeaturePipeline()
    try:
        feature_set = pipeline.process_feature_extraction(db, req)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err)
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Feature extraction failed: {str(exc)}"
        )

    return MlFeatureSetResponse.model_validate(feature_set)


@router.get(
    "/feature-sets",
    response_model=List[MlFeatureSetResponse],
    summary="List versioned ML feature sets",
    description="Retrieves metadata for all extracted feature set runs."
)
def list_feature_sets(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db)
) -> List[MlFeatureSetResponse]:
    """List versioned feature sets."""
    sets = db.query(MlFeatureSet).order_by(MlFeatureSet.created_at.desc()).limit(limit).all()
    return [MlFeatureSetResponse.model_validate(s) for s in sets]


@router.get(
    "/feature-sets/{set_id}",
    response_model=MlFeatureSetResponse,
    summary="Get feature set metadata",
    description="Retrieves metadata, scaling parameters, feature count, and leakage status for a specific feature set."
)
def get_feature_set_details(
    set_id: str,
    db: Session = Depends(get_db)
) -> MlFeatureSetResponse:
    """Fetch feature set details."""
    feature_set = db.query(MlFeatureSet).filter(MlFeatureSet.id == set_id).first()
    if not feature_set:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature set '{set_id}' not found"
        )
    return MlFeatureSetResponse.model_validate(feature_set)


@router.get(
    "/feature-sets/{set_id}/matrices",
    response_model=MlTrainTestSplitResponse,
    summary="Get preprocessed X_train, X_test, y_train, y_test matrices",
    description="Returns preprocessed, z-score scaled numerical feature matrices and ground truth label vectors for ML training."
)
def get_feature_set_matrices(
    set_id: str,
    db: Session = Depends(get_db)
) -> MlTrainTestSplitResponse:
    """Fetch train/test feature and label matrices."""
    feature_set = db.query(MlFeatureSet).filter(MlFeatureSet.id == set_id).first()
    if not feature_set:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature set '{set_id}' not found"
        )

    train_data = feature_set.train_split_json or {}
    test_data = feature_set.test_split_json or {}

    return MlTrainTestSplitResponse(
        feature_set_id=feature_set.id,
        pipeline_version=feature_set.pipeline_version,
        feature_names=FEATURE_NAMES,
        train_samples_count=feature_set.train_samples_count,
        test_samples_count=feature_set.test_samples_count,
        X_train=train_data.get("X_train", []),
        X_test=test_data.get("X_test", []),
        y_train=train_data.get("y_train", []),
        y_test=test_data.get("y_test", []),
        train_sample_ids=train_data.get("sample_ids", []),
        test_sample_ids=test_data.get("sample_ids", [])
    )


@router.get(
    "/feature-sets/{set_id}/leakage-check",
    response_model=MlDataLeakageReport,
    summary="Get data leakage verification report",
    description="Retrieves verification status confirming zero overlap between training and testing samples."
)
def get_feature_set_leakage_report(
    set_id: str,
    db: Session = Depends(get_db)
) -> MlDataLeakageReport:
    """Fetch data leakage verification report."""
    feature_set = db.query(MlFeatureSet).filter(MlFeatureSet.id == set_id).first()
    if not feature_set:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Feature set '{set_id}' not found"
        )

    leakage_details = feature_set.leakage_check_details_json or {}
    return MlDataLeakageReport(**leakage_details)
