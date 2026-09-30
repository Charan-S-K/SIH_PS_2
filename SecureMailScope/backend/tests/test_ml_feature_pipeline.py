"""
Unit and Integration Tests for ML Feature Pipeline.
Verifies defensible feature extraction, z-score preprocessing fitted strictly on training data,
stratified train/test splitting, zero data leakage proof, and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.ml_dataset import MlDatasetBatch, MlDatasetRecord
from app.models.ml_feature_pipeline import MlFeatureSet
from app.schemas.ml_dataset import MlDatasetGenerateRequest
from app.schemas.ml_feature_pipeline import MlFeatureExtractionRequest
from app.services.ml_dataset_generator import MlDatasetGenerator
from app.services.ml_feature_pipeline import MlFeaturePipeline, FEATURE_NAMES


def test_feature_extraction_and_stratified_split(db_session: Session):
    """Verify feature matrix extraction, preprocessing scaling parameters, and train/test split ratios."""
    gen = MlDatasetGenerator()
    batch = gen.generate_dataset_batch(
        db_session,
        MlDatasetGenerateRequest(name="Feature Pipeline Test Batch", sample_count=40, seed=42)
    )

    pipeline = MlFeaturePipeline()
    req = MlFeatureExtractionRequest(
        batch_id=batch.id,
        pipeline_version="v1.0.0",
        test_split_ratio=0.2,
        random_seed=42
    )

    feature_set = pipeline.process_feature_extraction(db_session, req)

    assert feature_set.pipeline_version == "v1.0.0"
    assert feature_set.total_samples == 40
    assert feature_set.feature_count == len(FEATURE_NAMES)
    assert feature_set.train_samples_count + feature_set.test_samples_count == 40
    assert feature_set.leakage_check_passed is True

    # Check preprocessing scaling params
    params = feature_set.preprocessing_params_json
    assert len(params) == len(FEATURE_NAMES)
    for name in FEATURE_NAMES:
        assert "mean" in params[name]
        assert "std" in params[name]


def test_zero_data_leakage_and_scaler_fit(db_session: Session):
    """
    PROVE: Zero data leakage between train and test splits.
    Verifies that train and test sample IDs have zero intersection and that scaler parameters
    were fitted strictly on training samples.
    """
    gen = MlDatasetGenerator()
    batch = gen.generate_dataset_batch(
        db_session,
        MlDatasetGenerateRequest(name="Leakage Proof Batch", sample_count=50, seed=100)
    )

    pipeline = MlFeaturePipeline()
    req = MlFeatureExtractionRequest(batch_id=batch.id, test_split_ratio=0.25, random_seed=100)
    feature_set = pipeline.process_feature_extraction(db_session, req)

    train_data = feature_set.train_split_json
    test_data = feature_set.test_split_json

    train_ids = set(train_data["sample_ids"])
    test_ids = set(test_data["sample_ids"])

    # PROVE: Zero overlap
    overlap = train_ids.intersection(test_ids)
    assert len(overlap) == 0, f"Data leakage detected! Overlapping sample IDs: {overlap}"
    assert feature_set.leakage_check_passed is True


def test_ml_pipeline_api_endpoints(client: TestClient, db_session: Session):
    """Integration test for Stage 14 ML Feature Pipeline REST API endpoints."""
    # 1. Generate dataset batch
    gen = MlDatasetGenerator()
    batch = gen.generate_dataset_batch(
        db_session,
        MlDatasetGenerateRequest(name="API Feature Pipeline Batch", sample_count=30, seed=555)
    )

    # 2. POST /api/v1/ml/pipeline/extract
    res_ext = client.post(
        "/api/v1/ml/pipeline/extract",
        json={
            "batch_id": batch.id,
            "pipeline_version": "v1.0.0",
            "test_split_ratio": 0.2,
            "random_seed": 555
        }
    )
    assert res_ext.status_code == 200
    set_data = res_ext.json()
    set_id = set_data["id"]
    assert set_data["pipeline_version"] == "v1.0.0"
    assert set_data["total_samples"] == 30
    assert set_data["leakage_check_passed"] is True

    # 3. GET /api/v1/ml/pipeline/feature-sets
    res_list = client.get("/api/v1/ml/pipeline/feature-sets")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1

    # 4. GET /api/v1/ml/pipeline/feature-sets/{set_id}
    res_get = client.get(f"/api/v1/ml/pipeline/feature-sets/{set_id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == set_id

    # 5. GET /api/v1/ml/pipeline/feature-sets/{set_id}/matrices
    res_mat = client.get(f"/api/v1/ml/pipeline/feature-sets/{set_id}/matrices")
    assert res_mat.status_code == 200
    mat_data = res_mat.json()
    assert mat_data["feature_set_id"] == set_id
    assert len(mat_data["X_train"]) == mat_data["train_samples_count"]
    assert len(mat_data["X_test"]) == mat_data["test_samples_count"]
    assert len(mat_data["feature_names"]) == len(FEATURE_NAMES)

    # 6. GET /api/v1/ml/pipeline/feature-sets/{set_id}/leakage-check
    res_leak = client.get(f"/api/v1/ml/pipeline/feature-sets/{set_id}/leakage-check")
    assert res_leak.status_code == 200
    leak_data = res_leak.json()
    assert leak_data["passed"] is True
    assert leak_data["overlap_sample_ids_count"] == 0
