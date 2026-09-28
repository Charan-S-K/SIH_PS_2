"""
Unit and Integration Tests for Stage 15: ML Risk Classifier.
Verifies Random Forest model training, evaluation metrics (precision, recall, F1, 5x5 confusion matrix),
model versioning, inference prediction, non-override of deterministic rule facts, and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.ml_dataset import MlDatasetBatch
from app.models.ml_feature_pipeline import MlFeatureSet
from app.models.ml_model import MlTrainedModel, MlPredictionResult
from app.schemas.ml_dataset import MlDatasetGenerateRequest
from app.schemas.ml_feature_pipeline import MlFeatureExtractionRequest
from app.schemas.ml_model import MlTrainModelRequest, MlPredictRequest
from app.services.ml_dataset_generator import MlDatasetGenerator
from app.services.ml_feature_pipeline import MlFeaturePipeline
from app.services.ml_risk_classifier import MlRiskClassifierService


@pytest.fixture
def prepare_feature_set(db_session: Session) -> MlFeatureSet:
    """Fixture to generate a synthetic dataset and extract a feature set for classifier testing."""
    gen = MlDatasetGenerator()
    batch = gen.generate_dataset_batch(
        db_session,
        MlDatasetGenerateRequest(name="Classifier Test Batch", sample_count=60, seed=123)
    )

    pipeline = MlFeaturePipeline()
    feature_set = pipeline.process_feature_extraction(
        db_session,
        MlFeatureExtractionRequest(batch_id=batch.id, test_split_ratio=0.2, random_seed=123)
    )
    return feature_set


def test_train_random_forest_model(db_session: Session, prepare_feature_set: MlFeatureSet):
    """Test Random Forest classifier model training, evaluation metrics, and feature importances."""
    service = MlRiskClassifierService()
    req = MlTrainModelRequest(
        feature_set_id=prepare_feature_set.id,
        version="rf-v1.0.test",
        name="Test Random Forest Classifier",
        n_estimators=50,
        max_depth=10,
        random_state=42
    )

    model_db = service.train_model(db_session, req)

    assert model_db.version == "rf-v1.0.test"
    assert model_db.algorithm == "RandomForestClassifier"
    assert model_db.is_active is True
    assert model_db.accuracy >= 0.0
    assert model_db.precision_macro >= 0.0
    assert model_db.recall_macro >= 0.0
    assert model_db.f1_macro >= 0.0

    # Verify confusion matrix structure (5x5 matrix)
    cm = model_db.confusion_matrix_json
    assert len(cm) == 5
    for row in cm:
        assert len(row) == 5

    # Verify feature importances
    importances = model_db.feature_importances_json
    assert len(importances) > 0
    assert "protocol_code" in importances


def test_inference_prediction_and_non_override_guardrail(db_session: Session, prepare_feature_set: MlFeatureSet):
    """
    PROVE: Inference prediction and non-override rule fact guardrail.
    Verifies that model inference predicts risk class, returns probability distribution,
    and strictly sets `is_deterministic_fact_overridden` to False.
    """
    service = MlRiskClassifierService()
    train_req = MlTrainModelRequest(
        feature_set_id=prepare_feature_set.id,
        version="rf-v1.0.infer",
        n_estimators=30
    )
    model_db = service.train_model(db_session, train_req)

    predict_req = MlPredictRequest(
        model_version=model_db.version,
        features_json={
            "protocol_code": 1,
            "tls_version_code": 0,
            "cipher_strength_bits": 0,
            "is_starttls_used": 0,
            "is_auth_encrypted": 0,
            "cert_validity_code": 0,
            "packet_count": 12,
            "duration_seconds": 1.0,
            "total_bytes": 1200,
            "avg_packet_size": 100.0
        }
    )

    pred = service.predict(db_session, predict_req)

    assert pred.model_version == "rf-v1.0.infer"
    assert pred.predicted_class_code in (0, 1, 2, 3, 4)
    assert pred.predicted_label in ("SECURE", "WEAK_CRYPTO", "PLAINTEXT_LEAK", "DOWNGRADE_ATTACK", "ANOMALOUS")
    assert len(pred.confidence_probabilities) > 0
    assert pred.is_deterministic_fact_overridden is False


def test_ml_model_api_endpoints(client: TestClient, db_session: Session, prepare_feature_set: MlFeatureSet):
    """Integration test for Stage 15 ML Risk Classifier REST API endpoints."""
    # 1. POST /api/v1/ml/models/train
    res_train = client.post(
        "/api/v1/ml/models/train",
        json={
            "feature_set_id": prepare_feature_set.id,
            "version": "rf-v1.0.api",
            "name": "API Random Forest",
            "n_estimators": 40,
            "max_depth": 8,
            "random_state": 42
        }
    )
    assert res_train.status_code == 200
    model_data = res_train.json()
    model_id = model_data["id"]
    assert model_data["version"] == "rf-v1.0.api"

    # 2. GET /api/v1/ml/models
    res_list = client.get("/api/v1/ml/models")
    assert res_list.status_code == 200
    assert len(res_list.json()) >= 1

    # 3. GET /api/v1/ml/models/{model_id}
    res_get = client.get(f"/api/v1/ml/models/{model_id}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == model_id

    # 4. POST /api/v1/ml/models/predict
    res_pred = client.post(
        "/api/v1/ml/models/predict",
        json={
            "model_version": "rf-v1.0.api",
            "features_json": {
                "protocol_code": 2,
                "tls_version_code": 5,
                "cipher_strength_bits": 256,
                "is_starttls_used": 0,
                "is_auth_encrypted": 1,
                "cert_validity_code": 1,
                "packet_count": 25,
                "duration_seconds": 1.5,
                "total_bytes": 4500,
                "avg_packet_size": 180.0
            }
        }
    )
    assert res_pred.status_code == 200
    pred_data = res_pred.json()
    assert pred_data["model_version"] == "rf-v1.0.api"
    assert pred_data["is_deterministic_fact_overridden"] is False
