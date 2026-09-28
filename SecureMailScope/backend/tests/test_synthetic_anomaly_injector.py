"""
Unit and Integration Tests for Stage 17: Synthetic Anomaly Injection & Evaluation.
Verifies controlled synthetic anomaly injection profiles, ground truth generation,
Isolation Forest detector evaluation metrics (precision, recall, F1, FPR), and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.ml_feature_pipeline import MlFeatureSet
from app.models.synthetic_anomaly import SyntheticAnomalyBatch, SyntheticAnomalyEvaluation
from app.schemas.ml_dataset import MlDatasetGenerateRequest
from app.schemas.ml_feature_pipeline import MlFeatureExtractionRequest
from app.schemas.tls_anomaly import TlsAnomalyTrainRequest
from app.schemas.synthetic_anomaly import (
    SyntheticAnomalyProfile,
    SyntheticAnomalyInjectRequest,
    SyntheticAnomalyEvaluateRequest
)
from app.services.ml_dataset_generator import MlDatasetGenerator
from app.services.ml_feature_pipeline import MlFeaturePipeline
from app.services.tls_anomaly_detector import TlsAnomalyDetectorService, DISCLAIMER_TEXT
from app.services.synthetic_anomaly_injector import SyntheticAnomalyInjectorService


@pytest.fixture
def prepare_feature_set(db_session: Session) -> MlFeatureSet:
    """Fixture to generate synthetic dataset batch and extract feature set for testing."""
    gen = MlDatasetGenerator()
    batch = gen.generate_dataset_batch(
        db_session,
        MlDatasetGenerateRequest(name="Stage 17 Test Batch", sample_count=60, seed=123)
    )

    pipeline = MlFeaturePipeline()
    feature_set = pipeline.process_feature_extraction(
        db_session,
        MlFeatureExtractionRequest(batch_id=batch.id, test_split_ratio=0.2, random_seed=123)
    )
    return feature_set


def test_inject_synthetic_anomalies(db_session: Session, prepare_feature_set: MlFeatureSet):
    """Test injecting controlled synthetic anomalies into baseline feature set."""
    service = SyntheticAnomalyInjectorService()
    req = SyntheticAnomalyInjectRequest(
        feature_set_id=prepare_feature_set.id,
        anomaly_profile=SyntheticAnomalyProfile.DEPRECATED_TLS_SPIKE,
        injection_rate=0.20,
        seed=42
    )

    batch_db = service.inject_anomalies(db_session, req)

    assert batch_db.baseline_feature_set_id == prepare_feature_set.id
    assert batch_db.anomaly_profile == "DEPRECATED_TLS_SPIKE"
    assert batch_db.injection_rate == 0.20
    assert batch_db.injected_samples_count > 0
    assert "y_ground_truth" in batch_db.injected_data_json
    assert sum(batch_db.injected_data_json["y_ground_truth"]) == batch_db.injected_samples_count


def test_evaluate_synthetic_injection(db_session: Session, prepare_feature_set: MlFeatureSet):
    """Test evaluating active Isolation Forest anomaly detector against injected ground truth."""
    # Train Isolation Forest detector
    detector_service = TlsAnomalyDetectorService()
    model_db = detector_service.train_detector(
        db_session,
        TlsAnomalyTrainRequest(feature_set_id=prepare_feature_set.id, version="iforest-eval-v1")
    )

    # Inject synthetic anomalies
    injector_service = SyntheticAnomalyInjectorService()
    batch_db = injector_service.inject_anomalies(
        db_session,
        SyntheticAnomalyInjectRequest(
            feature_set_id=prepare_feature_set.id,
            anomaly_profile=SyntheticAnomalyProfile.EXPIRED_CERT_SURGE,
            injection_rate=0.25,
            seed=42
        )
    )

    # Evaluate detector against injection batch
    eval_resp = injector_service.evaluate_injection(
        db_session,
        SyntheticAnomalyEvaluateRequest(
            injection_batch_id=batch_db.id,
            detector_version=model_db.version
        )
    )

    assert eval_resp.injection_batch_id == batch_db.id
    assert eval_resp.detector_version == model_db.version
    assert eval_resp.total_samples == batch_db.total_samples_count
    assert eval_resp.total_injected_anomalies == batch_db.injected_samples_count
    assert 0.0 <= eval_resp.precision <= 1.0
    assert 0.0 <= eval_resp.recall <= 1.0
    assert 0.0 <= eval_resp.f1_score <= 1.0
    assert 0.0 <= eval_resp.false_positive_rate <= 1.0
    assert eval_resp.disclaimer_text == DISCLAIMER_TEXT


def test_api_synthetic_anomaly_endpoints(client: TestClient, db_session: Session, prepare_feature_set: MlFeatureSet):
    """Test REST API POST /ml/anomaly/synthetic/inject, GET /injections, POST /evaluate."""
    # Train detector first
    detector_service = TlsAnomalyDetectorService()
    detector_service.train_detector(
        db_session,
        TlsAnomalyTrainRequest(feature_set_id=prepare_feature_set.id, version="iforest-api-eval")
    )

    # Inject endpoint
    inject_payload = {
        "feature_set_id": prepare_feature_set.id,
        "anomaly_profile": "UNENCRYPTED_AUTH_BURST",
        "injection_rate": 0.15,
        "seed": 42
    }
    resp = client.post("/api/v1/ml/anomaly/synthetic/inject", json=inject_payload)
    assert resp.status_code == 200
    batch_data = resp.json()

    assert batch_data["anomaly_profile"] == "UNENCRYPTED_AUTH_BURST"
    assert batch_data["injected_samples_count"] > 0

    # List injections endpoint
    list_resp = client.get("/api/v1/ml/anomaly/synthetic/injections")
    assert list_resp.status_code == 200
    injections = list_resp.json()
    assert len(injections) >= 1

    # Evaluate endpoint
    eval_payload = {
        "injection_batch_id": batch_data["id"]
    }
    eval_resp = client.post("/api/v1/ml/anomaly/synthetic/evaluate", json=eval_payload)
    assert eval_resp.status_code == 200
    eval_data = eval_resp.json()

    assert eval_data["injection_batch_id"] == batch_data["id"]
    assert "precision" in eval_data
    assert "recall" in eval_data
    assert "f1_score" in eval_data
    assert "false_positive_rate" in eval_data
    assert DISCLAIMER_TEXT in eval_data["disclaimer_text"]
