"""
Unit and Integration Tests for TLS Anomaly Detection.
Verifies unsupervised Isolation Forest model training, threshold calibration,
raw anomaly score evaluation, non-malice proof disclaimer text, and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.ml_feature_pipeline import MlFeatureSet
from app.models.tls_anomaly import TlsAnomalyDetectorModel, TlsAnomalyResult
from app.models.session import TcpSession
from app.schemas.ml_dataset import MlDatasetGenerateRequest
from app.schemas.ml_feature_pipeline import MlFeatureExtractionRequest
from app.schemas.tls_anomaly import TlsAnomalyTrainRequest, TlsAnomalyPredictRequest
from app.services.ml_dataset_generator import MlDatasetGenerator
from app.services.ml_feature_pipeline import MlFeaturePipeline
from app.services.tls_anomaly_detector import TlsAnomalyDetectorService, DISCLAIMER_TEXT


@pytest.fixture
def prepare_feature_set(db_session: Session) -> MlFeatureSet:
    """Fixture to generate synthetic dataset batch and extract feature set for anomaly detector training."""
    gen = MlDatasetGenerator()
    batch = gen.generate_dataset_batch(
        db_session,
        MlDatasetGenerateRequest(name="Anomaly Detector Test Batch", sample_count=80, seed=42)
    )

    pipeline = MlFeaturePipeline()
    feature_set = pipeline.process_feature_extraction(
        db_session,
        MlFeatureExtractionRequest(batch_id=batch.id, test_split_ratio=0.2, random_seed=42)
    )
    return feature_set


def test_train_tls_anomaly_detector(db_session: Session, prepare_feature_set: MlFeatureSet):
    """Test fitting Isolation Forest model and percentile decision threshold calibration."""
    service = TlsAnomalyDetectorService()
    req = TlsAnomalyTrainRequest(
        feature_set_id=prepare_feature_set.id,
        version="iforest-v1.0.test",
        name="Test TLS Anomaly Detector",
        contamination=0.05,
        n_estimators=50,
        random_state=42
    )

    model_db = service.train_detector(db_session, req)

    assert model_db.version == "iforest-v1.0.test"
    assert model_db.algorithm == "IsolationForest"
    assert model_db.contamination == 0.05
    assert model_db.is_active is True
    assert isinstance(model_db.calibrated_threshold, float)
    assert model_db.baseline_samples_count > 0


def test_predict_anomaly_score_and_disclaimer(db_session: Session, prepare_feature_set: MlFeatureSet):
    """Test raw anomaly score evaluation, threshold comparison, and non-malice disclaimer."""
    service = TlsAnomalyDetectorService()
    train_req = TlsAnomalyTrainRequest(
        feature_set_id=prepare_feature_set.id,
        version="iforest-v1.1.test",
        contamination=0.1,
        n_estimators=50,
        random_state=42
    )
    model_db = service.train_detector(db_session, train_req)

    # Normal-like sample features
    normal_features = {
        "cipher_suite_code": 0x1301,
        "tls_version_code": 0x0303,
        "key_exchange_bits": 256,
        "cert_validity_days": 365,
        "packet_count": 15,
        "total_bytes": 2048,
        "duration_ms": 150.0
    }

    pred_req = TlsAnomalyPredictRequest(
        model_version=model_db.version,
        features_json=normal_features
    )

    res = service.predict(db_session, pred_req)

    assert res.model_version == "iforest-v1.1.test"
    assert isinstance(res.raw_anomaly_score, float)
    assert res.calibrated_threshold == model_db.calibrated_threshold
    assert res.disclaimer_text == DISCLAIMER_TEXT
    assert res.anomaly_label in ["NORMAL_BEHAVIOR", "ANOMALOUS_BEHAVIOR"]
    assert res.is_anomalous == (res.raw_anomaly_score < res.calibrated_threshold)


def test_api_train_and_list_anomaly_detectors(client: TestClient, db_session: Session, prepare_feature_set: MlFeatureSet):
    """Test REST API POST /ml/anomaly/train and GET /ml/anomaly/detectors."""
    train_payload = {
        "feature_set_id": prepare_feature_set.id,
        "version": "iforest-api-v1",
        "name": "API TLS Anomaly Detector",
        "contamination": 0.05,
        "n_estimators": 30,
        "random_state": 42
    }

    resp = client.post("/api/v1/ml/anomaly/train", json=train_payload)
    assert resp.status_code == 200
    data = resp.json()
    assert data["version"] == "iforest-api-v1"
    assert data["algorithm"] == "IsolationForest"
    assert data["is_active"] is True

    # List detectors
    list_resp = client.get("/api/v1/ml/anomaly/detectors")
    assert list_resp.status_code == 200
    detectors = list_resp.json()
    assert len(detectors) >= 1
    assert detectors[0]["version"] == "iforest-api-v1"

    # Get detector details
    detail_resp = client.get(f"/api/v1/ml/anomaly/detectors/{data['id']}")
    assert detail_resp.status_code == 200
    assert detail_resp.json()["id"] == data["id"]


def test_api_predict_anomaly(client: TestClient, db_session: Session, prepare_feature_set: MlFeatureSet):
    """Test REST API POST /ml/anomaly/predict."""
    service = TlsAnomalyDetectorService()
    model_db = service.train_detector(
        db_session,
        TlsAnomalyTrainRequest(feature_set_id=prepare_feature_set.id, version="iforest-pred-v1")
    )

    predict_payload = {
        "model_version": model_db.version,
        "features_json": {
            "cipher_suite_code": 0x0005,
            "tls_version_code": 0x0300,
            "key_exchange_bits": 512,
            "cert_validity_days": 1,
            "packet_count": 500,
            "total_bytes": 100000,
            "duration_ms": 5.0
        }
    }

    resp = client.post("/api/v1/ml/anomaly/predict", json=predict_payload)
    assert resp.status_code == 200
    res_data = resp.json()

    assert "raw_anomaly_score" in res_data
    assert "calibrated_threshold" in res_data
    assert "is_anomalous" in res_data
    assert "disclaimer_text" in res_data
    assert DISCLAIMER_TEXT in res_data["disclaimer_text"]


def test_api_job_anomaly_detection(client: TestClient, db_session: Session, prepare_feature_set: MlFeatureSet):
    """Test REST API POST /ml/anomaly/predict-job/{job_id} and GET /ml/anomaly/job/{job_id}."""
    service = TlsAnomalyDetectorService()
    model_db = service.train_detector(
        db_session,
        TlsAnomalyTrainRequest(feature_set_id=prepare_feature_set.id, version="iforest-job-v1")
    )

    job_id = "test-job-anomaly-123"
    sess = TcpSession(
        id="sess-anom-1",
        job_id=job_id,
        tcp_stream=0,
        client_ip="192.168.1.50",
        server_ip="192.168.1.100",
        client_port=49152,
        server_port=465,
        first_frame_number=1,
        last_frame_number=10,
        packet_count=10,
        total_payload_bytes=1500
    )
    db_session.add(sess)
    db_session.commit()

    # Predict job anomalies
    resp = client.post(f"/api/v1/ml/anomaly/predict-job/{job_id}")
    assert resp.status_code == 200
    summary = resp.json()

    assert summary["job_id"] == job_id
    assert summary["total_sessions_evaluated"] == 1
    assert "anomaly_rate_percent" in summary
    assert "disclaimer_text" in summary

    # Get saved job anomaly summary
    get_resp = client.get(f"/api/v1/ml/anomaly/job/{job_id}")
    assert get_resp.status_code == 200
    saved_summary = get_resp.json()
    assert saved_summary["job_id"] == job_id
    assert len(saved_summary["results"]) == 1
