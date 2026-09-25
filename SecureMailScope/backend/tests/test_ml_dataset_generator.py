"""
Unit and Integration Tests for Stage 13: ML Dataset Generator.
Verifies seed determinism, ground truth security labeling, feature vector standardization,
label rationales, and REST API endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.ml_dataset import MlDatasetBatch, MlDatasetRecord
from app.schemas.ml_dataset import MlDatasetGenerateRequest
from app.services.ml_dataset_generator import MlDatasetGenerator, LABEL_MAP


def test_generate_dataset_batch_deterministic(db_session: Session):
    """Verify that using the same random seed produces identical synthetic dataset records."""
    generator = MlDatasetGenerator()
    req1 = MlDatasetGenerateRequest(name="Batch Seed 42 Run 1", sample_count=20, seed=42)
    req2 = MlDatasetGenerateRequest(name="Batch Seed 42 Run 2", sample_count=20, seed=42)

    batch1 = generator.generate_dataset_batch(db_session, req1)
    batch2 = generator.generate_dataset_batch(db_session, req2)

    assert batch1.sample_count == 20
    assert batch2.sample_count == 20

    records1 = db_session.query(MlDatasetRecord).filter(MlDatasetRecord.batch_id == batch1.id).order_by(MlDatasetRecord.sample_index).all()
    records2 = db_session.query(MlDatasetRecord).filter(MlDatasetRecord.batch_id == batch2.id).order_by(MlDatasetRecord.sample_index).all()

    assert len(records1) == len(records2) == 20

    for r1, r2 in zip(records1, records2):
        assert r1.scenario_name == r2.scenario_name
        assert r1.protocol == r2.protocol
        assert r1.ground_truth_label == r2.ground_truth_label
        assert r1.label_code == r2.label_code
        assert r1.packet_count == r2.packet_count
        assert r1.duration_seconds == r2.duration_seconds
        assert r1.features_json == r2.features_json


def test_ground_truth_labeling_and_rationales(db_session: Session):
    """Verify that every synthetic scenario receives the correct ground truth label, code, and rationale."""
    generator = MlDatasetGenerator()
    req = MlDatasetGenerateRequest(name="Ground Truth Test", sample_count=50, seed=123)
    batch = generator.generate_dataset_batch(db_session, req)

    records = db_session.query(MlDatasetRecord).filter(MlDatasetRecord.batch_id == batch.id).all()
    assert len(records) == 50

    for r in records:
        assert r.ground_truth_label in LABEL_MAP
        assert r.label_code == LABEL_MAP[r.ground_truth_label][0]
        assert len(r.label_rationale) > 10

        # Scenario specific assertions
        if r.scenario_name == "SECURE_SMTPS_TLS13":
            assert r.ground_truth_label == "SECURE"
            assert r.label_code == 0
            assert r.tls_version == "TLS 1.3"
        elif r.scenario_name == "WEAK_TLS10_DEPRECATED":
            assert r.ground_truth_label == "WEAK_CRYPTO"
            assert r.label_code == 1
            assert r.tls_version == "TLS 1.0"
        elif r.scenario_name == "PLAINTEXT_SMTP_AUTH":
            assert r.ground_truth_label == "PLAINTEXT_LEAK"
            assert r.label_code == 2
            assert r.tls_version is None
        elif r.scenario_name == "STARTTLS_STRIPPED_DOWNGRADE":
            assert r.ground_truth_label == "DOWNGRADE_ATTACK"
            assert r.label_code == 3
        elif r.scenario_name == "ANOMALOUS_BURST_TRAFFIC":
            assert r.ground_truth_label == "ANOMALOUS"
            assert r.label_code == 4


def test_standardized_ml_feature_vector(db_session: Session):
    """Verify extracted ML feature vector keys and data types."""
    generator = MlDatasetGenerator()
    req = MlDatasetGenerateRequest(name="Features Test", sample_count=10, seed=999)
    batch = generator.generate_dataset_batch(db_session, req)

    records = db_session.query(MlDatasetRecord).filter(MlDatasetRecord.batch_id == batch.id).all()

    required_keys = [
        "protocol_code", "tls_version_code", "cipher_strength_bits",
        "is_starttls_used", "is_auth_encrypted", "cert_validity_code",
        "packet_count", "duration_seconds", "total_bytes", "avg_packet_size"
    ]

    for r in records:
        f = r.features_json
        assert isinstance(f, dict)
        for key in required_keys:
            assert key in f, f"Missing feature key '{key}' in sample {r.sample_index}"

        assert isinstance(f["packet_count"], int)
        assert isinstance(f["duration_seconds"], (int, float))
        assert isinstance(f["avg_packet_size"], (int, float))


def test_ml_dataset_api_endpoints(client: TestClient, db_session: Session):
    """Integration test for Stage 13 ML Dataset Generator REST API endpoints."""
    # 1. POST /api/v1/ml/dataset/generate
    res_gen = client.post(
        "/api/v1/ml/dataset/generate",
        json={"name": "API Test Dataset", "sample_count": 30, "seed": 777}
    )
    assert res_gen.status_code == 200
    batch_data = res_gen.json()
    batch_id = batch_data["id"]
    assert batch_data["sample_count"] == 30
    assert batch_data["seed"] == 777

    # 2. GET /api/v1/ml/dataset/batches
    res_list = client.get("/api/v1/ml/dataset/batches")
    assert res_list.status_code == 200
    batches_list = res_list.json()
    assert len(batches_list) >= 1

    # 3. GET /api/v1/ml/dataset/batches/{batch_id}
    res_details = client.get(f"/api/v1/ml/dataset/batches/{batch_id}")
    assert res_details.status_code == 200
    details_data = res_details.json()
    assert details_data["id"] == batch_id
    assert len(details_data["records"]) == 30

    # 4. GET /api/v1/ml/dataset/export/{batch_id}/csv
    res_csv = client.get(f"/api/v1/ml/dataset/export/{batch_id}/csv")
    assert res_csv.status_code == 200
    assert "text/csv" in res_csv.headers["content-type"]
    assert "sample_index,scenario_name,protocol" in res_csv.text
