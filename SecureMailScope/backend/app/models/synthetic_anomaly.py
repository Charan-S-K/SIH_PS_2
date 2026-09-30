"""
SQLAlchemy models for Synthetic Anomaly Injection & Evaluation.
Tracks synthetic anomaly injection profiles, injected dataset ground truth,
and evaluation metrics (precision, recall, detection rate, false positive rate).
"""

import uuid
from sqlalchemy import Column, String, Integer, Float, Boolean, JSON, ForeignKey
from app.database import Base
from app.models.base import TimestampMixin


class SyntheticAnomalyBatch(Base, TimestampMixin):
    """Represents a dataset batch injected with controlled synthetic anomalies."""
    __tablename__ = "synthetic_anomaly_batches"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String(128), nullable=False)
    baseline_feature_set_id = Column(String(36), ForeignKey("ml_feature_sets.id", ondelete="CASCADE"), nullable=False)
    anomaly_profile = Column(String(64), nullable=False)  # e.g. DEPRECATED_TLS_SPIKE, UNENCRYPTED_AUTH_BURST
    injection_rate = Column(Float, nullable=False, default=0.10)  # Proportion of samples injected
    total_samples_count = Column(Integer, nullable=False, default=0)
    injected_samples_count = Column(Integer, nullable=False, default=0)
    
    # Serialized injected dataset matrix and ground truth binary vector
    injected_data_json = Column(JSON, nullable=False)  # {"X_injected": [...], "y_ground_truth": [...]}
    metadata_json = Column(JSON, nullable=True)


class SyntheticAnomalyEvaluation(Base, TimestampMixin):
    """Represents evaluation metrics of an anomaly detector tested against injected ground truth."""
    __tablename__ = "synthetic_anomaly_evaluations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    injection_batch_id = Column(String(36), ForeignKey("synthetic_anomaly_batches.id", ondelete="CASCADE"), nullable=False)
    detector_version = Column(String(64), nullable=False)
    
    # Evaluation Metrics
    total_samples = Column(Integer, nullable=False)
    total_injected_anomalies = Column(Integer, nullable=False)
    true_positives = Column(Integer, nullable=False, default=0)
    false_positives = Column(Integer, nullable=False, default=0)
    true_negatives = Column(Integer, nullable=False, default=0)
    false_negatives = Column(Integer, nullable=False, default=0)
    
    precision = Column(Float, nullable=False, default=0.0)
    recall = Column(Float, nullable=False, default=0.0)  # Detection rate
    f1_score = Column(Float, nullable=False, default=0.0)
    false_positive_rate = Column(Float, nullable=False, default=0.0)
    
    disclaimer_text = Column(String(255), nullable=False)
    evaluation_metadata_json = Column(JSON, nullable=True)
