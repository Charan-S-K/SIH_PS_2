"""
SQLAlchemy Model for Stage 16: TLS Anomaly Detection.
Stores unsupervised Isolation Forest detector models, calibrated decision thresholds,
raw anomaly scores, and explicit non-malice proof disclaimers.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class TlsAnomalyDetectorModel(Base):
    """
    Represents an unsupervised Isolation Forest anomaly detection model for TLS/email traffic.
    """
    __tablename__ = "tls_anomaly_detector_models"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, default="TLS Isolation Forest Anomaly Detector")
    version = Column(String, nullable=False, unique=True, default="iforest-v1.0.0")
    algorithm = Column(String, nullable=False, default="IsolationForest")
    contamination = Column(Float, nullable=False, default=0.05)
    calibrated_threshold = Column(Float, nullable=False, default=-0.1)
    n_estimators = Column(Integer, nullable=False, default=100)
    random_state = Column(Integer, nullable=False, default=42)
    feature_set_id = Column(String, ForeignKey("ml_feature_sets.id", ondelete="SET NULL"), nullable=True)

    baseline_samples_count = Column(Integer, nullable=False, default=0)
    is_active = Column(Boolean, nullable=False, default=True)
    model_artifact_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    results = relationship("TlsAnomalyResult", back_populates="model", cascade="all, delete-orphan")


class TlsAnomalyResult(Base):
    """
    Anomaly evaluation result for a single TCP session or feature vector.
    """
    __tablename__ = "tls_anomaly_results"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    model_id = Column(String, ForeignKey("tls_anomaly_detector_models.id", ondelete="CASCADE"), nullable=False)
    model_version = Column(String, nullable=False)
    job_id = Column(String, nullable=True)
    tcp_stream = Column(Integer, nullable=True)

    # Anomaly scoring outputs
    raw_anomaly_score = Column(Float, nullable=False)
    calibrated_threshold = Column(Float, nullable=False)
    is_anomalous = Column(Boolean, nullable=False, default=False)
    anomaly_label = Column(String, nullable=False, default="ANOMALOUS_BEHAVIOR")
    disclaimer_text = Column(
        String,
        nullable=False,
        default="Anomalous behavior indicator only; does not constitute definitive proof of a malicious attack."
    )

    features_json = Column(JSON, nullable=False, default=dict)
    execution_time_ms = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    model = relationship("TlsAnomalyDetectorModel", back_populates="results")
