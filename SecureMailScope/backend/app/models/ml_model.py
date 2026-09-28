"""
SQLAlchemy Model for Stage 15: ML Risk Classifier.
Stores trained Random Forest ML model versions, evaluation metrics (precision, recall, F1, confusion matrix),
feature importances, and inference prediction logs.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class MlTrainedModel(Base):
    """
    Represents a trained, evaluated, and versioned scikit-learn ML risk classification model.
    """
    __tablename__ = "ml_trained_models"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    name = Column(String, nullable=False, default="Random Forest Email Security Classifier")
    version = Column(String, nullable=False, unique=True, default="rf-v1.0.0")
    algorithm = Column(String, nullable=False, default="RandomForestClassifier")
    hyperparameters_json = Column(JSON, nullable=False, default=dict)
    feature_set_id = Column(String, ForeignKey("ml_feature_sets.id", ondelete="SET NULL"), nullable=True)

    # Evaluation Metrics
    accuracy = Column(Float, nullable=False, default=0.0)
    precision_macro = Column(Float, nullable=False, default=0.0)
    recall_macro = Column(Float, nullable=False, default=0.0)
    f1_macro = Column(Float, nullable=False, default=0.0)
    confusion_matrix_json = Column(JSON, nullable=False, default=list)
    class_report_json = Column(JSON, nullable=False, default=dict)
    feature_importances_json = Column(JSON, nullable=False, default=dict)

    is_active = Column(Boolean, nullable=False, default=True)
    model_artifact_path = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    predictions = relationship("MlPredictionResult", back_populates="model", cascade="all, delete-orphan")


class MlPredictionResult(Base):
    """
    Inference prediction log for a single session or feature vector.
    """
    __tablename__ = "ml_prediction_results"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    model_id = Column(String, ForeignKey("ml_trained_models.id", ondelete="CASCADE"), nullable=False)
    model_version = Column(String, nullable=False)
    job_id = Column(String, nullable=True)
    tcp_stream = Column(Integer, nullable=True)

    # Output probabilities and classification
    predicted_class_code = Column(Integer, nullable=False)
    predicted_label = Column(String, nullable=False)  # SECURE, WEAK_CRYPTO, PLAINTEXT_LEAK, DOWNGRADE_ATTACK, ANOMALOUS
    confidence_probabilities_json = Column(JSON, nullable=False, default=dict)

    # Non-override constraint flag (always False to ensure ML never overwrites deterministic facts)
    is_deterministic_fact_overridden = Column(Boolean, nullable=False, default=False)
    inference_time_ms = Column(Float, nullable=False, default=0.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    model = relationship("MlTrainedModel", back_populates="predictions")
