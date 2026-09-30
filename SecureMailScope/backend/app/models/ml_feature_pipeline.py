"""
SQLAlchemy Model for ML Feature Pipeline.
Stores versioned feature extraction definitions, preprocessed feature matrices,
train/test splits, and data leakage verification reports.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, JSON, DateTime, ForeignKey
from sqlalchemy.orm import relationship

from app.database import Base


class MlFeatureSet(Base):
    """
    Represents an extracted, preprocessed, and versioned feature dataset for ML training.
    """
    __tablename__ = "ml_feature_sets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    pipeline_version = Column(String, nullable=False, default="v1.0.0")
    source_batch_id = Column(String, nullable=True)  # Associated dataset batch ID
    source_job_id = Column(String, nullable=True)  # Associated analysis job ID
    total_samples = Column(Integer, nullable=False, default=0)
    feature_count = Column(Integer, nullable=False, default=10)
    
    # Train / Test split metadata
    test_split_ratio = Column(Float, nullable=False, default=0.2)
    train_samples_count = Column(Integer, nullable=False, default=0)
    test_samples_count = Column(Integer, nullable=False, default=0)
    random_seed = Column(Integer, nullable=False, default=42)
    
    # Feature schema and preprocessing parameters (mean, std, feature names)
    feature_schema_json = Column(JSON, nullable=False, default=dict)
    preprocessing_params_json = Column(JSON, nullable=False, default=dict)
    
    # Data leakage check verification status
    leakage_check_passed = Column(Boolean, nullable=False, default=True)
    leakage_check_details_json = Column(JSON, nullable=False, default=dict)

    # Extracted X_train, X_test, y_train, y_test matrices
    train_split_json = Column(JSON, nullable=False, default=dict)
    test_split_json = Column(JSON, nullable=False, default=dict)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
