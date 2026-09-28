"""
Pydantic Schemas for Stage 15: ML Risk Classifier.
Defines model training requests, evaluation metrics, prediction requests, and inference outputs.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MlTrainModelRequest(BaseModel):
    """Request payload to train an explainable ML Risk Classifier."""
    feature_set_id: str = Field(description="ID of the extracted feature set (Stage 14) to train on")
    version: Optional[str] = Field(default=None, description="Custom version identifier e.g. rf-v1.0.0")
    name: Optional[str] = Field(default="Random Forest Email Security Classifier", description="Model display name")
    n_estimators: int = Field(default=100, ge=10, le=500, description="Number of decision trees in Random Forest")
    max_depth: Optional[int] = Field(default=12, ge=2, le=50, description="Maximum depth of decision trees")
    random_state: int = Field(default=42, description="Random state seed for reproducible model training")


class MlEvaluationMetrics(BaseModel):
    """Schema for model evaluation metrics on test split."""
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    confusion_matrix: List[List[int]]
    class_report: Dict[str, Any]
    feature_importances: Dict[str, float]


class MlTrainedModelResponse(BaseModel):
    """Schema for trained ML model metadata and evaluation results."""
    id: str
    name: str
    version: str
    algorithm: str
    hyperparameters: Dict[str, Any] = Field(alias="hyperparameters_json")
    feature_set_id: Optional[str] = None
    accuracy: float
    precision_macro: float
    recall_macro: float
    f1_macro: float
    confusion_matrix: List[List[int]] = Field(alias="confusion_matrix_json")
    class_report: Dict[str, Any] = Field(alias="class_report_json")
    feature_importances: Dict[str, float] = Field(alias="feature_importances_json")
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


class MlPredictRequest(BaseModel):
    """Request payload for ML inference prediction on feature input."""
    model_version: Optional[str] = Field(default=None, description="Target model version (uses active model if None)")
    features_json: Dict[str, Any] = Field(description="Dictionary of input feature vector values")
    job_id: Optional[str] = Field(default=None, description="Associated job ID if predicting for a session")
    tcp_stream: Optional[int] = Field(default=None, description="Associated TCP stream ID")


class MlPredictionResponse(BaseModel):
    """Schema for ML risk prediction output."""
    id: str
    model_id: str
    model_version: str
    job_id: Optional[str] = None
    tcp_stream: Optional[int] = None
    predicted_class_code: int
    predicted_label: str
    confidence_probabilities: Dict[str, float]
    is_deterministic_fact_overridden: bool = Field(default=False, description="Guaranteed False: ML never overrides deterministic rule facts")
    inference_time_ms: float
    created_at: datetime

    class Config:
        from_attributes = True


class MlJobPredictionListResponse(BaseModel):
    """Schema for job-level predictions across streams."""
    job_id: str
    model_version: str
    total_predicted_sessions: number if False else int
    predictions: List[MlPredictionResponse]
