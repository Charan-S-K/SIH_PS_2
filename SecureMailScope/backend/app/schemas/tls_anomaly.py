"""
Pydantic Schemas for TLS Anomaly Detection.
Defines model training requests, anomaly score outputs, calibrated thresholds, and non-malice disclaimers.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TlsAnomalyTrainRequest(BaseModel):
    """Request payload to train an unsupervised Isolation Forest anomaly detector."""
    feature_set_id: str = Field(description="ID of the baseline feature set  to fit normal behavior")
    version: Optional[str] = Field(default=None, description="Custom version string e.g. iforest-v1.0.0")
    name: Optional[str] = Field(default="TLS Isolation Forest Anomaly Detector", description="Detector name")
    contamination: float = Field(default=0.05, ge=0.01, le=0.2, description="Expected proportion of anomalies in baseline")
    n_estimators: int = Field(default=100, ge=10, le=500, description="Number of isolation trees")
    random_state: int = Field(default=42, description="Random seed for reproducible training")


class TlsAnomalyDetectorResponse(BaseModel):
    """Schema for trained Isolation Forest detector model metadata."""
    id: str
    name: str
    version: str
    algorithm: str
    contamination: float
    calibrated_threshold: float
    n_estimators: int
    random_state: int
    feature_set_id: Optional[str] = None
    baseline_samples_count: int
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class TlsAnomalyPredictRequest(BaseModel):
    """Request payload to evaluate anomaly score for an input feature vector."""
    model_version: Optional[str] = Field(default=None, description="Target model version string")
    features_json: Dict[str, Any] = Field(description="Dictionary of input feature vector values")
    job_id: Optional[str] = Field(default=None, description="Associated job ID")
    tcp_stream: Optional[int] = Field(default=None, description="Associated TCP stream ID")


class TlsAnomalyResponse(BaseModel):
    """Schema for individual anomaly evaluation result."""
    id: str
    model_id: str
    model_version: str
    job_id: Optional[str] = None
    tcp_stream: Optional[int] = None
    raw_anomaly_score: float
    calibrated_threshold: float
    is_anomalous: bool
    anomaly_label: str
    disclaimer_text: str = Field(description="Explicit label: Anomalous behavior indicator only; not proof of attack")
    features_json: Dict[str, Any]
    execution_time_ms: float
    created_at: datetime

    class Config:
        from_attributes = True


class JobAnomalySummaryResponse(BaseModel):
    """Schema for aggregate job-level anomaly evaluation results."""
    job_id: str
    model_version: str
    total_sessions_evaluated: int
    anomalous_sessions_count: int
    anomaly_rate_percent: float
    calibrated_threshold: float
    disclaimer_text: str
    results: List[TlsAnomalyResponse]
