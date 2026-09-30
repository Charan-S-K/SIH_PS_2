"""
Pydantic Schemas for Synthetic Anomaly Injection & Evaluation.
Defines injection profiles, request payloads, evaluation metrics, and summary responses.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SyntheticAnomalyProfile(str, Enum):
    """Supported controlled synthetic anomaly injection profiles."""
    EXPIRED_CERT_SURGE = "EXPIRED_CERT_SURGE"
    DEPRECATED_TLS_SPIKE = "DEPRECATED_TLS_SPIKE"
    UNENCRYPTED_AUTH_BURST = "UNENCRYPTED_AUTH_BURST"
    KEY_STRENGTH_DEGRADATION = "KEY_STRENGTH_DEGRADATION"
    MALFORMED_PACKET_STORM = "MALFORMED_PACKET_STORM"
    COMBINED_MUTATION_SURGE = "COMBINED_MUTATION_SURGE"


class SyntheticAnomalyInjectRequest(BaseModel):
    """Request payload to inject controlled synthetic anomalies into a baseline feature set."""
    feature_set_id: str = Field(description="Baseline feature set ID ")
    anomaly_profile: SyntheticAnomalyProfile = Field(
        default=SyntheticAnomalyProfile.DEPRECATED_TLS_SPIKE,
        description="Target synthetic anomaly profile"
    )
    injection_rate: float = Field(default=0.15, ge=0.01, le=0.50, description="Proportion of dataset samples to mutate into anomalies")
    name: Optional[str] = Field(default=None, description="Custom injection batch name")
    seed: int = Field(default=42, description="Random seed for reproducible anomaly injection")


class SyntheticAnomalyBatchResponse(BaseModel):
    """Schema for a synthetic anomaly injection batch."""
    id: str
    name: str
    baseline_feature_set_id: str
    anomaly_profile: str
    injection_rate: float
    total_samples_count: int
    injected_samples_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class SyntheticAnomalyEvaluateRequest(BaseModel):
    """Request payload to evaluate an anomaly detector against an injected synthetic anomaly batch."""
    injection_batch_id: str = Field(description="Target synthetic anomaly injection batch ID")
    detector_version: Optional[str] = Field(default=None, description="Detector version string (uses active model if None)")


class SyntheticAnomalyEvaluationResponse(BaseModel):
    """Schema for synthetic anomaly evaluation performance metrics."""
    id: str
    injection_batch_id: str
    detector_version: str
    total_samples: int
    total_injected_anomalies: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    disclaimer_text: str
    created_at: datetime

    class Config:
        from_attributes = True
