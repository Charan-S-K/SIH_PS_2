"""
Pydantic Schemas for Stage 14: ML Feature Pipeline.
Defines requests, versioned feature schemas, train/test split metadata, and leakage check reports.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MlFeatureExtractionRequest(BaseModel):
    """Request payload to extract and preprocess feature matrix."""
    batch_id: Optional[str] = Field(default=None, description="Dataset batch ID to extract features from")
    job_id: Optional[str] = Field(default=None, description="Analysis job ID to extract features from")
    pipeline_version: str = Field(default="v1.0.0", description="Feature extraction pipeline version")
    test_split_ratio: float = Field(default=0.2, ge=0.1, le=0.5, description="Fraction of data allocated to test split")
    random_seed: int = Field(default=42, description="Random seed for reproducible train/test split")


class MlDataLeakageReport(BaseModel):
    """Report detailing verification against data leakage between train and test sets."""
    passed: bool
    overlap_sample_ids_count: int
    scaler_fit_on_train_only: bool
    train_samples_count: int
    test_samples_count: int
    summary: str


class MlFeatureSetResponse(BaseModel):
    """Schema for versioned feature set response."""
    id: str
    pipeline_version: str
    source_batch_id: Optional[str] = None
    source_job_id: Optional[str] = None
    total_samples: int
    feature_count: int
    test_split_ratio: float
    train_samples_count: int
    test_samples_count: int
    random_seed: int
    feature_schema: Dict[str, Any] = Field(alias="feature_schema_json")
    preprocessing_params: Dict[str, Any] = Field(alias="preprocessing_params_json")
    leakage_check_passed: bool
    leakage_check_details: Dict[str, Any] = Field(alias="leakage_check_details_json")
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


class MlTrainTestSplitResponse(BaseModel):
    """Schema returning X_train, X_test, y_train, y_test matrices."""
    feature_set_id: str
    pipeline_version: str
    feature_names: List[str]
    train_samples_count: int
    test_samples_count: int
    X_train: List[List[float]]
    X_test: List[List[float]]
    y_train: List[int]
    y_test: List[int]
    train_sample_ids: List[str]
    test_sample_ids: List[str]
